"""Tool: get_binary_signatures — certificate / code-signing info."""

from __future__ import annotations

from typing import Any

import lief

from app import mcp
from helpers import hex_addr, safe_enum, format_name, parse_binary, _error


def _x509_info(cert: lief.PE.x509) -> dict[str, Any]:
    """Extract fields from a single x509 certificate."""
    return {
        "issuer": cert.issuer,
        "subject": cert.subject,
        "version": cert.version,
        "serial_number": cert.serial_number,
        "valid_from": cert.valid_from,
        "valid_to": cert.valid_to,
        "signature_algorithm": cert.signature_algorithm,
        "is_ca": cert.is_ca,
    }


def _pe_signatures(binary: lief.PE.Binary) -> dict[str, Any]:
    """Authenticode / x509 info for a PE binary."""
    if not binary.has_signatures:
        return {"signed": False, "signatures": []}

    result: dict[str, Any] = {
        "signed": True,
        "verification": str(binary.verify_signature()),
        "signatures": [],
    }

    for sig in binary.signatures:
        sig_info: dict[str, Any] = {
            "version": sig.version,
            "digest_algorithm": safe_enum(sig.digest_algorithm),
        }

        # Content info
        ci = sig.content_info
        sig_info["content_info"] = {
            "content_type": ci.content_type,
            "digest_algorithm": safe_enum(ci.digest_algorithm),
            "digest": ci.digest.hex() if ci.digest else None,
        }

        # Signer info
        signers = []
        for signer in sig.signers:
            signer_info: dict[str, Any] = {
                "version": signer.version,
                "issuer": signer.issuer,
                "serial_number": signer.serial_number,
                "digest_algorithm": safe_enum(signer.digest_algorithm),
                "signature_algorithm": safe_enum(signer.signature_algorithm),
                "encrypted_digest": signer.encrypted_digest[:32].hex() + "..."
                if len(signer.encrypted_digest) > 32
                else signer.encrypted_digest.hex(),
            }
            cert = signer.cert
            if cert is not None:
                signer_info["certificate"] = _x509_info(cert)
            signers.append(signer_info)
        sig_info["signers"] = signers

        # Full certificate chain
        sig_info["certificates"] = [_x509_info(c) for c in sig.certificates]

        result["signatures"].append(sig_info)

    return result


def _macho_code_signature(binary: lief.MachO.Binary) -> dict[str, Any]:
    """LC_CODE_SIGNATURE info for a Mach-O binary."""
    result: dict[str, Any] = {
        "has_code_signature": binary.has_code_signature,
    }

    if not binary.has_code_signature:
        return result

    code_sig = binary.code_signature
    result["data_offset"] = hex_addr(code_sig.data_offset)
    result["data_size"] = code_sig.data_size

    # Content as raw bytes for the signature blob
    content = code_sig.content
    if content is not None and len(content) > 0:
        # Parse the SuperBlob magic to identify structure
        if len(content) >= 4:
            magic = int.from_bytes(bytes(content[:4]), "big")
            result["magic"] = hex_addr(magic)
            MAGIC_NAMES = {
                0xFADE0CC0: "CSMAGIC_EMBEDDED_SIGNATURE",
                0xFADE0B01: "CSMAGIC_REQUIREMENT",
                0xFADE0B02: "CSMAGIC_REQUIREMENTS",
                0xFADE0C00: "CSMAGIC_CODEDIRECTORY",
                0xFADE0C02: "CSMAGIC_EMBEDDED_ENTITLEMENTS",
                0xFADE7171: "CSMAGIC_BLOBWRAPPER",
            }
            result["magic_name"] = MAGIC_NAMES.get(magic, "UNKNOWN")
        if len(content) >= 12:
            blob_length = int.from_bytes(bytes(content[4:8]), "big")
            blob_count = int.from_bytes(bytes(content[8:12]), "big")
            result["blob_length"] = blob_length
            result["blob_count"] = blob_count

        # Parse CodeDirectory if present within the SuperBlob
        result["blobs"] = _parse_superblob(content)

    return result


def _parse_superblob(content) -> list[dict[str, Any]]:
    """Parse individual blob entries from an embedded signature SuperBlob."""
    data = bytes(content)
    if len(data) < 12:
        return []

    magic = int.from_bytes(data[:4], "big")
    if magic != 0xFADE0CC0:  # CSMAGIC_EMBEDDED_SIGNATURE
        return []

    count = int.from_bytes(data[8:12], "big")
    blobs = []

    SLOT_NAMES = {
        0: "CodeDirectory",
        1: "InfoSlot",
        2: "Requirements",
        3: "ResourceDir",
        4: "Application",
        5: "Entitlements",
        0x1000: "CMS_Signature",
    }
    BLOB_MAGIC_NAMES = {
        0xFADE0C00: "CSMAGIC_CODEDIRECTORY",
        0xFADE0B01: "CSMAGIC_REQUIREMENT",
        0xFADE0B02: "CSMAGIC_REQUIREMENTS",
        0xFADE0C02: "CSMAGIC_EMBEDDED_ENTITLEMENTS",
        0xFADE7171: "CSMAGIC_BLOBWRAPPER",
    }

    for i in range(count):
        idx_offset = 12 + i * 8
        if idx_offset + 8 > len(data):
            break
        slot_type = int.from_bytes(data[idx_offset:idx_offset + 4], "big")
        blob_offset = int.from_bytes(data[idx_offset + 4:idx_offset + 8], "big")

        blob_entry: dict[str, Any] = {
            "slot": slot_type,
            "slot_name": SLOT_NAMES.get(slot_type, f"Unknown(0x{slot_type:x})"),
            "offset": hex_addr(blob_offset),
        }

        if blob_offset + 8 <= len(data):
            blob_magic = int.from_bytes(data[blob_offset:blob_offset + 4], "big")
            blob_length = int.from_bytes(data[blob_offset + 4:blob_offset + 8], "big")
            blob_entry["magic"] = hex_addr(blob_magic)
            blob_entry["magic_name"] = BLOB_MAGIC_NAMES.get(
                blob_magic, f"Unknown(0x{blob_magic:x})"
            )
            blob_entry["length"] = blob_length

            # Extract CodeDirectory details
            if blob_magic == 0xFADE0C00 and blob_offset + 44 <= len(data):
                cd = data[blob_offset:]
                blob_entry["code_directory"] = _parse_code_directory(cd)

        blobs.append(blob_entry)

    return blobs


def _parse_code_directory(cd: bytes) -> dict[str, Any]:
    """Parse a CodeDirectory blob."""
    HASH_TYPES = {
        0: "none",
        1: "SHA-1",
        2: "SHA-256",
        3: "SHA-256_truncated",
        4: "SHA-384",
    }

    version = int.from_bytes(cd[8:12], "big")
    flags = int.from_bytes(cd[12:16], "big")
    ident_offset = int.from_bytes(cd[20:24], "big")
    n_special_slots = int.from_bytes(cd[24:28], "big")
    n_code_slots = int.from_bytes(cd[28:32], "big")
    code_limit = int.from_bytes(cd[32:36], "big")
    hash_size = cd[36]
    hash_type = cd[37]
    page_size = cd[39]

    info: dict[str, Any] = {
        "version": hex_addr(version),
        "flags": hex_addr(flags),
        "hash_type": HASH_TYPES.get(hash_type, f"Unknown({hash_type})"),
        "hash_size": hash_size,
        "page_size": 2 ** page_size if page_size else 0,
        "n_special_slots": n_special_slots,
        "n_code_slots": n_code_slots,
        "code_limit": code_limit,
    }

    # Extract the signing identity string
    if ident_offset < len(cd):
        end = cd.index(0, ident_offset) if 0 in cd[ident_offset:] else len(cd)
        info["identity"] = cd[ident_offset:end].decode("utf-8", errors="replace")

    return info


@mcp.tool()
def get_binary_signatures(file_path: str) -> dict:
    """Certificate and code-signing info for a binary.

    PE: Authenticode signatures, x509 certificate chain, verification status.
    Mach-O: LC_CODE_SIGNATURE — SuperBlob structure, CodeDirectory, identity, hash type.
    """
    try:
        binary = parse_binary(file_path)
    except ValueError as exc:
        return _error(str(exc))

    fmt = format_name().get(binary.format, "Unknown")

    if isinstance(binary, lief.PE.Binary):
        result = _pe_signatures(binary)
    elif isinstance(binary, lief.MachO.Binary):
        result = _macho_code_signature(binary)
    else:
        return _error(f"Signature extraction not supported for {fmt} binaries.")

    result["format"] = fmt
    return result
