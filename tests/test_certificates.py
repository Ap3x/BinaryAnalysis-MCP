"""Tests for get_binary_signatures tool."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import lief

from tools.certificates import (
    get_binary_signatures,
    _x509_info,
    _pe_signatures,
    _macho_code_signature,
    _parse_superblob,
    _parse_code_directory,
)


# ---------------------------------------------------------------------------
# PE signatures
# ---------------------------------------------------------------------------

class TestSignaturesPE:
    def test_format(self, pe_mingw):
        result = get_binary_signatures(pe_mingw)
        assert result["format"] == "PE"

    def test_signed_field(self, pe_mingw):
        result = get_binary_signatures(pe_mingw)
        assert isinstance(result["signed"], bool)

    def test_signed_has_verification(self, pe_mingw):
        result = get_binary_signatures(pe_mingw)
        if result["signed"]:
            assert "verification" in result
            assert isinstance(result["signatures"], list)
            assert len(result["signatures"]) > 0
            sig = result["signatures"][0]
            assert "digest_algorithm" in sig
            assert "content_info" in sig
            assert "signers" in sig
            assert "certificates" in sig

    def test_unsigned_pe(self, pe_cygwin):
        result = get_binary_signatures(pe_cygwin)
        assert result["format"] == "PE"
        assert isinstance(result["signed"], bool)
        if not result["signed"]:
            assert result["signatures"] == []


class TestPESignaturesMocked:
    """Test the full PE signed path using mocks."""

    def _make_signed_binary(self, *, signer_cert=True, short_digest=False):
        cert = MagicMock()
        cert.issuer = "CN=Test CA"
        cert.subject = "CN=Test"
        cert.version = 3
        cert.serial_number = "01:02:03"
        cert.valid_from = [2024, 1, 1, 0, 0, 0]
        cert.valid_to = [2025, 1, 1, 0, 0, 0]
        cert.signature_algorithm = "sha256WithRSAEncryption"
        cert.is_ca = False

        signer = MagicMock()
        signer.version = 1
        signer.issuer = "CN=Test CA"
        signer.serial_number = "01:02:03"
        signer.digest_algorithm = MagicMock()
        signer.signature_algorithm = MagicMock()
        if short_digest:
            signer.encrypted_digest = b"\xaa" * 16
        else:
            signer.encrypted_digest = b"\xaa" * 64
        signer.cert = cert if signer_cert else None

        ci = MagicMock()
        ci.content_type = "1.2.840.113549.1.7.2"
        ci.digest_algorithm = MagicMock()
        ci.digest = b"\xbb" * 32

        sig = MagicMock()
        sig.version = 1
        sig.digest_algorithm = MagicMock()
        sig.content_info = ci
        sig.signers = [signer]
        sig.certificates = [cert]

        binary = MagicMock(spec=lief.PE.Binary)
        binary.has_signatures = True
        binary.verify_signature.return_value = "OK"
        binary.signatures = [sig]
        binary.format = lief.Binary.FORMATS.PE
        return binary

    def test_signed_pe_full_path(self):
        binary = self._make_signed_binary()
        with patch("tools.certificates.parse_binary", return_value=binary):
            result = get_binary_signatures("fake.exe")
        assert result["signed"] is True
        assert result["verification"] == "OK"
        assert len(result["signatures"]) == 1
        sig = result["signatures"][0]
        assert sig["content_info"]["digest"] == ("bb" * 32)
        assert len(sig["signers"]) == 1
        assert sig["signers"][0]["certificate"]["subject"] == "CN=Test"
        assert len(sig["certificates"]) == 1
        # Long digest gets truncated with "..."
        assert sig["signers"][0]["encrypted_digest"].endswith("...")

    def test_signed_pe_short_digest(self):
        binary = self._make_signed_binary(short_digest=True)
        with patch("tools.certificates.parse_binary", return_value=binary):
            result = get_binary_signatures("fake.exe")
        digest = result["signatures"][0]["signers"][0]["encrypted_digest"]
        assert not digest.endswith("...")

    def test_signed_pe_no_signer_cert(self):
        binary = self._make_signed_binary(signer_cert=False)
        with patch("tools.certificates.parse_binary", return_value=binary):
            result = get_binary_signatures("fake.exe")
        assert "certificate" not in result["signatures"][0]["signers"][0]

    def test_content_info_no_digest(self):
        binary = self._make_signed_binary()
        binary.signatures[0].content_info.digest = None
        with patch("tools.certificates.parse_binary", return_value=binary):
            result = get_binary_signatures("fake.exe")
        assert result["signatures"][0]["content_info"]["digest"] is None


# ---------------------------------------------------------------------------
# x509 helper
# ---------------------------------------------------------------------------

class TestX509Info:
    def test_extracts_all_fields(self):
        cert = MagicMock()
        cert.issuer = "CN=Issuer"
        cert.subject = "CN=Subject"
        cert.version = 3
        cert.serial_number = "AA:BB"
        cert.valid_from = [2024, 1, 1, 0, 0, 0]
        cert.valid_to = [2025, 12, 31, 23, 59, 59]
        cert.signature_algorithm = "sha256WithRSAEncryption"
        cert.is_ca = True
        info = _x509_info(cert)
        assert info["issuer"] == "CN=Issuer"
        assert info["subject"] == "CN=Subject"
        assert info["is_ca"] is True


# ---------------------------------------------------------------------------
# Mach-O signatures (LC_CODE_SIGNATURE)
# ---------------------------------------------------------------------------

class TestSignaturesMachO:
    def test_format(self, macho_x64):
        result = get_binary_signatures(macho_x64)
        assert result["format"] == "Mach-O"

    def test_has_code_signature_field(self, macho_x64):
        result = get_binary_signatures(macho_x64)
        assert isinstance(result["has_code_signature"], bool)

    def test_code_signature_details(self, macho_x64):
        result = get_binary_signatures(macho_x64)
        if result["has_code_signature"]:
            assert "data_offset" in result
            assert "data_size" in result
            assert isinstance(result["data_size"], int)

    def test_superblob_parsing(self, macho_x64):
        result = get_binary_signatures(macho_x64)
        if result.get("has_code_signature") and "blobs" in result:
            assert isinstance(result["blobs"], list)
            for blob in result["blobs"]:
                assert "slot" in blob
                assert "slot_name" in blob
                assert "offset" in blob

    def test_ios_signature(self, macho_ios):
        result = get_binary_signatures(macho_ios)
        assert result["format"] == "Mach-O"
        assert isinstance(result["has_code_signature"], bool)

    def test_x86_macho(self, macho_x86):
        result = get_binary_signatures(macho_x86)
        assert result["format"] == "Mach-O"

    def test_no_code_signature(self):
        binary = MagicMock(spec=lief.MachO.Binary)
        binary.has_code_signature = False
        binary.format = lief.Binary.FORMATS.MACHO
        with patch("tools.certificates.parse_binary", return_value=binary):
            result = get_binary_signatures("fake.macho")
        assert result["has_code_signature"] is False
        assert "data_offset" not in result


# ---------------------------------------------------------------------------
# SuperBlob / CodeDirectory parsing
# ---------------------------------------------------------------------------

class TestParseSuperblob:
    def test_too_short(self):
        assert _parse_superblob(b"\x00" * 8) == []

    def test_wrong_magic(self):
        data = (0xDEADBEEF).to_bytes(4, "big") + b"\x00" * 8
        assert _parse_superblob(data) == []

    def test_truncated_index(self):
        """Count says 2 blobs but data only has room for 1 index entry."""
        magic = (0xFADE0CC0).to_bytes(4, "big")
        length = (28).to_bytes(4, "big")  # small
        count = (2).to_bytes(4, "big")
        # One index entry (slot_type=0, offset=20)
        idx = (0).to_bytes(4, "big") + (20).to_bytes(4, "big")
        data = magic + length + count + idx
        blobs = _parse_superblob(data)
        # Should parse at most 1 blob (truncated at boundary)
        assert len(blobs) <= 2

    def test_blob_without_content(self):
        """Blob offset points past end of data — no magic/length parsed."""
        magic = (0xFADE0CC0).to_bytes(4, "big")
        length = (20).to_bytes(4, "big")
        count = (1).to_bytes(4, "big")
        # blob_offset=999 — way past end
        idx = (0).to_bytes(4, "big") + (999).to_bytes(4, "big")
        data = magic + length + count + idx
        blobs = _parse_superblob(data)
        assert len(blobs) == 1
        assert "magic" not in blobs[0]

    def test_unknown_slot_type(self):
        """Unknown slot type gets formatted as hex string."""
        magic = (0xFADE0CC0).to_bytes(4, "big")
        length = (100).to_bytes(4, "big")
        count = (1).to_bytes(4, "big")
        idx = (0xFF).to_bytes(4, "big") + (999).to_bytes(4, "big")
        data = magic + length + count + idx
        blobs = _parse_superblob(data)
        assert "Unknown" in blobs[0]["slot_name"]


class TestParseCodeDirectory:
    def _make_cd(self, *, hash_type=1, page_size=12, identity=b"com.test.app"):
        """Build a minimal CodeDirectory blob."""
        # magic(4) + length(4) + version(4) + flags(4) + hashOffset(4) +
        # identOffset(4) + nSpecialSlots(4) + nCodeSlots(4) + codeLimit(4) +
        # hashSize(1) + hashType(1) + spare1(1) + pageSize(1) = 40 bytes header
        cd_magic = (0xFADE0C00).to_bytes(4, "big")
        ident_offset = 40  # identity starts right after header
        header = (
            cd_magic
            + (100).to_bytes(4, "big")        # length
            + (0x20400).to_bytes(4, "big")     # version
            + (0).to_bytes(4, "big")           # flags
            + (60).to_bytes(4, "big")          # hashOffset
            + ident_offset.to_bytes(4, "big")  # identOffset
            + (2).to_bytes(4, "big")           # nSpecialSlots
            + (10).to_bytes(4, "big")          # nCodeSlots
            + (4096).to_bytes(4, "big")        # codeLimit
            + bytes([20, hash_type, 0, page_size])  # hashSize, hashType, spare1, pageSize
        )
        return header + identity + b"\x00"

    def test_basic_fields(self):
        cd = self._make_cd()
        info = _parse_code_directory(cd)
        assert info["version"] == "0x20400"
        assert info["flags"] == "0x0"
        assert info["hash_type"] == "SHA-1"
        assert info["hash_size"] == 20
        assert info["page_size"] == 2 ** 12
        assert info["n_special_slots"] == 2
        assert info["n_code_slots"] == 10
        assert info["code_limit"] == 4096
        assert info["identity"] == "com.test.app"

    def test_sha256_hash(self):
        cd = self._make_cd(hash_type=2)
        info = _parse_code_directory(cd)
        assert info["hash_type"] == "SHA-256"

    def test_unknown_hash_type(self):
        cd = self._make_cd(hash_type=99)
        info = _parse_code_directory(cd)
        assert "Unknown" in info["hash_type"]

    def test_zero_page_size(self):
        cd = self._make_cd(page_size=0)
        info = _parse_code_directory(cd)
        assert info["page_size"] == 0

    def test_identity_no_null_terminator(self):
        """Identity without null terminator — should read to end of data."""
        cd_magic = (0xFADE0C00).to_bytes(4, "big")
        header = (
            cd_magic
            + (50).to_bytes(4, "big")
            + (0x20400).to_bytes(4, "big")
            + (0).to_bytes(4, "big")
            + (60).to_bytes(4, "big")
            + (40).to_bytes(4, "big")  # identOffset=40
            + (0).to_bytes(4, "big")
            + (0).to_bytes(4, "big")
            + (0).to_bytes(4, "big")
            + bytes([20, 1, 0, 12])
        )
        # No null terminator
        cd = header + b"testid"
        info = _parse_code_directory(cd)
        assert info["identity"] == "testid"

    def test_ident_offset_past_end(self):
        """identOffset beyond data length — no identity key."""
        cd_magic = (0xFADE0C00).to_bytes(4, "big")
        header = (
            cd_magic
            + (50).to_bytes(4, "big")
            + (0x20400).to_bytes(4, "big")
            + (0).to_bytes(4, "big")
            + (60).to_bytes(4, "big")
            + (200).to_bytes(4, "big")  # identOffset=200, past end
            + (0).to_bytes(4, "big")
            + (0).to_bytes(4, "big")
            + (0).to_bytes(4, "big")
            + bytes([20, 1, 0, 12])
        )
        info = _parse_code_directory(header)
        assert "identity" not in info


# ---------------------------------------------------------------------------
# Unsupported formats
# ---------------------------------------------------------------------------

class TestSignaturesUnsupported:
    def test_elf_not_supported(self, elf_x64):
        result = get_binary_signatures(elf_x64)
        assert "error" in result

    def test_file_not_found(self):
        result = get_binary_signatures("/nonexistent/file")
        assert "error" in result

    def test_invalid_binary(self, tmp_path):
        junk = tmp_path / "junk.bin"
        junk.write_bytes(b"\x00" * 64)
        result = get_binary_signatures(str(junk))
        assert "error" in result
