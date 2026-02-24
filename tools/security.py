"""Tool: get_binary_security — security features and hardening."""

from __future__ import annotations

from typing import Any

import lief

from app import mcp
from helpers import safe_enum, format_name, parse_binary, _error


def _pe_security(binary: lief.PE.Binary) -> dict:
    """Gather PE security features."""
    opt = binary.optional_header
    dll_chars = opt.dll_characteristics_lists

    def has_char(flag: lief.PE.OptionalHeader.DLL_CHARACTERISTICS) -> bool:
        return flag in dll_chars

    DLL = lief.PE.OptionalHeader.DLL_CHARACTERISTICS

    result: dict[str, Any] = {
        "aslr_dynamic_base": has_char(DLL.DYNAMIC_BASE),
        "aslr_high_entropy_va": has_char(DLL.HIGH_ENTROPY_VA),
        "dep_nx_compat": has_char(DLL.NX_COMPAT),
        "seh": not has_char(DLL.NO_SEH),
        "guard_cf": has_char(DLL.GUARD_CF),
        "force_integrity": has_char(DLL.FORCE_INTEGRITY),
        "appcontainer": has_char(DLL.APPCONTAINER),
        "is_pie": binary.is_pie,
        "has_nx": binary.has_nx,
    }

    # Code signing
    result["signed"] = binary.has_signatures
    if binary.has_signatures:
        sig_status = str(binary.verify_signature())
        result["signature_verification"] = sig_status

    return result


def _elf_security(binary: lief.ELF.Binary) -> dict:
    """Gather ELF security features."""
    result: dict[str, Any] = {
        "has_nx": binary.has_nx,
        "is_pie": binary.is_pie,
    }

    # RELRO detection
    has_gnu_relro = False
    has_bind_now = False

    for seg in binary.segments:
        if seg.type == lief.ELF.Segment.TYPE.GNU_RELRO:
            has_gnu_relro = True
            break

    for entry in binary.dynamic_entries:
        if entry.tag == lief.ELF.DynamicEntry.TAG.BIND_NOW:
            has_bind_now = True
        if entry.tag == lief.ELF.DynamicEntry.TAG.FLAGS:
            # BIND_NOW can also appear as a FLAGS bit
            if hasattr(entry, "value") and (entry.value & 0x8):  # DF_BIND_NOW = 0x8
                has_bind_now = True

    if has_gnu_relro and has_bind_now:
        result["relro"] = "Full"
    elif has_gnu_relro:
        result["relro"] = "Partial"
    else:
        result["relro"] = "None"

    # Stack canary heuristic: presence of __stack_chk_fail in imports
    imported_names = set()
    for fn in binary.imported_functions:
        name = fn.name if hasattr(fn, "name") else str(fn)
        imported_names.add(name)
    result["stack_canary"] = "__stack_chk_fail" in imported_names

    # FORTIFY_SOURCE heuristic: any __*_chk function
    result["fortify_source"] = any(
        "_chk" in name for name in imported_names if name.startswith("__")
    )

    # Interpreter
    if binary.has_interpreter:
        result["interpreter"] = binary.interpreter

    return result


def _macho_security(binary: lief.MachO.Binary) -> dict:
    """Gather Mach-O security features."""
    result: dict[str, Any] = {
        "is_pie": binary.is_pie,
        "has_nx": binary.has_nx,
        "has_nx_stack": binary.has_nx_stack,
        "has_nx_heap": binary.has_nx_heap,
        "has_code_signature": binary.has_code_signature,
    }

    # Flags from the Mach-O header
    flag_names = [safe_enum(f) for f in binary.header.flags_list]
    result["header_flags"] = flag_names

    # Platform info
    if binary.has_build_version:
        bv = binary.build_version
        result["platform"] = safe_enum(bv.platform) if hasattr(bv, "platform") else None

    # ARC / stack canary heuristic
    imported_names = set()
    for fn in binary.imported_functions:
        name = fn.name if hasattr(fn, "name") else str(fn)
        imported_names.add(name)
    result["stack_canary"] = "___stack_chk_fail" in imported_names

    return result


@mcp.tool()
def get_binary_security(file_path: str) -> dict:
    """Security features and hardening of a binary.

    PE: ASLR, DEP/NX, SEH, Control Flow Guard, code signing.
    ELF: NX, PIE, RELRO, stack canaries, FORTIFY_SOURCE.
    Mach-O: PIE, NX stack/heap, code signature, header flags.
    """
    try:
        binary = parse_binary(file_path)
    except ValueError as exc:
        return _error(str(exc))

    fmt = format_name().get(binary.format, "Unknown")

    if isinstance(binary, lief.PE.Binary):
        sec = _pe_security(binary)
    elif isinstance(binary, lief.ELF.Binary):
        sec = _elf_security(binary)
    elif isinstance(binary, lief.MachO.Binary):
        sec = _macho_security(binary)
    else:
        sec = {
            "has_nx": binary.has_nx,
            "is_pie": binary.is_pie,
        }

    sec["format"] = fmt
    return sec
