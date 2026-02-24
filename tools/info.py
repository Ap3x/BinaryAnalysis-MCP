"""Tool: get_binary_info — quick triage of a binary file."""

from __future__ import annotations

from typing import Any

import lief

from app import mcp
from helpers import hex_addr, safe_enum, format_name, parse_binary, _error


@mcp.tool()
def get_binary_info(file_path: str) -> dict:
    """Quick triage of a binary file.

    Returns format, architecture, entry point, image base, section / import /
    export counts, and high-level security flags (NX, PIE).
    """
    try:
        binary = parse_binary(file_path)
    except ValueError as exc:
        return _error(str(exc))

    fmt = format_name().get(binary.format, "Unknown")

    info: dict[str, Any] = {
        "file": file_path,
        "format": fmt,
        "entrypoint": hex_addr(binary.entrypoint),
        "imagebase": hex_addr(binary.imagebase),
        "is_pie": binary.is_pie,
        "has_nx": binary.has_nx,
        "sections": len(list(binary.sections)),
        "imported_functions": len(list(binary.imported_functions)),
        "exported_functions": len(list(binary.exported_functions)),
        "libraries": len(list(binary.libraries)),
    }

    # Format-specific extras
    if isinstance(binary, lief.PE.Binary):
        info["machine"] = safe_enum(binary.header.machine)
        info["subsystem"] = safe_enum(binary.optional_header.subsystem)
        info["has_signatures"] = binary.has_signatures
        info["has_tls"] = binary.has_tls
        info["has_resources"] = binary.has_resources
        info["has_rich_header"] = binary.has_rich_header
        info["has_relocations"] = binary.has_relocations
    elif isinstance(binary, lief.ELF.Binary):
        info["machine"] = safe_enum(binary.header.machine_type)
        info["file_type"] = safe_enum(binary.header.file_type)
        info["has_interpreter"] = binary.has_interpreter
        if binary.has_interpreter:
            info["interpreter"] = binary.interpreter
        info["segments"] = len(list(binary.segments))
    elif isinstance(binary, lief.MachO.Binary):
        info["cpu_type"] = safe_enum(binary.header.cpu_type)
        info["file_type"] = safe_enum(binary.header.file_type)
        info["segments"] = len(list(binary.segments))
        info["has_code_signature"] = binary.has_code_signature
        info["has_entrypoint"] = binary.has_entrypoint

    return info
