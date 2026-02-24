"""Tool: get_binary_sections — list all sections with metadata."""

from __future__ import annotations

from typing import Any

import lief

from app import mcp
from helpers import hex_addr, safe_str, safe_enum, format_name, parse_binary, _error


@mcp.tool()
def get_binary_sections(file_path: str) -> dict:
    """List all sections with name, sizes, virtual address, permissions, and entropy."""
    try:
        binary = parse_binary(file_path)
    except ValueError as exc:
        return _error(str(exc))

    sections = []
    for section in binary.sections:
        entry: dict[str, Any] = {
            "name": safe_str(section.name),
            "virtual_address": hex_addr(section.virtual_address),
            "size": section.size,
            "entropy": round(section.entropy, 4),
        }

        if isinstance(binary, lief.PE.Binary):
            entry["virtual_size"] = section.virtual_size
            entry["sizeof_raw_data"] = section.sizeof_raw_data
            entry["characteristics"] = [safe_enum(c) for c in section.characteristics_lists]

        elif isinstance(binary, lief.ELF.Binary):
            entry["type"] = safe_enum(section.type)
            entry["flags"] = [safe_enum(f) for f in section.flags_list]
            entry["alignment"] = section.alignment
            entry["offset"] = hex_addr(section.offset)

        elif isinstance(binary, lief.MachO.Binary):
            entry["segment_name"] = safe_str(section.segment_name)
            entry["alignment"] = section.alignment
            entry["offset"] = section.offset
            entry["type"] = safe_enum(section.type)
            entry["flags"] = [safe_enum(f) for f in section.flags_list]

        sections.append(entry)

    return {
        "format": format_name().get(binary.format, "Unknown"),
        "count": len(sections),
        "sections": sections,
    }
