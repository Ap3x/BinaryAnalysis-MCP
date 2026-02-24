"""Tool: get_binary_exports — exported functions / symbols."""

from __future__ import annotations

from typing import Any

import lief

from app import mcp
from helpers import safe_str, hex_addr, safe_enum, format_name, parse_binary, _error


@mcp.tool()
def get_binary_exports(file_path: str, limit: int = 0) -> dict:
    """Exported functions / symbols.

    For PE files with an export table, returns name, ordinal, address, and
    forwarded-function info.  For ELF / Mach-O returns a list of exported
    symbol names.

    Set *limit* > 0 to cap the number of entries returned.
    """
    try:
        binary = parse_binary(file_path)
    except ValueError as exc:
        return _error(str(exc))

    total = 0

    if isinstance(binary, lief.PE.Binary) and binary.has_exports:
        export = binary.get_export()
        entries = []
        for entry in export.entries:
            if 0 < limit <= total:
                break
            rec: dict[str, Any] = {
                "name": safe_str(entry.name),
                "ordinal": entry.ordinal,
                "address": hex_addr(entry.address),
                "is_forwarded": entry.is_forwarded,
            }
            if entry.is_forwarded:
                fwd = entry.forward_information
                rec["forward_library"] = safe_str(fwd.library) if fwd else None
                rec["forward_function"] = safe_str(fwd.function) if fwd else None
            entries.append(rec)
            total += 1
        return {
            "format": "PE",
            "export_name": safe_str(export.name),
            "total_returned": total,
            "limited": limit > 0 and total >= limit,
            "exports": entries,
        }

    # ELF / Mach-O — use abstract exported_functions
    funcs = []
    for fn in binary.exported_functions:
        if 0 < limit <= total:
            break
        funcs.append(safe_str(fn.name) if hasattr(fn, "name") else safe_str(fn))
        total += 1

    return {
        "format": format_name().get(binary.format, "Unknown"),
        "total_returned": total,
        "limited": limit > 0 and total >= limit,
        "exports": funcs,
    }
