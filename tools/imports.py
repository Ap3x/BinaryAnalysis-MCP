"""Tool: get_binary_imports — imported functions grouped by library."""

from __future__ import annotations

from typing import Any

import lief

from app import mcp
from helpers import safe_str, hex_addr, format_name, parse_binary, _error


@mcp.tool()
def get_binary_imports(file_path: str, limit: int = 0) -> dict:
    """Imported functions, grouped by library.

    For PE binaries imports are grouped by DLL.  For ELF / Mach-O a flat list
    of imported function names is returned.

    Set *limit* > 0 to cap the total number of entries returned.
    """
    try:
        binary = parse_binary(file_path)
    except ValueError as exc:
        return _error(str(exc))

    total = 0

    if isinstance(binary, lief.PE.Binary):
        libraries: list[dict] = []
        for imp in binary.imports:
            entries = []
            for entry in imp.entries:
                if 0 < limit <= total:
                    break
                entries.append({
                    "name": safe_str(entry.name) or f"ordinal#{entry.ordinal}",
                    "hint": entry.hint,
                    "iat_address": hex_addr(entry.iat_address),
                })
                total += 1
            libraries.append({
                "library": safe_str(imp.name),
                "functions": entries,
            })
            if 0 < limit <= total:
                break
        return {
            "format": "PE",
            "total_returned": total,
            "limited": limit > 0 and total >= limit,
            "imports": libraries,
        }

    # ELF / Mach-O — flat list via abstract API
    funcs = []
    for fn in binary.imported_functions:
        if 0 < limit <= total:
            break
        funcs.append(safe_str(fn.name) if hasattr(fn, "name") else safe_str(fn))
        total += 1

    return {
        "format": format_name().get(binary.format, "Unknown"),
        "total_returned": total,
        "limited": limit > 0 and total >= limit,
        "imports": funcs,
    }
