"""Tool: get_binary_imports — imported functions grouped by library."""

from __future__ import annotations

from typing import Any

import lief

from app import mcp
from helpers import safe_str, hex_addr, safe_enum, format_name, parse_binary, _error


@mcp.tool()
def get_binary_imports(file_path: str, limit: int = 0) -> dict:
    """Imported functions, grouped by library.

    For PE binaries imports are grouped by DLL.  For ELF binaries imports are
    grouped by shared library (via symbol version requirements) and include
    binding/type info.  For Mach-O binaries imports are grouped by dylib
    (via binding info) and include addresses.

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

    if isinstance(binary, lief.ELF.Binary):
        # Build version-index -> library name mapping from .gnu.version_r
        ver_to_lib: dict[int, str] = {}
        for req in binary.symbols_version_requirement:
            lib_name = safe_str(req.name)
            for aux in req.get_auxiliary_symbols():
                ver_to_lib[aux.other] = lib_name

        lib_imports: dict[str, list[dict]] = {}
        for sym in binary.imported_symbols:
            if 0 < limit <= total:
                break
            name = safe_str(sym.name)
            if not name:
                continue
            # Determine source library via symbol version
            lib_name = ""
            sv = sym.symbol_version
            if sv is not None and sv.value != 0:
                lib_name = ver_to_lib.get(sv.value, "")
            lib_imports.setdefault(lib_name or "unknown", []).append({
                "name": name,
                "binding": safe_enum(sym.binding),
                "type": safe_enum(sym.type),
                "value": hex_addr(sym.value),
            })
            total += 1

        libraries: list[dict] = [
            {"library": lib, "functions": funcs}
            for lib, funcs in lib_imports.items()
        ]
        return {
            "format": "ELF",
            "total_returned": total,
            "limited": limit > 0 and total >= limit,
            "imports": libraries,
        }

    if isinstance(binary, lief.MachO.Binary):
        lib_imports_macho: dict[str, list[dict]] = {}
        seen: set[str] = set()

        # Use binding info to associate imports with their source dylib
        for info in binary.dyld_info.bindings:
            if 0 < limit <= total:
                break
            sym = info.symbol
            if sym is None:
                continue
            name = safe_str(sym.name)
            if not name or name in seen:
                continue
            seen.add(name)
            lib_name = safe_str(info.library.name) if info.has_library else "unknown"
            lib_imports_macho.setdefault(lib_name, []).append({
                "name": name,
                "address": hex_addr(info.address),
            })
            total += 1

        # Fall back to imported_symbols for anything not covered by bindings
        for sym in binary.imported_symbols:
            if 0 < limit <= total:
                break
            name = safe_str(sym.name)
            if not name or name in seen:
                continue
            seen.add(name)
            lib_imports_macho.setdefault("unknown", []).append({
                "name": name,
                "address": hex_addr(sym.value),
            })
            total += 1

        macho_libraries: list[dict] = [
            {"library": lib, "functions": funcs}
            for lib, funcs in lib_imports_macho.items()
        ]
        return {
            "format": "Mach-O",
            "total_returned": total,
            "limited": limit > 0 and total >= limit,
            "imports": macho_libraries,
        }

    # Fallback for unknown formats
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
