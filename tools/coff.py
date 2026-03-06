"""Tool: get_coff_info — parse COFF object files."""

from __future__ import annotations

import os
from typing import Any

import lief

from app import mcp
from helpers import hex_addr, safe_str, safe_enum, _error


@mcp.tool()
def get_coff_info(file_path: str, limit: int = 0) -> dict:
    """Parse a COFF object file and return header, sections, symbols, and relocations.

    COFF (.obj) files are not PE executables — they lack an image base and
    entry point.  This tool uses ``lief.COFF.parse`` directly.

    Set *limit* > 0 to cap the number of symbols returned.
    """
    if not os.path.isfile(file_path):
        return _error(f"File not found: {file_path}")

    binary = lief.COFF.parse(file_path)
    if binary is None:
        return _error(
            f"LIEF could not parse the file as COFF: {file_path}"
        )

    # ---- header ----
    hdr = binary.header
    header_info: dict[str, Any] = {
        "machine": safe_enum(hdr.machine),
        "nb_sections": hdr.nb_sections,
        "nb_symbols": hdr.nb_symbols,
        "timedatestamp": hdr.timedatestamp,
        "kind": safe_enum(hdr.kind),
    }
    if isinstance(hdr, lief.COFF.RegularHeader):
        header_info["characteristics"] = hex_addr(hdr.characteristics)
        header_info["sizeof_optionalheader"] = hdr.sizeof_optionalheader

    # ---- sections ----
    sections = []
    for sec in binary.sections:
        entry: dict[str, Any] = {
            "name": safe_str(sec.name),
            "virtual_address": hex_addr(sec.virtual_address),
            "virtual_size": sec.virtual_size,
            "size": sec.size,
            "sizeof_raw_data": sec.sizeof_raw_data,
            "entropy": round(sec.entropy, 4),
            "characteristics": [safe_enum(c) for c in sec.characteristics_lists],
            "numberof_relocations": sec.numberof_relocations,
        }
        sections.append(entry)

    # ---- symbols ----
    total = 0
    symbols = []
    for sym in binary.symbols:
        if 0 < limit <= total:
            break
        symbols.append({
            "name": safe_str(sym.name),
            "value": sym.value,
            "section_idx": sym.section_idx,
            "storage_class": safe_enum(sym.storage_class),
            "base_type": safe_enum(sym.base_type),
            "complex_type": safe_enum(sym.complex_type),
            "is_external": sym.is_external,
            "is_undefined": sym.is_undefined,
            "is_function": sym.is_function,
        })
        total += 1

    # ---- relocations ----
    relocations = []
    for rel in binary.relocations:
        rec: dict[str, Any] = {
            "address": hex_addr(rel.address),
            "type": safe_enum(rel.type),
            "symbol_idx": rel.symbol_idx,
        }
        if rel.symbol is not None:
            rec["symbol_name"] = safe_str(rel.symbol.name)
        if rel.section is not None:
            rec["section_name"] = safe_str(rel.section.name)
        relocations.append(rec)

    return {
        "format": "COFF",
        "header": header_info,
        "sections": sections,
        "symbols_returned": total,
        "symbols_limited": limit > 0 and total >= limit,
        "symbols": symbols,
        "relocations": relocations,
    }
