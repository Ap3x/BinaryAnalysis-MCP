"""Tool: get_binary_headers — detailed header fields for a binary."""

from __future__ import annotations

from typing import Any

import lief

from app import mcp
from helpers import hex_addr, safe_enum, format_name, parse_binary, _error


@mcp.tool()
def get_binary_headers(file_path: str) -> dict:
    """Detailed header fields for a binary.

    PE: DOS header + COFF header + Optional header.
    ELF: ELF header.
    Mach-O: Mach header.
    """
    try:
        binary = parse_binary(file_path)
    except ValueError as exc:
        return _error(str(exc))

    result: dict[str, Any] = {"format": format_name().get(binary.format, "Unknown")}

    if isinstance(binary, lief.PE.Binary):
        dos = binary.dos_header
        result["dos_header"] = {
            "magic": hex_addr(dos.magic),
            "addressof_new_exeheader": hex_addr(dos.addressof_new_exeheader),
            "addressof_relocation_table": hex_addr(dos.addressof_relocation_table),
        }

        hdr = binary.header
        result["coff_header"] = {
            "machine": safe_enum(hdr.machine),
            "numberof_sections": hdr.numberof_sections,
            "time_date_stamps": hdr.time_date_stamps,
            "sizeof_optional_header": hdr.sizeof_optional_header,
            "characteristics": [safe_enum(c) for c in hdr.characteristics_list],
        }

        opt = binary.optional_header
        result["optional_header"] = {
            "magic": safe_enum(opt.magic),
            "major_linker_version": opt.major_linker_version,
            "minor_linker_version": opt.minor_linker_version,
            "sizeof_code": hex_addr(opt.sizeof_code),
            "sizeof_initialized_data": hex_addr(opt.sizeof_initialized_data),
            "sizeof_uninitialized_data": hex_addr(opt.sizeof_uninitialized_data),
            "addressof_entrypoint": hex_addr(opt.addressof_entrypoint),
            "baseof_code": hex_addr(opt.baseof_code),
            "imagebase": hex_addr(opt.imagebase),
            "section_alignment": hex_addr(opt.section_alignment),
            "file_alignment": hex_addr(opt.file_alignment),
            "major_operating_system_version": opt.major_operating_system_version,
            "minor_operating_system_version": opt.minor_operating_system_version,
            "major_image_version": opt.major_image_version,
            "minor_image_version": opt.minor_image_version,
            "major_subsystem_version": opt.major_subsystem_version,
            "minor_subsystem_version": opt.minor_subsystem_version,
            "sizeof_image": hex_addr(opt.sizeof_image),
            "sizeof_headers": hex_addr(opt.sizeof_headers),
            "checksum": hex_addr(opt.checksum),
            "subsystem": safe_enum(opt.subsystem),
            "dll_characteristics": [safe_enum(c) for c in opt.dll_characteristics_lists],
            "sizeof_stack_reserve": hex_addr(opt.sizeof_stack_reserve),
            "sizeof_stack_commit": hex_addr(opt.sizeof_stack_commit),
            "sizeof_heap_reserve": hex_addr(opt.sizeof_heap_reserve),
            "sizeof_heap_commit": hex_addr(opt.sizeof_heap_commit),
        }

    elif isinstance(binary, lief.ELF.Binary):
        hdr = binary.header
        result["elf_header"] = {
            "identity_class": safe_enum(hdr.identity_class),
            "identity_data": safe_enum(hdr.identity_data),
            "identity_os_abi": safe_enum(hdr.identity_os_abi),
            "identity_abi_version": hdr.identity_abi_version,
            "file_type": safe_enum(hdr.file_type),
            "machine_type": safe_enum(hdr.machine_type),
            "entrypoint": hex_addr(hdr.entrypoint),
            "program_header_offset": hex_addr(hdr.program_header_offset),
            "section_header_offset": hex_addr(hdr.section_header_offset),
            "processor_flag": hdr.processor_flag,
            "header_size": hdr.header_size,
            "program_header_size": hdr.program_header_size,
            "numberof_segments": hdr.numberof_segments,
            "section_header_size": hdr.section_header_size,
            "numberof_sections": hdr.numberof_sections,
            "section_name_table_idx": hdr.section_name_table_idx,
        }

    elif isinstance(binary, lief.MachO.Binary):
        hdr = binary.header
        result["macho_header"] = {
            "magic": safe_enum(hdr.magic),
            "cpu_type": safe_enum(hdr.cpu_type),
            "cpu_subtype": hdr.cpu_subtype,
            "file_type": safe_enum(hdr.file_type),
            "nb_cmds": hdr.nb_cmds,
            "sizeof_cmds": hdr.sizeof_cmds,
            "flags": [safe_enum(f) for f in hdr.flags_list],
        }

    return result
