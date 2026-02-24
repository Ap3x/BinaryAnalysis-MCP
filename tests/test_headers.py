"""Tests for get_binary_headers tool."""

from __future__ import annotations

from tools.headers import get_binary_headers


# ---------------------------------------------------------------------------
# PE headers
# ---------------------------------------------------------------------------

class TestHeadersPE:
    def test_format(self, pe_mingw):
        result = get_binary_headers(pe_mingw)
        assert result["format"] == "PE"

    def test_dos_header(self, pe_mingw):
        result = get_binary_headers(pe_mingw)
        dos = result["dos_header"]
        assert dos["magic"].startswith("0x")
        assert dos["addressof_new_exeheader"].startswith("0x")
        assert dos["addressof_relocation_table"].startswith("0x")

    def test_coff_header(self, pe_mingw):
        result = get_binary_headers(pe_mingw)
        coff = result["coff_header"]
        assert isinstance(coff["machine"], str)
        assert isinstance(coff["numberof_sections"], int)
        assert coff["numberof_sections"] > 0
        assert isinstance(coff["time_date_stamps"], int)
        assert isinstance(coff["sizeof_optional_header"], int)
        assert isinstance(coff["characteristics"], list)

    def test_optional_header(self, pe_mingw):
        result = get_binary_headers(pe_mingw)
        opt = result["optional_header"]
        assert isinstance(opt["magic"], str)
        assert opt["imagebase"].startswith("0x")
        assert opt["addressof_entrypoint"].startswith("0x")
        assert isinstance(opt["major_linker_version"], int)
        assert isinstance(opt["minor_linker_version"], int)
        assert isinstance(opt["subsystem"], str)
        assert isinstance(opt["dll_characteristics"], list)

    def test_cygwin_headers(self, pe_cygwin):
        result = get_binary_headers(pe_cygwin)
        assert result["format"] == "PE"
        assert "dos_header" in result
        assert "coff_header" in result
        assert "optional_header" in result


# ---------------------------------------------------------------------------
# ELF headers
# ---------------------------------------------------------------------------

class TestHeadersELF:
    def test_format(self, elf_x64):
        result = get_binary_headers(elf_x64)
        assert result["format"] == "ELF"

    def test_elf_header_fields(self, elf_x64):
        result = get_binary_headers(elf_x64)
        hdr = result["elf_header"]
        assert isinstance(hdr["identity_class"], str)
        assert isinstance(hdr["identity_data"], str)
        assert isinstance(hdr["identity_os_abi"], str)
        assert isinstance(hdr["file_type"], str)
        assert isinstance(hdr["machine_type"], str)
        assert hdr["entrypoint"].startswith("0x")
        assert isinstance(hdr["numberof_segments"], int)
        assert isinstance(hdr["numberof_sections"], int)
        assert hdr["numberof_sections"] > 0

    def test_x86_elf(self, elf_x86):
        result = get_binary_headers(elf_x86)
        assert result["format"] == "ELF"
        assert "elf_header" in result

    def test_no_pe_headers(self, elf_x64):
        """ELF results should not include PE-specific headers."""
        result = get_binary_headers(elf_x64)
        assert "dos_header" not in result
        assert "coff_header" not in result
        assert "optional_header" not in result


# ---------------------------------------------------------------------------
# Mach-O headers
# ---------------------------------------------------------------------------

class TestHeadersMachO:
    def test_format(self, macho_x64):
        result = get_binary_headers(macho_x64)
        assert result["format"] == "Mach-O"

    def test_macho_header_fields(self, macho_x64):
        result = get_binary_headers(macho_x64)
        hdr = result["macho_header"]
        assert isinstance(hdr["magic"], str)
        assert isinstance(hdr["cpu_type"], str)
        assert isinstance(hdr["cpu_subtype"], int)
        assert isinstance(hdr["file_type"], str)
        assert isinstance(hdr["nb_cmds"], int)
        assert hdr["nb_cmds"] > 0
        assert isinstance(hdr["sizeof_cmds"], int)
        assert isinstance(hdr["flags"], list)

    def test_x86_macho(self, macho_x86):
        result = get_binary_headers(macho_x86)
        assert result["format"] == "Mach-O"
        assert "macho_header" in result

    def test_ios_macho(self, macho_ios):
        result = get_binary_headers(macho_ios)
        assert result["format"] == "Mach-O"

    def test_no_elf_headers(self, macho_x64):
        """Mach-O results should not include ELF-specific headers."""
        result = get_binary_headers(macho_x64)
        assert "elf_header" not in result


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestHeadersErrors:
    def test_file_not_found(self):
        result = get_binary_headers("/nonexistent/file")
        assert "error" in result

    def test_invalid_binary(self, tmp_path):
        junk = tmp_path / "junk.bin"
        junk.write_bytes(b"\x00" * 64)
        result = get_binary_headers(str(junk))
        assert "error" in result
