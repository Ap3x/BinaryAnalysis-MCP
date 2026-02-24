"""Tests for get_binary_libraries tool."""

from __future__ import annotations

from tools.libraries import get_binary_libraries


# ---------------------------------------------------------------------------
# PE libraries
# ---------------------------------------------------------------------------

class TestLibrariesPE:
    def test_format(self, pe_mingw):
        result = get_binary_libraries(pe_mingw)
        assert result["format"] == "PE"

    def test_structure(self, pe_mingw):
        result = get_binary_libraries(pe_mingw)
        assert isinstance(result["count"], int)
        assert result["count"] > 0
        assert isinstance(result["libraries"], list)
        assert len(result["libraries"]) == result["count"]

    def test_libraries_are_strings(self, pe_mingw):
        result = get_binary_libraries(pe_mingw)
        for lib in result["libraries"]:
            assert isinstance(lib, str)

    def test_has_kernel32(self, pe_mingw):
        result = get_binary_libraries(pe_mingw)
        lib_names = [lib.lower() for lib in result["libraries"]]
        assert any("kernel32" in n for n in lib_names)

    def test_cygwin_libraries(self, pe_cygwin):
        result = get_binary_libraries(pe_cygwin)
        assert result["format"] == "PE"
        assert result["count"] > 0


# ---------------------------------------------------------------------------
# ELF libraries
# ---------------------------------------------------------------------------

class TestLibrariesELF:
    def test_format(self, elf_x64):
        result = get_binary_libraries(elf_x64)
        assert result["format"] == "ELF"

    def test_structure(self, elf_x64):
        result = get_binary_libraries(elf_x64)
        assert isinstance(result["count"], int)
        assert isinstance(result["libraries"], list)
        assert len(result["libraries"]) == result["count"]

    def test_libraries_are_strings(self, elf_x64):
        result = get_binary_libraries(elf_x64)
        for lib in result["libraries"]:
            assert isinstance(lib, str)

    def test_shared_library_deps(self, elf_so):
        result = get_binary_libraries(elf_so)
        assert result["format"] == "ELF"


# ---------------------------------------------------------------------------
# Mach-O libraries
# ---------------------------------------------------------------------------

class TestLibrariesMachO:
    def test_format(self, macho_x64):
        result = get_binary_libraries(macho_x64)
        assert result["format"] == "Mach-O"

    def test_structure(self, macho_x64):
        result = get_binary_libraries(macho_x64)
        assert isinstance(result["count"], int)
        assert isinstance(result["libraries"], list)
        assert len(result["libraries"]) == result["count"]

    def test_libraries_are_strings(self, macho_x64):
        result = get_binary_libraries(macho_x64)
        for lib in result["libraries"]:
            assert isinstance(lib, str)

    def test_ios_libraries(self, macho_ios):
        result = get_binary_libraries(macho_ios)
        assert result["format"] == "Mach-O"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestLibrariesErrors:
    def test_file_not_found(self):
        result = get_binary_libraries("/nonexistent/file")
        assert "error" in result

    def test_invalid_binary(self, tmp_path):
        junk = tmp_path / "junk.bin"
        junk.write_bytes(b"\x00" * 64)
        result = get_binary_libraries(str(junk))
        assert "error" in result
