"""Tests for get_binary_imports tool."""

from __future__ import annotations

from tools.imports import get_binary_imports


# ---------------------------------------------------------------------------
# PE imports
# ---------------------------------------------------------------------------

class TestImportsPE:
    def test_format(self, pe_mingw):
        result = get_binary_imports(pe_mingw)
        assert result["format"] == "PE"

    def test_structure(self, pe_mingw):
        result = get_binary_imports(pe_mingw)
        assert isinstance(result["total_returned"], int)
        assert result["total_returned"] > 0
        assert isinstance(result["limited"], bool)
        assert not result["limited"]
        assert isinstance(result["imports"], list)

    def test_pe_import_entries(self, pe_mingw):
        result = get_binary_imports(pe_mingw)
        for lib in result["imports"]:
            assert isinstance(lib["library"], str)
            assert isinstance(lib["functions"], list)
            for func in lib["functions"]:
                assert "name" in func
                assert "hint" in func
                assert "iat_address" in func

    def test_has_kernel32(self, pe_mingw):
        result = get_binary_imports(pe_mingw)
        lib_names = [lib["library"].lower() for lib in result["imports"]]
        assert any("kernel32" in n for n in lib_names)

    def test_limit(self, pe_mingw):
        unlimited = get_binary_imports(pe_mingw)
        limited = get_binary_imports(pe_mingw, limit=5)
        assert limited["total_returned"] <= 5
        assert limited["limited"] is True
        assert limited["total_returned"] <= unlimited["total_returned"]

    def test_cygwin_imports(self, pe_cygwin):
        result = get_binary_imports(pe_cygwin)
        assert result["format"] == "PE"
        assert result["total_returned"] > 0


# ---------------------------------------------------------------------------
# ELF imports
# ---------------------------------------------------------------------------

class TestImportsELF:
    def test_format(self, elf_x64):
        result = get_binary_imports(elf_x64)
        assert result["format"] == "ELF"

    def test_structure(self, elf_x64):
        result = get_binary_imports(elf_x64)
        assert isinstance(result["total_returned"], int)
        assert isinstance(result["limited"], bool)
        assert isinstance(result["imports"], list)

    def test_flat_list(self, elf_x64):
        """ELF imports should be a flat list of strings, not grouped by library."""
        result = get_binary_imports(elf_x64)
        for item in result["imports"]:
            assert isinstance(item, str)

    def test_limit(self, elf_x64):
        unlimited = get_binary_imports(elf_x64)
        if unlimited["total_returned"] > 5:
            limited = get_binary_imports(elf_x64, limit=5)
            assert limited["total_returned"] <= 5
            assert limited["limited"] is True

    def test_x86_imports(self, elf_x86):
        result = get_binary_imports(elf_x86)
        assert result["format"] == "ELF"


# ---------------------------------------------------------------------------
# Mach-O imports
# ---------------------------------------------------------------------------

class TestImportsMachO:
    def test_format(self, macho_x64):
        result = get_binary_imports(macho_x64)
        assert result["format"] == "Mach-O"

    def test_structure(self, macho_x64):
        result = get_binary_imports(macho_x64)
        assert isinstance(result["total_returned"], int)
        assert isinstance(result["limited"], bool)
        assert isinstance(result["imports"], list)

    def test_flat_list(self, macho_x64):
        """Mach-O imports should be a flat list of strings."""
        result = get_binary_imports(macho_x64)
        for item in result["imports"]:
            assert isinstance(item, str)

    def test_ios_imports(self, macho_ios):
        result = get_binary_imports(macho_ios)
        assert result["format"] == "Mach-O"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestImportsErrors:
    def test_file_not_found(self):
        result = get_binary_imports("/nonexistent/file")
        assert "error" in result

    def test_invalid_binary(self, tmp_path):
        junk = tmp_path / "junk.bin"
        junk.write_bytes(b"\x00" * 64)
        result = get_binary_imports(str(junk))
        assert "error" in result

    def test_limit_zero_means_unlimited(self, pe_mingw):
        result = get_binary_imports(pe_mingw, limit=0)
        assert not result.get("limited", False)
