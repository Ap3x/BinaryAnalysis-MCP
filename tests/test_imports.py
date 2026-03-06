"""Tests for get_binary_imports tool."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import lief

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

    def test_limit_breaks_inner_loop(self):
        """Verify limit breaks inside entry iteration (line 37)."""
        entry1 = MagicMock()
        entry1.name = b"Func1"
        entry1.ordinal = 1
        entry1.hint = 0
        entry1.iat_address = 0x1000
        entry2 = MagicMock()
        entry2.name = b"Func2"
        entry2.ordinal = 2
        entry2.hint = 1
        entry2.iat_address = 0x1008

        imp = MagicMock()
        imp.name = b"test.dll"
        imp.entries = [entry1, entry2]

        binary = MagicMock(spec=lief.PE.Binary)
        binary.imports = [imp]

        with patch("tools.imports.parse_binary", return_value=binary):
            result = get_binary_imports("fake.exe", limit=1)
        assert result["total_returned"] == 1
        assert result["limited"] is True

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

    def test_grouped_by_library(self, elf_x64):
        result = get_binary_imports(elf_x64)
        for lib in result["imports"]:
            assert isinstance(lib["library"], str)
            assert isinstance(lib["functions"], list)

    def test_elf_import_entries(self, elf_x64):
        result = get_binary_imports(elf_x64)
        for lib in result["imports"]:
            for func in lib["functions"]:
                assert "name" in func
                assert "binding" in func
                assert "type" in func
                assert "value" in func

    def test_has_known_library(self, elf_x64):
        result = get_binary_imports(elf_x64)
        lib_names = [lib["library"].lower() for lib in result["imports"]]
        assert any(name != "unknown" for name in lib_names)

    def test_limit(self, elf_x64):
        unlimited = get_binary_imports(elf_x64)
        if unlimited["total_returned"] > 5:
            limited = get_binary_imports(elf_x64, limit=5)
            assert limited["total_returned"] <= 5
            assert limited["limited"] is True

    def test_x86_imports(self, elf_x86):
        result = get_binary_imports(elf_x86)
        assert result["format"] == "ELF"
        assert isinstance(result["imports"], list)

    def test_empty_symbol_name_skipped(self):
        """Symbols with empty names should be skipped (line 71)."""
        sym_empty = MagicMock()
        sym_empty.name = ""
        sym_empty.symbol_version = None

        sym_valid = MagicMock()
        sym_valid.name = "printf"
        sym_valid.symbol_version = None
        sym_valid.binding = MagicMock()
        sym_valid.type = MagicMock()
        sym_valid.value = 0

        binary = MagicMock(spec=lief.ELF.Binary)
        binary.symbols_version_requirement = []
        binary.imported_symbols = [sym_empty, sym_valid]

        with patch("tools.imports.parse_binary", return_value=binary):
            result = get_binary_imports("fake.elf")
        assert result["total_returned"] == 1


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

    def test_grouped_by_library(self, macho_x64):
        result = get_binary_imports(macho_x64)
        for lib in result["imports"]:
            assert isinstance(lib["library"], str)
            assert isinstance(lib["functions"], list)

    def test_macho_import_entries(self, macho_x64):
        result = get_binary_imports(macho_x64)
        for lib in result["imports"]:
            for func in lib["functions"]:
                assert "name" in func
                assert "address" in func

    def test_ios_imports(self, macho_ios):
        result = get_binary_imports(macho_ios)
        assert result["format"] == "Mach-O"

    def test_limit(self, macho_x64):
        unlimited = get_binary_imports(macho_x64)
        if unlimited["total_returned"] > 3:
            limited = get_binary_imports(macho_x64, limit=3)
            assert limited["total_returned"] <= 3
            assert limited["limited"] is True

    def test_null_symbol_skipped(self):
        """Binding with sym=None should be skipped (line 106)."""
        binding = MagicMock()
        binding.symbol = None

        dyld = MagicMock()
        dyld.bindings = [binding]

        binary = MagicMock(spec=lief.MachO.Binary)
        binary.dyld_info = dyld
        binary.imported_symbols = []

        with patch("tools.imports.parse_binary", return_value=binary):
            result = get_binary_imports("fake.macho")
        assert result["total_returned"] == 0

    def test_imported_symbols_fallback(self):
        """Symbols not in bindings should be picked up from imported_symbols."""
        # Empty bindings
        dyld = MagicMock()
        dyld.bindings = []

        sym = MagicMock()
        sym.name = "_extra_func"
        sym.value = 0x2000

        binary = MagicMock(spec=lief.MachO.Binary)
        binary.dyld_info = dyld
        binary.imported_symbols = [sym]

        with patch("tools.imports.parse_binary", return_value=binary):
            result = get_binary_imports("fake.macho")
        assert result["total_returned"] == 1
        assert result["imports"][0]["functions"][0]["name"] == "_extra_func"

    def test_imported_symbols_limit(self):
        """Limit should apply in the imported_symbols fallback loop (line 121)."""
        dyld = MagicMock()
        dyld.bindings = []

        syms = []
        for i in range(5):
            s = MagicMock()
            s.name = f"_func{i}"
            s.value = 0x1000 + i
            syms.append(s)

        binary = MagicMock(spec=lief.MachO.Binary)
        binary.dyld_info = dyld
        binary.imported_symbols = syms

        with patch("tools.imports.parse_binary", return_value=binary):
            result = get_binary_imports("fake.macho", limit=2)
        assert result["total_returned"] == 2
        assert result["limited"] is True


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
