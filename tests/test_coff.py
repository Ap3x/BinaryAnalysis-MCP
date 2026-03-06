"""Tests for get_coff_info tool."""

from __future__ import annotations

from tools.coff import get_coff_info


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

class TestCoffHeader:
    def test_format(self, coff_x64):
        result = get_coff_info(coff_x64)
        assert result["format"] == "COFF"

    def test_header_fields(self, coff_x64):
        hdr = get_coff_info(coff_x64)["header"]
        assert isinstance(hdr["machine"], str)
        assert isinstance(hdr["nb_sections"], int)
        assert isinstance(hdr["nb_symbols"], int)
        assert isinstance(hdr["timedatestamp"], int)
        assert isinstance(hdr["kind"], str)

    def test_x64_machine(self, coff_x64):
        hdr = get_coff_info(coff_x64)["header"]
        assert "AMD64" in hdr["machine"]

    def test_x86_machine(self, coff_x86):
        hdr = get_coff_info(coff_x86)["header"]
        assert "I386" in hdr["machine"]


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

class TestCoffSections:
    def test_section_count(self, coff_x64):
        result = get_coff_info(coff_x64)
        assert len(result["sections"]) == result["header"]["nb_sections"]

    def test_section_fields(self, coff_x64):
        result = get_coff_info(coff_x64)
        for sec in result["sections"]:
            assert "name" in sec
            assert "virtual_address" in sec
            assert "virtual_size" in sec
            assert "size" in sec
            assert "sizeof_raw_data" in sec
            assert isinstance(sec["entropy"], float)
            assert isinstance(sec["characteristics"], list)
            assert isinstance(sec["numberof_relocations"], int)

    def test_has_text_section(self, coff_x64):
        result = get_coff_info(coff_x64)
        names = [sec["name"] for sec in result["sections"]]
        assert ".text" in names

    def test_multiple_sections(self, coff_x86):
        result = get_coff_info(coff_x86)
        assert len(result["sections"]) == 2
        names = [sec["name"] for sec in result["sections"]]
        assert ".text" in names
        assert ".data" in names


# ---------------------------------------------------------------------------
# Symbols
# ---------------------------------------------------------------------------

class TestCoffSymbols:
    def test_symbol_fields(self, coff_x64):
        result = get_coff_info(coff_x64)
        assert result["symbols_returned"] > 0
        for sym in result["symbols"]:
            assert "name" in sym
            assert "value" in sym
            assert "section_idx" in sym
            assert "storage_class" in sym
            assert "base_type" in sym
            assert "complex_type" in sym
            assert isinstance(sym["is_external"], bool)
            assert isinstance(sym["is_undefined"], bool)
            assert isinstance(sym["is_function"], bool)

    def test_has_main(self, coff_x64):
        result = get_coff_info(coff_x64)
        names = [sym["name"] for sym in result["symbols"]]
        assert "_main" in names

    def test_function_flag(self, coff_x64):
        result = get_coff_info(coff_x64)
        main = next(s for s in result["symbols"] if s["name"] == "_main")
        assert main["is_function"] is True

    def test_undefined_symbol(self, coff_x86):
        """_printf in x86 sample is external and undefined."""
        result = get_coff_info(coff_x86)
        printf = next(s for s in result["symbols"] if s["name"] == "_printf")
        assert printf["is_external"] is True
        assert printf["is_undefined"] is True

    def test_limit(self, coff_x86):
        unlimited = get_coff_info(coff_x86)
        limited = get_coff_info(coff_x86, limit=1)
        assert limited["symbols_returned"] == 1
        assert limited["symbols_limited"] is True
        assert limited["symbols_returned"] < unlimited["symbols_returned"]

    def test_limit_zero_means_unlimited(self, coff_x86):
        result = get_coff_info(coff_x86, limit=0)
        assert result["symbols_limited"] is False


# ---------------------------------------------------------------------------
# Relocations
# ---------------------------------------------------------------------------

class TestCoffRelocations:
    def test_relocations_list(self, coff_x64):
        result = get_coff_info(coff_x64)
        assert isinstance(result["relocations"], list)


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestCoffErrors:
    def test_file_not_found(self):
        result = get_coff_info("/nonexistent/file")
        assert "error" in result

    def test_not_a_coff_file(self, pe_mingw):
        """A PE file should not parse as COFF."""
        result = get_coff_info(pe_mingw)
        assert "error" in result

    def test_invalid_binary(self, tmp_path):
        junk = tmp_path / "junk.bin"
        junk.write_bytes(b"\x00" * 64)
        result = get_coff_info(str(junk))
        assert "error" in result
