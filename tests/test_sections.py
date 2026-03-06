"""Tests for get_binary_sections tool."""

from __future__ import annotations

from tools.sections import get_binary_sections


def _assert_common_section(section: dict):
    """Every section entry must have these base keys."""
    assert "name" in section
    assert section["virtual_address"].startswith("0x")
    assert isinstance(section["size"], int)
    assert isinstance(section["entropy"], float)
    assert 0.0 <= section["entropy"] <= 8.0


# ---------------------------------------------------------------------------
# PE sections
# ---------------------------------------------------------------------------

class TestSectionsPE:
    def test_format_and_count(self, pe_mingw):
        result = get_binary_sections(pe_mingw)
        assert result["format"] == "PE"
        assert result["count"] > 0
        assert len(result["sections"]) == result["count"]

    def test_image_base_and_entrypoint(self, pe_mingw):
        result = get_binary_sections(pe_mingw)
        assert result["image_base"].startswith("0x")
        assert result["entrypoint"].startswith("0x")

    def test_pe_section_fields(self, pe_mingw):
        result = get_binary_sections(pe_mingw)
        for sec in result["sections"]:
            _assert_common_section(sec)
            assert isinstance(sec["virtual_size"], int)
            assert isinstance(sec["sizeof_raw_data"], int)
            assert isinstance(sec["characteristics"], list)

    def test_has_text_section(self, pe_mingw):
        result = get_binary_sections(pe_mingw)
        names = [s["name"] for s in result["sections"]]
        assert any(".text" in n for n in names if n)

    def test_cygwin_sections(self, pe_cygwin):
        result = get_binary_sections(pe_cygwin)
        assert result["format"] == "PE"
        assert result["count"] > 0


# ---------------------------------------------------------------------------
# ELF sections
# ---------------------------------------------------------------------------

class TestSectionsELF:
    def test_format_and_count(self, elf_x64):
        result = get_binary_sections(elf_x64)
        assert result["format"] == "ELF"
        assert result["count"] > 0
        assert len(result["sections"]) == result["count"]

    def test_image_base_and_entrypoint(self, elf_x64):
        result = get_binary_sections(elf_x64)
        assert result["image_base"].startswith("0x")
        assert result["entrypoint"].startswith("0x")

    def test_elf_section_fields(self, elf_x64):
        result = get_binary_sections(elf_x64)
        for sec in result["sections"]:
            _assert_common_section(sec)
            assert isinstance(sec["type"], str)
            assert isinstance(sec["flags"], list)
            assert isinstance(sec["alignment"], int)
            assert sec["offset"].startswith("0x")

    def test_has_text_section(self, elf_x64):
        result = get_binary_sections(elf_x64)
        names = [s["name"] for s in result["sections"]]
        assert any(".text" in n for n in names if n)

    def test_no_pe_fields(self, elf_x64):
        result = get_binary_sections(elf_x64)
        for sec in result["sections"]:
            assert "virtual_size" not in sec
            assert "sizeof_raw_data" not in sec
            assert "characteristics" not in sec

    def test_shared_library_sections(self, elf_so):
        result = get_binary_sections(elf_so)
        assert result["format"] == "ELF"
        assert result["count"] > 0


# ---------------------------------------------------------------------------
# Mach-O sections
# ---------------------------------------------------------------------------

class TestSectionsMachO:
    def test_format_and_count(self, macho_x64):
        result = get_binary_sections(macho_x64)
        assert result["format"] == "Mach-O"
        assert result["count"] > 0
        assert len(result["sections"]) == result["count"]

    def test_image_base_and_entrypoint(self, macho_x64):
        result = get_binary_sections(macho_x64)
        assert result["image_base"].startswith("0x")
        assert result["entrypoint"].startswith("0x")

    def test_macho_section_fields(self, macho_x64):
        result = get_binary_sections(macho_x64)
        for sec in result["sections"]:
            _assert_common_section(sec)
            assert "segment_name" in sec
            assert isinstance(sec["alignment"], int)
            assert isinstance(sec["offset"], int)
            assert isinstance(sec["type"], str)
            assert isinstance(sec["flags"], list)

    def test_has_text_segment(self, macho_x64):
        result = get_binary_sections(macho_x64)
        segment_names = [s["segment_name"] for s in result["sections"]]
        assert any("__TEXT" in n for n in segment_names if n)

    def test_ios_sections(self, macho_ios):
        result = get_binary_sections(macho_ios)
        assert result["format"] == "Mach-O"
        assert result["count"] > 0


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestSectionsErrors:
    def test_file_not_found(self):
        result = get_binary_sections("/nonexistent/file")
        assert "error" in result

    def test_invalid_binary(self, tmp_path):
        junk = tmp_path / "junk.bin"
        junk.write_bytes(b"\x00" * 64)
        result = get_binary_sections(str(junk))
        assert "error" in result
