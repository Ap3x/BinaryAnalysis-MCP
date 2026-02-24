"""Tests for get_binary_exports tool."""

from __future__ import annotations

from tools.exports import get_binary_exports


# ---------------------------------------------------------------------------
# PE exports
# ---------------------------------------------------------------------------

class TestExportsPE:
    def test_format(self, pe_mingw):
        result = get_binary_exports(pe_mingw)
        # pe-mingw32-strip.exe may not have exports; just check format key
        assert result.get("format") in ("PE", "Unknown") or "error" not in result

    def test_structure(self, pe_mingw):
        result = get_binary_exports(pe_mingw)
        assert "error" not in result
        assert isinstance(result["total_returned"], int)
        assert isinstance(result["limited"], bool)
        assert isinstance(result["exports"], list)


# ---------------------------------------------------------------------------
# ELF exports
# ---------------------------------------------------------------------------

class TestExportsELF:
    def test_shared_library_has_exports(self, elf_so):
        result = get_binary_exports(elf_so)
        assert result["format"] == "ELF"
        assert result["total_returned"] > 0
        assert isinstance(result["exports"], list)
        for item in result["exports"]:
            assert isinstance(item, str)

    def test_executable_exports(self, elf_x64):
        result = get_binary_exports(elf_x64)
        assert result["format"] == "ELF"
        assert isinstance(result["exports"], list)

    def test_limit(self, elf_so):
        unlimited = get_binary_exports(elf_so)
        if unlimited["total_returned"] > 3:
            limited = get_binary_exports(elf_so, limit=3)
            assert limited["total_returned"] <= 3
            assert limited["limited"] is True


# ---------------------------------------------------------------------------
# Mach-O exports
# ---------------------------------------------------------------------------

class TestExportsMachO:
    def test_format(self, macho_x64):
        result = get_binary_exports(macho_x64)
        assert result["format"] == "Mach-O"
        assert isinstance(result["exports"], list)

    def test_structure(self, macho_x64):
        result = get_binary_exports(macho_x64)
        assert isinstance(result["total_returned"], int)
        assert isinstance(result["limited"], bool)

    def test_ios_exports(self, macho_ios):
        result = get_binary_exports(macho_ios)
        assert result["format"] == "Mach-O"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestExportsErrors:
    def test_file_not_found(self):
        result = get_binary_exports("/nonexistent/file")
        assert "error" in result

    def test_invalid_binary(self, tmp_path):
        junk = tmp_path / "junk.bin"
        junk.write_bytes(b"\x00" * 64)
        result = get_binary_exports(str(junk))
        assert "error" in result
