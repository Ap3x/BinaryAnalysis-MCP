"""Tests for get_binary_info tool."""

from __future__ import annotations

import pytest

from tools.info import get_binary_info


# ---------------------------------------------------------------------------
# Shared assertions
# ---------------------------------------------------------------------------

def _assert_common_fields(result: dict, expected_format: str):
    """Every successful info result must have these keys."""
    assert "error" not in result
    assert result["format"] == expected_format
    assert result["file"]
    assert isinstance(result["entrypoint"], (str, type(None)))
    assert isinstance(result["imagebase"], (str, type(None)))
    assert isinstance(result["is_pie"], bool)
    assert isinstance(result["has_nx"], bool)
    assert isinstance(result["sections"], int) and result["sections"] >= 0
    assert isinstance(result["imported_functions"], int)
    assert isinstance(result["exported_functions"], int)
    assert isinstance(result["libraries"], int)


# ---------------------------------------------------------------------------
# PE
# ---------------------------------------------------------------------------

class TestInfoPE:
    def test_basic_fields(self, pe_mingw):
        result = get_binary_info(pe_mingw)
        _assert_common_fields(result, "PE")

    def test_pe_specific_fields(self, pe_mingw):
        result = get_binary_info(pe_mingw)
        assert "machine" in result
        assert "subsystem" in result
        assert isinstance(result["has_signatures"], bool)
        assert isinstance(result["has_tls"], bool)
        assert isinstance(result["has_resources"], bool)
        assert isinstance(result["has_rich_header"], bool)
        assert isinstance(result["has_relocations"], bool)

    def test_entrypoint_is_hex(self, pe_mingw):
        result = get_binary_info(pe_mingw)
        assert result["entrypoint"].startswith("0x")

    def test_has_sections(self, pe_mingw):
        result = get_binary_info(pe_mingw)
        assert result["sections"] > 0

    def test_has_imports(self, pe_mingw):
        result = get_binary_info(pe_mingw)
        assert result["imported_functions"] > 0

    def test_cygwin_exe(self, pe_cygwin):
        result = get_binary_info(pe_cygwin)
        _assert_common_fields(result, "PE")
        assert result["sections"] > 0


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------

class TestInfoELF:
    def test_basic_fields(self, elf_x64):
        result = get_binary_info(elf_x64)
        _assert_common_fields(result, "ELF")

    def test_elf_specific_fields(self, elf_x64):
        result = get_binary_info(elf_x64)
        assert "machine" in result
        assert "file_type" in result
        assert isinstance(result["has_interpreter"], bool)
        assert isinstance(result["segments"], int)

    def test_has_interpreter(self, elf_x64):
        result = get_binary_info(elf_x64)
        if result["has_interpreter"]:
            assert "interpreter" in result

    def test_x86_binary(self, elf_x86):
        result = get_binary_info(elf_x86)
        _assert_common_fields(result, "ELF")

    def test_shared_library(self, elf_so):
        result = get_binary_info(elf_so)
        _assert_common_fields(result, "ELF")
        assert result["exported_functions"] > 0

    def test_arm64_binary(self, elf_arm64):
        result = get_binary_info(elf_arm64)
        _assert_common_fields(result, "ELF")


# ---------------------------------------------------------------------------
# Mach-O
# ---------------------------------------------------------------------------

class TestInfoMachO:
    def test_basic_fields(self, macho_x64):
        result = get_binary_info(macho_x64)
        _assert_common_fields(result, "Mach-O")

    def test_macho_specific_fields(self, macho_x64):
        result = get_binary_info(macho_x64)
        assert "cpu_type" in result
        assert "file_type" in result
        assert isinstance(result["segments"], int)
        assert isinstance(result["has_code_signature"], bool)
        assert isinstance(result["has_entrypoint"], bool)

    def test_x86_binary(self, macho_x86):
        result = get_binary_info(macho_x86)
        _assert_common_fields(result, "Mach-O")

    def test_ios_binary(self, macho_ios):
        result = get_binary_info(macho_ios)
        _assert_common_fields(result, "Mach-O")


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestInfoErrors:
    def test_file_not_found(self):
        result = get_binary_info("/nonexistent/file.exe")
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_invalid_binary(self, tmp_path):
        junk = tmp_path / "junk.bin"
        junk.write_bytes(b"\x00" * 64)
        result = get_binary_info(str(junk))
        assert "error" in result
