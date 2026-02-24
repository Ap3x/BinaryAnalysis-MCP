"""Tests for helpers.py — parsing and formatting utilities."""

from __future__ import annotations

import os
from enum import Enum

import lief
import pytest

from helpers import hex_addr, safe_str, safe_enum, format_name, parse_binary, _error


# ---------------------------------------------------------------------------
# hex_addr
# ---------------------------------------------------------------------------

class TestHexAddr:
    def test_integer(self):
        assert hex_addr(0) == "0x0"
        assert hex_addr(255) == "0xff"
        assert hex_addr(0x400000) == "0x400000"

    def test_none(self):
        assert hex_addr(None) is None


# ---------------------------------------------------------------------------
# safe_str
# ---------------------------------------------------------------------------

class TestSafeStr:
    def test_string(self):
        assert safe_str("hello") == "hello"

    def test_bytes(self):
        assert safe_str(b"hello") == "hello"

    def test_bytes_invalid_utf8(self):
        result = safe_str(b"\xff\xfe")
        assert isinstance(result, str)

    def test_none(self):
        assert safe_str(None) is None

    def test_other(self):
        assert safe_str(42) == "42"


# ---------------------------------------------------------------------------
# safe_enum
# ---------------------------------------------------------------------------

class TestSafeEnum:
    def test_enum(self):
        class Color(Enum):
            RED = 1
        assert safe_enum(Color.RED) == "RED"

    def test_none(self):
        assert safe_enum(None) is None

    def test_other(self):
        assert safe_enum(42) == "42"


# ---------------------------------------------------------------------------
# format_name
# ---------------------------------------------------------------------------

class TestFormatName:
    def test_returns_all_formats(self):
        names = format_name()
        assert names[lief.Binary.FORMATS.PE] == "PE"
        assert names[lief.Binary.FORMATS.ELF] == "ELF"
        assert names[lief.Binary.FORMATS.MACHO] == "Mach-O"


# ---------------------------------------------------------------------------
# _error
# ---------------------------------------------------------------------------

class TestError:
    def test_returns_dict(self):
        assert _error("boom") == {"error": "boom"}


# ---------------------------------------------------------------------------
# parse_binary
# ---------------------------------------------------------------------------

class TestParseBinary:
    def test_file_not_found(self):
        with pytest.raises(ValueError, match="File not found"):
            parse_binary("/nonexistent/binary")

    def test_unsupported_format(self, tmp_path):
        junk = tmp_path / "junk.bin"
        junk.write_bytes(b"\x00" * 64)
        with pytest.raises(ValueError, match="could not parse"):
            parse_binary(str(junk))

    def test_parse_pe(self, pe_mingw):
        binary = parse_binary(pe_mingw)
        assert isinstance(binary, lief.PE.Binary)

    def test_parse_elf(self, elf_x64):
        binary = parse_binary(elf_x64)
        assert isinstance(binary, lief.ELF.Binary)

    def test_parse_macho(self, macho_x64):
        binary = parse_binary(macho_x64)
        assert isinstance(binary, lief.MachO.Binary)

    def test_parse_fat_macho(self):
        """Fat Mach-O binaries should still return the first slice."""
        from conftest import SAMPLES_DIR
        fat_path = os.path.join(SAMPLES_DIR, "MachO-OSX-ppc-and-i386-bash")
        if not os.path.isfile(fat_path):
            pytest.skip("Fat MachO sample not found")
        binary = parse_binary(fat_path)
        assert isinstance(binary, lief.MachO.Binary)
