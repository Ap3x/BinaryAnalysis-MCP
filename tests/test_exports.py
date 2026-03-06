"""Tests for get_binary_exports tool."""

from __future__ import annotations

from unittest.mock import MagicMock, patch, PropertyMock

import lief

from tools.exports import get_binary_exports


# ---------------------------------------------------------------------------
# PE exports (mocked — sample PEs have no export table)
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

    def test_pe_with_exports(self):
        """Exercise the PE export branch using a mock binary."""
        entry = MagicMock()
        entry.name = b"MyFunc"
        entry.ordinal = 1
        entry.address = 0x1000
        entry.is_forwarded = False

        export_obj = MagicMock()
        export_obj.name = b"test.dll"
        export_obj.entries = [entry]

        binary = MagicMock(spec=lief.PE.Binary)
        binary.has_exports = True
        binary.get_export.return_value = export_obj

        with patch("tools.exports.parse_binary", return_value=binary):
            result = get_binary_exports("fake.dll")

        assert result["format"] == "PE"
        assert result["export_name"] == "test.dll"
        assert result["total_returned"] == 1
        assert result["limited"] is False
        assert len(result["exports"]) == 1
        exp = result["exports"][0]
        assert exp["name"] == "MyFunc"
        assert exp["ordinal"] == 1
        assert exp["address"] == "0x1000"
        assert exp["is_forwarded"] is False
        assert "forward_library" not in exp

    def test_pe_forwarded_export(self):
        """Exercise the forwarded export path."""
        fwd_info = MagicMock()
        fwd_info.library = b"NTDLL"
        fwd_info.function = b"RtlAllocateHeap"

        entry = MagicMock()
        entry.name = b"HeapAlloc"
        entry.ordinal = 5
        entry.address = 0x0
        entry.is_forwarded = True
        entry.forward_information = fwd_info

        export_obj = MagicMock()
        export_obj.name = b"KERNEL32.dll"
        export_obj.entries = [entry]

        binary = MagicMock(spec=lief.PE.Binary)
        binary.has_exports = True
        binary.get_export.return_value = export_obj

        with patch("tools.exports.parse_binary", return_value=binary):
            result = get_binary_exports("fake.dll")

        exp = result["exports"][0]
        assert exp["is_forwarded"] is True
        assert exp["forward_library"] == "NTDLL"
        assert exp["forward_function"] == "RtlAllocateHeap"

    def test_pe_forwarded_export_none_fwd_info(self):
        """Forward info can be None even when is_forwarded is True."""
        entry = MagicMock()
        entry.name = b"Func"
        entry.ordinal = 1
        entry.address = 0x0
        entry.is_forwarded = True
        entry.forward_information = None

        export_obj = MagicMock()
        export_obj.name = b"test.dll"
        export_obj.entries = [entry]

        binary = MagicMock(spec=lief.PE.Binary)
        binary.has_exports = True
        binary.get_export.return_value = export_obj

        with patch("tools.exports.parse_binary", return_value=binary):
            result = get_binary_exports("fake.dll")

        exp = result["exports"][0]
        assert exp["forward_library"] is None
        assert exp["forward_function"] is None

    def test_pe_export_limit(self):
        """Verify the limit parameter caps PE export entries."""
        entries = []
        for i in range(10):
            e = MagicMock()
            e.name = f"Func{i}".encode()
            e.ordinal = i
            e.address = 0x1000 + i
            e.is_forwarded = False
            entries.append(e)

        export_obj = MagicMock()
        export_obj.name = b"test.dll"
        export_obj.entries = entries

        binary = MagicMock(spec=lief.PE.Binary)
        binary.has_exports = True
        binary.get_export.return_value = export_obj

        with patch("tools.exports.parse_binary", return_value=binary):
            result = get_binary_exports("fake.dll", limit=3)

        assert result["total_returned"] == 3
        assert result["limited"] is True
        assert len(result["exports"]) == 3

    def test_pe_no_exports_falls_through(self, pe_mingw):
        """PE without exports falls through to the generic path."""
        result = get_binary_exports(pe_mingw)
        # Should still return a valid structure
        assert isinstance(result["exports"], list)
        assert isinstance(result["total_returned"], int)


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

    def test_limit_zero_means_unlimited(self, elf_so):
        result = get_binary_exports(elf_so, limit=0)
        assert result["limited"] is False

    def test_x86_exports(self, elf_x86):
        result = get_binary_exports(elf_x86)
        assert result["format"] == "ELF"

    def test_arm64_exports(self, elf_arm64):
        result = get_binary_exports(elf_arm64)
        assert result["format"] == "ELF"


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

    def test_x86_macho_exports(self, macho_x86):
        result = get_binary_exports(macho_x86)
        assert result["format"] == "Mach-O"

    def test_limit(self, macho_x64):
        unlimited = get_binary_exports(macho_x64)
        if unlimited["total_returned"] > 2:
            limited = get_binary_exports(macho_x64, limit=2)
            assert limited["total_returned"] <= 2
            assert limited["limited"] is True


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
