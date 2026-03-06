"""Tests for get_binary_security tool."""

from __future__ import annotations

from unittest.mock import MagicMock, patch, PropertyMock

import lief

from tools.security import get_binary_security, _pe_security, _elf_security, _macho_security


# ---------------------------------------------------------------------------
# PE security
# ---------------------------------------------------------------------------

class TestSecurityPE:
    def test_format(self, pe_mingw):
        result = get_binary_security(pe_mingw)
        assert result["format"] == "PE"

    def test_pe_security_fields(self, pe_mingw):
        result = get_binary_security(pe_mingw)
        assert isinstance(result["aslr_dynamic_base"], bool)
        assert isinstance(result["aslr_high_entropy_va"], bool)
        assert isinstance(result["dep_nx_compat"], bool)
        assert isinstance(result["seh"], bool)
        assert isinstance(result["guard_cf"], bool)
        assert isinstance(result["force_integrity"], bool)
        assert isinstance(result["appcontainer"], bool)
        assert isinstance(result["is_pie"], bool)
        assert isinstance(result["has_nx"], bool)
        assert isinstance(result["signed"], bool)

    def test_signed_has_verification(self, pe_mingw):
        result = get_binary_security(pe_mingw)
        if result["signed"]:
            assert "signature_verification" in result

    def test_cygwin_security(self, pe_cygwin):
        result = get_binary_security(pe_cygwin)
        assert result["format"] == "PE"
        assert isinstance(result["is_pie"], bool)

    def test_signed_pe_verification(self):
        """Exercise the signed PE path (lines 38-39)."""
        binary = MagicMock(spec=lief.PE.Binary)
        opt = MagicMock()
        opt.dll_characteristics_lists = []
        binary.optional_header = opt
        binary.is_pie = True
        binary.has_nx = True
        binary.has_signatures = True
        binary.verify_signature.return_value = "OK"

        result = _pe_security(binary)
        assert result["signed"] is True
        assert result["signature_verification"] == "OK"


# ---------------------------------------------------------------------------
# ELF security
# ---------------------------------------------------------------------------

class TestSecurityELF:
    def test_format(self, elf_x64):
        result = get_binary_security(elf_x64)
        assert result["format"] == "ELF"

    def test_elf_security_fields(self, elf_x64):
        result = get_binary_security(elf_x64)
        assert isinstance(result["has_nx"], bool)
        assert isinstance(result["is_pie"], bool)
        assert result["relro"] in ("Full", "Partial", "None")
        assert isinstance(result["stack_canary"], bool)
        assert isinstance(result["fortify_source"], bool)

    def test_has_interpreter(self, elf_x64):
        result = get_binary_security(elf_x64)
        if "interpreter" in result:
            assert isinstance(result["interpreter"], str)

    def test_x86_security(self, elf_x86):
        result = get_binary_security(elf_x86)
        assert result["format"] == "ELF"
        assert result["relro"] in ("Full", "Partial", "None")

    def test_shared_library_security(self, elf_so):
        result = get_binary_security(elf_so)
        assert result["format"] == "ELF"

    def test_full_relro_via_bind_now(self):
        """Full RELRO via BIND_NOW tag (line 62)."""
        seg = MagicMock()
        seg.type = lief.ELF.Segment.TYPE.GNU_RELRO

        entry_bind = MagicMock()
        entry_bind.tag = lief.ELF.DynamicEntry.TAG.BIND_NOW

        fn = MagicMock()
        fn.name = "test"

        binary = MagicMock(spec=lief.ELF.Binary)
        binary.has_nx = True
        binary.is_pie = True
        binary.segments = [seg]
        binary.dynamic_entries = [entry_bind]
        binary.imported_functions = [fn]
        binary.has_interpreter = False

        result = _elf_security(binary)
        assert result["relro"] == "Full"

    def test_full_relro_via_flags(self):
        """Full RELRO via FLAGS with DF_BIND_NOW (lines 65-66)."""
        seg = MagicMock()
        seg.type = lief.ELF.Segment.TYPE.GNU_RELRO

        entry_flags = MagicMock()
        entry_flags.tag = lief.ELF.DynamicEntry.TAG.FLAGS
        entry_flags.value = 0x8  # DF_BIND_NOW

        fn = MagicMock()
        fn.name = "test"

        binary = MagicMock(spec=lief.ELF.Binary)
        binary.has_nx = True
        binary.is_pie = True
        binary.segments = [seg]
        binary.dynamic_entries = [entry_flags]
        binary.imported_functions = [fn]
        binary.has_interpreter = False

        result = _elf_security(binary)
        assert result["relro"] == "Full"


# ---------------------------------------------------------------------------
# Mach-O security
# ---------------------------------------------------------------------------

class TestSecurityMachO:
    def test_format(self, macho_x64):
        result = get_binary_security(macho_x64)
        assert result["format"] == "Mach-O"

    def test_macho_security_fields(self, macho_x64):
        result = get_binary_security(macho_x64)
        assert isinstance(result["is_pie"], bool)
        assert isinstance(result["has_nx"], bool)
        assert isinstance(result["has_nx_stack"], bool)
        assert isinstance(result["has_nx_heap"], bool)
        assert isinstance(result["has_code_signature"], bool)
        assert isinstance(result["header_flags"], list)
        assert isinstance(result["stack_canary"], bool)

    def test_ios_security(self, macho_ios):
        result = get_binary_security(macho_ios)
        assert result["format"] == "Mach-O"
        assert isinstance(result["is_pie"], bool)

    def test_x86_macho_security(self, macho_x86):
        result = get_binary_security(macho_x86)
        assert result["format"] == "Mach-O"

    def test_build_version_platform(self):
        """Exercise has_build_version path (lines 110-111)."""
        hdr = MagicMock()
        hdr.flags_list = []

        bv = MagicMock()
        bv.platform = MagicMock()

        fn = MagicMock()
        fn.name = "test"

        binary = MagicMock(spec=lief.MachO.Binary)
        binary.is_pie = True
        binary.has_nx = True
        binary.has_nx_stack = True
        binary.has_nx_heap = True
        binary.has_code_signature = False
        binary.header = hdr
        binary.has_build_version = True
        binary.build_version = bv
        binary.imported_functions = [fn]

        result = _macho_security(binary)
        assert "platform" in result


# ---------------------------------------------------------------------------
# Fallback / unknown format
# ---------------------------------------------------------------------------

class TestSecurityFallback:
    def test_unknown_format(self):
        """Exercise the else branch for unknown binary types (line 145)."""
        binary = MagicMock()
        binary.has_nx = True
        binary.is_pie = False
        binary.format = 999  # unknown

        with patch("tools.security.parse_binary", return_value=binary):
            result = get_binary_security("fake.bin")
        assert result["has_nx"] is True
        assert result["is_pie"] is False


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestSecurityErrors:
    def test_file_not_found(self):
        result = get_binary_security("/nonexistent/file")
        assert "error" in result

    def test_invalid_binary(self, tmp_path):
        junk = tmp_path / "junk.bin"
        junk.write_bytes(b"\x00" * 64)
        result = get_binary_security(str(junk))
        assert "error" in result
