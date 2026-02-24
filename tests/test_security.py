"""Tests for get_binary_security tool."""

from __future__ import annotations

from tools.security import get_binary_security


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
