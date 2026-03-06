"""Shared fixtures for binary analysis tool tests."""

from __future__ import annotations

import os
import sys

import pytest

# Ensure project root is on sys.path so tool modules can be imported.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

SAMPLES_DIR = os.path.join(PROJECT_ROOT, "binary-samples")

# ---------------------------------------------------------------------------
# Sample file paths
# ---------------------------------------------------------------------------

PE_SAMPLES = {
    "pe_cygwin": os.path.join(SAMPLES_DIR, "pe-cygwin-ls.exe"),
    "pe_mingw": os.path.join(SAMPLES_DIR, "pe-mingw32-strip.exe"),
}

ELF_SAMPLES = {
    "elf_x64": os.path.join(SAMPLES_DIR, "elf-Linux-x64-bash"),
    "elf_x86": os.path.join(SAMPLES_DIR, "elf-Linux-x86-bash"),
    "elf_so": os.path.join(SAMPLES_DIR, "elf-Linux-lib-x64.so"),
    "elf_arm64": os.path.join(SAMPLES_DIR, "elf-Linux-ARM64-bash"),
}

MACHO_SAMPLES = {
    "macho_x64": os.path.join(SAMPLES_DIR, "MachO-OSX-x64-ls"),
    "macho_x86": os.path.join(SAMPLES_DIR, "MachO-OSX-x86-ls"),
    "macho_ios": os.path.join(SAMPLES_DIR, "MachO-iOS-armv7s-Helloworld"),
}

COFF_SAMPLES = {
    "coff_x64": os.path.join(SAMPLES_DIR, "coff-x64-obj.o"),
    "coff_x86": os.path.join(SAMPLES_DIR, "coff-x86-obj.o"),
}

ALL_SAMPLES = {**PE_SAMPLES, **ELF_SAMPLES, **MACHO_SAMPLES, **COFF_SAMPLES}


def _skip_missing(path: str) -> str:
    """Return the path or skip the test if the sample file is absent."""
    if not os.path.isfile(path):
        pytest.skip(f"Sample not found: {path}")
    return path


# ---------------------------------------------------------------------------
# Fixtures — one per sample binary
# ---------------------------------------------------------------------------

@pytest.fixture
def pe_cygwin():
    return _skip_missing(PE_SAMPLES["pe_cygwin"])


@pytest.fixture
def pe_mingw():
    return _skip_missing(PE_SAMPLES["pe_mingw"])


@pytest.fixture
def elf_x64():
    return _skip_missing(ELF_SAMPLES["elf_x64"])


@pytest.fixture
def elf_x86():
    return _skip_missing(ELF_SAMPLES["elf_x86"])


@pytest.fixture
def elf_so():
    return _skip_missing(ELF_SAMPLES["elf_so"])


@pytest.fixture
def elf_arm64():
    return _skip_missing(ELF_SAMPLES["elf_arm64"])


@pytest.fixture
def macho_x64():
    return _skip_missing(MACHO_SAMPLES["macho_x64"])


@pytest.fixture
def macho_x86():
    return _skip_missing(MACHO_SAMPLES["macho_x86"])


@pytest.fixture
def macho_ios():
    return _skip_missing(MACHO_SAMPLES["macho_ios"])


@pytest.fixture
def coff_x64():
    return _skip_missing(COFF_SAMPLES["coff_x64"])


@pytest.fixture
def coff_x86():
    return _skip_missing(COFF_SAMPLES["coff_x86"])
