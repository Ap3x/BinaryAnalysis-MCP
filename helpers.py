"""Shared helpers for binary parsing and value formatting."""

from __future__ import annotations

import os
from enum import Enum
from typing import Any

import lief


def hex_addr(value: int | None) -> str | None:
    """Format an integer as a hex address string, or return None."""
    if value is None:
        return None
    return f"0x{value:x}"


def safe_str(value: Any) -> str | None:
    """Convert bytes / str / other to a plain string, or None."""
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def safe_enum(value: Any) -> str | None:
    """Return the .name of an enum member, or str() for everything else."""
    if value is None:
        return None
    if isinstance(value, Enum):
        return value.name
    return str(value)


def format_name() -> dict[lief.Binary.FORMATS, str]:
    """Map LIEF format enum -> human label."""
    return {
        lief.Binary.FORMATS.PE: "PE",
        lief.Binary.FORMATS.ELF: "ELF",
        lief.Binary.FORMATS.MACHO: "Mach-O",
    }


def parse_binary(file_path: str) -> lief.Binary:
    """Parse a binary file with LIEF, handling Mach-O fat binaries.

    Returns the concrete (PE/ELF/MachO) Binary object.
    Raises ``ValueError`` with a user-friendly message on failure.
    """
    if not os.path.isfile(file_path):
        raise ValueError(f"File not found: {file_path}")

    # Try Mach-O first — lief.parse() on a fat binary returns None.
    try:
        fat = lief.MachO.parse(file_path)
        if fat is not None:
            binary = fat.at(0)
            if binary is not None:
                return binary
    except Exception:
        pass  # Not a Mach-O — fall through to generic parse.

    binary = lief.parse(file_path)
    if binary is None:
        raise ValueError(
            f"LIEF could not parse the file (unsupported format?): {file_path}"
        )
    return binary


def _error(msg: str) -> dict:
    """Return a structured error dict instead of raising."""
    return {"error": msg}
