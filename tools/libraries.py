"""Tool: get_binary_libraries — dynamic library dependencies."""

from __future__ import annotations

from app import mcp
from helpers import safe_str, format_name, parse_binary, _error


@mcp.tool()
def get_binary_libraries(file_path: str) -> dict:
    """Dynamic library dependencies (DLLs / shared objects / dylibs)."""
    try:
        binary = parse_binary(file_path)
    except ValueError as exc:
        return _error(str(exc))

    libs = [safe_str(lib) for lib in binary.libraries]
    return {
        "format": format_name().get(binary.format, "Unknown"),
        "count": len(libs),
        "libraries": libs,
    }
