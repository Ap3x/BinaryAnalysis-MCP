"""FastMCP application instance — imported by tool modules and server.py."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "Binary Analysis",
    instructions=(
        "This server analyses PE, ELF, and Mach-O binary files. "
        "Pass an absolute file path to any tool. The format is auto-detected."
    ),
)
