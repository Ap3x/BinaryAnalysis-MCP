"""Binary Analysis MCP Server — entrypoint."""

from app import mcp  # noqa: F401 — used by tools via app.mcp

import tools  # noqa: F401 — registers all @mcp.tool() handlers

if __name__ == "__main__":
    mcp.run(transport="stdio")
