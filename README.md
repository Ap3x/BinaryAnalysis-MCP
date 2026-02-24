# BinaryAnalysis-MCP

![Tests](https://github.com/Ap3x/BinaryAnalysis-MCP/actions/workflows/tests.yml/badge.svg)

An MCP server for analysing PE, ELF, and Mach-O binary files using [LIEF](https://lief-project.github.io/).
Pass an absolute file path to any tool and the format is auto-detected.

## Tools

| Tool | Description |
|---|---|
| `get_binary_info` | Quick triage — format, architecture, entry point, section/import/export counts, NX & PIE flags |
| `get_binary_headers` | Full header dump (PE DOS/COFF/Optional, ELF header, Mach-O header) |
| `get_binary_sections` | All sections with name, size, virtual address, entropy, and permissions |
| `get_binary_imports` | Imported functions grouped by library (PE by DLL, flat list for ELF/Mach-O) |
| `get_binary_exports` | Exported functions/symbols with ordinals, addresses, and forwarding info |
| `get_binary_libraries` | Dynamic library dependencies (DLLs / shared objects / dylibs) |
| `get_binary_security` | Security hardening — ASLR, DEP/NX, SEH, CFG, RELRO, stack canaries, code signing |

## Requirements

- Python 3.10+
- Dependencies listed in `requirements.txt`:
  - `mcp[cli]` — Model Context Protocol SDK
  - `lief>=0.17.0` — binary parsing library

## Installation

```bash
git clone https://github.com/your-username/BinaryAnalysis-MCP.git
cd BinaryAnalysis-MCP
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

## Running the server

```bash
python server.py
```

The server communicates over **stdio** using the MCP protocol.

## MCP client configuration

### Claude Desktop

Add the following to your Claude Desktop config file:

- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "binary-analysis": {
      "command": "python",
      "args": ["C:/path/to/BinaryAnalysis-MCP/server.py"],
      "env": {}
    }
  }
}
```

If you're using a virtual environment, point directly to the venv Python:

```json
{
  "mcpServers": {
    "binary-analysis": {
      "command": "C:/path/to/BinaryAnalysis-MCP/.venv/Scripts/python.exe",
      "args": ["C:/path/to/BinaryAnalysis-MCP/server.py"],
      "env": {}
    }
  }
}
```

### Claude Code (CLI)

In your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "binary-analysis": {
      "command": "python",
      "args": ["C:/path/to/BinaryAnalysis-MCP/server.py"],
      "env": {}
    }
  }
}
```

### Generic MCP client (stdio)

Any MCP-compatible client can launch the server as a subprocess:

```json
{
  "command": "python",
  "args": ["/absolute/path/to/server.py"],
  "transport": "stdio"
}
```

## Example usage

Once connected, ask your MCP client to call the tools with an absolute file path:

```
Analyse the security hardening of C:\Windows\System32\notepad.exe
```

```
List all imported DLLs for /usr/bin/ls
```

```
Show me the PE headers of C:\Windows\explorer.exe
```

## Project structure

```
server.py              — entrypoint: imports tools, runs mcp
app.py                 — FastMCP instance
helpers.py             — parse_binary, hex_addr, safe_str, safe_enum, format_name, _error
tools/
  __init__.py          — imports all tool modules (triggers @mcp.tool registration)
  info.py              — get_binary_info
  headers.py           — get_binary_headers
  sections.py          — get_binary_sections
  imports.py           — get_binary_imports
  exports.py           — get_binary_exports
  libraries.py         — get_binary_libraries
  security.py          — get_binary_security + _pe_security, _elf_security, _macho_security
tests/
  conftest.py          — shared fixtures and sample file paths
  test_helpers.py      — tests for helpers.py utilities
  test_info.py         — tests for get_binary_info
  test_headers.py      — tests for get_binary_headers
  test_sections.py     — tests for get_binary_sections
  test_imports.py      — tests for get_binary_imports
  test_exports.py      — tests for get_binary_exports
  test_libraries.py    — tests for get_binary_libraries
  test_security.py     — tests for get_binary_security
binary-samples/        — test binaries (git submodule)
.github/workflows/
  tests.yml            — CI: runs pytest on push/PR to main
```

## Pairs well with

This MCP pairs well with [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) — an MCP server that exposes Ghidra's reverse engineering capabilities. Use BinaryAnalysis-MCP for quick static triage (headers, imports, security flags) and GhidraMCP for deeper decompilation and control-flow analysis.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
