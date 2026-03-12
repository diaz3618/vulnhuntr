# MCP Integration

Vulnhuntr includes an MCP (Model Context Protocol) client that connects to external MCP servers for enhanced analysis capabilities. When analysis integration is enabled (`mode: auto` or `force`), the vulnerability analysis agent is made aware of available MCP tools and can invoke them during analysis iterations. When disabled (`mode: off`, the default), behavior is identical to a non-MCP installation.

## Quick Start

### 1. Install the optional MCP dependency

```bash
pip install 'vulnhuntr[mcp]'
```

This installs the official [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) (`mcp >= 1.0.0`).

### 2. Add MCP servers to `.vulnhuntr.yaml`

Create or edit `.vulnhuntr.yaml` in your project root (or `~/.vulnhuntr.yaml`):

```yaml
mcp:
  enabled: true
  servers:
    analyzer:
      transport: stdio
      command: uvx
      args: [mcp-server-analyzer]
```

See [`vulnhuntr/mcp/example_config.yaml`](../vulnhuntr/mcp/example_config.yaml) for an example with all transport types.

### 3. Use the client in Python

```python
import asyncio
from vulnhuntr.mcp import MCPClientManager, load_mcp_config

async def main():
    settings = load_mcp_config()
    async with MCPClientManager(settings) as manager:
        tools = await manager.list_all_tools()
        print(tools)

        result = await manager.call_tool_auto("ruff-check", {"file_path": "src/app.py"})
        print(result)

asyncio.run(main())
```

---

## File Layout

```
vulnhuntr/mcp/
├── __init__.py          # Public exports
├── analysis.py          # Analysis pipeline integration (MCPAnalysisHelper)
├── config.py            # Pydantic config models + YAML parsing
├── client.py            # MCPClientManager (connection lifecycle)
└── example_config.yaml  # Full example with all transport types
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `MCP Python SDK not installed` | Run `pip install 'vulnhuntr[mcp]'` |
| Server connection timeout | Increase `timeout` in config, verify the server process starts |
| `command not found` | Ensure `npx`/`uvx`/`python` is on your PATH |
| `No MCP section in config file` | Add `mcp:` section to `.vulnhuntr.yaml` |
| YAML parse error | Check indentation — YAML is whitespace-sensitive |
| Server listed but tools empty | Verify the server implements `tools/list` |

---

See also:

- [configuration.md](configuration.md) — Transport types, config reference, API reference
- [analysis-integration.md](analysis-integration.md) — Analysis integration settings and examples
