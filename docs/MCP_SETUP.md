# MCP Integration Guide

Vulnhuntr includes an MCP (Model Context Protocol) client that lets you connect to external MCP servers for enhanced analysis capabilities. When the analysis integration is enabled (mode `auto` or `force`), the vulnerability analysis LLM agent is made aware of available MCP tools and can invoke them during analysis iterations. When the analysis integration is disabled (mode `off`, the default), behavior is identical to a non-MCP installation.

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

See [`vulnhuntr/mcp/example_config.yaml`](../vulnhuntr/mcp/example_config.yaml) for a comprehensive example with all transport types.

### 3. Use the client in Python

```python
import asyncio
from vulnhuntr.mcp import MCPClientManager, load_mcp_config

async def main():
    settings = load_mcp_config()
    async with MCPClientManager(settings) as manager:
        # See what's available
        tools = await manager.list_all_tools()
        print(tools)

        # Call a tool (auto-routes to the right server)
        result = await manager.call_tool_auto("ruff-check", {"file_path": "src/app.py"})
        print(result)

asyncio.run(main())
```

---

## Transport Types

MCP defines three transports. The `transport` field in your server config selects which one to use.

| Transport | Value | Use Case |
|-----------|-------|----------|
| **stdio** | `stdio` | Launch a subprocess, communicate via stdin/stdout. Covers `npx`, `uvx`, `python`, any local binary. |
| **Streamable HTTP** | `streamable-http` | Connect to an HTTP endpoint. Recommended for remote/production servers. |
| **SSE** | `sse` | Server-Sent Events endpoint (legacy — use `streamable-http` for new deployments). |

### stdio

Launches the server as a child process. The `command` and `args` fields specify what to run.

```yaml
servers:
  # Node.js package via npx
  ripgrep:
    transport: stdio
    command: npx
    args: ["-y", "mcp-ripgrep@latest"]

  # Python package via uvx
  analyzer:
    transport: stdio
    command: uvx
    args: [mcp-server-analyzer]

  # Direct Python script
  custom:
    transport: stdio
    command: python
    args: [/path/to/server.py]
    env:
      MY_API_KEY: "secret"

  # Any local binary
  binary:
    transport: stdio
    command: /usr/local/bin/my-server
    args: ["--config", "/etc/mcp/config.json"]
```

### streamable-http

Connects to an HTTP endpoint. Supports authentication via `headers`.

```yaml
servers:
  remote:
    transport: streamable-http
    url: "https://mcp.example.com/api/mcp"
    headers:
      Authorization: "Bearer your-token"
    timeout: 60
```

### sse (legacy)

Server-Sent Events transport. Being superseded by `streamable-http` in the MCP spec.

```yaml
servers:
  legacy:
    transport: sse
    url: "http://localhost:9000/sse"
```

---

## Configuration Reference

### Global Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Global toggle — set to `false` to disable all MCP servers. |
| `log_level` | string | `"info"` | Logging level for MCP operations. |

### Server Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `transport` | string | No | `"stdio"` | Transport type: `stdio`, `streamable-http`, or `sse`. |
| `enabled` | bool | No | `true` | Enable/disable this specific server. |
| `command` | string | stdio only | — | Executable to run (e.g., `npx`, `uvx`, `python`). |
| `args` | list | No | `[]` | Arguments for the command. |
| `url` | string | http/sse only | — | Endpoint URL. |
| `headers` | dict | No | `{}` | HTTP headers (for `streamable-http`/`sse`). |
| `env` | dict | No | `{}` | Environment variables passed to subprocess (stdio only). |
| `timeout` | int | No | `30` | Connection timeout in seconds (`0` = no timeout). |
| `description` | string | No | `""` | Human-readable description. |

### Validation Rules

- **stdio** transport requires `command`.
- **streamable-http** and **sse** transports require `url`.
- Invalid server entries are logged as warnings and skipped (they don't prevent other servers from loading).

---

## API Reference

### `load_mcp_config(config_path=None, start_dir=None) -> MCPSettings`

Finds `.vulnhuntr.yaml` and parses the `mcp:` section. Searches project root → parent directories → home directory.

### `MCPClientManager(settings: MCPSettings)`

Async context manager for MCP server connections.

| Method | Description |
|--------|-------------|
| `connect_all()` | Connect to all enabled servers concurrently. Returns `dict[name, success]`. |
| `disconnect_all()` | Disconnect from all servers and clear state. |
| `list_all_tools()` | Returns `dict[server_name, list[tool_info]]` from all connected servers. |
| `list_server_tools(name)` | List tools from a specific server. |
| `find_tool(tool_name)` | Find which server provides a tool. Returns `(server_name, tool_info)` or `None`. |
| `call_tool(server, tool, args)` | Call a tool on a specific server. |
| `call_tool_auto(tool, args)` | Call a tool, auto-routing to the correct server. |
| `list_resources(server)` | List resources from a server. |
| `read_resource(server, uri)` | Read a resource by URI. |
| `get_status()` | Status dict for all configured servers. |
| `print_status()` | Human-readable status string. |
| `connected_servers` | Property: list of connected server names. |
| `has_connections` | Property: whether any servers are connected. |

### `MCPServerConfig` / `MCPSettings` / `TransportType`

Pydantic models for configuration. See source in `vulnhuntr/mcp/config.py`.

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

## Analysis Integration

### How It Works

When `mcp.analysis.mode` is set to `auto` or `force` in `.vulnhuntr.yaml`, Vulnhuntr:

1. **Loads MCP config** and connects to all enabled servers.
2. **Discovers available tools** from each server.
3. **Filters out destructive tools** (write, delete, execute, etc.) unless `allow_destructive_tools: true`.
4. **Injects tool descriptions into the LLM system prompt**, so the analysis agent knows what tools are available.
5. **After each LLM response**, checks for `mcp_tool_calls` in the structured output and executes them.
6. **Feeds tool results back** into the next analysis iteration as XML context.
7. **Shuts down** all MCP connections when analysis completes.

### Analysis Policy Configuration

Add an `analysis` sub-section under `mcp` in `.vulnhuntr.yaml`:

```yaml
mcp:
  enabled: true
  servers:
    # ... your server definitions ...
  analysis:
    mode: auto                        # off | auto | force (default: off)
    max_tool_calls_per_iteration: 3   # cap per LLM iteration (default: 3)
    allow_destructive_tools: false    # block write/delete/execute tools (default: false)
    tool_timeout_seconds: 30          # per-tool timeout in seconds (default: 30)
    # force_servers: [scanner]        # required when mode=force
```

### Analysis Settings Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `"off"` | `off`: no MCP during analysis. `auto`: tools available, LLM decides usage. `force`: LLM must attempt tool calls from `force_servers`. |
| `force_servers` | list | `[]` | Server names required in `force` mode. At least one must be listed when mode is `force`. |
| `max_tool_calls_per_iteration` | int | `3` | Maximum tool calls the runner will execute per analysis iteration. Extra requests are logged and dropped. |
| `allow_destructive_tools` | bool | `false` | When `false`, tools whose names contain `write`, `delete`, `create`, `modify`, `update`, `execute`, `run`, `remove`, `drop`, `put`, `post`, `patch`, or `send` are blocked. |
| `tool_timeout_seconds` | int | `30` | Per-tool invocation timeout. `0` = no timeout. |

### Example Configurations

#### Off (default — no MCP)

```yaml
mcp:
  enabled: true
  servers:
    analyzer:
      transport: stdio
      command: uvx
      args: [mcp-server-analyzer]
  # No analysis section → defaults to mode: off
```

The servers are configured but not used during analysis. They can still be used programmatically via `MCPClientManager`.

#### Auto Mode

```yaml
mcp:
  enabled: true
  servers:
    snyk:
      transport: stdio
      command: npx
      args: ["-y", "snyk-mcp-server"]
      env:
        SNYK_TOKEN: "${SNYK_TOKEN}"
    cve-db:
      transport: streamable-http
      url: "https://cve-api.example.com/mcp"
  analysis:
    mode: auto
    max_tool_calls_per_iteration: 3
    tool_timeout_seconds: 30
```

The LLM sees available tools and **may** call them when they would aid vulnerability detection. Most analysis iterations will complete without tool calls.

#### Force Mode

```yaml
mcp:
  enabled: true
  servers:
    security-scanner:
      transport: stdio
      command: uvx
      args: [security-scanner-mcp]
  analysis:
    mode: force
    force_servers: [security-scanner]
    max_tool_calls_per_iteration: 5
    tool_timeout_seconds: 60
```

The LLM is instructed that it **must** attempt at least one tool call from `security-scanner` per analysis iteration. Graceful fallback occurs if the server is unavailable.

### Security Considerations

- **Tool outputs are untrusted.** The analysis agent is instructed to cross-reference MCP results with its own analysis. Never trust tool outputs as ground truth.
- **Destructive tools are blocked by default.** Only read-only tools are exposed unless `allow_destructive_tools: true`.
- **Credentials stay in config.** Use `env` for API keys — they are passed as environment variables to stdio subprocesses, never logged or sent to the LLM.
- **Output truncation.** Tool outputs are truncated to 4 KiB before being fed back to the LLM to prevent context overflow.
- **Prompt injection defense.** The system prompt explicitly warns the LLM that tool outputs may contain adversarial content.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `MCP Python SDK not installed` | Run `pip install 'vulnhuntr[mcp]'` |
| Server connection timeout | Increase `timeout` in config, verify the server process starts correctly |
| `command not found` | Ensure `npx`/`uvx`/`python` is on your PATH |
| `No MCP section in config file` | Add `mcp:` section to `.vulnhuntr.yaml` |
| YAML parse error | Check indentation — YAML is whitespace-sensitive |
| Server listed but tools empty | Check the server actually implements `tools/list` |
