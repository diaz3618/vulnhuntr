# Configuration

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

## Global Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Global toggle — set to `false` to disable all MCP servers. |
| `log_level` | string | `"info"` | Logging level for MCP operations. |

## Server Fields

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

## Validation Rules

- **stdio** transport requires `command`.
- **streamable-http** and **sse** transports require `url`.
- Invalid server entries are logged as warnings and skipped — they do not prevent other servers from loading.

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
| `print_status()` | Readable status string. |
| `connected_servers` | Property: list of connected server names. |
| `has_connections` | Property: whether any servers are connected. |

### `MCPServerConfig` / `MCPSettings` / `TransportType`

Pydantic models for configuration. See source in `vulnhuntr/mcp/config.py`.
