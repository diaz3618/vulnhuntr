# Analysis Integration

When `mcp.analysis.mode` is set to `auto` or `force` in `.vulnhuntr.yaml`, Vulnhuntr:

1. Loads MCP config and connects to all enabled servers.
2. Discovers available tools from each server.
3. Filters out destructive tools (write, delete, execute, etc.) unless `allow_destructive_tools: true`.
4. Injects tool descriptions into the LLM system prompt so the analysis agent knows what tools are available.
5. After each LLM response, checks for `mcp_tool_calls` in the structured output and executes them.
6. Feeds tool results back into the next analysis iteration as XML context.
7. Shuts down all MCP connections when analysis completes.

## Policy Configuration

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

## Settings Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `"off"` | `off`: no MCP during analysis. `auto`: tools available, LLM decides usage. `force`: LLM must attempt tool calls from `force_servers`. |
| `force_servers` | list | `[]` | Server names required in `force` mode. At least one must be listed when mode is `force`. |
| `max_tool_calls_per_iteration` | int | `3` | Maximum tool calls executed per analysis iteration. Extra requests are logged and dropped. |
| `allow_destructive_tools` | bool | `false` | When `false`, tools whose names contain `write`, `delete`, `create`, `modify`, `update`, `execute`, `run`, `remove`, `drop`, `put`, `post`, `patch`, or `send` are blocked. |
| `tool_timeout_seconds` | int | `30` | Per-tool invocation timeout. `0` = no timeout. |

---

## Example Configurations

### Off (default)

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

Servers are configured but not used during analysis. They can still be called programmatically via `MCPClientManager`.

### Auto Mode

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

The LLM sees available tools and may call them when they aid vulnerability detection. Most iterations complete without tool calls.

### Force Mode

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

The LLM is instructed to attempt at least one tool call from `security-scanner` per iteration. Graceful fallback occurs if the server is unavailable.

---

## Security Considerations

- **Tool outputs are untrusted.** The analysis agent is instructed to cross-reference MCP results with its own analysis. Do not treat tool outputs as ground truth.
- **Destructive tools are blocked by default.** Only read-only tools are exposed unless `allow_destructive_tools: true`.
- **Credentials stay in config.** Use `env` for API keys — they are passed as environment variables to stdio subprocesses, never logged or sent to the LLM.
- **Output truncation.** Tool outputs are truncated to 4 KiB before being fed back to the LLM to prevent context overflow.
- **Prompt injection.** The system prompt explicitly warns the LLM that tool outputs may contain adversarial content.
