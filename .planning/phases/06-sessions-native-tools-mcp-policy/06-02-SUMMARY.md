# Plan 02 Summary — Provider Session/MCP Wire-up

**Commit**: `ef22305`
**Status**: COMPLETE

## Changes

### ClaudeCodeLLM (`vulnhuntr/cli_providers/claude_code.py`)
- `send_message()`: replaced hardcoded `--no-session-persistence` with dynamic session_mode logic:
  - `stateless` → `--no-session-persistence`
  - `continue` → `--continue`
  - `resume` + no `session_id` → raises `CLIRuntimeError`
  - `resume` + `session_id` → `--resume <session_id>`
- `send_message()`: extracts `self.session_id = payload.get("session_id")` from response
- `send_message()`: calls `cmd.extend(self._build_mcp_config_args())`
- `probe()`: sets `self._last_probe_version = version`
- `_build_mcp_config_args()`: writes `{"mcpServers": {}}` stub to `{workdir}/mcp_config.json` for `mcp_mode="vulnhuntr"` or `"both"`, returns `["--mcp-config", str(path)]`

### GeminiCLILLM (`vulnhuntr/cli_providers/gemini_cli.py`)
- `probe()`: sets `self._last_probe_version = version_str`
- `send_message()`: logs warning for non-stateless session_mode and falls back silently
- `send_message()`: calls `cmd.extend(self._build_mcp_config_args())`

### CodexLLM (`vulnhuntr/cli_providers/codex.py`)
- `probe()`: sets `self._last_probe_version = version_str`
- `send_message()`: config-driven sandbox_mode (explicit `"workspace-write"` overrides tool_mode fallback)
- `send_message()`: logs warning for non-stateless session_mode
- `send_message()`: calls `cmd.extend(self._build_mcp_config_args())`

### QwenCodeLLM (`vulnhuntr/cli_providers/qwen_code.py`)
- `probe()`: sets `self._last_probe_version = version_str`
- `send_message()`: logs warning for non-stateless session_mode
- `send_message()`: calls `cmd.extend(self._build_mcp_config_args())`

## Verification
All assertions passed via inline Python verification script.
