# Phase 6: Sessions, Native Tools, and MCP Policy — Research

**Researched:** 2026-05-04
**Phase:** 6 — Sessions, Native Tools, and MCP Policy
**Requirements:** SESSION-01, SESSION-02, SESSION-03, SESSION-04

---

## Summary

Phase 6 wires three sets of already-declared `CLIPolicy` fields into working
behavior: `session_mode`, `tool_mode`/`sandbox_mode`, and `mcp_mode`. All
structural fields landed in Phase 3; none are added here. Research confirms
the concrete flag mappings, validates D-18's serialization claim, and
establishes the `--mcp-config` stub contract for ClaudeCodeLLM.

---

## Open Questions Resolved

### D-02 — Qwen Code Session Behavior

**Question:** Does Qwen Code support `--continue` or `--resume <session_id>`?

**Finding:** Qwen Code 0.15.6 is stateless by design. The CLI accepts
`-p <prompt> --output-format json [--approval-mode plan|--yolo]`. There is no
`--continue`, `--session`, or `--resume` flag in the public interface. OAuth
was discontinued April 15, 2026; auth is now key-based (direct Qwen or
bridge mode). The Phase 5 implementation confirms this — `send_message()` has
no session flags and the `type:system` entry in the JSON array carries a
`session_id` field, but it is a read-only correlation ID, not a resumption
handle the operator can pass back.

**Decision applied:** D-02's "warn + stateless" rule applies for Qwen Code.
When `session_mode` is `"continue"` or `"resume"`, log a structured warning
and proceed with stateless behavior.

---

### D-18 — Serialization of `session_mode` and `mcp_mode`

**Question:** Do these fields need to be explicitly added to
`VulnhuntrConfig.to_dict()` / `from_dict()`?

**Finding (from `vulnhuntr/config.py`):**

`to_dict()` serializes the entire `CLIPolicy` via `dataclasses.asdict()`:
```python
"cli": dataclasses.asdict(self.cli),
```

`from_dict()` explicitly deserializes every `CLIPolicy` field including
`session_mode` (line 169) and `mcp_mode` (line 177). Both round-trip
correctly with no changes.

**Decision applied:** No changes to `to_dict()` / `from_dict()`. D-18 closes
as confirmed.

---

## Current State Audit (What Exists vs. What Phase 6 Adds)

### `CLIProviderLLM` base class (`vulnhuntr/cli_providers/base.py`)

| Symbol | State | Phase 6 action |
|--------|-------|----------------|
| `self.session_id` | **Missing** | Add as `str \| None = None` in `__init__()` |
| `self._last_probe_version` | **Missing** | Add as `str \| None = None` in `__init__()` |
| `get_session_metadata()` | **Missing** | Add method returning `dict \| None` |
| `_build_mcp_config_args()` | **Missing** | Add default returning `[]`; logs warning when `mcp_mode != "none"` |

### `CLIPolicy` docstring (`vulnhuntr/config.py`)

| Field | Current docstring coverage | Phase 6 action |
|-------|---------------------------|----------------|
| `tool_mode` | Lists three values but omits MCP category | Extend per D-09 |
| `sandbox_mode` | Not documented at class level | Document as Codex-specific per D-10 |

### Provider `send_message()` implementations

| Provider | `session_mode` wired | `_last_probe_version` set | `_build_mcp_config_args()` called |
|---------|---------------------|--------------------------|----------------------------------|
| `ClaudeCodeLLM` | **No** — hardcodes `--no-session-persistence` | **No** | **No** |
| `GeminiCLILLM` | **No** — no session handling | **No** | **No** |
| `CodexLLM` | **No** — no session handling | **No** | **No** |
| `QwenCodeLLM` | **No** — no session handling | **No** | **No** |

### `CheckpointData` (`vulnhuntr/checkpoint.py`)

| Field | State | Phase 6 action |
|-------|-------|----------------|
| `session_metadata` | **Missing** | Add `session_metadata: dict[str, Any] \| None = None`; update `to_dict()` / `from_dict()` |

### Runner (`vulnhuntr/cli/runner.py`)

| Behavior | State | Phase 6 action |
|----------|-------|----------------|
| Write `session_metadata` to checkpoint after first successful call | **Missing** | Add after first provider `send_message()` when `session_mode != "stateless"` |

---

## Session Flag Mapping (Confirmed)

### Claude Code (`claude` binary)

Confirmed from `claude_code.py` and Claude Code documentation:

| `session_mode` | CLI flag(s) |
|---|---|
| `"stateless"` | `--no-session-persistence` (replace hardcoded default) |
| `"continue"` | `--continue` |
| `"resume"` | `--resume <session_id>` |

The current code hardcodes `--no-session-persistence` in the command list
(phase 4 implementation). Phase 6 replaces this with a dynamic lookup:
```python
session_mode = self._policy.session_mode if self._policy else "stateless"
if session_mode == "stateless":
    cmd.append("--no-session-persistence")
elif session_mode == "continue":
    cmd.append("--continue")
elif session_mode == "resume":
    if not self.session_id:
        raise CLIRuntimeError(
            "session_mode='resume' requires a stored session_id; ..."
        )
    cmd.extend(["--resume", self.session_id])
```

Claude Code's JSON envelope contains a top-level `"session_id"` key.
`send_message()` should extract and store it in `self.session_id` after
parsing the payload:
```python
self.session_id = payload.get("session_id")
```

### Gemini CLI (`gemini` binary, 0.40.1)

Gemini CLI 0.40.1 has no session continuation flags. There is no `--continue`,
`--resume`, or `--session` flag. Each invocation is fully stateless.

D-02 applies: warn + stateless for any non-stateless `session_mode`.

### Codex (`codex` binary, 0.128.0 Rust CLI)

Codex CLI is stateless by design — each `codex exec` invocation is an
independent execution context. No session flags exist.

D-02 applies: warn + stateless for any non-stateless `session_mode`.

The `turn.completed` JSONL event does not contain a session ID. `self.session_id`
stays `None` after a Codex call.

### Qwen Code (`qwen` binary, 0.15.6)

Confirmed stateless. The `type:system` JSON array entry carries `"session_id"` as
a read-only correlation ID, not a resumption handle. No `--continue`/`--resume` flag.

D-02 applies: warn + stateless for any non-stateless `session_mode`.

Phase 6 does NOT set `self.session_id` from the system entry's correlation ID
because it cannot be passed back to resume a session.

---

## MCP Config Injection (D-13, D-15)

### Claude Code `--mcp-config` flag

Claude Code accepts `--mcp-config <path>` where `<path>` is a JSON file:
```json
{
  "mcpServers": {
    "server-name": {
      "command": "...",
      "args": [...],
      "env": {...}
    }
  }
}
```

Phase 6 writes an empty stub — `{"mcpServers": {}}` — to satisfy the flag
contract and exercise the code path. Phase 7 populates it with real servers.

The temp file must be written to `self.workdir` to avoid permission issues and
to keep cleanup predictable. Use `pathlib.Path(self.workdir) / "mcp_config.json"`.

### Base class default

`_build_mcp_config_args()` in `CLIProviderLLM`:
- When `_policy` is None or `mcp_mode == "none"`: return `[]`
- When `mcp_mode != "none"`: log warning (D-14), return `[]`

This ensures non-Claude providers degrade gracefully with an operator-visible
warning rather than silently ignoring the setting.

---

## Test Patterns (from existing `tests/test_cli_providers.py`)

Phase 6 follows the established patterns exactly:
- `unittest.mock.patch("subprocess.run")` for subprocess interception
- `MagicMock` with `.stdout`, `.returncode = 0` for fake results
- Parametrized classes with `@pytest.mark.parametrize` for flag variants
- One test class per behavioral group (e.g., `TestClaudeCodeSessionMode`)

The CONTEXT.md D-11 call-out confirms this approach.

**Layout decision (CONTEXT.md "the agent's Discretion"):** Phase 6 extends
`tests/test_cli_providers.py` rather than splitting to `test_session_policy.py`.
The file already covers all four providers and growing it is lower overhead than
introducing cross-file fixture duplication. If it exceeds ~600 lines after Phase 6,
a split is appropriate in a later phase.

---

## Implementation Order

```
Wave 1:  Plan 01 — Base class contracts + CheckpointData + CLIPolicy docstring
Wave 2:  Plan 02 — Provider wire-up (all 4 providers)   [no file overlap with Plan 03]
         Plan 03 — Runner session metadata integration   [parallel with Plan 02]
Wave 3:  Plan 04 — Parametrized tests
```

Wave 2 parallelism is safe: Plan 02 touches the four provider files; Plan 03
touches only `runner.py`. No overlap.

---

## Architecture Responsibility Map

| Layer | Responsibility |
|-------|----------------|
| `CLIProviderLLM` (base) | Declare `session_id`, `_last_probe_version`, `get_session_metadata()`, `_build_mcp_config_args()` contracts |
| Each provider (leaf) | Implement session-flag mapping in `send_message()`; set `self.session_id`; set `self._last_probe_version` in `probe()`; override `_build_mcp_config_args()` (Claude Code only) |
| `CheckpointData` | Store `session_metadata` as an opaque dict |
| `run_analysis()` | Write `session_metadata` to checkpoint after first successful call when mode is non-stateless |
| `CLIPolicy` docstring | Document `tool_mode` and `sandbox_mode` coverage scope |

---

## Standard Stack (from Phases 3–5)

| Concern | Pattern |
|---------|---------|
| subprocess interception | `unittest.mock.patch("subprocess.run")` |
| structured logging | `log.warning(...)` via `structlog` |
| error taxonomy | `CLIRuntimeError` for resume without session_id |
| typing | `str \| None` for optional string fields |
| serialization | `to_dict()` / `from_dict()` dict expansion |

---

## Common Pitfalls to Avoid

1. **`--no-session-persistence` removal** — the flag must be REPLACED by the dynamic
   lookup, not just appended. The hardcoded flag is currently the last item in `cmd`
   before the subprocess call.
2. **Qwen Code correlation ID** — do NOT store the `session_id` from the `type:system`
   entry as `self.session_id`. It cannot resume a session and would mislead the runner.
3. **Temp file collision** — write `mcp_config.json` to `self.workdir`; do not use
   `tempfile.mkstemp()` in a random location (Phase 7 must find and replace the file
   predictably).
4. **`dataclasses.asdict()` depth** — `session_metadata` is `dict | None`, not a nested
   dataclass. `asdict()` will handle it correctly without extra work.

---

*Phase 6 research complete. Implementation is fully deterministic — no further research needed before planning.*
