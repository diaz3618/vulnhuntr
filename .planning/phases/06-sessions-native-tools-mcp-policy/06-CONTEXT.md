# Phase 6: Sessions, Native Tools, and MCP Policy - Context

**Gathered:** 2026-05-04
**Status:** Ready for planning

<domain>
## Phase Boundary

Make `CLIPolicy.session_mode` and `CLIPolicy.mcp_mode` fields functional
rather than stored-but-ignored. Concretely:

1. **Session modes** — wire `session_mode` into each provider's
   `send_message()` so operators can choose stateless, continue, or resume
   behavior through config rather than through hardcoded flags.
2. **Session metadata** — capture session identifiers from provider responses
   and persist them in `CheckpointData` so resumed scans can record which
   session was reused.
3. **Native-tool policy documentation** — formally scope `tool_mode` across
   all provider-native tool categories (file access, shell, web, computer-use,
   provider-managed MCP) in code and YAML schema.
4. **MCP ownership policy** — define and gate the four `mcp_mode` values
   (`"none"` / `"vulnhuntr"` / `"provider"` / `"both"`); wire a
   `_build_mcp_config_args()` hook in the base class so Claude Code can pass
   `--mcp-config` when `mcp_mode` requires it. Full MCP server forwarding
   lands in Phase 7.

No new `CLIPolicy` dataclass fields. All structural fields
(`session_mode`, `mcp_mode`, `sandbox_mode`, `tool_mode`) landed in Phase 3.

</domain>

<decisions>
## Implementation Decisions

### Session Mode Wire-Up (SESSION-01, SESSION-02)

- **D-01:** `session_mode` values and semantics:
  - `"stateless"` (default) — no cross-call state; every subprocess call is
    independent. Translates to the current hardcoded behavior per provider.
  - `"continue"` — attach to the most-recent provider session. Supported only
    by Claude Code (`--continue`). Other providers: log a warning, fall back
    to stateless.
  - `"resume"` — resume a specific previous session by ID. Supported only by
    Claude Code (`--resume <session_id>`). Other providers: log a warning,
    fall back to stateless. Requires a stored `session_id` in `CheckpointData`
    for the target repo.

- **D-02:** Flag mapping per provider (implemented in each `send_message()`):

  | `session_mode` | Claude Code | Gemini CLI | Codex | Qwen Code |
  |---|---|---|---|---|
  | `"stateless"` | `--no-session-persistence` | _(no flag; default)_ | _(no flag; stateless by design)_ | _(no flag; researcher confirms)_ |
  | `"continue"` | `--continue` | warn + stateless | warn + stateless | warn + stateless |
  | `"resume"` | `--resume <session_id>` | warn + stateless | warn + stateless | warn + stateless |

  Researcher must confirm Qwen Code's session behavior; if it supports resume,
  the planner adds the appropriate flag mapping.

- **D-03:** Claude Code's `--no-session-persistence` is removed from the
  hardcoded default in `send_message()` and replaced by a lookup of
  `self._policy.session_mode if self._policy else "stateless"`. The behavior
  is identical for the current default; it is now config-driven.

- **D-04:** When `session_mode == "resume"` and no `session_id` is stored in
  `CheckpointData.session_metadata`, raise `CLIRuntimeError` with a clear
  message: `"session_mode='resume' requires a stored session_id; run with
  session_mode='stateless' or 'continue' first to create one."` Do NOT fall
  back silently to stateless — the operator explicitly requested resume and
  should know it failed.

### Session Metadata Capture and Storage (SESSION-02)

- **D-05:** Add `session_id: str | None = None` as a new instance attribute
  to `CLIProviderLLM.__init__()`. After `_run_subprocess()` returns, each
  provider's `send_message()` sets `self.session_id` if the JSON envelope
  contains a session ID field. Claude Code uses `"session_id"` key in its
  JSON envelope.

- **D-06:** Add a new base-class method:
  ```python
  def get_session_metadata(self) -> dict[str, Any] | None:
      """Return session metadata after a send_message() call, or None."""
      if not self.session_id:
          return None
      return {
          "provider": self.__class__.__name__,
          "session_id": self.session_id,
          "started_at": datetime.utcnow().isoformat(),
          "workdir": self.workdir,
          "binary_version": getattr(self, "_last_probe_version", None),
      }
  ```
  Subclasses do not override this method; they only set `self.session_id`.

- **D-07:** Extend `CheckpointData` with a new field:
  ```python
  session_metadata: dict[str, Any] | None = None
  ```
  Serialize/deserialize via the existing `to_dict()` / `from_dict()` pattern.
  The runner writes `session_metadata` to the checkpoint after the first
  successful call when `session_mode != "stateless"`.

- **D-08:** `_last_probe_version: str | None = None` — set by `probe()` on
  success so `get_session_metadata()` can include it without requiring an
  extra method call. This is a private detail; not part of the public API.

### Native Tool Policy Scope (SESSION-03)

- **D-09:** `tool_mode` governs ALL provider-native capability categories.
  Add explicit documentation to the `CLIPolicy` docstring:

  > `tool_mode` controls access to ALL provider-native tools during a scan:
  > file-system reads/writes, shell execution, web browsing, computer-use
  > actions, and MCP servers the provider manages on its own. It does NOT
  > govern Vulnhuntr-managed MCP servers (that is `mcp_mode`).
  >
  > `"none"` — disable all tools (safe default for scanning)
  > `"read-only"` — file reads only; shell, web, and computer-use disabled
  > `"full"` — all tools the provider supports are enabled (explicit opt-in)

- **D-10:** `sandbox_mode` remains Codex-specific. It maps to
  `--sandbox read-only|workspace-write` in `CodexLLM.send_message()`. No
  other provider currently uses this field. Phase 6 wires the Codex mapping
  (replacing any hardcoded value from Phase 5) and documents that it's a
  Codex-specific knob.

  | `sandbox_mode` | Codex flag |
  |---|---|
  | `"none"` / `"read-only"` | `--sandbox read-only` |
  | `"workspace-write"` | `--sandbox workspace-write` |

- **D-11:** No tests verify that `tool_mode` and `sandbox_mode` actually
  inject the correct flags today. Phase 6 adds parametrized tests covering
  every `tool_mode` value for each provider and every `sandbox_mode` value
  for Codex. These tests use `unittest.mock.patch("subprocess.run")` exactly
  as the existing test suite does.

### MCP Ownership Policy (SESSION-04)

- **D-12:** `mcp_mode` values and their meaning:

  | Value | Provider-native MCP | Vulnhuntr MCP forwarded | Notes |
  |---|---|---|---|
  | `"none"` | disabled | no | Default; safest |
  | `"vulnhuntr"` | disabled | yes | Vulnhuntr-managed servers only |
  | `"provider"` | provider's own config | no | Operator uses their own MCP setup |
  | `"both"` | provider's own config | yes | Full access; operator must opt in |

- **D-13:** Add `_build_mcp_config_args(self) -> list[str]` to
  `CLIProviderLLM` as a non-abstract method returning `[]` by default.
  `ClaudeCodeLLM` overrides it: when `mcp_mode in ("vulnhuntr", "both")`,
  it writes a temp JSON file to `self.workdir` and returns
  `["--mcp-config", str(temp_file)]`. The temp file content is provided by
  the runner (Phase 7); Phase 6 wires the call site and the temp-file stub.

- **D-14:** In Phase 6, when `mcp_mode != "none"` and the provider is not
  Claude Code (which has the `--mcp-config` flag), log a structured warning:
  ```
  mcp_mode='<value>' requested but <Provider> does not implement MCP config
  injection; continuing with mcp_mode='none' behavior.
  ```
  Do NOT raise an error — operators may set `mcp_mode` in a shared config
  that applies to multiple providers. The warning makes the degradation
  visible without breaking the scan.

- **D-15:** The temp MCP config file written by `ClaudeCodeLLM` in Phase 6
  is an empty `{"mcpServers": {}}` stub — enough to satisfy the
  `--mcp-config` flag contract and verify the code path. Phase 7 populates
  it with real server definitions from `MCPSettings`.

- **D-16:** `mcp_mode == "provider"` means Vulnhuntr does nothing: it
  neither disables provider-native MCP nor injects its own config. The
  provider uses whatever MCP configuration exists in its own config files.
  This mode is an operator escape hatch; Vulnhuntr makes no guarantees about
  what tools the provider can access.

### Config Fields (No New Fields)

- **D-17:** No new `CLIPolicy` dataclass fields in Phase 6. All required
  fields (`session_mode`, `mcp_mode`, `sandbox_mode`, `tool_mode`,
  `strip_env_vars`, `overrides`, `workdir`, `timeout`, `max_turns`) landed
  in Phase 3. Phase 6 wires behavior to them.

- **D-18:** Researcher confirms whether `mcp_mode` and `session_mode` need
  to be added to `VulnhuntrConfig.to_dict()` / `from_dict()` — currently
  both are serialized correctly because they live inside `CLIPolicy` which is
  already serialized in the `"cli"` section.

### the agent's Discretion

- Whether to add a `SessionMode` literal type alias (e.g.
  `SessionMode = Literal["stateless", "continue", "resume"]`) alongside the
  existing string field — planner decides based on project typing conventions
  and whether it creates meaningful static-analysis benefit.
- Test file layout: extend `tests/test_cli_providers.py` or split session-
  specific tests into `tests/test_session_policy.py` — planner decides based
  on total test count after implementation.
- Exact Qwen Code session behavior — researcher confirms; if Qwen Code
  supports sessions, planner adds the mapping; if not, D-02's "warn +
  stateless" rule applies.
- Whether `get_session_metadata()` should be an abstract method or concrete
  base method — concrete (D-06) is recommended since subclasses only set
  `self.session_id`, not the full schema.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase Requirements
- `.planning/REQUIREMENTS.md` §SESSION-01..04 — acceptance criteria for all
  four Phase 6 requirements

### Base Class and Existing Providers
- `vulnhuntr/cli_providers/base.py` — `CLIProviderLLM`, error taxonomy,
  `_build_env()`, `_run_subprocess()`, `chat()`; D-05, D-06, D-13 all add
  to this file
- `vulnhuntr/cli_providers/claude_code.py` — reference for D-03, D-04
  (session flag injection), D-13 (`_build_mcp_config_args()` override)
- `vulnhuntr/cli_providers/gemini_cli.py` — reference for D-02 warn-and-
  fall-back pattern
- `vulnhuntr/cli_providers/codex.py` — D-10 (`sandbox_mode` wiring);
  current hardcoded `--sandbox read-only` must be replaced by policy lookup
- `vulnhuntr/cli_providers/qwen_code.py` — researcher confirms session
  support before D-02 table is finalized for this provider

### Config and Checkpoint
- `vulnhuntr/config.py` — `CLIPolicy` (all fields in scope); D-09 adds
  docstring only; D-17 confirms no new fields
- `vulnhuntr/checkpoint.py` — `CheckpointData`; D-07 adds
  `session_metadata: dict[str, Any] | None = None` with serialization

### MCP Infrastructure (reference only in Phase 6)
- `vulnhuntr/mcp/config.py` — `MCPSettings`, `MCPServerConfig`; Phase 7
  will pass an `MCPSettings` instance to `_build_mcp_config_args()`;
  Phase 6 stubs are empty
- `vulnhuntr/mcp/client.py` — standalone client; NOT integrated in Phase 6

### Prior Phase Context
- `.planning/phases/03-cli-provider-contract-config-schema/03-CONTEXT.md` —
  defines `CLIPolicy` fields and `overrides` pattern
- `.planning/phases/04-claude-code-gemini-cli/04-CONTEXT.md` — D-11 through
  D-22 define `tool_mode` mapping, `_STRIP_ENV_VARS`, test strategy, and
  D-16 (system prompt delivery pattern); all carry forward unchanged
- `.planning/phases/05-codex-qwen-code/05-CONTEXT.md` — D-01 through D-12
  define Codex sandbox approach and Qwen Code overrides pattern

### Existing Tests (extend, not replace)
- `tests/test_cli_providers.py` — extend with session-mode and mcp-mode flag
  injection tests; new parametrized test cases for all providers
- `tests/test_checkpoint.py` — extend to cover `session_metadata`
  serialization roundtrip

</canonical_refs>

<code_context>
## Existing Code Insights

### Current State — What Exists but Is Not Wired
- `CLIPolicy.session_mode = "stateless"` — parsed from YAML, not read in
  any provider
- `CLIPolicy.mcp_mode = "none"` — parsed from YAML, not read anywhere
- `CLIPolicy.sandbox_mode = "none"` — parsed from YAML; Codex hardcodes
  `--sandbox read-only` in Phase 5 rather than reading this field
- `ClaudeCodeLLM.send_message()` — hardcodes `"--no-session-persistence"` at
  line 132; Phase 6 replaces this with `_session_flags()` lookup

### Reusable Assets
- `CLIProviderLLM._build_env()` — the pattern for per-call env construction;
  `_build_mcp_config_args()` follows the same optional-override pattern
- `CheckpointData.to_dict()` / `from_dict()` — add `session_metadata` key;
  the dict is already `json`-serialized; no new serialization logic needed
- `GeminiCLILLM.send_message()` — shows the warn-and-continue pattern for
  unsupported flags (approval_mode fallback); reuse for session_mode warnings

### Integration Points
- `vulnhuntr/cli/runner.py` `_init_providers()` — already passes `policy` to
  each provider constructor; no runner changes needed for Phase 6 unless the
  runner is responsible for writing `session_metadata` to the checkpoint
  (confirm during planning — the runner may need a small update to call
  `provider.get_session_metadata()` after the first successful call)
- `vulnhuntr/checkpoint.py` `CheckpointData` — extend here; the checkpoint
  manager already handles serialization and file I/O

### Established Patterns
- `tool_mode` → flag table in `send_message()` — copy for `session_mode`
- `_STRIP_ENV_VARS: ClassVar[tuple[str, ...]]` — not changed in Phase 6
- `@pytest.mark.live` — not applicable to session policy tests (all mocked)
- `unittest.mock.patch("subprocess.run")` — standard mock for all new tests

</code_context>
