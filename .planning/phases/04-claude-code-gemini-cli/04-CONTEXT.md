# Phase 4: Claude Code & Gemini CLI - Context

**Gathered:** 2026-05-02
**Updated:** 2026-05-04 (post-implementation review; captures CR-01, CR-02, WR-01, WR-04 findings)
**Status:** Complete — verified 16/16

<domain>
## Phase Boundary

Turn the Phase 3 `CLIProviderLLM` base class into two production-grade backends:

1. **`ClaudeCodeLLM`** (`vulnhuntr/cli_providers/claude_code.py`) — promoted from `internal/experiments/vulnhuntr_claude_code/claude_code_llm.py`, restructured as a thin subclass implementing only the 4 abstract methods (`probe()`, `send_message()`, `get_response()`, `_extract_usage()`).
2. **`GeminiCLILLM`** (`vulnhuntr/cli_providers/gemini_cli.py`) — new implementation with version-aware probe and Gemini-specific JSON envelope parsing.
3. **Runner wiring** — replace `NotImplementedError` stubs in `_init_providers()` with real instantiation for `"claude-code"` and `"gemini-cli"`.
4. **Tests** — mocked subprocess tests covering success, timeout, parse failure, and missing-binary for each provider; optional live-path markers.
5. **`CLIPolicy` extension** — add `tool_mode` and `strip_env_vars` fields to the existing dataclass.

No Codex or Qwen Code in this phase — those land in Phase 5.

</domain>

<decisions>
## Implementation Decisions

### Claude Code Adapter (`ClaudeCodeLLM`)

- **D-01:** `ClaudeCodeLLM` is a **thin adapter** implementing only `probe()`, `send_message()`, `get_response()`, and `_extract_usage()`. The base class `CLIProviderLLM.chat()` handles the full subprocess + validation pipeline. No custom `chat()` override.
- **D-02:** `send_message()` passes prompts via `-p <text>` CLI argument (matches experiment; large prompts are fine via `-p`).
- **D-03:** Default flags: `--output-format json`, `--permission-mode bypassPermissions`, `--no-session-persistence`. These are required for headless operation.
- **D-04:** `probe()` checks binary availability with `shutil.which("claude")`, runs `claude --version` to capture version, sets `auth_valid=None` (auth only verifiable at first real call). Returns a clear install hint if binary is missing.
- **D-05:** `_STRIP_ENV_VARS = ["ANTHROPIC_API_KEY"]` — strips the API key to force CLI (OAuth) auth, matching the experiment.

### Gemini CLI Adapter (`GeminiCLILLM`)

- **D-06:** JSON envelope field is `response` (not `result` like Claude Code). `get_response()` returns `payload.get("response")`.
- **D-07:** ~~`_extract_usage()` parses `stats.inputTokenCount` and `stats.outputTokenCount`~~ — **CORRECTED.** `stats.inputTokenCount` / `stats.outputTokenCount` do not exist in Gemini CLI 0.40.1. The actual path is `stats.models.<model_name>.tokens.input` and `stats.models.<model_name>.tokens.candidates`. Use `for name, mdata in (response.get("stats") or {}).get("models", {}).items()` to iterate. Fall back to 0 if the path is absent.
- **D-08:** `probe()` checks binary with `shutil.which("gemini")`, parses version from `gemini --version`, and gates on `>= 0.6.0` (the version that added `--output-format json`). Version parsing uses **tuple comparison with 3-element padding** (see D-21) — string comparison is incorrect because `"0.40.1" < "0.9.0"` as strings.
- **D-09:** `_STRIP_ENV_VARS = ("GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GENAI_USE_VERTEXAI")` — all three must be stripped. `GOOGLE_GENAI_USE_VERTEXAI` forces Vertex AI routing if present; always strip it.
- **D-10:** Default flags: `-p <prompt>`, `--output-format json`. `--approval-mode` controls tool access (see D-20). `--allowed-tools` is deprecated in 0.40.1 — do not use.

### Tool Use (all CLI providers)

- **D-11:** `CLIPolicy` gains a `tool_mode: str = "none"` field (values: `"none"` | `"read-only"` | `"full"`). Controls whether CLI backends can use their own built-in tools during analysis.
- **D-12:** **Actual per-provider flag mapping (verified in implementation):**

  | `tool_mode` | Claude Code | Gemini CLI |
  |---|---|---|
  | `"none"` | `--tools "" --permission-mode bypassPermissions` | `--approval-mode plan` |
  | `"read-only"` | `--permission-mode plan` | `--approval-mode plan` |
  | `"full"` | `--permission-mode bypassPermissions` (no `--tools` arg) | `--approval-mode yolo` |

  Note: `--allowed-tools` was deprecated in Gemini CLI 0.40.1 — use `--approval-mode` only.
- **D-13:** Default `tool_mode: "none"` — safe starting point. Operators opt in explicitly.

### Env-Var Stripping

- **D-14:** Each provider class declares `_STRIP_ENV_VARS: ClassVar[tuple[str, ...]]` (tuple, not list) with safe hardcoded defaults. `CLIPolicy.strip_env_vars: list[str]` provides operator overrides — appended at `_build_env()` time. **Pattern for all future providers:** base strips are provider-class-level constants; operator additions are in `CLIPolicy.strip_env_vars`.

### Runner Wiring

- **D-15:** Replace the `NotImplementedError` block in `_init_providers()` for `"claude-code"` and `"gemini-cli"` with real provider instantiation. Each provider receives its `CLIPolicy` (base + per-provider override merged). The existing probe-call path (`if hasattr(llm, "probe"): llm.probe()`) already handles early exit on `CapabilityResult.ok = False`.

### Post-Implementation Corrections (from code review)

- **D-16 (CR-01 — System prompt delivery):** Both providers accept `system_prompt` in the base `LLM.__init__`. Without forwarding it to the subprocess, the model receives no vulnerability-analysis instructions — a silent but critical failure. **Fix pattern (all providers):** In `send_message()`, construct `full_prompt = f"{self.system_prompt}\n\n{user_prompt}"` when `self.system_prompt` is set. Pass `full_prompt` to the `-p` flag. This is the **only portable approach** — Claude Code's `--system-prompt` flag is version-specific, and Gemini CLI has no dedicated system-prompt flag.

- **D-17 (CR-02 — Abstract method contract):** `CLIProviderLLM` must declare **all four methods as `@abstractmethod`**: `probe()`, `get_response()`, `send_message()`, `_extract_usage()`. Without this enforcement, a subclass missing `send_message()` or `_extract_usage()` instantiates successfully and only crashes at runtime. **Future provider pattern:** all four must be concrete in every subclass.

- **D-18 (WR-01 — workdir as cwd):** `_run_subprocess()` must pass `cwd=self.workdir if self.workdir else None` to `subprocess.run()`. Without this, `CLIPolicy.workdir` has no effect on subprocess execution.

- **D-19 (WR-04 — Version tuple normalization):** Version gates must pad parsed tuple to 3 elements: `while len(parts) < 3: parts.append(0)`. Raw `split(".", 2)` produces `(0, 6)` for a 2-part version; Python tuple comparison `(0, 6) < (0, 6, 0)` is `True`, incorrectly rejecting a valid version. **Use this pattern for Codex and Qwen Code too.**

### Testing

- **D-20:** Tests live in `tests/test_cli_providers.py`. All subprocess calls are mocked via `unittest.mock.patch("subprocess.run")`. Cover: success path, `CLITimeoutError`, `CLIParseError`, `CLIBinaryNotFoundError`, and `probe()` version gate.
- **D-21:** Live tests (requiring actual installed binaries) are marked `@pytest.mark.live` and excluded from CI.
- **D-22 (WR-05 — env var mutation):** Tests that set real env vars must use `patch.dict(os.environ, {...})` or `monkeypatch.setenv()` — never `os.environ[key] = value` directly. Direct mutation leaves keys polluted if an assert fails before the cleanup line.

### MCP Servers and Skills (executor tooling directive)

- **D-23:** Executor agents implementing Phase 4 MUST use the following MCP servers:
  - `mcp__ripgrep__*` and `mcp__python-lsp-mcp__*` — codebase search and symbol navigation during implementation
  - `mcp__analyzer__*` (ruff-check, vulture-scan) — run after each file is written
  - `mcp__semgrep__*` — SAST check on new provider code before committing
  - `mcp__context7__*` — fetch up-to-date docs for Gemini CLI and Claude Code during implementation
- **D-24:** Executor agents MUST invoke the following skills before/during implementation:
  - `python-guardian-orchestrator` — before committing each provider file
  - `api-integration` — for subprocess transport and error handling patterns
  - `secure-code-review` + `threat-modeling` — review provider code for env handling, subprocess injection, and sandbox policy

### Claude's Discretion

- Exact abstract method signatures for `send_message()` (parameter names, return type) — follow `send_message(self, user_prompt: str, max_tokens: int, response_model: Any = None) -> dict[str, Any]`.
- Whether `GeminiCLILLM` needs a workdir or can run from CWD — resolved: `cwd=self.workdir if self.workdir else None` is passed.
- Test file name — resolved: `tests/test_cli_providers.py`.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase Requirements
- `.planning/REQUIREMENTS.md` §CLAUDECLI-01, §GEMINI-CLI-01 — acceptance criteria for both Phase 4 requirements

### Phase 3 Base Class (read before implementing any new CLI provider)
- `vulnhuntr/cli_providers/base.py` — `CLIProviderLLM`, abstract interface (all four methods abstract post-CR-02), error taxonomy, `_run_subprocess()` (passes `cwd=self.workdir` post-WR-01), `_build_env()`
- `vulnhuntr/cli_providers/__init__.py` — re-exports; update to include new provider classes
- `vulnhuntr/config.py` — `CLIPolicy` dataclass with `tool_mode`, `strip_env_vars` fields

### Phase 4 Implementations (reference for Phase 5)
- `vulnhuntr/cli_providers/claude_code.py` — `ClaudeCodeLLM` adapter; system-prompt prepend pattern (D-16), `_STRIP_ENV_VARS` tuple pattern (D-14), version regex + semver extraction
- `vulnhuntr/cli_providers/gemini_cli.py` — `GeminiCLILLM` adapter; `_MIN_VERSION` tuple gate with 3-element padding (D-19), `stats.models.<name>.tokens.*` usage extraction (D-07 corrected), `--approval-mode` flag mapping (D-12)
- `tests/test_cli_providers.py` — test patterns; `patch.dict(os.environ, {...})` for env mutation (D-22), `unittest.mock.patch("subprocess.run")` patterns, `@pytest.mark.live` marker usage

### Runner Wiring
- `vulnhuntr/cli/runner.py` — `initialize_llm()` (lines 86–117); stub slots for `"codex"` and `"qwen-code"` already present from Phase 4; config fallback fixed (WR-03 fix: `if config.provider is None`)

### Code Review Report
- `.planning/phases/04-claude-code-gemini-cli/04-REVIEW.md` — 7 findings (CR-01 system prompt, CR-02 abstract methods, WR-01..05); all fixed
- `.planning/phases/04-claude-code-gemini-cli/04-REVIEW-FIX.md` — fix implementation details per finding

### External CLI Docs (researcher must consult for Phase 5)
- Gemini CLI headless docs: `https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/headless.md`
- Gemini CLI automation tutorial: `https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/tutorials/automation.md`

### Prior Phase Context
- `.planning/phases/03-cli-provider-contract-config-schema/03-CONTEXT.md` — D-01 through D-10 define the base class contract

### Architecture Context
- `.planning/codebase/ARCHITECTURE.md` — LLM layer description, data flow, error handling strategy
- `.planning/codebase/INTEGRATIONS.md` — existing provider auth patterns and env var conventions

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `CLIProviderLLM.chat()` in `vulnhuntr/cli_providers/base.py` — full subprocess + validation pipeline; Phase 5 adapters do NOT override this
- `CLIProviderLLM._run_subprocess()` — subprocess transport with timeout, binary-not-found, and non-zero exit; passes `cwd=self.workdir if self.workdir else None` (post-WR-01 fix)
- `CLIProviderLLM._build_env()` — strips `_STRIP_ENV_VARS` from subprocess environment; each provider declares its own strip list as a `ClassVar[tuple[str, ...]]`
- `LLM._validate_response()` in `vulnhuntr/llms.py` — multi-pass JSON repair + Pydantic validation; reused via `CLIProviderLLM.chat()` without changes
- `ClaudeCodeLLM._extract_usage()` — cache-inclusive input token sum: `input_tokens + cache_creation_input_tokens + cache_read_input_tokens`
- `GeminiCLILLM._extract_usage()` — iterates `stats.models.<name>.tokens.{input, candidates}`; falls back to 0 if path is absent
- `LLMUsage` in `vulnhuntr/core/models.py` — return type for `_extract_usage()`

### Established Patterns
- `from __future__ import annotations` at top of every source file
- `log = structlog.get_logger(__name__)` in every module
- `_STRIP_ENV_VARS: ClassVar[tuple[str, ...]] = (...)` — tuple, not list
- `_MIN_VERSION: ClassVar[tuple[int, ...]] = (X, Y, Z)` — tuple for version gating
- `unittest.mock.patch("subprocess.run")` for CLI subprocess tests
- `patch.dict(os.environ, {...})` (not direct `os.environ[key] = value`) for env mutation in tests
- `@dataclass` with `field(default_factory=...)` for config fields

### Integration Points
- `vulnhuntr/cli/runner.py:initialize_llm()` — stubs for `"codex"` and `"qwen-code"` already present (lines ~86–117); follow same pattern as `"claude-code"` / `"gemini-cli"` blocks
- `vulnhuntr/cli_providers/__init__.py` — add exports for each new provider class
- Provider registration map — maps `"codex"` → `CodexLLM`, `"qwen-code"` → `QwenCodeLLM` following Phase 4 naming

</code_context>

<specifics>
## Specific Ideas

- **Gemini CLI JSON envelope (verified 0.40.1):**
  ```json
  { "response": "...", "stats": { "models": { "<model-name>": { "tokens": { "input": N, "candidates": N } } } } }
  ```
  `get_response()` returns `payload.get("response")`. `_extract_usage()` iterates `stats.models.<name>.tokens`.

- **Claude Code JSON envelope (verified 2.1.126):**
  ```json
  { "result": "...", "usage": { "input_tokens": N, "cache_creation_input_tokens": N, "cache_read_input_tokens": N, "output_tokens": N }, "modelUsage": { "<model>": { ... } }, "total_cost_usd": 0.0 }
  ```
  Input token sum: `input_tokens + cache_creation_input_tokens + cache_read_input_tokens`.

- **System prompt prepend (all CLI providers):**
  ```python
  full_prompt = f"{self.system_prompt}\n\n{user_prompt}" if self.system_prompt else user_prompt
  ```

- **Version tuple normalization (all CLI providers):**
  ```python
  parts = [int(x) for x in version_str.split(".", 2)]
  while len(parts) < 3:
      parts.append(0)
  if tuple(parts) < self._MIN_VERSION:
      # reject
  ```

- **`tool_mode` in `.vulnhuntr.yaml`:**
  ```yaml
  cli:
    tool_mode: none        # default
    # tool_mode: read-only
    # tool_mode: full
  ```

- MCP server usage is mandatory for executor agents — not optional. See D-23 and D-24.

</specifics>

<deferred>
## Deferred Ideas

- Session modes (stateless/resume) for Claude Code and Gemini CLI — Phase 6
- Native tool ownership policy (which tools Vulnhuntr allows vs. blocks) — Phase 6 (Phase 4 adds `tool_mode` field; Phase 6 adds full policy semantics)
- Codex and Qwen Code adapters — Phase 5
- Mixed API/CLI fallback routing — Phase 7

</deferred>

---

*Phase: 04-claude-code-gemini-cli*
*Context gathered: 2026-05-02*
*Context updated: 2026-05-04 (post-implementation; CR-01, CR-02, WR-01, WR-04 corrections applied)*
