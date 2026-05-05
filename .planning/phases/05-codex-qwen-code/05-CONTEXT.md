# Phase 5: Codex & Qwen Code - Context

**Gathered:** 2026-05-04
**Status:** Ready for planning

<domain>
## Phase Boundary

Add the two remaining CLI provider adapters to complete the Phase 3/4 CLI transport foundation:

1. **`CodexLLM`** (`vulnhuntr/cli_providers/codex.py`) — OpenAI Codex CLI adapter with explicit approval-mode/sandbox handling. Supports both ChatGPT-Pro session auth (default) and API-key auth (operator opt-in).
2. **`QwenCodeLLM`** (`vulnhuntr/cli_providers/qwen_code.py`) — Qwen Code adapter with version-gated probe and dual-mode config: direct Qwen backend or bridge to any OpenAI-compatible API (OpenRouter, Ollama, Azure, etc.) via `OPENAI_BASE_URL`.
3. **Runner wiring** — replace the remaining `NotImplementedError` in `_init_providers()` for `"codex"` and `"qwen-code"`.
4. **Tests** — extend `tests/test_cli_providers.py` with mocked subprocess tests for both providers; `@pytest.mark.live` markers for optional real-binary paths.

No new `CLIPolicy` dataclass fields land in this phase. Codex sandbox config and session-state fields land in Phase 6.

</domain>

<decisions>
## Implementation Decisions

### Codex Adapter (`CodexLLM`)

- **D-01:** `_STRIP_ENV_VARS = ("OPENAI_API_KEY",)` — strip by default to force ChatGPT-Pro session auth (consistent with Claude Code stripping `ANTHROPIC_API_KEY`). Operators who want API-key mode set `strip_env_vars: []` in `CLIPolicy` or simply leave `OPENAI_API_KEY` unset.
- **D-02:** `tool_mode` → `--approval-mode` mapping for Codex:
  - `"none"` → `--approval-mode suggest` (no autonomous changes — safest default for a scanner)
  - `"read-only"` → `--approval-mode auto-edit` (files only; shell requires confirmation)
  - `"full"` → `--approval-mode full-auto` (fully autonomous — operator must explicitly opt in)
- **D-03:** No new `CLIPolicy` fields for Codex sandbox in Phase 5. Codex-specific network sandbox or additional flags go in `overrides["codex"]["extra_flags"]` as an escape hatch. Phase 6 formalizes sandbox policy across all providers.
- **D-04:** Binary name is `codex`. Researcher confirms minimum version and the exact `--output-format json` flag or equivalent before implementation begins.

### Qwen Code Adapter (`QwenCodeLLM`)

- **D-05:** API bridge mode is configured via `CLIPolicy.overrides["qwen-code"]["base_url"]` — the adapter injects this as `OPENAI_BASE_URL` in the subprocess environment before spawn. No new `CLIPolicy` fields.
- **D-06:** Researcher confirms: binary name (`qwen` or `qwen-code`), minimum version that added JSON output support, JSON envelope field names, and which env vars to strip for direct-Qwen-OAuth mode. Implementation proceeds after researcher delivers these facts.
- **D-07:** `_MIN_VERSION: ClassVar[tuple[int, ...]]` gate added to `QwenCodeLLM.probe()` (same pattern as `GeminiCLILLM`). The researcher pins the exact minimum version tuple.
- **D-08:** Output parsing is batch JSON only — no streaming in Phase 5. Streaming (`stream-json`) adds complexity and can be added in a dedicated phase if operators need it.
- **D-09:** `_STRIP_ENV_VARS` for Qwen Code targets direct-Qwen-OAuth env vars (e.g., `QWEN_API_KEY`, `DASHSCOPE_API_KEY`) — researcher confirms exact names. In bridge mode, `OPENAI_API_KEY` is NOT stripped (operator sets it explicitly for the bridge target). The adapter should NOT strip `OPENAI_API_KEY` by default.

### Shared / Carry-Forward

- **D-10:** Both adapters follow the Phase 4 thin-adapter contract: implement only `probe()`, `send_message()`, `get_response()`, `_extract_usage()`. Base class `chat()` handles subprocess dispatch and validation — no overrides.
- **D-11:** `send_message()` passes prompts via `-p <text>` (established in Phase 4). Researcher confirms Qwen Code supports `-p`; if not, document the correct flag and use that instead.
- **D-12:** Tests extend `tests/test_cli_providers.py`. Coverage: success path, `CLITimeoutError`, `CLIParseError`, `CLIBinaryNotFoundError`, `probe()` version gate, and `tool_mode`→`--approval-mode` flag injection for Codex.

### the Agent's Discretion

- Whether Qwen Code uses `-p <text>` or a different flag for prompt delivery — researcher confirms; planner picks based on findings.
- Exact `_MIN_VERSION` tuple for `QwenCodeLLM` — researcher pins from Qwen Code changelog.
- Exact JSON envelope field names for Qwen Code (`response`, `result`, or other) — researcher confirms from docs/source.
- Whether the Codex `probe()` can gate on a minimum version or must accept any version — researcher checks Codex changelog for when `--output-format json` was added.
- Test file structure: add to existing `test_cli_providers.py` vs split into `test_codex.py` + `test_qwen_code.py` — planner decides based on total volume after implementation.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase Requirements
- `.planning/REQUIREMENTS.md` §CODEX-01, §QWEN-01 — acceptance criteria for both Phase 5 providers

### Phase 4 Base (read before implementing)
- `vulnhuntr/cli_providers/base.py` — `CLIProviderLLM`, abstract interface (`probe`, `send_message`, `get_response`, `_extract_usage`), `_run_subprocess()`, `_build_env()`
- `vulnhuntr/cli_providers/claude_code.py` — reference implementation for the thin-adapter pattern and `_STRIP_ENV_VARS` class variable
- `vulnhuntr/cli_providers/gemini_cli.py` — reference for `_MIN_VERSION` gate in `probe()` and version tuple comparison; also reference for JSON envelope parsing
- `vulnhuntr/cli_providers/__init__.py` — add `CodexLLM` and `QwenCodeLLM` exports here
- `vulnhuntr/config.py` — `CLIPolicy` dataclass; `overrides` dict is the escape hatch for per-provider flags

### Runner Wiring
- `vulnhuntr/cli/runner.py` — `_init_providers()` (~line 86); replace `NotImplementedError` for `"codex"` and `"qwen-code"` with real instantiation

### External CLI Docs (researcher must consult before implementation)
- Codex CLI docs / README — binary name, `--approval-mode` values, `--output-format json` support, minimum version
- Qwen Code / Qwen CLI docs — binary name (`qwen` vs `qwen-code`), minimum version with JSON support, JSON envelope schema, env vars for direct-Qwen auth vs bridge mode, whether `-p` flag is supported

### Prior Phase Context
- `.planning/phases/03-cli-provider-contract-config-schema/03-CONTEXT.md` — D-01 through D-10 define base class contract; D-09 establishes `overrides` dict pattern
- `.planning/phases/04-claude-code-gemini-cli/04-CONTEXT.md` — D-01 through D-19 define thin-adapter contract, `tool_mode` values, `_STRIP_ENV_VARS` pattern, and test strategy

### Existing Tests
- `tests/test_cli_providers.py` — extend this file; review existing fixture/mock patterns before adding new test classes

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `CLIProviderLLM.chat()` in `vulnhuntr/cli_providers/base.py` — full subprocess + validation pipeline; Phase 5 adapters do NOT override this
- `CLIProviderLLM._run_subprocess()` — subprocess transport with timeout, binary-not-found, and non-zero exit handling; already handles `shell=False`, `cwd=workdir`
- `CLIProviderLLM._build_env()` — strips `_STRIP_ENV_VARS` from subprocess environment; Phase 5 adapters declare their own strip list
- `GeminiCLILLM._MIN_VERSION` / version-tuple comparison pattern — copy this for `QwenCodeLLM`
- `ClaudeCodeLLM._build_env()` override — copy this for both Phase 5 adapters (adds operator `strip_env_vars` from `CLIPolicy` on top of class defaults)

### Established Patterns
- Thin adapter: only 4 abstract methods to implement; `chat()` is inherited
- `_STRIP_ENV_VARS: ClassVar[tuple[str, ...]]` — class-level defaults; `CLIPolicy.strip_env_vars` appended at subprocess build time
- `CLIPolicy.overrides["<provider>"]["<key>"]` — per-provider runtime knobs without new dataclass fields
- `@pytest.mark.live` — marks tests that need a real binary; excluded from CI

### Integration Points
- `vulnhuntr/cli/runner.py` `_init_providers()` — already dispatches `claude-code`/`gemini-cli` correctly; Phase 5 adds identical blocks for `codex` and `qwen-code`
- `vulnhuntr/config.py` `CLIPolicy` — `overrides` dict already available; `tool_mode` field already there; no changes needed in Phase 5

</code_context>
