# Phase 3: CLI Provider Contract & Config Schema - Context

**Gathered:** 2026-05-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Add the common abstractions that Phase 4 (Claude Code + Gemini CLI) and Phase 5 (Codex + Qwen Code) will build on:

1. A new `vulnhuntr/cli_providers/` package with a `CLIProviderLLM(LLM)` intermediate base class that holds shared subprocess execution, timeout, env-stripping, failure classification, and capability probe logic.
2. A `CapabilityResult` model returned by `CLIProviderLLM.probe()`, called from `_init_providers()` before the scan starts.
3. A `CLIPolicy` dataclass added as a nested sub-object on `VulnhuntrConfig`, with provider-specific overrides via a dict.
4. Response normalization (`_extract_usage()` abstract) and failure taxonomy (`LLMError` subclasses) for CLI-specific error classes.

No individual provider implementations in this phase — those land in Phases 4 and 5. `llms.py` is NOT modified.

</domain>

<decisions>
## Implementation Decisions

### CLI Base Class Architecture (AICLI-01)
- **D-01:** Add an intermediate `CLIProviderLLM(LLM)` base class (not direct `LLM` subclasses per provider). Shared logic — subprocess execution, timeout, env-stripping, output parsing, and capability probe — lives in `CLIProviderLLM`. `get_response()` and `_extract_usage()` are abstract, implemented per provider in Phases 4/5.
- **D-02:** `CLIProviderLLM` lives in `vulnhuntr/cli_providers/base.py`. New `vulnhuntr/cli_providers/__init__.py` re-exports `CLIProviderLLM` and `CapabilityResult`. `llms.py` is untouched — existing `Claude`, `ChatGPT`, `OpenRouter`, `Ollama` classes are not modified.

### Capability Probe (AICLI-02)
- **D-03:** `CLIProviderLLM.probe()` is called from the runner's `_init_providers()` stage (Phase 2 pattern), not inside `__init__`. Runner calls `probe()` for each CLI provider before scan starts; if `CapabilityResult.ok` is False, runner logs the `diagnostic_message` via structlog and exits with error.
- **D-04:** `CapabilityResult` is a dataclass with fields: `ok: bool`, `binary_found: bool`, `version: str | None`, `auth_valid: bool | None` (None = cannot check statically), `diagnostic_message: str`.

### Response Normalization & Failure Taxonomy (AICLI-03, AICLI-04)
- **D-05:** Failure classes extend the existing `LLMError` hierarchy. New CLI-specific subclasses: `CLIBinaryNotFoundError`, `CLIAuthError`, `CLITimeoutError` (vs. existing `RateLimitError`/`APIConnectionError`), `CLIParseError`, `CLISandboxError`, `CLIRuntimeError`. These live in `cli_providers/base.py`.
- **D-06:** Response normalization: `CLIProviderLLM.chat()` calls `get_response()` (abstract) to extract the raw text from the provider's JSON envelope, then feeds it into the existing `_validate_response()` path (already handles multi-pass JSON repair + Pydantic validation). Each provider subclass implements `get_response()` to handle its own envelope format.

### Config Schema (CONFIG-01, CONFIG-02, CONFIG-03)
- **D-07:** Add a `CLIPolicy` dataclass to `vulnhuntr/config.py` with fields: `timeout: int = 300`, `workdir: str = "/tmp/vulnhuntr"`, `auth_mode: str = "auto"`, `session_mode: str = "stateless"`, `approval_mode: str = "auto"`, `sandbox_mode: str = "none"`, `max_turns: int = 10`, `mcp_mode: str = "none"`, `overrides: dict[str, dict] = field(default_factory=dict)`.
- **D-08:** `VulnhuntrConfig` gains a `cli: CLIPolicy = field(default_factory=CLIPolicy)` field. In YAML, this maps to a `cli:` sub-section. Existing `.vulnhuntr.yaml` files without a `cli:` section are unaffected — `CLIPolicy` defaults apply.
- **D-09:** `VulnhuntrConfig.from_dict()` is extended to parse the nested `cli:` dict into a `CLIPolicy`. Per-provider overrides are accessed as `config.cli.overrides.get("claude-code", {})` in the provider's `__init__`.
- **D-10:** CLI provider selection: `--llm claude-code`, `--llm gemini-cli`, etc. map to CLI providers. `config.provider` accepts these same strings. Provider registration maps string → class, including CLI providers, so the fallback chain (ROUTING-01) can mix API and CLI providers.

### Claude's Discretion
- Exact abstract method signatures for `get_response()` and `_extract_usage()` in `CLIProviderLLM` — planner/researcher can define these based on what the experiment's `ClaudeCodeLLM` already uses.
- Whether `CLIProviderLLM.chat()` fully overrides `LLM.chat()` or calls `super().chat()` — the experiment's approach (full override) is a reasonable default.
- Exact env-stripping logic (which vars to remove per provider type) — researcher should check what the experiment strips (`ANTHROPIC_API_KEY` removed for Claude Code to force CLI auth; other providers may differ).
- Test file location: new `tests/test_cli_providers.py` vs. extending `tests/test_cli.py` — planner can decide based on test volume.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase Requirements
- `.planning/REQUIREMENTS.md` §AICLI-01..04, §CONFIG-01..03 — acceptance criteria for all 7 requirements in this phase

### Existing Code to Extend (read before planning)
- `vulnhuntr/llms.py` — existing `LLM` base class, `LLMError` hierarchy, `_validate_response()`, cost callback pattern; `CLIProviderLLM` inherits from `LLM`
- `vulnhuntr/config.py` — `VulnhuntrConfig` dataclass and `from_dict()` parsing; `CLIPolicy` is added here
- `vulnhuntr/cli/runner.py` — `_init_providers()` stage (Phase 2); probe call is wired here

### Proof-of-Concept to Promote
- `internal/experiments/vulnhuntr_claude_code/claude_code_llm.py` — working `ClaudeCodeLLM(LLM)` experiment; `CLIProviderLLM` extracts its shared patterns; read before defining abstract interface

### Architecture Context
- `.planning/codebase/ARCHITECTURE.md` — layer diagram, LLM layer description, data flow
- `.planning/codebase/INTEGRATIONS.md` — existing provider auth patterns and env var conventions

### Prior Phase Decisions
- `.planning/phases/02-runner-decomposition/02-CONTEXT.md` — `_init_providers()` stage interface and `llm_factory` injection pattern used by tests

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `LLM._validate_response()` at `vulnhuntr/llms.py:85` — multi-pass JSON repair + Pydantic validation; CLI providers reuse this via `CLIProviderLLM.chat()` feeding `get_response()` output into it
- `LLM._add_to_history()`, `LLM.set_context()`, `LLM._cost_callback` — all inherited by `CLIProviderLLM` at no cost
- `LLMError` hierarchy (`RateLimitError`, `APIConnectionError`, `APIStatusError`) at `vulnhuntr/llms.py` — CLI-specific subclasses extend this
- `VulnhuntrConfig.from_dict()` at `vulnhuntr/config.py` — extend to parse `cli:` nested dict
- `ClaudeCodeLLM` at `internal/experiments/vulnhuntr_claude_code/claude_code_llm.py` — `subprocess.run()` pattern, env-stripping, JSON envelope parsing, `call_records` cost tracking; this becomes a Phase 4 thin subclass of `CLIProviderLLM`

### Established Patterns
- `from __future__ import annotations` at top of every source file (Phase 1/2 convention)
- `log = structlog.get_logger()` in every module; all logging via structlog
- Private helpers prefixed with `_`; individual function params (no shared context dataclass) — Phase 2 pattern
- `unittest.mock.MagicMock` for LLM stubs; `tmp_path` for filesystem fixtures in tests
- `dataclass` with `field(default_factory=...)` — matches `CheckpointData` and existing `VulnhuntrConfig` pattern

### Integration Points
- `vulnhuntr/cli/runner.py:_init_providers()` — where `probe()` is called per CLI provider; runner must import and instantiate `CLIProviderLLM` subclasses here
- `vulnhuntr/__init__.py` — public API re-exports; `CLIProviderLLM` and `CapabilityResult` should be re-exported if they are public
- Provider registration map in `runner.py` (or a new `providers.py` registry) — maps `"claude-code"` → `ClaudeCodeLLM`, etc.; Phase 3 adds the registry stub with CLI provider slots; Phases 4/5 fill them in

</code_context>

<specifics>
## Specific Ideas

- The YAML sub-section for CLI policy should use key `cli:` (not `cli_provider:` or `providers:`), matching the user's confirmed preference.
- `CapabilityResult.auth_valid` is `bool | None` — `None` means the provider cannot check auth statically at probe time (e.g., auth only fails at first real call). This avoids false-positive failures for providers where auth validation requires an actual API call.
- The experiment's `ClaudeCodeLLM` strips `ANTHROPIC_API_KEY` from the subprocess env to force CLI-based auth. This env-strip logic should be a configurable hook in `CLIProviderLLM` so each provider can define which keys to strip (or none).
- Per-provider config overrides accessed as `config.cli.overrides.get("claude-code", {})` — the override dict merges with the base `CLIPolicy` defaults at provider instantiation (not at config parse time).

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 03-cli-provider-contract-config-schema*
*Context gathered: 2026-05-01*
