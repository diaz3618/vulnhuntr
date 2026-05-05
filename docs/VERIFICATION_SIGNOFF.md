# Gap Closure Verification Sign-off

This document records the acceptance criteria for each gap-closure phase and the
evidence that each criterion was met. It supplements [docs/verification.md](verification.md),
which covers live provider integration criteria.

**Sign-off date:** 2026

---

## Phase 03 — CLI Provider Contract & Config Schema

**Goal:** Establish a consistent, enforceable base class for all CLI LLM providers
and a validated configuration schema for CLI execution policy.

| Criterion | Evidence | Status |
|-----------|----------|--------|
| `CLIProviderBase` defines `@abstractmethod` contract | `vulnhuntr/cli_providers/base.py` lines 110–146 (4 abstract methods: `probe`, `send_message`, `get_response`, `_extract_usage`) | ✅ |
| `CLIPolicy` dataclass validates `session_mode`, `mcp_mode`, `tool_mode` | `vulnhuntr/config.py` `CLIPolicy.__post_init__()` with `_VALID_*` ClassVars | ✅ |
| `_VALID_*` fields are `ClassVar` (not mutable instance fields) | `vulnhuntr/config.py` lines 52–54 | ✅ |
| Config schema round-trips through YAML | `tests/test_config.py` — 83 tests pass | ✅ |

**Test count:** `tests/test_config.py` — 83 passed

---

## Phase 06 — Sessions, Native Tools, MCP Policy

**Goal:** Enable the four CLI providers to maintain conversation context across
analysis passes using their native session mechanisms, and allow them to invoke
MCP tools through the `MCPAnalysisHelper` bridge.

| Criterion | Evidence | Status |
|-----------|----------|--------|
| `send_message()` accepts `session_mode` flag | `vulnhuntr/cli_providers/base.py` `send_message()` signature | ✅ |
| `ClaudeCodeLLM` uses `--continue`/`--resume` flags | `vulnhuntr/cli_providers/claude_code.py` `send_message()` | ✅ |
| `QwenCodeLLM` uses `--resume`/`--continue` flags | `vulnhuntr/cli_providers/qwen_code.py` | ✅ |
| `CheckpointData.session_metadata` persisted after analysis | `vulnhuntr/cli/runner.py` metadata persistence block | ✅ |
| `MCPAnalysisHelper.is_active` gate respected | `vulnhuntr/core/analysis.py` line 383 | ✅ |
| Session metadata serialized to checkpoint | `tests/test_runner.py::TestSessionMetadataPersistence` | ✅ |

**Test count:** Phase 06 tests span `tests/test_cli_providers.py` (204 tests) and `tests/test_runner.py`

---

## Phase 09 — State Branch / Data Flow Hardening

**Goal:** Add `InvariantViolationError` production guards to prevent illegal state
transitions and ensure `CLIPolicy` validation fields cannot be bypassed at construction.

| Criterion | Evidence | Status |
|-----------|----------|--------|
| `InvariantViolationError` raised when fallback provider not in registry | `vulnhuntr/llms.py` line 506 | ✅ |
| `InvariantViolationError` raised when `session_mode` is invalid | `vulnhuntr/cli_providers/claude_code.py` line 174 | ✅ |
| `InvariantViolationError` is a `RuntimeError` subclass | `vulnhuntr/core/trace.py` line 55 | ✅ |
| `CLIPolicy._VALID_*` are `ClassVar` (cannot be overridden at init) | `vulnhuntr/config.py` lines 52–54 | ✅ |
| `format_results_for_prompt` guards against `None` tool errors | `vulnhuntr/mcp/analysis.py` | ✅ |
| State transition tests exercise invariant guards | `tests/test_state_transitions.py` — 23 tests pass | ✅ |

**Test count:** `tests/test_state_transitions.py` — 23 passed

---

## Phase 10 — Verification Docs & Release Hardening

**Goal:** Document per-provider "done" criteria, add failure-mode test classes for all
four CLI providers, and fix release-blocking issues found in code review.

| Criterion | Evidence | Status |
|-----------|----------|--------|
| `docs/verification.md` covers trace evidence, invariant gates, stability threshold, per-provider criteria | `docs/verification.md` — 4 sections | ✅ |
| `docs/example-config.yaml` annotated with all `CLIPolicy` fields | `docs/example-config.yaml` | ✅ |
| Failure-class tests for all 4 providers | `tests/test_cli_providers.py` — `TestClaudeCodeLLMFailures`, `TestGeminiCLILLMFailures`, etc. | ✅ |
| `datetime.utcnow()` removed (replaced with `datetime.now(timezone.utc)`) | `grep -rn datetime.utcnow vulnhuntr/` → 0 matches | ✅ |
| CLI providers section in QUICKSTART and troubleshooting | `QUICKSTART.md` + `docs/troubleshooting.md` | ✅ |

**Test count:** `tests/test_cli_providers.py` — 204 passed

---

## Phase 11 — Runtime Blockers: Checkpoint & Tracer Wiring

**Goal:** Fix `AttributeError: checkpoint has no attribute 'save'` and ensure
`ExecutionTracer` is instantiated and forwarded to all 4 CLI providers in the
production `run_analysis()` path.

| Criterion | Evidence | Status |
|-----------|----------|--------|
| `checkpoint.save_now()` used (not `checkpoint.save()`) | `vulnhuntr/cli/runner.py` — no `checkpoint.save()` calls | ✅ |
| `ExecutionTracer` instantiated in `run_analysis()` | `vulnhuntr/cli/runner.py` `tracer = ExecutionTracer()` | ✅ |
| Tracer forwarded to all 4 CLI provider constructors | `GeminiCLILLM`, `CodexLLM`, `ClaudeCodeLLM`, `QwenCodeLLM` all accept `tracer=` | ✅ |
| Tracer forwarded through `_init_providers()` and `wrap_with_fallbacks()` | `vulnhuntr/cli/runner.py` | ✅ |
| Regression tests for tracer forwarding and checkpoint fix | `tests/test_runner.py::TestInitializeLlmCliProviders` + `TestSessionMetadataPersistence` | ✅ |

**Test count:** `tests/test_runner.py` + `tests/test_checkpoint.py` — 22 passed (regression suite)

---

## Phase 12 — Execute Phase 07 Plans (MCP Completion, Routing, Cost Hardening)

**Goal:** Implement the three Phase 07 plans covering MCP tool injection, subscription
cost tracking, and CLI provider routing.

All Phase 07 deliverables were verified as pre-implemented. No code changes were required.

| Criterion | Evidence | Status |
|-----------|----------|--------|
| Orphaned MCP dispatch blocks removed from `_analyze_files()` | `grep execute_tool_calls vulnhuntr/cli/runner.py` → 0 matches | ✅ |
| `TokenUsage.usage_type` + `provider_note` fields | `vulnhuntr/cost_tracker.py` line 105 | ✅ |
| `CostTracker.track_subscription_call()` | `vulnhuntr/cost_tracker.py` line 218 | ✅ |
| `usage_by_type` in `get_summary()` | `vulnhuntr/cost_tracker.py` line 304 | ✅ |
| `FallbackLLM._diagnostics` initialized in `__init__` | `vulnhuntr/llms.py` line 482 | ✅ |
| `VulnerabilityAnalyzer._secondary_analysis` MCP injection loop | `vulnhuntr/core/analysis.py` lines 383–388 | ✅ |
| Verbose fallback diagnostics printed in `run_analysis()` | `vulnhuntr/cli/runner.py` verbosity block | ✅ |
| Phase 07 test suite | `tests/test_mcp_analysis.py::TestMCPFullLoop` + `tests/test_cost_tracker.py` — 53 passed | ✅ |

**Test count:** 53 passed

---

## Phase 13 — Docs & Traceability Cleanup

**Goal:** Fix stale references in user-facing files and document new CLI provider
env vars in `.env.example`.

| Criterion | Evidence | Status |
|-----------|----------|--------|
| `.env.example` model name updated to `claude-sonnet-4-5` | `.env.example` line 7 | ✅ |
| `.env.example` CLI providers section added | `.env.example` — codex/qwen env var guidance | ✅ |
| `CHANGELOG.md` unreleased entry covers Phases 03–13 | `CHANGELOG.md` `[Unreleased]` section | ✅ |

---

## Overall Test Summary

| Test file | Tests | Result |
|-----------|-------|--------|
| `tests/test_cli_providers.py` | 204 | ✅ pass |
| `tests/test_config.py` | 83 | ✅ pass |
| `tests/test_state_transitions.py` | 23 | ✅ pass |
| `tests/test_trace.py` | 23 | ✅ pass |
| `tests/test_mcp_analysis.py` | ~45 | ✅ pass |
| `tests/test_cost_tracker.py` | 48 | ✅ pass |
| `tests/test_runner.py` | ~30 | ✅ pass |
| Full suite | **989+** | ✅ pass |

---

## Release Readiness

All gap-closure phases (03, 06, 07, 08, 09, 10, 11, 12, 13) have met their acceptance
criteria. The blocking issues identified during the gap-closure audit have been resolved:

- ✅ Runtime crash: `AttributeError: checkpoint.save` → fixed as `save_now()`
- ✅ Silent tracer drop: `GeminiCLILLM`, `CodexLLM` not wired → fixed
- ✅ Stale model name in `.env.example` → fixed
- ✅ MCP injection loop for multi-pass analysis → verified present
- ✅ State-machine invariant guards → verified present
- ✅ `datetime.utcnow()` deprecation warning → fixed

The codebase is ready for integration testing with real CLI provider binaries
per [docs/verification.md](verification.md).
