# Phase 09: State, Branch, and Data-Flow Hardening - Context

**Gathered:** 2025-07-17
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 9 delivers explicit state-transition and data-flow test coverage for the
three most failure-prone execution paths — provider fallback, session resume,
and MCP tool dispatch — plus runtime invariants that raise loudly when
progression or policy constraints are violated.

**Delivers:**
- `tests/test_state_transitions.py` — new file; state-transition and invariant
  tests covering EVAL-04 and EVAL-06
- `TestDataFlowParsing` class added to `tests/test_behavior.py` — data-flow
  tests for `_validate_response()` and MCP result injection (EVAL-05)
- `InvariantViolationError` in `vulnhuntr/core/` — lightweight guard exception
  raised when internal state constraints are broken
- Guard raises in `FallbackLLM.chat()` and session-mode flag builder
- `@pytest.mark.repeat(3)` on 2 critical routing tests, gated `@pytest.mark.slow`

**Does NOT deliver:**
- File I/O for trace events (deferred to Phase 10)
- New `ProviderState` enum in production code (scope creep)
- Per-file pytest-cov thresholds (ruled out in Phase 8 D-13)
- Any changes to the LLM API surface or prompt templates

</domain>

<decisions>
## Implementation Decisions

### State Machine Representation (EVAL-04)

**Trade-off analysis (--analyze):**

| Approach | Pros | Cons |
|---|---|---|
| Trace-event ordering assertions only | Reuses Phase 8 infra; zero production risk | Invariant violations invisible in production |
| New `ProviderState` enum in production | Explicit, clean semantics | Scope creep; Phase 9 is hardening, not architecture |
| Guard raises inside existing production code | Fails loudly at runtime; minimal new code | Slightly more invasive than pure-test |

- **D-01:** No new `ProviderState` FSM type. The state machine remains **conceptual** — its states (`primary_active`, `fallback_N_active`, `all_failed`) and transitions are documented as partition docstrings in each test class. Production code gets narrow guard raises at the 2–3 highest-risk invariant check points.
- **D-02:** In `tests/test_state_transitions.py`, each test class MUST open with a `"""Partitions tested: ..."""` docstring enumerating the state × event × outcome triples it covers. This is the EVAL-04 "explicit coverage goals" requirement — matches the pattern from Phase 8 D-11.

### New Exception Type

- **D-03:** Add `InvariantViolationError(RuntimeError)` to `vulnhuntr/core/trace.py` (co-locate with `ExecutionTracer` since both are observability/hardening primitives). This is a `RuntimeError` subclass — NOT an `LLMError` subclass — because invariant violations are programming errors, not recoverable LLM-level failures.
  - Signature: `InvariantViolationError(message: str, *, invariant: str, actual_value: Any = None)`
  - Export it from `vulnhuntr/core/__init__.py` alongside `ExecutionTracer`.

### Guard Locations in Production Code

- **D-04:** Add one guard in `FallbackLLM.chat()` (in `vulnhuntr/llms.py`) at the top of the iteration loop:
  ```python
  if self._active not in self._all_llms:
      raise InvariantViolationError(
          "FallbackLLM._active is not a member of _all_llms",
          invariant="active_in_registry",
          actual_value=type(self._active).__name__,
      )
  ```
  This is the only production guard in `llms.py`. Import `InvariantViolationError` from `vulnhuntr.core`.
- **D-05:** Add one guard in the session-mode flag builder inside `CLIProviderLLM` (or whichever method constructs the `--continue`/`--resume` flags) to assert that `policy.session_mode` is one of `{"stateless", "continue", "resume"}` before constructing the flag string:
  ```python
  _VALID_SESSION_MODES = frozenset({"stateless", "continue", "resume"})
  if policy.session_mode not in _VALID_SESSION_MODES:
      raise InvariantViolationError(
          f"Unrecognized session_mode: {policy.session_mode!r}",
          invariant="session_mode_is_known",
          actual_value=policy.session_mode,
      )
  ```
  Locate this in `CLIProviderLLM._build_session_flags()` (or wherever session-mode flags are constructed — check before planning).

### Data-Flow Test Targets (EVAL-05)

**Trade-off analysis (--analyze):**

| Path | Risk | Existing coverage |
|---|---|---|
| `LLM._validate_response()` — 3-step JSON repair chain | HIGH | Low — Phase 8 only tested shape |
| MCP tool result → `format_tool_results_for_prompt()` → XML → next prompt | HIGH | Partial via test_mcp_analysis.py |
| `context_code` propagation in `analyze_file()` | MEDIUM | Moderate via test_analysis.py |
| Session ID capture in `CLIProviderLLM` | MEDIUM | Partial via test_behavior.py |

- **D-06:** EVAL-05 data-flow tests focus on two primary paths:
  1. `_validate_response()` JSON repair chain — test each of the 3 parse fallback paths individually (happy path, Python-literal repair, escape-char repair, all-fail path). Add as `TestValidateResponseDataFlow` in `tests/test_behavior.py`.
  2. MCP tool result injection — trace a `MCPToolCallResult` through `format_tool_results_for_prompt()` → verify the XML block appears verbatim in the next-iteration prompt string. Add as `TestMCPToolResultPropagation` in `tests/test_behavior.py`.
- **D-07:** Each data-flow test drives from **definition** (the object returned by the producing function) through **use** (the consuming function's input) to **observable output** — this directly maps to data-flow testing's def-use pair coverage criterion.

### Test File Placement

- **D-08:** New file `tests/test_state_transitions.py` — contains:
  - `TestFallbackTransitions` — tests that `_active` progresses primary → fallback-0 → fallback-1 → raise
  - `TestFallbackInvariants` — tests that guard raises fire on broken `_active` state
  - `TestSessionModeInvariants` — tests that unknown `session_mode` raises `InvariantViolationError`
  - Repeat-trial routing tests (marked `@pytest.mark.slow` + `@pytest.mark.repeat(3)`)
- **D-09:** `tests/test_behavior.py` gets two new test classes appended:
  - `TestDataFlowParsing` — `_validate_response()` chain (EVAL-05)
  - `TestMCPToolResultPropagation` — MCP result → prompt injection (EVAL-05)

### Repeat-Trial Stability (EVAL-04 success criterion 4)

**Trade-off analysis (--analyze):**

| Approach | Pros | Cons |
|---|---|---|
| `@pytest.mark.repeat(3)` via pytest-repeat | Standard plugin; already in dev deps | Triples test duration for these tests |
| Multiple parametrize IDs covering same flow | No extra deps; no duration cost | Not truly repeated-trial — variant coverage only |
| Custom re-run fixture | Full control | Boilerplate |

- **D-10:** Apply `@pytest.mark.repeat(3)` to exactly 2 tests: `test_fallback_progression_stable` (that `FallbackLLM` always progresses in the same order across runs) and `test_session_decision_flag_stable` (that the same `CLIPolicy` always produces identical flag strings). Both tests are also marked `@pytest.mark.slow`. The default CI run uses `pytest -m "not slow"` — these tests only run in the full suite.

### Branch Coverage Goals Format (EVAL-04)

- **D-11:** Partition tables live in `"""Partitions tested: ..."""` docstrings at the **class level** in each new test class. No per-file pytest-cov `--cov-fail-under` configuration (ruled out in Phase 8 D-13). The explicit partition enumeration IS the "branch coverage goals" artifact — it documents which branches are targeted without requiring tooling changes.

### Agent's Discretion

- The exact location of the session-mode guard (D-05) — whether it's in `_build_session_flags()`, `_build_mcp_config_args()`, or a shared `_validate_policy()` helper — should be chosen during planning after reading the full `cli_providers/base.py` and each provider's override. Place it where the `policy.session_mode` value is first consumed to build a flag string.
- The exact structure of `_VALID_SESSION_MODES` (module-level frozenset vs. computed from a Literal type) — prefer frozenset for O(1) lookup; only use `Literal.__args__` introspection if the Literal type is already defined and importable without circular imports.
- Whether `InvariantViolationError` is defined in `vulnhuntr/core/trace.py` or a new `vulnhuntr/core/invariants.py` — prefer co-location in `trace.py` unless the file grows past ~200 lines.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase history and locked decisions
- `.planning/phases/08-behavioral-evaluation-trace-capture/08-CONTEXT.md` — D-01 through D-14; establishes `ExecutionTracer`, `TraceEvent`, `TraceEventType`, injection pattern, and test organization
- `.planning/phases/07-mcp-completion-routing-cost-hardening/07-CONTEXT.md` — D-01 through D-08; establishes `FallbackLLM._diagnostics` pattern, `asyncio.run()` in runner, session mode semantics
- `.planning/phases/06-cli-provider-integration/06-CONTEXT.md` — session mode semantics (`stateless`/`continue`/`resume`)

### Roadmap
- `.planning/ROADMAP.md` — EVAL-04, EVAL-05, EVAL-06 requirement descriptions
- `.planning/STATE.md` — current progress state

### Core source files
- `vulnhuntr/core/trace.py` — `TraceEvent`, `ExecutionTracer`, `TraceEventType`; Phase 9 adds `InvariantViolationError` here
- `vulnhuntr/llms.py` — `LLM._validate_response()` (JSON repair chain); `FallbackLLM.chat()` (receives guard raise D-04)
- `vulnhuntr/cli_providers/base.py` — `CLIProviderLLM`, session-mode flag building; receives guard raise D-05
- `vulnhuntr/core/analysis.py` — `VulnerabilityAnalyzer`; MCP tool result injection path

### Existing test files to extend
- `tests/test_behavior.py` — Phase 8 behavioral tests; Phase 9 appends `TestDataFlowParsing` and `TestMCPToolResultPropagation`
- `tests/test_state_transitions.py` — new file; created by Phase 9

### Project configuration
- `pyproject.toml` — `[tool.pytest.ini_options]` and test markers; `pytest-repeat` in dev deps
- `pytest.ini` or `pyproject.toml` — verify `slow` marker is registered before adding `@pytest.mark.slow`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `ExecutionTracer.emit()` / `ExecutionTracer.filter()` — use `filter()` in transition tests to assert event ordering (e.g., `filter("fallback_triggered")` returns events in emission order)
- `FallbackLLM._diagnostics` — list of failure records already written in `chat()`; transition tests can assert its length and content alongside trace events
- `_FakeCLIProvider` from `tests/test_cli_providers.py` — reuse pattern for creating stub CLI providers with controllable `_do_probe()` and `get_response()` outcomes

### Established Patterns
- Constructor injection for `tracer: ExecutionTracer | None = None` — every new test that needs a tracer creates `ExecutionTracer()` directly; no fixture needed
- Partition docstring at class level — `"""Partitions tested:\n  (input_A, trigger_X) → outcome_1\n  ..."""` — established in Phase 8 D-11; ALL new test classes in Phase 9 must follow this
- `@pytest.mark.parametrize` with explicit IDs (`ids=[...]`) — established in Phase 8 D-12; data-flow tests should use this for the 4 JSON repair path variants
- History sync pattern in `FallbackLLM.chat()` — the actual lines that copy `history`, `system_prompt`, `prev_prompt`, `prev_response` are the def-use boundary for the fallback data-flow tests

### Integration Points
- `InvariantViolationError` must be importable from `vulnhuntr.core` (public API); add to `vulnhuntr/core/__init__.py`
- The guard in `FallbackLLM.chat()` (D-04) must import from `vulnhuntr.core` — check that this doesn't introduce a circular import (llms.py already imports from vulnhuntr.core in Phase 8)
- `format_tool_results_for_prompt()` — verify exact function name and location before writing data-flow tests; search `vulnhuntr/core/analysis.py` and `vulnhuntr/mcp/`

</code_context>

<specifics>
## Specific Ideas

- The `_active not in _all_llms` guard (D-04) is the most important production change in this phase. It catches a class of bugs where manual `_active` reassignment or subclassing breaks the fallback chain silently.
- For `TestValidateResponseDataFlow`: mock `response.model_validate_json` to raise `ValidationError` on the first call, then pass on the second — this exercises the Python-literal repair path. Use `unittest.mock.patch` on the Pydantic model class directly.
- For `TestMCPToolResultPropagation`: use a real (non-mock) `format_tool_results_for_prompt()` call with a minimal `MCPToolCallResult` — test the actual XML serialization rather than mocking it away. This is a data-flow test, not a unit test.
- Repeat-trial tests (D-10) should use `monkeypatch` to fully determinize the environment (no real subprocess, no real API calls) so that `@pytest.mark.repeat(3)` proves algorithmic stability, not environmental stability.

</specifics>

<deferred>
## Deferred Ideas

- **Trace file I/O** — persisting `ExecutionTracer.events` to disk as JSONL/JSON belongs in Phase 10, not here. Do not add file writes to `ExecutionTracer` in this phase.
- **Coverage enforcement via pytest-cov thresholds** — ruled out in Phase 8 D-13; deferred indefinitely.
- **Full FSM with `ProviderState` enum** — too architectural for a hardening phase. Revisit if Phase 10+ introduces provider health polling.
- **MCP server-level state invariants** — MCP session lifecycle (connected/disconnected/error) is not in scope; that belongs with the MCP integration layer if ever formalized.

</deferred>
