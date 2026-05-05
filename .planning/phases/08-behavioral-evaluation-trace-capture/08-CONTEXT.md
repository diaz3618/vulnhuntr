# Phase 8: Behavioral Evaluation & Trace Capture - Context

**Gathered:** 2026-05-04
**Status:** Ready for planning

<domain>
## Phase Boundary

Add the evidence layer that proves critical provider flows behave correctly
end-to-end, not just that they produce a correctly-shaped final response.

Three work streams:

1. **Trace contract** — Define a `TraceEvent` dataclass and `ExecutionTracer`
   accumulator. Wire emission points into `CLIProviderLLM.probe()`,
   `CLIProviderLLM.send_message()`, response validation, `FallbackLLM.chat()`,
   and session decision paths.

2. **Behavioral evaluations** — Tests that drive multi-step provider flows with
   mocked subprocesses and assert that the intermediate trace events occurred in
   the correct order with the correct content — not just that the final
   `Response` is valid.

3. **Boundary-focused tests** — Equivalence-partition and boundary tests for
   `CLIPolicy` config parsing, provider selection (`initialize_llm`), and the
   CLI error taxonomy, added to existing `test_config.py` and
   `test_cli_providers.py` with explicit partition tables in docstrings.

Out of scope: state-transition invariants (Phase 9), report integration of
trace output (Phase 10), any new `CLIPolicy` fields, any changes to Phase 7
MCP wiring.

</domain>

<decisions>
## Implementation Decisions

### Trace Event Model (EVAL-01)

- **D-01:** Add a new module `vulnhuntr/core/trace.py` with two public types:

  ```python
  from __future__ import annotations
  import dataclasses
  from datetime import datetime, timezone
  from typing import Any, Literal

  TraceEventType = Literal[
      "probe_result",
      "response_validated",
      "tool_call",
      "fallback_triggered",
      "session_decision",
  ]

  @dataclasses.dataclass
  class TraceEvent:
      event_type: TraceEventType
      provider: str          # class name or provider key
      timestamp: datetime    # UTC; set to datetime.now(timezone.utc) at emission
      data: dict[str, Any]   # event-specific payload — see per-event schema below
  ```

  The five event types are the exact five listed in EVAL-01.

- **D-02:** `ExecutionTracer` is a simple accumulator class:

  ```python
  class ExecutionTracer:
      def __init__(self) -> None:
          self.events: list[TraceEvent] = []

      def emit(
          self,
          event_type: TraceEventType,
          provider: str,
          **data: Any,
      ) -> None:
          self.events.append(
              TraceEvent(
                  event_type=event_type,
                  provider=provider,
                  timestamp=datetime.now(timezone.utc),
                  data=data,
              )
          )

      def filter(self, event_type: TraceEventType) -> list[TraceEvent]:
          return [e for e in self.events if e.event_type == event_type]
  ```

  No threading, no async — scoped to a single scan call. Thread-safety is
  deferred to Phase 9 if ever needed.

- **D-03:** Per-event `data` schemas (minimum required fields per type):

  | `event_type` | Required `data` keys |
  |---|---|
  | `probe_result` | `ok`, `binary_found`, `version`, `auth_valid`, `diagnostic_message` |
  | `response_validated` | `vuln_type`, `confidence`, `valid` (bool), `error` (str or None) |
  | `tool_call` | `server`, `tool`, `success`, `error` (str or None), `duration_ms` |
  | `fallback_triggered` | `failed_provider`, `error_class`, `fallback_to`, `fallback_index` |
  | `session_decision` | `session_mode`, `flags_added` (list of str), `warned` (bool) |

  Downstream agents must keep data keys consistent — do not add required
  keys not listed here; extra optional keys are allowed.

### Trace Injection Pattern (EVAL-01)

- **D-04:** `ExecutionTracer` is passed as an optional keyword argument to
  components that emit events, matching the existing `mcp_helper` injection
  pattern from Phase 7:

  - `CLIProviderLLM.__init__` gains `tracer: ExecutionTracer | None = None`
  - `VulnerabilityAnalyzer.__init__` gains `tracer: ExecutionTracer | None = None`
  - `FallbackLLM.__init__` gains `tracer: ExecutionTracer | None = None`

  When `tracer is None`, every emit call is a no-op (zero behavioral
  difference for existing callers). The runner creates one `ExecutionTracer`
  per scan when `--verbose` or later a `--trace-output` flag is set.

- **D-05:** `run_analysis()` returns the `ExecutionTracer` instance alongside
  its existing result. Signature change:

  ```python
  def run_analysis(...) -> tuple[list[AnalysisResult], ExecutionTracer | None]:
  ```

  When no tracer was created (default), second element is `None`. Existing
  call sites that unpack only the first element continue to work.

- **D-06:** Trace storage is **in-memory only** for Phase 8. No file I/O, no
  checkpoint integration. A `--trace-output <file>` flag and `CheckpointData`
  attachment are deferred to Phase 10.

### Trace Emission Wiring (EVAL-01)

- **D-07:** Emission sites and event types:

  | Location | Event | When |
  |---|---|---|
  | `CLIProviderLLM.probe()` base default impl | `probe_result` | After `CapabilityResult` is returned |
  | Each provider `send_message()` after successful response | `response_validated` | After Pydantic model validates successfully |
  | Each provider `send_message()` on `CLIParseError` | `response_validated` | `valid=False`, `error=str(exc)` |
  | `FallbackLLM.chat()` on fallback | `fallback_triggered` | Each time a provider fails and fallback activates |
  | `CLIProviderLLM.send_message()` session flag path | `session_decision` | When `session_mode` causes flags to be added or a warning is logged |
  | `MCPAnalysisHelper.execute_tool_calls()` per call | `tool_call` | After each MCP tool call resolves (success or timeout) |

  `probe_result` emission happens in the base class `probe()` wrapper so
  subclasses don't need to emit it themselves. Subclasses call `super().probe()`
  or the base adds a post-probe hook. Researcher confirms the cleanest approach.

### Behavioral Evaluation Tests (EVAL-02)

- **D-08:** Two new test files:
  - `tests/test_trace.py` — unit tests for `TraceEvent`, `ExecutionTracer`
    (emit, filter, schema validation). No mocked providers needed here.
  - `tests/test_behavior.py` — integration-style tests driving full multi-step
    flows with mocked subprocesses and asserting trace event ordering and content.

- **D-09:** Four behavior test targets (one test class per flow):

  **Flow 1 — Probe → Send → Trace emitted** (`TestProbeToSendTrace`):
  Mock `_run_subprocess` to return a valid JSON response. Assert that after
  `send_message()` completes, the tracer contains one `probe_result` and one
  `response_validated` event with `valid=True`.

  **Flow 2 — Fallback chain** (`TestFallbackChainTrace`):
  Use two providers: a fake CLI provider whose `_run_subprocess` raises
  `CLIRuntimeError`, and a fake API provider that succeeds. Drive through
  `FallbackLLM.chat()`. Assert the tracer contains one `fallback_triggered`
  event with the correct `failed_provider`, `error_class`, and `fallback_to`
  fields.

  **Flow 3 — Session resume with stored ID** (`TestSessionResumeTrace`):
  Construct a `ClaudeCodeLLM` with `session_mode="resume"` and a stored
  `session_id`. Mock `_run_subprocess`. Assert the tracer emits a
  `session_decision` event with `session_mode="resume"`, `flags_added`
  containing `"--resume <id>"`, and `warned=False`.

  **Flow 4 — Response validation failure** (`TestValidationFailureTrace`):
  Mock `_run_subprocess` to return malformed JSON. Assert the tracer emits
  `response_validated` with `valid=False` and a non-empty `error` string.
  Assert `CLIParseError` is raised to the caller.

- **D-10:** Each behavior test asserts **semantic content** of trace events
  (e.g., `event.data["valid"] is True`), not just that events were appended.
  Test names should read as behavioral sentences:
  `test_probe_and_send_emit_expected_trace_events`.

### Boundary Tests for Config and Provider Selection (EVAL-03)

- **D-11:** Boundary tests land in **existing files** with explicit partition
  tables in the test class docstring:

  - `tests/test_config.py` → `TestCLIPolicyBoundaries` class
  - `tests/test_cli_providers.py` → `TestProviderSelectionBoundaries` class

- **D-12:** `TestCLIPolicyBoundaries` covers these equivalence partitions with
  `@pytest.mark.parametrize`:

  | Field | Partitions |
  |---|---|
  | `session_mode` | valid values: `"stateless"`, `"continue"`, `"resume"`; invalid: `"unknown"` |
  | `mcp_mode` | valid: `"none"`, `"vulnhuntr"`, `"provider"`, `"both"`; invalid: `"auto"` |
  | `tool_mode` | valid: `"none"`, `"read-only"`, `"full"`; invalid: `""` (empty string) |
  | `timeout` | boundary: 0, 1, 300 (default), `sys.maxsize`; invalid: -1 |
  | `max_turns` | boundary: 1, 10 (default), 100; invalid: 0 |
  | `overrides` | empty dict, valid nested dict, nested dict with invalid field name |

  Invalid-value tests assert that parsing either raises a `ValueError` or logs
  a warning (whichever the implementation chooses — researcher confirms). Tests
  must not assume validation strategy; they assert observable behavior.

- **D-13:** `TestProviderSelectionBoundaries` covers these partitions:

  | Scenario | Expected |
  |---|---|
  | Valid CLI provider name (`"claude-code"`) | Returns `ClaudeCodeLLM` instance |
  | Valid API provider name (`"claude"`) | Returns `Claude` instance (unchanged) |
  | Unknown provider name (`"gpt-99"`) | Raises `ValueError` with provider name in message |
  | CLI provider with `binary_found=False` (mocked probe) | Raises `CLIBinaryNotFoundError` |
  | CLI provider with `auth_valid=False` (mocked probe) | Raises `CLIAuthError` |
  | Fallback spec with CLI provider (`"claude-code,claude"`) | Returns `FallbackLLM` wrapping both |
  | Fallback spec with unknown CLI provider name | Raises `ValueError` at spec parse time |

- **D-14:** Each `@pytest.mark.parametrize` call uses IDs (`pytest.param(..., id="...")`
  for every case so failure output names the partition, not just a numeric index.

### Agent Discretion

- Which base-class method or hook is cleanest for emitting `probe_result` without
  forcing every subclass to call `super()` — researcher proposes options; planner picks.
- Exact `run_analysis()` return-type handling — tuple vs. named return struct — left
  to planner based on what minimizes downstream change.
- Whether `CLIPolicyBoundaries` invalid-value tests assert `ValueError` or just a
  structlog `warning` depends on what the current config loader actually does —
  researcher confirms before planner commits to it.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements
- `.planning/REQUIREMENTS.md` — EVAL-01, EVAL-02, EVAL-03 (lines ~120–135)

### Architecture and Prior Decisions
- `.planning/phases/06-sessions-native-tools-mcp-policy/06-CONTEXT.md` — D-01 through D-04 (session_mode semantics, session_id capture)
- `.planning/phases/07-mcp-completion-routing-cost-hardening/07-CONTEXT.md` — D-18 through D-22 (FallbackLLM._diagnostics pattern, MCP integration tests)

### Source Files (read before planning)
- `vulnhuntr/cli_providers/base.py` — `CLIProviderLLM`, error taxonomy, `CapabilityResult`
- `vulnhuntr/cli_providers/claude_code.py` — `send_message()`, session flag mapping
- `vulnhuntr/cli_providers/gemini_cli.py` — cross-reference for session and parse patterns
- `vulnhuntr/core/analysis.py` — `VulnerabilityAnalyzer` constructor injection pattern
- `vulnhuntr/llms.py` — `FallbackLLM.chat()` — existing fallback chain and diagnostic list
- `vulnhuntr/config.py` — `CLIPolicy` dataclass fields and defaults

### Test Files (read before planning)
- `tests/test_cli_providers.py` — `_FakeCLIProvider` pattern, existing error-taxonomy tests
- `tests/test_config.py` — existing `CLIPolicy` tests and YAML round-trip tests
- `tests/test_mcp_analysis.py` — MCP integration test pattern from Phase 7
- `tests/test_analysis.py` — `VulnerabilityAnalyzer` test patterns

</canonical_refs>
