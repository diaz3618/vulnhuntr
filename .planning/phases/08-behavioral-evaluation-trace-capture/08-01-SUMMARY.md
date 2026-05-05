---
phase: 08-behavioral-evaluation-trace-capture
plan: "01"
subsystem: testing
tags: [trace, execution-tracer, cli-providers, config-validation, behavioral-evaluation]

# Dependency graph
requires:
  - phase: 06-sessions-native-tools-mcp-policy
    provides: CLIPolicy dataclass, CLIProviderLLM base class with probe() and chat()
  - phase: 07-mcp-completion-routing-cost-hardening
    provides: FallbackLLM, MCPAnalysisHelper, VulnerabilityAnalyzer wiring
provides:
  - vulnhuntr/core/trace.py — TraceEvent dataclass and ExecutionTracer accumulator
  - CLIProviderLLM template-method pattern with _do_probe() and concrete probe()
  - response_validated trace events on success and failure paths in chat()
  - CLIPolicy.__post_init__ validation for session_mode, mcp_mode, tool_mode, timeout, max_turns
  - VulnhuntrConfig.from_dict() cli section passes kwargs to CLIPolicy constructor
affects: [08-02, 08-03, 09-01, 09-02, 09-03, 09-04]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Template method: abstract _do_probe() + concrete probe() for trace emission"
    - "Optional tracer injection — None means no-op throughout codebase"
    - "CLIPolicy dataclass __post_init__ as validation layer for untrusted YAML input"

key-files:
  created:
    - vulnhuntr/core/trace.py
  modified:
    - vulnhuntr/cli_providers/base.py
    - vulnhuntr/config.py

key-decisions:
  - "ExecutionTracer is a leaf module (stdlib-only) to avoid circular imports"
  - "Template method pattern chosen over hook callbacks for probe emission — simpler and testable"
  - "CLIPolicy validation at __post_init__ rather than field-level for cohesive error messages"
  - "_VALID_* sets declared as class-level frozenset constants (not annotated) so dataclass does not treat them as fields"
  - "from_dict() collects all kwargs before constructing CLIPolicy — ensures __post_init__ fires with user-supplied values"

patterns-established:
  - "Tracer injection: tracer: ExecutionTracer | None = None in constructor, guarded with `if self._tracer is not None` at emit sites"
  - "Trace events emitted on both success and failure paths for accurate behavioral evidence"

requirements-completed: [EVAL-01, EVAL-03]

# Metrics
duration: 5min
completed: 2026-05-05
---

# Phase 8 Plan 01: ExecutionTracer Infrastructure and CLIPolicy Validation Summary

**ExecutionTracer accumulator with probe_result and response_validated events, template-method refactor of CLIProviderLLM.probe(), and CLIPolicy.__post_init__ guard against invalid YAML-sourced config values**

## Performance

- **Duration:** ~5 min (plan already implemented in commit 5a5088c)
- **Started:** 2026-05-05T01:05:46Z
- **Completed:** 2026-05-05T01:10:00Z
- **Tasks:** 3 (all verified complete)
- **Files modified:** 3

## Accomplishments

- `vulnhuntr/core/trace.py` created as a stdlib-only leaf module exporting `TraceEvent`, `ExecutionTracer`, `TraceEventType`
- `CLIProviderLLM.probe()` refactored to template method: abstract `_do_probe()` for subclasses, concrete `probe()` emits `probe_result` event and raises `CLIBinaryNotFoundError`/`CLIAuthError` on capability failures
- `CLIProviderLLM.__init__` accepts `tracer: ExecutionTracer | None = None` and stores as `self._tracer`; `chat()` emits `response_validated` on both success and failure paths
- `CLIPolicy.__post_init__` validates `session_mode`, `mcp_mode`, `tool_mode` against known enums and `timeout >= 0`, `max_turns >= 1`
- `VulnhuntrConfig.from_dict()` accumulates all CLI dict values into `kwargs` before calling `CLIPolicy(**kwargs)`, ensuring `__post_init__` fires with user-supplied values
- 143 `test_cli_providers.py` tests pass; 84 `test_config.py` tests pass

## Task Commits

All three tasks were committed in the prior Phase 08 wave commit:

1. **Task 1: Create vulnhuntr/core/trace.py** - `5a5088c` (feat)
2. **Task 2: Refactor CLIProviderLLM — template method + tracer + response_validated** - `5a5088c` (feat)
3. **Task 3: Add CLIPolicy.__post_init__ validation + update from_dict()** - `5a5088c` (feat)

## Files Created/Modified

- `vulnhuntr/core/trace.py` — New leaf module: `TraceEventType` Literal, `TraceEvent` dataclass, `ExecutionTracer` with `emit()` and `filter()`, plus `InvariantViolationError`
- `vulnhuntr/cli_providers/base.py` — Renamed abstract `probe()` to `_do_probe()`; added concrete `probe()` with trace emission and error raising; added `tracer` kwarg to `__init__`; wired `response_validated` events in `chat()`
- `vulnhuntr/config.py` — Added `_VALID_*` frozenset class constants and `__post_init__` to `CLIPolicy`; updated `from_dict()` cli section to collect kwargs before `CLIPolicy(**kwargs)`

## Decisions Made

- `ExecutionTracer` kept as stdlib-only to avoid import cycles — no vulnhuntr imports in `trace.py`
- Template method (`_do_probe` + `probe`) chosen over monkey-patching or decorator approach for clarity and testability
- `_VALID_*` constants declared as unannotated class variables in the dataclass — avoids them becoming dataclass fields while keeping them co-located with the validation logic

## Deviations from Plan

None - plan executed exactly as written. All three changes were already in place when this agent was spawned (committed in `5a5088c` during Phase 08 wave 1 execution).

## Issues Encountered

None — all verification commands passed on first attempt.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `trace.py` is fully importable; Wave 2 (08-02) can import `ExecutionTracer` and build on it immediately
- All subclasses (`ClaudeCodeLLM`, `GeminiCLILLM`, `CodexLLM`, `QwenCodeLLM`) already implement `_do_probe()` — the rename from `probe()` propagated in the same commit
- `CLIPolicy` validation fires on config load — any invalid YAML-sourced values will raise `ValueError` before reaching the scan pipeline

## Self-Check: PASSED

- vulnhuntr/core/trace.py: FOUND
- vulnhuntr/cli_providers/base.py: FOUND
- vulnhuntr/config.py: FOUND
- 08-01-SUMMARY.md: FOUND
- Implementation commit 5a5088c: FOUND

---
*Phase: 08-behavioral-evaluation-trace-capture*
*Completed: 2026-05-05*
