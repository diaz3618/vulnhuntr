---
phase: 08-behavioral-evaluation-trace-capture
plan: 02
subsystem: testing
tags: [trace, execution-tracer, cli-providers, fallback-llm, mcp, analysis]

# Dependency graph
requires:
  - phase: 08-01
    provides: ExecutionTracer infrastructure, CLIProviderLLM._tracer, _do_probe() abstract

provides:
  - "probe() -> _do_probe() rename complete in all 4 CLI provider files and _FakeCLIProvider"
  - "ClaudeCodeLLM.send_message() emits session_decision event with session_mode, flags_added, warned=False"
  - "FallbackLLM.__init__ accepts tracer kwarg; chat() emits fallback_triggered in LLMError block"
  - "VulnerabilityAnalyzer.tracer public attribute + run_analysis() convenience method (D-05)"
  - "MCPAnalysisHelper.execute_tool_calls() emits tool_call events with duration_ms for all paths (success, timeout, exception, blocked)"

affects: [08-03, behavioral-tests, trace-evaluation]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "ExecutionTracer injected via tracer kwarg at construction time, stored as self._tracer (private) or self.tracer (public per D-05)"
    - "Blocked-tool path emits tool_call with duration_ms=0 for consistent trace coverage across all outcomes"
    - "VulnerabilityAnalyzer.run_analysis() wraps analyze_file() for programmatic callers needing (results, tracer) tuple"

key-files:
  created: []
  modified:
    - "vulnhuntr/core/analysis.py — added run_analysis() convenience wrapper returning (list[AnalysisResult], ExecutionTracer | None)"
    - "vulnhuntr/mcp/analysis.py — added tool_call tracer emission in blocked-tool path (duration_ms=0)"

key-decisions:
  - "run_analysis() delegates to analyze_file(path, file_paths) rather than per-vtype dispatch because analyze_file handles all types internally"
  - "Blocked-tool path should emit tool_call trace event (Rule 2 addition) to ensure uniform trace coverage in behavioral tests (08-03)"

patterns-established:
  - "Pattern: All outcome paths in execute_tool_calls() emit tool_call — success, timeout, exception, and blocked"
  - "Pattern: VulnerabilityAnalyzer.tracer is public (not _tracer) so tests access analyzer.tracer.events directly"

requirements-completed: [EVAL-01, EVAL-02]

# Metrics
duration: 15min
completed: 2026-05-05
---

# Phase 08 Plan 02: Wire Trace Emission Sites Summary

**Probe renamed to _do_probe across all 4 CLI providers, session_decision + fallback_triggered + tool_call events wired in production code, VulnerabilityAnalyzer.run_analysis() D-05 method added**

## Performance

- **Duration:** ~15 min
- **Started:** 2026-05-05T01:00:00Z
- **Completed:** 2026-05-05T01:13:05Z
- **Tasks:** 4 (1-3 pre-existing from wave 1; Task 4 implemented in this wave)
- **Files modified:** 2

## Accomplishments

- Verified and confirmed Tasks 1-3 were already complete from wave 1 (08-01 worktree): all 4 providers renamed probe() → _do_probe(), ClaudeCodeLLM session_decision emission, FallbackLLM fallback_triggered emission, VulnerabilityAnalyzer.tracer public attribute, MCPAnalysisHelper tool_call emission for success/timeout/exception paths
- Added `VulnerabilityAnalyzer.run_analysis()` convenience method (Task 4 / D-05): returns `tuple[list[AnalysisResult], ExecutionTracer | None]`
- Added blocked-tool path tracer emission in MCPAnalysisHelper.execute_tool_calls() for uniform tool_call event coverage (deviation Rule 2)
- All 953 tests pass (excluding pre-existing test_checkpoint.py infra failure unrelated to this plan)

## Task Commits

1. **Tasks 1-3: probe rename + session_decision + fallback_triggered + tracer attributes** - `439a8ce` (pre-existing from wave 1, docs(phase-08): update tracking after wave 1)
2. **Task 4: VulnerabilityAnalyzer.run_analysis() + blocked-tool trace emission** - `d09a4cc` (feat(08-02))

**Plan metadata:** (SUMMARY commit below)

## Files Created/Modified

- `/home/diaz/workspace/CS5374/vulnhuntr/vulnhuntr/core/analysis.py` - Added run_analysis() method returning (results, tracer) tuple
- `/home/diaz/workspace/CS5374/vulnhuntr/vulnhuntr/mcp/analysis.py` - Added tool_call tracer emission in blocked destructive-tool path

## Decisions Made

- `run_analysis()` delegates to `analyze_file(path, file_paths)` — the existing method handles all VulnType iteration internally, so a per-vtype loop would duplicate logic
- `vuln_types` parameter accepted in signature for API symmetry but not used in dispatch (documented in docstring)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added tool_call tracer emission in blocked-tool path**
- **Found during:** Task 3 verification
- **Issue:** Plan spec required blocked-tool path in execute_tool_calls() to emit tool_call event with duration_ms=0, but the code only emitted for success/timeout/exception paths
- **Fix:** Added self._tracer.emit("tool_call", ..., duration_ms=0) immediately after the blocked-path log.warning()
- **Files modified:** vulnhuntr/mcp/analysis.py
- **Verification:** All 91 MCP/analysis tests pass
- **Committed in:** d09a4cc (Task 4 commit)

---

**Total deviations:** 1 auto-fixed (Rule 2 - missing critical trace emission)
**Impact on plan:** Required for behavioral test correctness in 08-03 — blocked-tool scenarios must produce trace events testable assertions can check.

## Issues Encountered

- Tasks 1-3 were already complete from the wave 1 08-01 worktree agent (which was a broader execution that landed probe rename + tracer wiring across all files). No rework needed.

## Known Stubs

None — all trace emission paths wired with production-code logic.

## Next Phase Readiness

- 08-03 behavioral tests can now drive all 5 EVAL-01 event types and assert on semantic trace content
- ExecutionTracer.events is populated by: session_decision (ClaudeCodeLLM), fallback_triggered (FallbackLLM), tool_call (MCPAnalysisHelper), probe_result (CLIProviderLLM base), analysis_complete (future)
- VulnerabilityAnalyzer.run_analysis() gives 08-03 tests a clean entry point returning (results, tracer) tuple

## Self-Check: PASSED

- vulnhuntr/core/analysis.py: FOUND
- vulnhuntr/mcp/analysis.py: FOUND
- 08-02-SUMMARY.md: FOUND
- Commit d09a4cc: FOUND
- VulnerabilityAnalyzer.run_analysis() method: VERIFIED (contains 'tuple', 'tracer', 'AnalysisResult')
- MCPAnalysisHelper blocked-tool duration_ms=0: VERIFIED

---
*Phase: 08-behavioral-evaluation-trace-capture*
*Completed: 2026-05-05*
