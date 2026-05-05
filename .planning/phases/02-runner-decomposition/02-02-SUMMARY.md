---
phase: 02-runner-decomposition
plan: "02"
subsystem: cli/runner
tags: [refactor, testability, llm-injection, runner-decomposition]
dependency_graph:
  requires: [02-01]
  provides: [_analyze_files, llm_factory-injection]
  affects: [vulnhuntr/cli/runner.py, tests/test_cli.py]
tech_stack:
  patterns: [individual-param stage functions, optional callable injection]
key_files:
  modified:
    - vulnhuntr/cli/runner.py
    - tests/test_cli.py
decisions:
  - "verbosity passed as int param to _analyze_files() — cleaner than reading analyzer._config directly"
  - "llm_factory path calls positionally; initialize_llm default keeps model_override= keyword to preserve existing test assertions"
metrics:
  duration_minutes: 5
  completed_date: "2026-04-10"
  tasks_completed: 2
  files_modified: 2
---

# Phase 02 Plan 02: _analyze_files() Extraction and llm_factory Injection Summary

**One-liner:** Extracted per-file analysis loop into `_analyze_files()` (RUNNER-03) and added `llm_factory=None` to `run_analysis()` and `_init_providers()` for test injection (RUNNER-06).

## What Was Built

### Task 1: `_analyze_files()` extraction (RUNNER-03)

Added `_analyze_files()` as a module-level private stage function immediately before `_generate_reports()` in `runner.py`. The function encapsulates the entire per-file analysis loop including:
- Budget-enforcer pre-check with console output on abort
- `checkpoint.set_current_file()` and `checkpoint.mark_file_complete()` calls
- `analyzer.analyze_file()` with `(OSError, UnicodeDecodeError, ValueError)` error handling
- MCP tool dispatch for both initial and per-vuln-type reports (when `mcp_helper` is active)
- Finding collection via `response_to_finding()`
- Verbosity-controlled `print_readable()` for secondary reports

`run_analysis()` now delegates to `_analyze_files()` with all context passed as individual parameters (D-01 pattern).

Verbosity is passed as an `int` parameter rather than reading `analyzer._config.verbosity` — simpler and more explicit per the plan's suggested fallback approach.

### Task 2: `llm_factory` injection (RUNNER-06)

- `run_analysis()` signature: `run_analysis(args, llm_factory=None)`
- `_init_providers()` signature: `_init_providers(args, config, cost_callback, system_prompt, llm_factory=None)`
- When `llm_factory is None`: calls `initialize_llm(args.llm, system_prompt, cost_callback, model_override=config.model)` — unchanged production path
- When `llm_factory is not None`: calls `llm_factory(args.llm, system_prompt, cost_callback, config.model)` positionally
- Both `_init_providers()` calls inside `run_analysis()` forward `llm_factory`

## Commits

| Hash | Description |
|------|-------------|
| 75caa10 | test(02-02): add failing tests for _analyze_files() extraction |
| 90076d5 | feat(02-02): extract _analyze_files() from run_analysis() loop |
| 5e11a43 | feat(02-02): add llm_factory parameter to run_analysis() and _init_providers() |

## Verification Results

```
652 passed, 79% coverage (≥72% required)
run_analysis params: ['args', 'llm_factory']
_init_providers params: ['args', 'config', 'cost_callback', 'system_prompt', 'llm_factory']
```

## Deviations from Plan

### Auto-fixed Issues

None.

### Implementation Notes

**1. `verbosity` param instead of `analyzer._config.verbosity`**
- **Found during:** Task 1 implementation
- **Decision:** The plan explicitly flagged this option: "accept a `verbosity: int = 0` parameter instead and use it directly." Used this approach — it avoids accessing a private attribute and keeps `_analyze_files()` decoupled from the `AnalysisConfig` internals.

**2. `llm_factory` calling convention**
- **Found during:** Task 2, TestInitProviders failures
- **Issue:** The plan's `_factory(args.llm, system_prompt, cost_callback, config.model)` pattern broke existing tests that assert `initialize_llm` is called with `model_override=` as a keyword arg.
- **Fix:** Used an explicit `if llm_factory is not None` branch: the default path calls `initialize_llm(..., model_override=config.model)` preserving the keyword convention; the factory path calls positionally. Both are correct per the RUNNER-06 acceptance criteria.

## Known Stubs

None — all data flows are wired through to the analysis pipeline.

## Threat Flags

No new trust boundaries introduced. `llm_factory` is only callable at test time; the CLI production path always passes `None`.

## Self-Check: PASSED

- `vulnhuntr/cli/runner.py` exists and contains `def _analyze_files(` ✓
- `vulnhuntr/cli/runner.py` contains `llm_factory` in both `run_analysis` and `_init_providers` ✓
- Commits 75caa10, 90076d5, 5e11a43 exist ✓
- 652 tests pass, coverage 79% ✓
