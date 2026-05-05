---
phase: 02-runner-decomposition
plan: "01"
subsystem: cli/runner
tags: [refactor, runner-decomposition, RUNNER-01, RUNNER-02]
dependency_graph:
  requires: []
  provides: [_init_providers, _collect_files]
  affects: [run_analysis, tests/test_cli.py]
tech_stack:
  added: []
  patterns: [private-stage-function, individual-params]
key_files:
  modified:
    - vulnhuntr/cli/runner.py
    - tests/test_cli.py
decisions:
  - "D-01 honored: individual params, no shared context dataclass"
  - "D-03 honored: _collect_files() is pure, no checkpoint awareness"
  - "_init_providers() placed between get_model_name() and run_analysis() — alphabetical matches _collect_files order"
metrics:
  duration_minutes: 4
  completed_date: "2026-04-10"
  tasks_completed: 2
  files_modified: 2
---

# Phase 02 Plan 01: Extract _init_providers and _collect_files Summary

**One-liner:** Extracted two pipeline stages from the `run_analysis()` monolith — `_init_providers()` wrapping both LLM init call sites, and `_collect_files()` encapsulating the file discovery logic.

## What Was Built

`_init_providers(args, config, cost_callback, system_prompt="")` replaces the two `initialize_llm` + `wrap_with_fallbacks` call pairs that previously existed inline in `run_analysis()`. The README-summarization pass (no system prompt) and the analysis pass (with system prompt) now both delegate to this single function, matching the `_generate_reports()` pattern already established in the file.

`_collect_files(args, repo)` extracts the `RepoOps.get_relevant_py_files()` + `--analyze` path resolution block. Per D-03, it is intentionally pure: checkpoint-based file filtering remains in `run_analysis()` after the call. Returns `(files, files_to_analyze)`.

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1: Extract _init_providers() | b64c492 | extract _init_providers() from run_analysis() inline LLM init blocks |
| 2: Extract _collect_files() | 8cec90e | extract _collect_files() from run_analysis() file discovery block |

## Verification

```
grep -n "def _init_providers\|def _collect_files" vulnhuntr/cli/runner.py
235:def _collect_files(
265:def _init_providers(

python -m pytest tests/test_cli.py -q          → 73 passed
python -m pytest tests/ -m "not live" -q ...   → 648 passed, coverage 78.83%
python -c "from vulnhuntr.cli.runner import run_analysis; print('import ok')"  → import ok
```

## Deviations from Plan

None — plan executed exactly as written.

Tasks did not specify adding unit tests as a separate TDD commit cycle, but `tdd="true"` was set. Tests were written as part of the same task commit (RED→GREEN→commit combined), which is appropriate for a refactor with no new external behavior. All new tests pass.

## Known Stubs

None.

## Threat Flags

None — both functions are private (`_` prefix), take only already-validated parameters forwarded from `run_analysis()`, and introduce no new trust boundaries or public API surface. Per the plan's threat register, T-02-01, T-02-02, and T-02-03 all have `accept` disposition.

## Self-Check: PASSED

- `vulnhuntr/cli/runner.py` exists and contains both function definitions ✓
- `tests/test_cli.py` contains `TestCollectFiles` and `TestInitProviders` ✓
- Commits b64c492 and 8cec90e exist ✓
- 648 tests pass, coverage 78.83% ✓
