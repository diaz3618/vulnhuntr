---
phase: 01-quick-wins-test-infrastructure
plan: 02
subsystem: tests
tags: [testing, traversal-guard, integration-test, mocked-llm, coverage]
dependency_graph:
  requires: [01-01-PLAN.md]
  provides: [traversal-guard-tests, run-analysis-integration-tests]
  affects: [tests/test_cli.py]
tech_stack:
  added: []
  patterns: [unittest.mock.patch, pytest-tmp_path, argparse.Namespace fixture, JSON report assertion]
key_files:
  created: []
  modified:
    - tests/test_cli.py
decisions:
  - "Patch initialize_llm at call site (vulnhuntr.cli.runner.initialize_llm) rather than definition site to correctly intercept both calls inside run_analysis()"
  - "D-11 assertion implemented by writing JSON report via json= arg and reading it back, not by checking exit code only"
  - "test_analyze_outside_root uses tmp_path.parent sibling directory (outside_dir) to avoid relying on absolute paths that could vary by environment"
metrics:
  duration: "~11 minutes"
  completed: "2026-04-09"
  commits: 2
  tasks_completed: 2
  tasks_total: 2
  files_changed: 1
  lines_added: 123
requirements_satisfied: [INFRA-02, INFRA-04]
---

# Phase 01 Plan 02: Traversal Guard Tests + Run Analysis Integration Tests Summary

**One-liner:** Path-traversal guard coverage via `test_analyze_inside/outside_root` and full `run_analysis()` E2E smoke test with mocked LLM writing an inspectable JSON report (D-11 satisfied).

## What Was Built

### Task 1 — Traversal guard tests in TestValidateArgs (commit `cc531ee`)

Added two test methods to the existing `TestValidateArgs` class in `tests/test_cli.py`:

- **`test_analyze_inside_root`** — creates a real file under `tmp_path`, passes it as `--analyze` with `--root=tmp_path`; asserts `validate_args()` returns `None` (no error).
- **`test_analyze_outside_root`** — creates `tmp_path.parent / "outside_dir" / "evil.py"` (a sibling directory outside `tmp_path`), passes it as `--analyze`; asserts the returned error string is not `None` and contains the word `"outside"`.

Both tests exercise `validate_args()` from `vulnhuntr/cli/parser.py` which was hardened in Plan 01 with `Path.resolve()` + `Path.is_relative_to()`.

### Task 2 — TestRunAnalysisIntegration (commit `af673d1`)

Appended a new `TestRunAnalysisIntegration` class (87 lines) at the end of `tests/test_cli.py` with four tests:

| Test | Assertion |
|------|-----------|
| `test_run_analysis_produces_finding` | JSON report file exists and contains ≥1 finding with `confidence_score >= 1` **(D-11)** |
| `test_run_analysis_returns_zero_exit_code` | `run_analysis()` returns `0` |
| `test_run_analysis_does_not_call_real_api` | `initialize_llm` was called via mock; `mock_llm.chat` was invoked; no real HTTP |
| `test_run_analysis_no_checkpoint_file_created` | `tmp_path / ".vulnhuntr_checkpoint"` does not exist |

The `_make_args()` helper constructs a minimal `argparse.Namespace` with all required fields, writing a 3-line Python fixture as the analysis target and passing `json=str(report_path)` for the D-11 test. The `mock_llm` fixture from `conftest.py` (VulnType.SQLI, confidence_score=8) is injected automatically by pytest.

## Verification Results

```
pytest tests/test_cli.py -q
65 passed in 0.96s

pytest tests/ -m "not live" -q --cov=vulnhuntr --cov-report=term-missing
640 passed — coverage 78.74% (≥ 72% floor ✓)
```

All success criteria from the plan are satisfied:
- `TestValidateArgs::test_analyze_inside_root` ✓
- `TestValidateArgs::test_analyze_outside_root` ✓ (error contains "outside")
- `TestRunAnalysisIntegration` all 4 methods ✓
- D-11 JSON-report assertion ✓
- No regressions ✓
- Coverage ≥ 72% ✓

## Decisions Made

1. **Patch at call site, not definition site.** `initialize_llm` is imported into `runner.py`, so the correct patch target is `vulnhuntr.cli.runner.initialize_llm`. Patching the definition site (`vulnhuntr.llms.initialize_llm`) would leave the already-imported reference unaffected inside `run_analysis()`.

2. **D-11 via JSON report file inspection.** The plan required asserting an actual `Finding` with `confidence_score >= 1` — not just `exit_code == 0`. Passing `json=str(report_path)` to `_make_args()` causes the JSON reporter to write a real file that the test reads and inspects.

3. **Outside-root fixture using `tmp_path.parent` sibling.** Using `tmp_path.parent / "outside_dir"` avoids hardcoded absolute paths and is guaranteed to be outside `tmp_path` regardless of the test runner's working directory or platform.

## Deviations from Plan

None — plan executed exactly as written. Both tasks matched the plan's action blocks verbatim with only minor import hoisting (`import json as json_mod` to the top-level imports section) to satisfy Ruff isort ordering.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. All file I/O is confined to `tmp_path` (pytest-managed temp directories). Mock patch fully intercepts `initialize_llm` before any HTTP socket could be opened (T-02-01 mitigated).

## Self-Check

- [x] `tests/test_cli.py` modified — confirmed (665 lines, +123 vs pre-plan)
- [x] Commit `cc531ee` exists — confirmed
- [x] Commit `af673d1` exists — confirmed
- [x] 65 tests pass in `test_cli.py`
- [x] `TestValidateArgs::test_analyze_outside_root` asserts `"outside" in error`
- [x] `TestRunAnalysisIntegration::test_run_analysis_produces_finding` reads JSON report and asserts `confidence_score >= 1`

## Self-Check: PASSED
