# Phase 2: Runner Decomposition - Context

**Gathered:** 2026-04-09
**Status:** Ready for planning

<domain>
## Phase Boundary

Extract `run_analysis()` in `vulnhuntr/cli/runner.py` into 5 independently testable pipeline stages (RUNNER-01–05) and add an optional LLM factory parameter to `run_analysis()` for test injection (RUNNER-06). No external behavior changes — the CLI interface and all existing flags remain identical.

</domain>

<decisions>
## Implementation Decisions

### Stage Interface Shape (RUNNER-01–05)
- **D-01:** Each extracted stage takes individual params — no shared context dataclass. Matches the existing `_generate_reports(args, all_findings, cost_tracker, files_to_analyze)` pattern already in `runner.py`. Keeps stages independently testable without coupling to a shared mutable object.

### LLM Factory Injection (RUNNER-06)
- **D-02:** `run_analysis(args, llm_factory=None)` — optional callable, `None` means use existing `initialize_llm()`. Signature: `Callable[[str, str, Callable, str | None], LLM] | None`. When provided in tests, callers pass a lambda returning a `MagicMock` — no patch paths needed. The Phase 1 `TestRunAnalysisIntegration` test should be updated to use this param rather than `unittest.mock.patch`.

### File Collection / Checkpoint Resume (RUNNER-02)
- **D-03:** `_collect_files()` is pure — returns the full file list with no checkpoint awareness. `run_analysis()` handles the checkpoint-based filtering after calling `_collect_files()`. Keeps `_collect_files()` testable without an `AnalysisCheckpoint` object.

### Test Organization (RUNNER-01–06)
- **D-04:** Per-stage unit tests go in new classes in `tests/test_cli.py` (e.g., `TestInitProviders`, `TestCollectFiles`, `TestAnalyzeFiles`). Consistent with Phase 1 approach; does NOT require moving `TestRunAnalysisIntegration`.

### Claude's Discretion
- Exact param signatures for each private stage function — follow the individual-params pattern and let the planner decide what each stage needs.
- Whether `llm_factory` also covers `wrap_with_fallbacks` (the fallback wrapping step) or only `initialize_llm`. Planner can decide — the requirement says "optional LLM factory callable."
- Exact test helper names and fixture shapes for each new test class.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase Requirements
- `.planning/REQUIREMENTS.md` §RUNNER-01–06 — acceptance criteria for all 6 requirements

### Primary Target
- `vulnhuntr/cli/runner.py` — the 714-line file being decomposed; read top-to-bottom before planning

### Already-Extracted Helpers (do NOT re-extract)
- `_generate_reports()` at `runner.py:529` — reports dispatch already extracted (RUNNER-04 is structurally done)
- `_export_all_reports()` at `runner.py:601` — export helper already exists
- `_create_github_issues()` at `runner.py:639` — GitHub dispatch already extracted (RUNNER-05 partially done)
- `_send_webhook()` at `runner.py:680` — webhook dispatch already extracted

### Existing Tests to Extend
- `tests/test_cli.py` — add new per-stage test classes here; `TestRunAnalysisIntegration` already exists
- `tests/conftest.py` — shared fixtures; check before creating new ones

### Architecture Context
- `.planning/codebase/ARCHITECTURE.md` — layer diagram and data flow
- `.planning/codebase/TESTING.md` — mocking patterns and test organization

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `initialize_llm()` at `runner.py:39` — already a standalone function; RUNNER-01 is mostly a rename/wrapper exercise
- `parse_fallback_spec()` at `runner.py:87` — already extracted
- `wrap_with_fallbacks()` at `runner.py:159` — already extracted
- `_generate_reports()` at `runner.py:529` — RUNNER-04 already done structurally; may just need a test class
- `_create_github_issues()` + `_send_webhook()` at `runner.py:639,680` — RUNNER-05 structurally done

### What Still Needs Extraction
- File collection logic at `runner.py:313–323` — inline in `run_analysis()`; needs `_collect_files(args, repo)` extraction
- The analysis loop at `runner.py:444–506` — the main `for py_f in files_to_analyze:` block; needs `_analyze_files()` extraction
- LLM init calls at `runner.py:391–392,418–419` — currently called twice inline; RUNNER-01 wraps these into `_init_providers()`

### Established Patterns
- Private stage functions prefixed with `_`; individual params (no shared dataclass)
- `unittest.mock.MagicMock` for LLM stubs; `tmp_path` for filesystem fixtures
- `from __future__ import annotations` at top of every source file
- `structlog` for all logging (`log = structlog.get_logger()`)

### Integration Points
- `run_analysis()` is the only public function called by `__main__.py` — its signature change (adding `llm_factory=None`) must remain backward-compatible
- `VulnerabilityAnalyzer` in `vulnhuntr/core/analysis.py` — `_analyze_files()` will call `analyzer.analyze_file()` per file

</code_context>

<specifics>
## Specific Ideas

- The LLM is initialized twice in `run_analysis()`: once without a system prompt (for README summarization) and once with one. `_init_providers()` should handle both, or the planner can decide how to structure this — it's flagged here so it's not missed.
- `_generate_reports()` and the integration dispatch functions are already extracted; RUNNER-04 and RUNNER-05 may only need test classes added, not code changes. Planner should verify before writing new extraction code.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 02-runner-decomposition*
*Context gathered: 2026-04-09*
