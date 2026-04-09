# Phase 1: Quick Wins & Test Infrastructure - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

Fix 4 standalone, independent bugs/gaps: checkpoint version string, path traversal guard on `--analyze`, coverage threshold enforcement in CI, and an integration test for `run_analysis()` with a mocked LLM. No changes to the core analysis pipeline. No external behavior changes visible to end users.

</domain>

<decisions>
## Implementation Decisions

### INFRA-01: Checkpoint Version Fix
- **D-01:** Use `importlib.metadata.version("vulnhuntr")` in a `field(default_factory=...)` on `CheckpointData.vulnhuntr_version`. Avoids circular import since `importlib.metadata` is stdlib.

### INFRA-02: Path Traversal Guard
- **D-02:** Guard lives in `validate_args()` in `cli/parser.py` — policy validation belongs there, not in `normalize_args()` which is purely path math.
- **D-03:** Return an error string on failure — matches the existing `validate_args()` return contract (all other checks return a string or None).
- **D-04:** Containment check: resolve both paths, then use `Path.is_relative_to()` on the resolved `Path` objects. **Updated from original `str.startswith()` after research confirmed a false-positive: `/tmp/project-evil` incorrectly passes `str.startswith("/tmp/project")`. `is_relative_to()` uses parts-based comparison and is immune to this. Safe on Python 3.9+ (project requires >=3.10).**
- **D-05:** The check runs on the resolved analyze path vs the resolved root path. If `--analyze` is outside `--root`, return an error string describing the traversal violation.

### INFRA-03: Coverage Threshold
- **D-06:** Threshold value: `72` — matches REQUIREMENTS.md exactly; no rounding up.
- **D-07:** Add `--cov-fail-under=72` to BOTH `pyproject.toml` `[tool.pytest.ini_options]` `addopts` AND the GitHub Actions CI workflow step. Belt-and-suspenders enforcement.

### INFRA-04: Integration Test
- **D-08:** Test lives in `tests/test_cli.py`. Class: `TestRunAnalysisIntegration`.
- **D-09:** Stub the LLM by patching the LLM client (via `unittest.mock`). Call full `run_analysis(args)` — this is the most realistic approach and exercises the glue code.
- **D-10:** Target: a small Python fixture file written into `tmp_path`. Something minimal but realistic (e.g., a function with a path parameter) — not an existing vulnhuntr source file.
- **D-11:** Assertion: verify that a `Finding` (or `AnalysisResult`) is produced — not just exit code 0. The mocked LLM returns a canned `Response` with at least one finding.

### Claude's Discretion
- Exact `Response` fixture shape for the canned LLM stub (confidence level, vuln type, etc.) — follow existing test patterns in `tests/conftest.py` and `test_analysis.py`.
- Whether to add the coverage flag to the existing `addopts` string or as a separate list entry in pyproject.toml.
- Exact error message text for the path traversal violation.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase Requirements
- `.planning/REQUIREMENTS.md` §INFRA-01–04 — acceptance criteria for all 4 tasks

### Existing Code to Modify
- `vulnhuntr/checkpoint.py` — `CheckpointData.vulnhuntr_version` field (line ~40)
- `vulnhuntr/cli/parser.py` — `validate_args()` (line ~172), `normalize_args()` (line ~224)
- `pyproject.toml` — `[tool.pytest.ini_options]` `addopts`
- `tests/test_cli.py` — add `TestRunAnalysisIntegration` class

### Existing Tests to Not Break
- `tests/test_checkpoint.py` — tests `CheckpointData`; version fix must not break deserialization
- `tests/test_cli.py` — all existing `TestValidateArgs` and `TestNormalizeArgs` tests must continue to pass

### CI Workflow
- `.github/workflows/` — locate the pytest step to add `--cov-fail-under=72`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `validate_args()` already returns `str | None` for all other validation failures — follow this exact pattern for the path traversal check
- `normalize_args()` already calls `Path(args.root).resolve()` and `(Path(args.root) / analyze_path).resolve()` — the resolved values are available; guard just needs to compare them
- `conftest.py` and existing fixture patterns in test files for mocking LLM clients

### Established Patterns
- `CheckpointData` uses `dataclass` with `field(default_factory=...)` — use the same pattern for the version factory
- `unittest.mock.patch` is already imported in `test_cli.py` and used throughout
- `tmp_path` pytest fixture is used in `test_cli.py` for all path-dependent tests

### Integration Points
- `run_analysis()` in `cli/runner.py` at line ~235 — the integration test calls this directly
- `VulnerabilityAnalyzer` in `core/analysis.py` — its `llm` attribute is where the mock needs to be injected
- GitHub Actions workflow step for pytest — needs `--cov-fail-under=72` added

</code_context>

<specifics>
## Specific Ideas

- The path traversal error string should make the problem obvious: something like `"--analyze path must be within --root: {path} is outside {root}"`.
- The integration test fixture file should be realistic enough to exercise the LFI or RCE detection path — a Python function that opens a file based on user input is sufficient.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 01-quick-wins-test-infrastructure*
*Context gathered: 2026-04-08*
