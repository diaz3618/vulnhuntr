# Phase 1: Quick Wins & Test Infrastructure — Validation Architecture

**Source:** Extracted from `01-RESEARCH.md` §Validation Architecture (lines 457–485)
**Phase:** 01-quick-wins-test-infrastructure
**Generated:** 2026-04-09

---

## Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest 9.0.2 |
| Config file | `pyproject.toml` `[tool.pytest.ini_options]` |
| Quick run command | `pytest tests/test_cli.py tests/test_checkpoint.py -x -q` |
| Full suite command | `pytest tests/ --cov=vulnhuntr --cov-report=term --cov-fail-under=72` |

---

## Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| INFRA-01 | `CheckpointData()` records actual package version (not `"0.1.0"`) | unit | `pytest tests/test_checkpoint.py::TestCheckpointData -x` | ✅ (extend existing) |
| INFRA-02 | `validate_args()` rejects `--analyze` outside `--root` | unit | `pytest tests/test_cli.py::TestValidateArgs -x` | ✅ (extend existing) |
| INFRA-03 | `--cov-fail-under=72` present in addopts and CI | config/smoke | `pytest tests/ --cov=vulnhuntr --cov-fail-under=72 -q` | ✅ (no new file) |
| INFRA-04 | `run_analysis()` with mocked LLM produces a Finding (not just exit code 0) | integration | `pytest tests/test_cli.py::TestRunAnalysisIntegration -x` | ❌ Wave 0 — created in Plan 01-02 |

---

## Sampling Rate

| Gate | Command |
|------|---------|
| Per task commit | `pytest tests/test_cli.py tests/test_checkpoint.py -x -q` |
| Per wave merge | `pytest tests/ --cov=vulnhuntr --cov-report=term --cov-fail-under=72` |
| Phase gate | Full suite (`pytest tests/ -m "not live"`) green before `/gsd-verify-work` |

---

## Wave 0 Gaps

- [ ] `TestRunAnalysisIntegration` class in `tests/test_cli.py` — covers INFRA-04
      (Plan 01-02, Task 2: must assert JSON report with >= 1 Finding, confidence_score >= 1)
- [ ] New test methods in `TestCheckpointData` to assert version is not `"0.1.0"` — covers INFRA-01
      (Plan 01-01, Task 1: test_version_is_not_hardcoded_literal, test_from_dict_missing_version_falls_back)
- [ ] New test methods in `TestValidateArgs` for traversal accept/reject cases — covers INFRA-02
      (Plan 01-02, Task 1: test_analyze_inside_root, test_analyze_outside_root)

*(INFRA-03 has no test gap — it's a config flag, verified by running the full suite)*

---

## D-11 Assertion Contract

**Locked decision:** D-11 states "verify that a Finding (or AnalysisResult) is produced — not just exit code 0."

**How satisfied:** `test_run_analysis_produces_finding` in `TestRunAnalysisIntegration`:
1. Passes `json=str(tmp_path / "report.json")` in the args Namespace so the runner writes a machine-readable JSON report.
2. Reads the written file after `run_analysis()` returns.
3. Asserts `len(findings) >= 1` and `findings[0]["confidence_score"] >= 1`.

The mock_llm fixture (conftest.py) returns a Response with `VulnType.SQLI`, `confidence_score=8` — the JSON report will contain that finding.

---

## Security Domain

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V5 Input Validation | **Yes (INFRA-02)** | `Path.is_relative_to()` — stdlib, no hand-rolling |
| V2 Authentication | No | — |
| V3 Session Management | No | — |
| V4 Access Control | No | — |
| V6 Cryptography | No | — |

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Path traversal via `--analyze` | Tampering / Elevation | Containment check in `validate_args()` using `Path.is_relative_to()` |
