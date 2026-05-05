# Phase 1: Quick Wins & Test Infrastructure - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-08
**Phase:** 01-quick-wins-test-infrastructure
**Areas discussed:** Path traversal guard placement, Integration test design, Coverage threshold strategy

---

## Path Traversal Guard Placement

| Option | Description | Selected |
|--------|-------------|----------|
| In validate_args() | Policy validation belongs there; normalize_args() is purely path math | ✓ |
| In normalize_args() | Co-locate with path resolution; fewer code locations | |
| In run_analysis() | Last line of defense; keeps parser.py untouched | |

**User's choice:** `validate_args()` — policy belongs there

---

| Option | Description | Selected |
|--------|-------------|----------|
| Return error string | Matches existing validate_args() return contract | ✓ |
| Raise ValueError | More explicit but breaks the string-return contract | |
| parser.error() | Argparse-style exit; terminates immediately | |

**User's choice:** Return error string — matches existing pattern

---

| Option | Description | Selected |
|--------|-------------|----------|
| str.startswith on resolved paths | Simple and explicit | ✓ |
| Path.relative_to() | Raises ValueError if outside — Pythonic but raises | |
| Claude's discretion | Either approach is fine | |

**User's choice:** `str.startswith()` on resolved paths

---

## Integration Test Design

| Option | Description | Selected |
|--------|-------------|----------|
| Full run_analysis() with mocked LLM client | Most realistic; exercises glue code | ✓ |
| Stub VulnerabilityAnalyzer.analyze_file() | Simpler but tests less | |
| llm_factory injection (INFRA-04 + RUNNER-06 combined) | Cleanest but requires adding param in this phase | |

**User's choice:** Full `run_analysis()` with mocked LLM client

---

| Option | Description | Selected |
|--------|-------------|----------|
| Small fixture file in tmp_path | Minimal but realistic | ✓ |
| Point at existing source file | No fixture needed but ties test to internals | |
| Dry-run mode only | Fastest but barely tests analysis loop | |

**User's choice:** Small fixture file in `tmp_path`

---

| Option | Description | Selected |
|--------|-------------|----------|
| Assert exit code 0 | Minimal but clear | |
| Assert a finding is produced | Validates output shape | ✓ |
| Both | Assert exit code 0 AND result list non-empty | |

**User's choice:** Assert a finding is produced

---

## Coverage Threshold Strategy

| Option | Description | Selected |
|--------|-------------|----------|
| 72 — match requirement exactly | Documents intent; matches REQUIREMENTS.md | ✓ |
| 75 — small buffer | Reduces flakiness from test refactors | |
| 80 — push higher | Aspirational | |

**User's choice:** 72 — match the requirement exactly

---

| Option | Description | Selected |
|--------|-------------|----------|
| pyproject.toml addopts only | Single source of truth | |
| pyproject.toml + CI workflow | Belt-and-suspenders enforcement | ✓ |
| CI workflow only | Keeps pyproject.toml clean | |

**User's choice:** Both `pyproject.toml` and the CI workflow

---

## Claude's Discretion

- Exact `Response` fixture shape for the canned LLM stub
- Whether to add the coverage flag inline to `addopts` string or as a separate list entry
- Exact error message text for the path traversal violation

## Deferred Ideas

None — discussion stayed within phase scope.
