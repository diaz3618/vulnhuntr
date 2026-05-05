# Phase 8: Behavioral Evaluation & Trace Capture - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-04
**Phase:** 08-behavioral-evaluation-trace-capture
**Mode:** `--all --analyze --auto` (fully autonomous; all gray areas; trade-off analysis)
**Areas discussed:** Trace Event Model, Trace Emission Points, Trace Storage & Access, Behavior Test Targets, Boundary Test Strategy, Test File Organization

---

## Trace Event Model

| Option | Description | Selected |
|--------|-------------|----------|
| `TraceEvent` dataclass + `ExecutionTracer` | Typed, testable without log capture; follows `CapabilityResult` pattern | ✓ |
| Structured structlog only | Zero new types; log stream is the trace | |
| Python `logging.Handler` subclass | Standard stdlib | |

**Auto-selected:** `TraceEvent` dataclass + `ExecutionTracer` container
**Rationale:** EVAL-01 requires programmatic inspection of trace events in tests. structlog-only approach forces log-capture assertions, which are fragile. Follows the `CapabilityResult` and `FallbackLLM._diagnostics` patterns already in the codebase.

---

## Trace Emission Points

| Option | Description | Selected |
|--------|-------------|----------|
| Provider boundaries only (probe + send_message) | Minimal surface | |
| All five EVAL-01 event types (probe, validated, tool, fallback, session) | Full coverage per spec | ✓ |
| Failure paths only | Easy to add | |

**Auto-selected:** All five EVAL-01 event types
**Rationale:** The requirement explicitly names probe results, response validation, tool calls, fallback decisions, and session decisions. Partial emission would leave EVAL-01 partially unmet.

---

## Trace Storage & Access

| Option | Description | Selected |
|--------|-------------|----------|
| In-memory on `ExecutionTracer`, returned from `run_analysis()` | Simple; no I/O; fully testable | ✓ |
| Write to `.vulnhuntr-trace.jsonl` per run | Persisted; inspectable offline | |
| Attach to `CheckpointData` | Unified persistence | |

**Auto-selected:** In-memory only; `run_analysis()` returns `(results, tracer)`
**Rationale:** File I/O and checkpoint integration are out-of-scope for Phase 8. Keeping the tracer in-memory makes it trivially testable without filesystem setup. File output deferred to Phase 10.

---

## Behavior Test Targets

| Flow | Description | Selected |
|------|-------------|----------|
| Probe → send_message → trace emitted | Primary happy path | ✓ |
| Fallback chain: CLI fails → API succeeds | Verifies fallback + trace integration | ✓ |
| Session mode "resume" with stored session_id | Verifies session_decision event | ✓ |
| Response validation failure | Verifies valid=False trace event | ✓ |
| MCP tool call flow | Already covered in Phase 7 D-21/D-22 | (excluded, no duplication) |

**Auto-selected:** All four flows (MCP excluded as Phase 7 already covers it)
**Rationale:** The four flows cover the distinct trace event types and represent the highest-risk behavioral assumptions not yet under test.

---

## Boundary Test Strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Implicit coverage | Write tests until it feels covered | |
| Explicit partition tables in test docstrings + `@pytest.mark.parametrize` | Reviewable; aligns with EVAL-03 wording | ✓ |
| External boundary matrix doc | Shareable but over-engineered | |

**Auto-selected:** Explicit partition tables + `@pytest.mark.parametrize` with `id=` on every case
**Rationale:** EVAL-03 specifically says "equivalence-partition and boundary-focused tests." Making the partition table explicit in the docstring makes the coverage auditable.

---

## Test File Organization

| Option | Description | Selected |
|--------|-------------|----------|
| Single new `tests/test_evaluation.py` | One file for everything | |
| `test_trace.py` + `test_behavior.py` + extend existing files | Clear responsibility per file | ✓ |
| Extend existing test files only | No new files | |

**Auto-selected:** Two new files (`test_trace.py`, `test_behavior.py`) + extend `test_config.py` + `test_cli_providers.py`
**Rationale:** Trace unit tests and behavioral integration tests have different setup needs; keeping them in separate files avoids a large mixed-concern test file.

---

## Agent's Discretion

- How to emit `probe_result` cleanly from the base class without requiring every subclass to call `super()` — researcher proposes; planner decides.
- Whether `run_analysis()` returns a plain `tuple` or a named return type — planner decides based on downstream impact.
- Whether invalid `CLIPolicy` field values raise `ValueError` or emit a structlog warning — researcher confirms from current config loader code.

## Deferred Ideas

- `--trace-output <file>` CLI flag for persisting traces → Phase 10
- `CheckpointData.trace` field for resumed-scan trace continuity → Phase 10
- Thread-safe `ExecutionTracer` for parallel provider execution → Phase 9 or later if needed
