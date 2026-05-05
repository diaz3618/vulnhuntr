# Phase 2: Runner Decomposition - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-09
**Phase:** 02-runner-decomposition
**Areas discussed:** Stage interface shape, LLM factory injection (RUNNER-06), Checkpoint/resume in _collect_files(), Where new stage tests live

---

## Stage Interface Shape

| Option | Description | Selected |
|--------|-------------|----------|
| Individual params per stage | Each stage takes only the params it needs; run_analysis() threads values explicitly. Matches existing _generate_reports pattern. | ✓ |
| Shared RunContext dataclass | A dataclass holds all shared state; stages accept and return it. Less param threading, but shared mutable object. | |
| You decide per-stage | No uniform interface; shapes decided per-stage by the planner. | |

**User's choice:** "I have no idea, pick the best option based on research" → Claude's Discretion applied: individual params selected, matching the already-established `_generate_reports` pattern.

**Notes:** User deferred entirely to Claude. Individual params chosen for consistency with existing extracted helpers and clean testability.

---

## LLM Factory Injection (RUNNER-06)

| Option | Description | Selected |
|--------|-------------|----------|
| Optional callable, None = default | run_analysis(args, llm_factory=None) — None uses initialize_llm(). Tests pass a lambda. | ✓ |
| Protocol type annotation | Define LLMFactory Protocol for type safety. Adds abstraction. | |
| Keep patching, no new param | Tests continue using unittest.mock.patch on initialize_llm. No signature change. | |

**User's choice:** "Pick the best option based on research. Tell which one you recommend for future questions" → Claude's Discretion applied: optional callable selected. User also asked Claude to state recommendations explicitly going forward.

**Notes:** Optional callable matches RUNNER-06 requirement verbatim ("accepts optional LLM factory callable") and avoids adding a new Protocol type. Phase 1 integration test should be updated to use this param.

---

## Checkpoint/Resume in _collect_files()

| Option | Description | Selected |
|--------|-------------|----------|
| Collection pure, caller filters | _collect_files() returns full list; run_analysis() handles resume filtering after. | ✓ |
| _collect_files() owns filtering | Stage accepts checkpoint and returns already-filtered list. | |

**User's choice:** Collection pure, caller filters.

**Notes:** Keeps _collect_files() testable without an AnalysisCheckpoint dependency. Separation of concerns: collection vs. resume state management are different responsibilities.

---

## Where New Stage Tests Live

| Option | Description | Selected |
|--------|-------------|----------|
| New classes in test_cli.py | TestInitProviders, TestCollectFiles, TestAnalyzeFiles added to existing file. | ✓ |
| New test_runner.py file | Clean split, but requires moving TestRunAnalysisIntegration from Phase 1. | |
| Add to TestRunAnalysisIntegration | Simplest, but class loses focus. | |

**User's choice:** New classes in test_cli.py.

**Notes:** Consistent with Phase 1 approach. Does not require moving existing tests.

---

## Claude's Discretion

- Stage interface: individual params (user deferred)
- LLM factory: optional callable, None = default (user deferred, recommendation given)
- Exact param signatures per stage — planner decides
- Whether llm_factory covers wrap_with_fallbacks as well — planner decides

## Deferred Ideas

None raised during discussion.
