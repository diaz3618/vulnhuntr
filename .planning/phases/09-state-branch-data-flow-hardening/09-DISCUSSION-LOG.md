# Phase 09: Discussion Log

**Mode:** `--all --auto --analyze`
**Date:** 2025-07-17
**Facilitator:** GitHub Copilot (autonomous)

---

## Gray Areas Identified and Resolved

All four gray areas were auto-selected (--all) and auto-resolved with the
recommended option (--auto). Trade-off tables were logged per --analyze mode.

---

### Gray Area 1: State machine representation (EVAL-04)

**Options considered:**
1. Trace-event ordering assertions only
2. New `ProviderState` enum in production
3. Guard raises in existing production code

**Auto-selected:** Option 3 (with Option 1 as complement)

**Rationale:** Phase 9 is a hardening phase, not an architecture phase.
Adding a `ProviderState` FSM to production code is scope creep. The combined
approach — trace-event ordering assertions in tests + minimal guard raises in
`FallbackLLM.chat()` and session-mode builder — satisfies "fail loudly" without
redesigning the provider routing architecture.

**Decision captured:** D-01, D-02, D-04, D-05

---

### Gray Area 2: Data-flow test targets (EVAL-05)

**Options considered:**
1. All four data-flow paths (JSON repair, MCP injection, context_code, session ID)
2. Two highest-risk paths only (JSON repair + MCP injection)
3. One path per test class, all four

**Auto-selected:** Option 2

**Rationale:** `_validate_response()` repair chain and MCP tool result injection
are the highest-risk paths with the lowest existing coverage. The other two
paths (context_code propagation, session ID) already have moderate coverage from
Phase 8 and test_analysis.py. Focusing on the two highest-risk paths delivers
maximum EVAL-05 value without scope expansion.

**Decision captured:** D-06, D-07

---

### Gray Area 3: Production invariant enforcement depth (EVAL-06)

**Options considered:**
1. Test-only assertions
2. `assert` statements in production
3. `raise InvariantViolationError` (new exception type)

**Auto-selected:** Option 3

**Rationale:** `assert` statements can be disabled with `python -O`. The success
criteria for EVAL-06 require that invariant violations "fail loudly" — this means
they must fire in optimized mode too. A `RuntimeError` subclass (`InvariantViolationError`)
satisfies this and follows Python conventions for programming-error exceptions.

**Decision captured:** D-03

---

### Gray Area 4: Repeat-trial stability testing (EVAL-04 success criterion 4)

**Options considered:**
1. `@pytest.mark.repeat(3)` from pytest-repeat
2. Multiple parametrize IDs covering the same flow
3. Custom re-run fixture

**Auto-selected:** Option 1

**Rationale:** pytest-repeat is already listed in dev dependencies. The
`@pytest.mark.slow` gate ensures these tests don't slow down the default CI
run. Repeating the exact same test 3 times proves algorithmic stability
(given a determinized environment via monkeypatch), which is what the
success criterion calls for.

**Decision captured:** D-10

---

## No Blocking Antipatterns Found

- No SPEC.md found for Phase 9 (no spec-lock section needed)
- No existing `09-CONTEXT.md` or phase directory found (clean start)
- No cross-reference todos matched this phase's scope

## Prior Context Loaded

- Phase 8 CONTEXT.md: D-01 through D-14 all carried forward
- Phase 7 CONTEXT.md: D-01 (FallbackLLM._diagnostics) carried forward
- Phase 6 CONTEXT.md: session mode semantics (`stateless`/`continue`/`resume`)

## Auto-Advance

After writing this log and CONTEXT.md, the `--auto` flag triggers auto-advance
to `gsd-plan-phase 09`.
