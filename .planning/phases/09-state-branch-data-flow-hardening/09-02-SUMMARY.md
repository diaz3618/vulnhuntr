# Summary: Plan 09-02

**Plan**: 09-02 — Create tests/test_state_transitions.py  
**Phase**: 9 — State, Branch, and Data-Flow Hardening  
**Wave**: 2  
**Status**: COMPLETE  

## What Was Done

Created `tests/test_state_transitions.py` with three test classes covering `FallbackLLM` state transitions and runtime invariant guards:

- **TestFallbackTransitions** (6 tests) — verifies that `FallbackLLM._active` progresses through primary → fallback0 → fallback1 on successive failures, and stays on the active provider after successful fallback
- **TestFallbackInvariants** (5 tests) — verifies that `InvariantViolationError` is raised when `_active` is not in `_all_llms`, and that the error carries the correct `invariant` key and `actual_value`
- **TestSessionModeInvariants** (6 tests) — verifies that `InvariantViolationError` is raised for unrecognized `session_mode` values, and that `stateless`/`continue` pass without error

## Test Counts

17 tests, all passing (0 skipped, 0 errors).

## Key Decisions

- Used `class RogueLLM: pass` (a real class) rather than a `MagicMock` with `__class__` reassignment, because `type(obj).__name__` ignores the `__class__` attribute on MagicMock instances.
- Used `object.__setattr__(policy, "session_mode", bad_value)` to bypass `CLIPolicy.__post_init__` validation when constructing test fixtures with invalid `session_mode`.

## Commit

`201d710` — `test(core): add state-transition and invariant tests (09-02, 09-03)`

## Requirements Covered

- EVAL-04: State-transition tests for FallbackLLM routing
- EVAL-06: Runtime invariant guards (active_in_registry, session_mode_is_known)
