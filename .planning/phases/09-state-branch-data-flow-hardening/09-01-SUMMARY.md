# Plan 09-01 Summary: InvariantViolationError and Production Guards

## Outcome

All three tasks completed successfully. Production guards and the new error class are live.

## What Was Built

- **`InvariantViolationError(RuntimeError)`** added to `vulnhuntr/core/trace.py` with `.invariant` (machine-readable key) and `.actual_value` (observed bad value) attributes.
- Re-exported from `vulnhuntr/core/__init__.py` alongside `ExecutionTracer` in a new `# Observability` section.
- **`active_in_registry` guard** in `FallbackLLM.chat()` — raises `InvariantViolationError` immediately when `self._active not in self._all_llms`.
- **`session_mode_is_known` guard** in `ClaudeCodeLLM.send_message()` — raises `InvariantViolationError` for any `session_mode` outside `{"stateless", "continue", "resume"}`.

## Verification

```
grep -c "class InvariantViolationError" vulnhuntr/core/trace.py  → 1
grep -c "active_in_registry" vulnhuntr/llms.py                   → 1
grep -c "session_mode_is_known" vulnhuntr/cli_providers/claude_code.py → 1
python -m pytest tests/test_behavior.py tests/test_cli_providers.py -x -q → 164 passed
```

## Commit

`e944133` feat(core): add InvariantViolationError and production guards (09-01)
