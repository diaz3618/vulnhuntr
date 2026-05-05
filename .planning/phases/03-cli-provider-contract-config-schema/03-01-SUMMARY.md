# Plan 03-01 Summary: CLIProviderLLM Base Class, CapabilityResult, CLI*Error Classes

**Status:** Complete
**Completed:** 2026-05-02
**Requirements closed:** AICLI-01, AICLI-02, AICLI-03, AICLI-04

---

## What Was Built

### `vulnhuntr/cli_providers/__init__.py`
Package re-export of all public symbols: `CLIProviderLLM`, `CapabilityResult`, and the six `CLI*Error` classes. Defines `__all__` for clean star-import behavior.

### `vulnhuntr/cli_providers/base.py`
- **`CLIProviderLLM(LLM, ABC)`** — abstract intermediate base class. Inherits all of `LLM`'s history, cost tracking, and validation machinery. Adds:
  - `_run_subprocess(cmd, input_text)` — list-form `subprocess.run()`, `shell=False`, `stdin=DEVNULL` by default, timeout enforcement, env-stripping via `_STRIP_ENV_VARS`
  - `_build_env()` — copies `os.environ` and strips provider-specific secrets
  - `chat()` override — calls `send_message()` → `_log_response()` → `get_response()` → `_validate_response()` → history
  - Abstract methods: `probe()`, `get_response()`, `_extract_usage()` (inherited abstract from `LLM`)
- **`CapabilityResult`** — dataclass with exactly 5 fields: `ok`, `binary_found`, `version`, `auth_valid`, `diagnostic_message`
- **Six `CLI*Error` subclasses** of `LLMError`: `CLIBinaryNotFoundError`, `CLIAuthError`, `CLITimeoutError`, `CLIParseError`, `CLISandboxError`, `CLIRuntimeError`

### `tests/test_cli_providers.py`
33 tests across 6 test classes:
- `TestInheritance` — issubclass checks, instantiation
- `TestErrorTaxonomy` — all 6 error classes are `LLMError` subclasses; parametrized
- `TestPackageExports` — importability, `__all__` presence
- `TestCapabilityResult` — exactly 5 fields, field types, probe() return type
- `TestProbeAbstract` — cannot instantiate without implementing `probe()`
- `TestSubprocessDispatch` — list-form cmd, `shell=False`, `stdin=DEVNULL`, pipe mode, `FileNotFoundError` → `CLIBinaryNotFoundError`, timeout → `CLITimeoutError`, non-zero exit → `CLIRuntimeError`, env stripping
- `TestChatCostTracking` — `_log_response()` called, history updated, cost callback fires, `create_messages()` raises `NotImplementedError`

**Result:** 33/33 passed.

---

## Key Decisions Made

- Used `CLIProviderLLM(LLM, ABC)` (not just `LLM`) so `@abstractmethod` enforcement works correctly in Python's MRO
- `chat()` fully overrides `LLM.chat()` — CLI providers don't use `create_messages()`/`send_message()` in the HTTP sense; `send_message()` is repurposed as the subprocess dispatch hook
- `_STRIP_ENV_VARS` is a class-level tuple so subclasses can extend it without overriding `_build_env()`
- `stdin=subprocess.DEVNULL` is the default; `subprocess.PIPE` is used only when `input_text` is provided

---

## Files Modified

- `vulnhuntr/cli_providers/__init__.py` (new)
- `vulnhuntr/cli_providers/base.py` (new, 175 lines)
- `tests/test_cli_providers.py` (new, 280 lines)
