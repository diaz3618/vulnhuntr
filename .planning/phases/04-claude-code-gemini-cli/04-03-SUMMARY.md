---
phase: 04-claude-code-gemini-cli
plan: "03"
subsystem: runner-wiring
tags: [runner, initialize_llm, cli-providers, tdd, test-coverage]
dependency_graph:
  requires:
    - "04-01: ClaudeCodeLLM adapter"
    - "04-02: GeminiCLILLM adapter"
  provides:
    - "initialize_llm: config parameter, ClaudeCodeLLM/GeminiCLILLM dispatch"
    - "TestClaudeCodeLLM: consolidated test class"
    - "TestGeminiCLILLM: test_send_message_binary_not_found added"
    - "Live round-trip tests for both providers"
  affects:
    - "vulnhuntr/cli/runner.py: initialize_llm signature, _init_providers call site"
    - "tests/test_cli_providers.py: new test classes appended"
    - "tests/test_runner.py: new test file"
    - "tests/test_cli.py: updated assertions for new behavior"
tech_stack:
  added: []
  patterns:
    - "CLIPolicy.overrides.get(llm_arg) for per-provider timeout/workdir overrides"
    - "getattr(config, 'cli', None) or CLIPolicy() — safe default when config is None"
    - "Inline imports inside elif branch to avoid circular import at module load"
decisions:
  - "config=None safe default: getattr(config, 'cli', None) or CLIPolicy() handles None gracefully"
  - "Codex/qwen-code kept as NotImplementedError stubs with 'lands in Phase 5' message"
  - "TDD RED for Task 1 was genuine (TypeError on missing config param); Task 2 RED was structural (class TestClaudeCodeLLM not yet in file)"
  - "Split test classes from Phase 3 (TestClaudeCodeLLMImport, etc.) retained alongside new consolidated TestClaudeCodeLLM"
key_files:
  created:
    - tests/test_runner.py
  modified:
    - vulnhuntr/cli/runner.py
    - tests/test_cli_providers.py
    - tests/test_cli.py
metrics:
  duration: "~6 minutes"
  completed: "2026-05-03"
  tasks_completed: 2
  files_changed: 4
requirements_satisfied:
  - CLAUDECLI-01
  - GEMINI-CLI-01
---

# Phase 04 Plan 03: Runner Wiring and Comprehensive CLI Provider Tests Summary

**One-liner:** Wire ClaudeCodeLLM and GeminiCLILLM into initialize_llm() with CLIPolicy config injection, and add consolidated test classes plus live round-trip stubs.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 RED | test(04-03): failing tests for initialize_llm wiring | a516dc2 | tests/test_runner.py |
| 1 GREEN | feat(04-03): wire ClaudeCodeLLM and GeminiCLILLM into initialize_llm() | 1cc8abc | vulnhuntr/cli/runner.py |
| 2 GREEN | feat(04-03): add TestClaudeCodeLLM and TestGeminiCLILLM test classes | c746e56 | tests/test_cli_providers.py, tests/test_cli.py |

## What Was Built

### Task 1: initialize_llm() CLI Provider Wiring (1cc8abc)

Three targeted changes to `vulnhuntr/cli/runner.py`:

**CHANGE 1 — New `config` parameter:**
```python
def initialize_llm(
    llm_arg: str,
    system_prompt: str = "",
    cost_callback: Callable | None = None,
    model_override: str | None = None,
    config: Any | None = None,      # <-- new
):
```

**CHANGE 2 — Replace NotImplementedError stub with real dispatch:**
- `policy = getattr(config, "cli", None) or CLIPolicy()` — safe default when config is None
- `overrides = policy.overrides.get(llm_arg, {})` — per-provider timeout/workdir overrides
- Returns `ClaudeCodeLLM(...)` for `"claude-code"`, `GeminiCLILLM(...)` for `"gemini-cli"`
- `codex` and `qwen-code` raise `NotImplementedError("...lands in Phase 5.")`

**CHANGE 3 — Update call site in `_init_providers()`:**
```python
llm = initialize_llm(args.llm, system_prompt, cost_callback, model_override=config.model, config=config)
```

### Task 2: Consolidated Test Classes (c746e56)

**`tests/test_runner.py`** (new file) — 8 tests in `TestInitializeLlmCliProviders`:
- TDD RED tests covering all six behaviors before runner.py was updated
- All 8 pass after GREEN implementation

**`tests/test_cli_providers.py`** (extended):
- Added `import os` to imports
- Added `_CLAUDE_SUCCESS_JSON` and `_GEMINI_SUCCESS_JSON` payload constants
- Added `class TestClaudeCodeLLM` (11 tests): probe ok/missing, send_message success/timeout/bad json/empty stdout, get_response extract/missing, _extract_usage cache sum, env stripping, binary not found
- Added `test_send_message_binary_not_found` to existing `TestGeminiCLILLM`
- Added `test_claude_code_live_round_trip` and `test_gemini_cli_live_round_trip` module-level `@pytest.mark.live` tests (excluded from CI)

**`tests/test_cli.py`** (bug fixes per Rule 1):
- `TestInitializeLLMCLIStubs`: updated `test_claude_code_raises_not_implemented` and `test_gemini_cli_raises_not_implemented` to expect `ClaudeCodeLLM`/`GeminiCLILLM` instances instead of `NotImplementedError`
- `TestInitProviders`: added `config=config` to all three `assert_called_once_with` assertions

## TDD Gate Compliance

**Task 1:**
- RED gate: `a516dc2` — `tests/test_runner.py` with 8 failing tests (TypeError on missing `config` param)
- GREEN gate: `1cc8abc` — implementation making all 8 tests pass

**Task 2:**
- RED gate: Structural — `class TestClaudeCodeLLM` did not exist before this commit; `test_send_message_binary_not_found` was absent from `TestGeminiCLILLM`
- GREEN gate: `c746e56` — added consolidated test classes, all 83 non-live tests pass

Note: Task 2 implementations (ClaudeCodeLLM, GeminiCLILLM) were completed in Plans 04-01 and 04-02 respectively. Task 2 of this plan is a test-coverage addition to already-implemented providers, not a new implementation. The TDD cycle was genuine for Task 1 and structural for Task 2.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Updated test_cli.py to match new runner.py behavior**
- **Found during:** Task 2 full suite run
- **Issue:** `TestInitializeLLMCLIStubs.test_claude_code_raises_not_implemented` and `test_gemini_cli_raises_not_implemented` expected `NotImplementedError` but providers are now implemented. `TestInitProviders` assertions expected `initialize_llm()` called without `config=` keyword.
- **Fix:** Updated `TestInitializeLLMCLIStubs` to verify correct return types; added `config=config` to `TestInitProviders` call assertions.
- **Files modified:** `tests/test_cli.py`
- **Commit:** c746e56

## Test Coverage Summary

| File | Tests | Status |
|------|-------|--------|
| tests/test_runner.py | 8 | all passing |
| tests/test_cli_providers.py (new in this plan) | +13 mocked + 2 live | all passing |
| tests/test_cli.py | 5 updated | all passing |
| Full suite (non-checkpoint) | 762 | all passing |
| Coverage | 78% | exceeds 72% threshold |

## Known Stubs

None — both `ClaudeCodeLLM` and `GeminiCLILLM` are fully implemented. `codex` and `qwen-code` intentionally remain NotImplementedError stubs until Phase 5.

## Threat Model Coverage

All T-4-xx mitigations from the plan's threat register are enforced:

| Threat | Mitigation Status |
|--------|------------------|
| T-4-01 Tampering (provider dispatch) | `llm_arg.lower()` applied before matching; unknown values raise `ValueError` not arbitrary execution |
| T-4-02 Info Disclosure (config.cli passthrough) | CLIPolicy.strip_env_vars applied in `_build_env()` at subprocess time |
| T-4-03 EoP (tool_mode propagation) | `tool_mode` mapped to safe defaults; unrecognized values handled by CLIPolicy defaults |
| T-4-04 Test mock isolation | All new tests patch `subprocess.run` — no real binary invocation in CI |
| T-4-05 Remaining stubs | `codex`/`qwen-code` raise `NotImplementedError("...lands in Phase 5.")` |

## Threat Flags

None — no new network endpoints, auth paths, or schema changes beyond the plan's documented threat model.

## Self-Check

### Files Exist
- vulnhuntr/cli/runner.py: FOUND (modified)
- tests/test_cli_providers.py: FOUND (extended)
- tests/test_runner.py: FOUND (created)
- tests/test_cli.py: FOUND (updated)

### Commits Exist
- a516dc2: FOUND (test(04-03): add failing tests for initialize_llm CLI provider wiring)
- 1cc8abc: FOUND (feat(04-03): wire ClaudeCodeLLM and GeminiCLILLM into initialize_llm())
- c746e56: FOUND (feat(04-03): add TestClaudeCodeLLM and TestGeminiCLILLM test classes)

### Tests Pass
- 83/83 tests/test_cli_providers.py passed (non-live)
- 8/8 tests/test_runner.py passed
- 762/762 full suite (excluding pre-existing test_checkpoint.py failures) passed
- Coverage: 78% (threshold: 72%)

## Self-Check: PASSED
