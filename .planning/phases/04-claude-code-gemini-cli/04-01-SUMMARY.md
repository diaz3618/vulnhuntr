---
phase: 04-claude-code-gemini-cli
plan: "01"
subsystem: cli-providers
tags: [claude-code, cli-adapter, subprocess, auth, env-stripping]
dependency_graph:
  requires: [03-03]
  provides: [ClaudeCodeLLM, CLIPolicy.tool_mode, CLIPolicy.strip_env_vars]
  affects: [vulnhuntr/cli_providers, vulnhuntr/config.py]
tech_stack:
  added: [structlog, shutil.which, subprocess list-form, json.loads]
  patterns: [CLIProviderLLM subclass, _STRIP_ENV_VARS class var, CapabilityResult probe, policy injection]
key_files:
  created:
    - vulnhuntr/cli_providers/claude_code.py
  modified:
    - vulnhuntr/cli_providers/__init__.py
    - vulnhuntr/config.py
    - tests/test_cli_providers.py
    - tests/test_config.py
decisions:
  - "ClaudeCodeLLM does NOT override chat() — base CLIProviderLLM.chat() owns the full subprocess+validation pipeline (D-01)"
  - "ANTHROPIC_API_KEY stripped via _STRIP_ENV_VARS to force CLI-native OAuth instead of API key auth (T-4-02)"
  - "auth_valid always returns None from probe() — OAuth auth can only be verified at first real call (D-04)"
  - "tool_mode='none' default passes --tools '' to disable built-in tools even in bypassPermissions mode (T-4-05)"
  - "strip_env_vars validated as list in from_dict() — non-list values silently ignored"
metrics:
  duration: "~10 minutes"
  completed: "2026-05-03"
  tasks_completed: 2
  files_changed: 5
---

# Phase 04 Plan 01: ClaudeCodeLLM Adapter and CLIPolicy Extension Summary

ClaudeCodeLLM production subclass with OAuth-safe env stripping, JSON envelope parsing, and CLIPolicy tool_mode/strip_env_vars fields.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Extend CLIPolicy with tool_mode and strip_env_vars | 08b771c | vulnhuntr/config.py |
| 2 | Implement ClaudeCodeLLM adapter | 9b81d9d | vulnhuntr/cli_providers/claude_code.py, vulnhuntr/cli_providers/__init__.py |

## What Was Built

### Task 1: CLIPolicy Extension (08b771c)

Two new fields added to `CLIPolicy` dataclass:
- `tool_mode: str = "none"` — controls whether Claude Code built-in tools are enabled
- `strip_env_vars: list[str] = field(default_factory=list)` — operator-supplied env vars to strip before subprocess spawn

`from_dict()` parsing added for both fields. `to_dict()` includes them automatically via `dataclasses.asdict()`. Validation: `strip_env_vars` is ignored when not a list (safe default).

### Task 2: ClaudeCodeLLM Adapter (9b81d9d)

`vulnhuntr/cli_providers/claude_code.py` — 186 lines implementing:

- `_STRIP_ENV_VARS = ("ANTHROPIC_API_KEY",)` — strips API key before every subprocess spawn (T-4-02 mitigation)
- `probe()` — checks `shutil.which("claude")`, captures semver from `--version` output, returns `auth_valid=None` (OAuth not statically checkable)
- `send_message()` — builds list-form CLI command with `--output-format json`, `--permission-mode bypassPermissions`, `--no-session-persistence`; applies `tool_mode` policy; raises `CLIParseError` on empty stdout or JSON parse failure
- `get_response()` — extracts `payload["result"]`, raises `CLIParseError` if absent
- `_extract_usage()` — sums `input_tokens + cache_creation_input_tokens + cache_read_input_tokens`; output_tokens separate
- `_build_env()` — calls `super()._build_env()` first, then strips additional `CLIPolicy.strip_env_vars`

`vulnhuntr/cli_providers/__init__.py` updated with import and `__all__` entry.

## TDD Gate Compliance

Both tasks followed RED/GREEN cycle:

- Task 1 RED: `7c9d7b7` — 7 failing tests for CLIPolicy fields
- Task 1 GREEN: `08b771c` — implementation making all 64 config tests pass
- Task 2 RED: `47fe934` — failing tests for ClaudeCodeLLM (import, probe, send_message, get_response, _extract_usage, _build_env)
- Task 2 GREEN: `9b81d9d` — implementation making all 48 cli_providers tests pass

## Deviations from Plan

None — plan executed exactly as written.

## Threat Model Coverage

All T-4-xx mitigations from the plan's threat register are implemented:

| Threat | Mitigation Implemented |
|--------|------------------------|
| T-4-01 Tampering (prompt injection) | `cmd = ["claude", "-p", user_prompt, ...]` list-form, `shell=False` in base `_run_subprocess()` |
| T-4-02 Info Disclosure (API key) | `_STRIP_ENV_VARS = ("ANTHROPIC_API_KEY",)` + `_build_env()` override for CLIPolicy.strip_env_vars |
| T-4-03 EoP (PATH) | Accepted — documented as OS-level threat outside Vulnhuntr's boundary |
| T-4-04 Tampering (JSON parse) | `json.loads()` in `try/except`; empty-stdout guard before parse; `CLIParseError` with `stdout[:500]` |
| T-4-05 EoP (bypassPermissions) | `tool_mode="none"` default passes `--tools ""` to disable Claude Code built-in tools |

## Known Stubs

None — all methods are fully implemented with real logic.

## Self-Check

### Files Exist
- vulnhuntr/cli_providers/claude_code.py: FOUND
- vulnhuntr/cli_providers/__init__.py: FOUND (modified)
- vulnhuntr/config.py: FOUND (modified)

### Commits Exist
- 7c9d7b7: FOUND (test(04-01): add failing tests for CLIPolicy fields)
- 08b771c: FOUND (feat(04-01): extend CLIPolicy)
- 47fe934: FOUND (test(04-01): add failing tests for ClaudeCodeLLM)
- 9b81d9d: FOUND (feat(04-01): implement ClaudeCodeLLM adapter)

### Tests Pass
- 48/48 tests/test_cli_providers.py passed
- 64/64 tests/test_config.py passed

## Self-Check: PASSED
