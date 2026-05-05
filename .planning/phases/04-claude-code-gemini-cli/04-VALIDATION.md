---
phase: 4
slug: claude-code-gemini-cli
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-02
---

# Phase 4 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 7.x |
| **Config file** | `pyproject.toml` (existing) |
| **Quick run command** | `pytest tests/test_cli_providers.py -x -q` |
| **Full suite command** | `pytest -x -q -m "not live"` |
| **Estimated runtime** | ~10 seconds |

---

## Sampling Rate

- **After every task commit:** Run `pytest tests/test_cli_providers.py -x -q`
- **After every plan wave:** Run `pytest -x -q -m "not live"`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 04-01-01 | 01 | 1 | CLAUDECLI-01 | T-4-01 | `_STRIP_ENV_VARS` removes ANTHROPIC_API_KEY from subprocess env | unit | `pytest tests/test_cli_providers.py::test_claude_code_env_stripping -x -q` | ❌ W0 | ⬜ pending |
| 04-01-02 | 01 | 1 | CLAUDECLI-01 | — | `probe()` returns `CapabilityResult(ok=False)` when binary missing | unit | `pytest tests/test_cli_providers.py::test_claude_code_probe_missing_binary -x -q` | ❌ W0 | ⬜ pending |
| 04-01-03 | 01 | 1 | CLAUDECLI-01 | — | `chat()` raises `CLITimeoutError` on subprocess timeout | unit | `pytest tests/test_cli_providers.py::test_claude_code_timeout -x -q` | ❌ W0 | ⬜ pending |
| 04-01-04 | 01 | 1 | CLAUDECLI-01 | — | `chat()` raises `CLIParseError` on malformed JSON | unit | `pytest tests/test_cli_providers.py::test_claude_code_parse_error -x -q` | ❌ W0 | ⬜ pending |
| 04-01-05 | 01 | 1 | CLAUDECLI-01 | — | `chat()` returns validated `VulnhuntrResponse` on success | unit | `pytest tests/test_cli_providers.py::test_claude_code_success -x -q` | ❌ W0 | ⬜ pending |
| 04-02-01 | 02 | 1 | GEMINI-CLI-01 | T-4-02 | `_STRIP_ENV_VARS` removes GOOGLE_API_KEY, GEMINI_API_KEY, GOOGLE_GENAI_USE_VERTEXAI from subprocess env | unit | `pytest tests/test_cli_providers.py::test_gemini_cli_env_stripping -x -q` | ❌ W0 | ⬜ pending |
| 04-02-02 | 02 | 1 | GEMINI-CLI-01 | — | `probe()` returns `CapabilityResult(ok=False)` when version < 0.6.0 | unit | `pytest tests/test_cli_providers.py::test_gemini_cli_probe_version_too_old -x -q` | ❌ W0 | ⬜ pending |
| 04-02-03 | 02 | 1 | GEMINI-CLI-01 | — | `get_response()` reads from `payload["response"]` field | unit | `pytest tests/test_cli_providers.py::test_gemini_cli_get_response -x -q` | ❌ W0 | ⬜ pending |
| 04-02-04 | 02 | 1 | GEMINI-CLI-01 | — | `_extract_usage()` sums tokens across all `stats.models.*` entries | unit | `pytest tests/test_cli_providers.py::test_gemini_cli_extract_usage -x -q` | ❌ W0 | ⬜ pending |
| 04-02-05 | 02 | 1 | GEMINI-CLI-01 | — | `chat()` raises `CLITimeoutError` on subprocess timeout | unit | `pytest tests/test_cli_providers.py::test_gemini_cli_timeout -x -q` | ❌ W0 | ⬜ pending |
| 04-03-01 | 03 | 2 | CLAUDECLI-01 | — | `CLIPolicy.tool_mode` accepted and stored correctly | unit | `pytest tests/test_config.py::test_cli_policy_tool_mode -x -q` | ❌ W0 | ⬜ pending |
| 04-03-02 | 03 | 2 | CLAUDECLI-01 | — | `_init_providers()` instantiates `ClaudeCodeLLM` for `"claude-code"` | unit | `pytest tests/test_runner.py::test_init_providers_claude_code -x -q` | ❌ W0 | ⬜ pending |
| 04-03-03 | 03 | 2 | GEMINI-CLI-01 | — | `_init_providers()` instantiates `GeminiCLILLM` for `"gemini-cli"` | unit | `pytest tests/test_runner.py::test_init_providers_gemini_cli -x -q` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/test_cli_providers.py` — stub test file with all test functions for CLAUDECLI-01 and GEMINI-CLI-01
- [ ] `tests/conftest.py` — existing; verify `mock_subprocess` fixture is present or add it

*Existing pytest infrastructure covers all other Phase 4 requirements.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `--llm claude-code` runs full pipeline end-to-end | CLAUDECLI-01 | Requires installed `claude` binary with valid auth | `python -m vulnhuntr.cli.main --llm claude-code --path . --analyze vulnhuntr/config.py` |
| `--llm gemini-cli` runs full pipeline end-to-end | GEMINI-CLI-01 | Requires installed `gemini` binary with valid auth | `python -m vulnhuntr.cli.main --llm gemini-cli --path . --analyze vulnhuntr/config.py` |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
