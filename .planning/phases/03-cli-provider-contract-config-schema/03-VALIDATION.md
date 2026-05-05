---
phase: 3
slug: cli-provider-contract-config-schema
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-01
---

# Phase 3 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 9.0.2 |
| **Config file** | `pyproject.toml` `[tool.pytest.ini_options]` |
| **Quick run command** | `pytest tests/test_cli_providers.py tests/test_config.py -x -q` |
| **Full suite command** | `pytest -m "not live" -q` |
| **Estimated runtime** | ~10 seconds |

---

## Sampling Rate

- **After every task commit:** Run `pytest tests/test_cli_providers.py tests/test_config.py tests/test_llms.py -x -q`
- **After every plan wave:** Run `pytest -m "not live" -q`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 03-01-01 | 01 | 0 | AICLI-01 | T-03-01 | Never use `shell=True` in subprocess | unit | `pytest tests/test_cli_providers.py::TestCLIProviderLLMInheritance -x` | ❌ W0 | ⬜ pending |
| 03-01-02 | 01 | 0 | AICLI-04 | T-03-02 | Classify errors not swallow them | unit | `pytest tests/test_cli_providers.py::TestErrorClassification -x` | ❌ W0 | ⬜ pending |
| 03-01-03 | 01 | 0 | AICLI-02 | — | `stdin=DEVNULL` prevents hanging | unit | `pytest tests/test_cli_providers.py::TestProbe::test_binary_missing -x` | ❌ W0 | ⬜ pending |
| 03-01-04 | 01 | 1 | AICLI-03 | — | `_log_response()` called for cost tracking | unit | `pytest tests/test_cli_providers.py::TestCLIProviderChat -x` | ❌ W0 | ⬜ pending |
| 03-01-05 | 01 | 1 | AICLI-03 | — | Cost tracking active for CLI providers | unit | `pytest tests/test_cli_providers.py::TestCostTracking -x` | ❌ W0 | ⬜ pending |
| 03-02-01 | 02 | 0 | CONFIG-01 | — | `provider = "claude-code"` accepted | unit | `pytest tests/test_config.py::TestFromDictFlat::test_cli_provider_string -x` | ❌ W0 | ⬜ pending |
| 03-02-02 | 02 | 0 | CONFIG-02 | — | YAML without `cli:` loads with defaults | unit | `pytest tests/test_config.py::TestCLIPolicyDefaults -x` | ❌ W0 | ⬜ pending |
| 03-02-03 | 02 | 1 | CONFIG-02 | — | `cli:` section parsed from YAML | unit | `pytest tests/test_config.py::TestCLIPolicy -x` | ❌ W0 | ⬜ pending |
| 03-02-04 | 02 | 1 | CONFIG-03 | — | Per-provider overrides accessible | unit | `pytest tests/test_config.py::TestCLIPolicyOverrides -x` | ❌ W0 | ⬜ pending |
| 03-03-01 | 03 | 1 | AICLI-02 | T-03-03 | Probe called before FallbackLLM wrap | unit | `pytest tests/test_cli.py::TestInitProviders::test_probe_failure_exits -x` | ❌ W0 | ⬜ pending |
| 03-03-02 | 03 | 2 | AICLI-01 | — | Existing API providers still pass | unit | `pytest tests/test_llms.py -x` | ✅ exists | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/test_cli_providers.py` — new file; stubs for AICLI-01, AICLI-02, AICLI-03, AICLI-04
- [ ] `tests/test_config.py` additions — new test classes `TestCLIPolicy`, `TestCLIPolicyDefaults`, `TestCLIPolicyOverrides`, `TestFromDictFlat::test_cli_provider_string` covering CONFIG-01, CONFIG-02, CONFIG-03

*Existing `tests/test_llms.py` covers the API-provider regression (AICLI-01 non-regression). No new framework install needed — pytest 9.0.2 already installed.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `probe()` does not hang on interactive auth prompt | AICLI-02 | Requires a real CLI binary in an unauthed state | Run `vulnhuntr --llm claude-code` on a machine where `claude` is installed but not logged in; confirm it prints a diagnostic and exits within 10s |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
