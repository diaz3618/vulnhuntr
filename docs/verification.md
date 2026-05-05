# Verification Checklist

This document defines the trace evidence, invariant gates, and stability thresholds
required before declaring a CLI provider integration ready for release.

See [QUICKSTART.md](../QUICKSTART.md#cli-providers) for installation instructions and
[docs/troubleshooting.md](troubleshooting.md#cli-providers) for failure resolution.

---

## Trace Evidence

After a successful `vulnhuntr -l <provider> -r <repo>` run, the `ExecutionTracer`
accumulated in that session must contain at least these event types
(from `vulnhuntr/core/trace.py`):

| Event type | When emitted | Required for |
|------------|--------------|--------------|
| `probe_result` | `provider.probe()` at startup | All providers |
| `response_validated` | After each `provider.get_response()` call | All providers |
| `session_decision` | `provider.send_message()`, logs flags and mode | ClaudeCodeLLM, QwenCodeLLM |
| `fallback_triggered` | Only if a fallback chain fires | FallbackLLM routing |
| `tool_call` | Only if `tool_mode != "none"` | MCP-enabled runs |

### Checking trace events manually

```python
from vulnhuntr.core.trace import ExecutionTracer
tracer = ExecutionTracer()
# ... run analysis ...
probe_events = tracer.filter("probe_result")
assert len(probe_events) >= 1
assert probe_events[0].data["ok"] is True
```

---

## Invariant Gates

`InvariantViolationError` (a `RuntimeError` subclass) must NOT be raised during any
normal analysis run. Known invariant keys:

| Invariant key | Component | Condition guarded |
|---------------|-----------|-------------------|
| `active_in_registry` | `FallbackLLM` | Fallback provider must exist in provider registry |
| `session_mode_is_known` | `ClaudeCodeLLM` | `session_mode` must be one of `stateless / continue / resume` |

A production release is blocked if `InvariantViolationError` fires on any real-world
repository input. File an issue immediately if you observe it.

---

## Stability Threshold

Critical routing paths must pass `@pytest.mark.repeat(3)` with zero failures:

```bash
python -m pytest tests/test_state_transitions.py -m "not live" -v
```

The following tests carry `@pytest.mark.repeat(3)` and must remain green:

- `test_fallback_progression_stable` — verifies fallback LLM chain fires in order
- `test_session_decision_flag_stable` — verifies session flags are applied consistently

---

## Per-Provider "Done" Criteria

A provider integration is complete when ALL of the following are true:

### ClaudeCodeLLM (`--llm claude-code`)

- [ ] `tests/test_cli_providers.py::TestClaudeCodeLLM` — all non-live tests pass
- [ ] `tests/test_cli_providers.py::test_claude_code_live_round_trip` — passes locally
      (requires `claude` binary + `claude login`)
- [ ] `probe_result` event emitted with `ok=True` on a real repo
- [ ] `response_validated` event emitted with `valid=True` on a successful parse

### GeminiCLILLM (`--llm gemini-cli`)

- [ ] `tests/test_cli_providers.py::TestGeminiCLILLM` — all non-live tests pass
- [ ] `tests/test_cli_providers.py::test_gemini_cli_live_round_trip` — passes locally
      (requires `gemini` binary + `gemini login`)
- [ ] `probe_result` and `response_validated` events emitted on a real repo

### CodexLLM (`--llm codex`)

- [ ] `tests/test_cli_providers.py::TestCodexLLMSendMessage` — all non-live tests pass
- [ ] `tests/test_cli_providers.py::test_codex_live_round_trip` — passes locally
      (requires `codex` binary + `OPENAI_API_KEY` in env)
- [ ] `probe_result` and `response_validated` events emitted on a real repo

### QwenCodeLLM (`--llm qwen-code`)

- [ ] `tests/test_cli_providers.py::TestQwenCodeLLMSendMessage` — all non-live tests pass
- [ ] `tests/test_cli_providers.py::test_qwen_code_live_round_trip` — passes locally
      (requires `qwen` binary + `DASHSCOPE_API_KEY` in env)
- [ ] `probe_result` and `response_validated` events emitted on a real repo

---

## Running the Verification Suite

```bash
# Non-live (CI-equivalent):
python -m pytest tests/test_cli_providers.py tests/test_state_transitions.py -m "not live" -v

# Live (local only, requires all 4 binaries):
python -m pytest tests/test_cli_providers.py -m live -v
```
