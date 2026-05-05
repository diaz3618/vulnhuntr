# Plan 05-03 Summary: Wiring and Tests

## Status: COMPLETE

## What Was Built

1. **`vulnhuntr/cli_providers/__init__.py`** — added `CodexLLM` and `QwenCodeLLM` to imports and `__all__`.
2. **`vulnhuntr/cli/runner.py`** — added `elif llm_arg == "codex"` and `elif llm_arg == "qwen-code"` dispatch branches in `_init_providers()`.
3. **`tests/test_cli_providers.py`** — added 11 test classes (84 test cases) covering both new providers.

## Test Coverage

| Class | Tests | Coverage |
|-------|-------|----------|
| `TestCodexLLMImport` | 5 | import, `__all__`, subclass, strip vars, no chat override |
| `TestCodexLLMProbe` | 3 | missing binary, version too old, ok |
| `TestCodexLLMSendMessage` | 6 | success, empty stdout, unparseable, read-only sandbox, workspace-write, prompt positional |
| `TestCodexLLMGetResponse` | 3 | ok, last message wins, missing raises error |
| `TestCodexLLMExtractUsage` | 2 | turn.completed sums cached, empty returns zeros |
| `TestQwenCodeLLMImport` | 6 | import, `__all__`, subclass, strip vars, OPENAI_KEY not stripped, no chat override |
| `TestQwenCodeLLMProbe` | 2 | missing binary, ok |
| `TestQwenCodeLLMSendMessage` | 6 | success, empty stdout, non-array JSON, approval-mode plan, yolo, -p flag |
| `TestQwenCodeLLMGetResponse` | 3 | ok, no result entry, is_error raises |
| `TestQwenCodeLLMExtractUsage` | 2 | from result entry, fallback to assistant |
| `TestQwenCodeLLMBridgeMode` | 4 | base_url injected, no crash without base_url, DashScope stripped, OPENAI_KEY kept |

## Test Result

```
84 passed, 0 failed
```

## Files Changed

- `vulnhuntr/cli_providers/__init__.py` (modified)
- `vulnhuntr/cli/runner.py` (modified)
- `tests/test_cli_providers.py` (modified)
