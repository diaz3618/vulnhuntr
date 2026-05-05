# Plan 05-02 Summary: QwenCodeLLM Adapter

## Status: COMPLETE

## What Was Built

`vulnhuntr/cli_providers/qwen_code.py` — headless adapter for the Qwen Code CLI (npm, v0.1+).

## Key Decisions

- **Bridge mode support**: `OPENAI_API_KEY` is intentionally NOT stripped. When `policy.overrides["qwen-code"]["base_url"]` is set, `OPENAI_BASE_URL` is injected so Qwen Code forwards requests to any OpenAI-compatible endpoint (e.g., OpenRouter).
- **`--yolo` vs `--approval-mode plan`**: `tool_mode="full"` appends `--yolo`; all other modes use `["--approval-mode", "plan"]`.
- **JSON array output**: Qwen Code emits a top-level JSON array (not object, not JSONL). Validated with `isinstance(messages, list)`.
- **OAuth discontinued April 15 2026**: Auth is now `DASHSCOPE_API_KEY`, `BAILIAN_CODING_PLAN_API_KEY`, or OpenAI bridge key. Both DashScope keys are stripped to prevent accidental leakage.
- **Usage fallback**: If `result.usage` is all zeros, `_extract_usage` falls back to `assistant.message.usage`.

## Files Changed

- `vulnhuntr/cli_providers/qwen_code.py` (created)

## Verification

```
python -c "from vulnhuntr.cli_providers.qwen_code import QwenCodeLLM; p = QwenCodeLLM(); print('QwenCodeLLM OK')"
# QwenCodeLLM OK
```
