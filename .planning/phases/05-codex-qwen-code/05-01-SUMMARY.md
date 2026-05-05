# Plan 05-01 Summary: CodexLLM Adapter

## Status: COMPLETE

## What Was Built

`vulnhuntr/cli_providers/codex.py` — headless adapter for the OpenAI Codex CLI (Rust, v0.95+).

## Key Decisions

- **No `-p` flag**: Codex CLI takes the prompt as a positional argument (last element in the command list), unlike Gemini/Qwen which use `-p`.
- **JSONL output**: `codex exec --json` emits newline-delimited JSON, not a single JSON object. Parsed with `stdout.splitlines()` + `json.loads(line)`.
- **Sandbox instead of approval-mode**: The current Rust CLI uses `--sandbox read-only|workspace-write` + `--ask-for-approval never`, not the old `--approval-mode` flags from the deprecated TypeScript CLI.
- **`cached_input_tokens` summed into `input_tokens`**: Reflects real token billing (OpenAI counts cached reads as billed input).
- **`OPENAI_API_KEY` stripped**: Forces OAuth (device-code) auth flow rather than API-key auth, consistent with CLI-native usage pattern.

## Files Changed

- `vulnhuntr/cli_providers/codex.py` (created)

## Verification

```
python -c "from vulnhuntr.cli_providers.codex import CodexLLM; p = CodexLLM(); print('CodexLLM OK')"
# CodexLLM OK
```
