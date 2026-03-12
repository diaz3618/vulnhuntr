# OpenRouter Free Models

OpenRouter aggregates multiple LLM providers behind a single API endpoint. This page tracks the public `:free` catalog exposed by the live OpenRouter models API and was verified on March 12, 2026.

## Available Free Models

All public free catalog entries use the `:free` suffix. They are rate-limited but incur no API charges.

| Model ID | Context Length |
|----------|----------------|
| `arcee-ai/trinity-large-preview:free` | 131,000 |
| `arcee-ai/trinity-mini:free` | 131,072 |
| `cognitivecomputations/dolphin-mistral-24b-venice-edition:free` | 32,768 |
| `google/gemma-3-12b-it:free` | 32,768 |
| `google/gemma-3-27b-it:free` | 131,072 |
| `google/gemma-3-4b-it:free` | 32,768 |
| `google/gemma-3n-e2b-it:free` | 8,192 |
| `google/gemma-3n-e4b-it:free` | 8,192 |
| `liquid/lfm-2.5-1.2b-instruct:free` | 32,768 |
| `liquid/lfm-2.5-1.2b-thinking:free` | 32,768 |
| `meta-llama/llama-3.2-3b-instruct:free` | 131,072 |
| `meta-llama/llama-3.3-70b-instruct:free` | 128,000 |
| `mistralai/mistral-small-3.1-24b-instruct:free` | 128,000 |
| `nousresearch/hermes-3-llama-3.1-405b:free` | 131,072 |
| `nvidia/nemotron-3-nano-30b-a3b:free` | 256,000 |
| `nvidia/nemotron-3-super-120b-a12b:free` | 262,144 |
| `nvidia/nemotron-nano-12b-v2-vl:free` | 128,000 |
| `nvidia/nemotron-nano-9b-v2:free` | 128,000 |
| `openai/gpt-oss-120b:free` | 131,072 |
| `openai/gpt-oss-20b:free` | 131,072 |
| `qwen/qwen3-4b:free` | 40,960 |
| `qwen/qwen3-coder:free` | 262,000 |
| `qwen/qwen3-next-80b-a3b-instruct:free` | 262,144 |
| `stepfun/step-3.5-flash:free` | 256,000 |
| `z-ai/glm-4.5-air:free` | 131,072 |

The default model remains `qwen/qwen3-coder:free` (262K context, optimized for code analysis).

OpenRouter also exposes zero-cost router or alpha IDs such as `openrouter/free`, `openrouter/hunter-alpha`, and `openrouter/healer-alpha`, but this page intentionally tracks only the public concrete `:free` model IDs.

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENROUTER_API_KEY` | API key from [openrouter.ai/keys](https://openrouter.ai/keys) | - |
| `OPENROUTER_MODEL` | Model identifier | `qwen/qwen3-coder:free` |
| `OPENROUTER_BASE_URL` | API endpoint | `https://openrouter.ai/api/v1` |

## References

- [OpenRouter Models](https://openrouter.ai/models)
- [OpenRouter Models API](https://openrouter.ai/api/v1/models)
- [OpenRouter API Documentation](https://openrouter.ai/docs)
