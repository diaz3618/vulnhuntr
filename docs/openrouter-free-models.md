# OpenRouter Free Models

**Last Updated**: June 2025

OpenRouter provides access to many LLM providers through a single API. Several models are available for **free** (rate-limited), making them ideal for development and testing.

---

## Quick Start

```bash
# Set your OpenRouter API key
export OPENROUTER_API_KEY="sk-or-v1-your-key-here"

# Use the default free model (Qwen3 Coder)
vulnhuntr -r /path/to/repo -l openrouter

# Or specify a different free model
export OPENROUTER_MODEL="meta-llama/llama-3.3-70b-instruct:free"
vulnhuntr -r /path/to/repo -l openrouter
```

---

## Available Free Models

All free models end with `:free` suffix. They are rate-limited but cost $0.

### Recommended for Vulnhuntr

| Model | Context Length | Best For |
|-------|----------------|----------|
| `qwen/qwen3-coder:free` | 40,960 | **Default** - Code analysis, vulnerability detection |
| `deepseek/deepseek-r1-0528:free` | 163,840 | Complex reasoning, long context |
| `meta-llama/llama-3.3-70b-instruct:free` | 131,072 | General analysis, instruction following |
| `google/gemma-3-27b-it:free` | 131,072 | Fast inference, good reasoning |
| `mistralai/mistral-small-3.1-24b-instruct:free` | 131,072 | Code generation, structured output |

### Free Model List (31 models)

| Model ID | Context Length |
|----------|----------------|
| `deepseek/deepseek-r1-0528:free` | 163,840 |
| `deepseek/deepseek-r1-0528-qwen3-8b:free` | 163,840 |
| `qwen/qwen3-14b:free` | 40,960 |
| `qwen/qwen3-32b:free` | 40,960 |
| `qwen/qwen3-coder:free` | 40,960 |
| `qwen/qwen3-235b-a22b:free` | 40,960 |
| `qwen/qwq-32b:free` | 40,960 |
| `meta-llama/llama-3.3-70b-instruct:free` | 131,072 |
| `meta-llama/llama-3.2-3b-instruct:free` | 131,072 |
| `meta-llama/llama-3.2-1b-instruct:free` | 131,072 |
| `meta-llama/llama-3.1-8b-instruct:free` | 131,072 |
| `google/gemma-3-27b-it:free` | 131,072 |
| `google/gemma-3-12b-it:free` | 131,072 |
| `google/gemma-3-4b-it:free` | 131,072 |
| `google/gemma-3-1b-it:free` | 32,768 |
| `google/gemma-2-9b-it:free` | 8,192 |
| `microsoft/phi-4:free` | 16,384 |
| `microsoft/phi-4-reasoning:free` | 16,384 |
| `microsoft/phi-4-reasoning-plus:free` | 16,384 |
| `microsoft/phi-3-medium-128k-instruct:free` | 131,072 |
| `microsoft/phi-3-mini-128k-instruct:free` | 131,072 |
| `mistralai/mistral-small-3.1-24b-instruct:free` | 131,072 |
| `nvidia/llama-3.1-nemotron-70b-instruct:free` | 131,072 |
| `deepseek/deepseek-chat-v3-0324:free` | 131,072 |
| `deepseek/deepseek-chat:free` | 131,072 |
| `allenai/molmo-7b-d-0924:free` | 4,096 |
| `rekaai/reka-flash-3:free` | 131,072 |
| `moonshotai/moonlight-16b-a3b-instruct:free` | 8,192 |
| `bytedance-research/ui-tars-72b:free` | 32,768 |
| `shisa-ai/shisa-v2-llama-3-3-70b:free` | 131,072 |
| `open-r1/olympiccoder-32b:free` | 65,536 |

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENROUTER_API_KEY` | Your OpenRouter API key (required) | - |
| `OPENROUTER_MODEL` | Model to use | `qwen/qwen3-coder:free` |
| `OPENROUTER_BASE_URL` | API endpoint | `https://openrouter.ai/api/v1` |

---

## Example .env Configuration

```bash
# OpenRouter with free model (no cost)
OPENROUTER_API_KEY=sk-or-v1-your-key-here
OPENROUTER_MODEL=qwen/qwen3-coder:free
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
```

---

## Model Selection Tips

1. **For code analysis**: Use `qwen/qwen3-coder:free` (optimized for code)
2. **For long files**: Use `deepseek/deepseek-r1-0528:free` (163K context)
3. **For complex reasoning**: Use `deepseek/deepseek-r1-0528:free` or `microsoft/phi-4-reasoning:free`
4. **For fast iteration**: Use smaller models like `google/gemma-3-4b-it:free`

---

## Rate Limits

Free models have rate limits to prevent abuse:
- Typical: 20 requests/minute
- May vary by model and account tier

If you hit rate limits frequently, consider:
1. Using OpenRouter's paid models
2. Adding delays between requests
3. Using a different free model

---

## Getting an API Key

1. Go to [OpenRouter](https://openrouter.ai)
2. Sign up / Log in
3. Navigate to [API Keys](https://openrouter.ai/keys)
4. Create a new key
5. Copy and set as `OPENROUTER_API_KEY`

---

## Troubleshooting

### "Model not found" error
- Ensure the model ID includes `:free` suffix
- Check [OpenRouter Models](https://openrouter.ai/models?q=free) for current availability

### "Rate limit exceeded" error
- Wait a few minutes
- Try a different free model
- Consider paid models for heavy usage

### "Authentication failed" error
- Verify your `OPENROUTER_API_KEY` is set correctly
- Check the key hasn't expired at [OpenRouter Keys](https://openrouter.ai/keys)

---

## Links

- [OpenRouter Models](https://openrouter.ai/models)
- [OpenRouter API Docs](https://openrouter.ai/docs)
- [OpenRouter Pricing](https://openrouter.ai/docs/models)
