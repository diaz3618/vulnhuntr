# OpenRouter Free Models

**Last Updated**: February 15, 2026

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

# Use as fallback (free model picks up if primary fails)
vulnhuntr -r /path/to/repo -l claude --fallback1 "openrouter:qwen/qwen3-coder:free"
```

---

## Available Free Models

All free models end with `:free` suffix. They are rate-limited but cost $0.

### Recommended for Vulnhuntr

| Model | Context Length | Best For |
|-------|----------------|----------|
| `qwen/qwen3-coder:free` | 262,000 | **Default** - Code analysis, vulnerability detection |
| `deepseek/deepseek-r1-0528:free` | 163,840 | Complex reasoning, long context |
| `meta-llama/llama-3.3-70b-instruct:free` | 128,000 | General analysis, instruction following |
| `nousresearch/hermes-3-llama-3.1-405b:free` | 131,072 | Largest free model, advanced agentic |
| `mistralai/mistral-small-3.1-24b-instruct:free` | 128,000 | Code generation, structured output |
| `openai/gpt-oss-120b:free` | 131,072 | OpenAI open-weight MoE, strong reasoning |

### Free Model List (26 models)

| Model ID | Context Length |
|----------|----------------|
| `arcee-ai/trinity-large-preview:free` | 131,000 |
| `arcee-ai/trinity-mini:free` | 131,072 |
| `cognitivecomputations/dolphin-mistral-24b-venice-edition:free` | 32,768 |
| `deepseek/deepseek-r1-0528:free` | 163,840 |
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
| `nvidia/nemotron-nano-12b-v2-vl:free` | 128,000 |
| `nvidia/nemotron-nano-9b-v2:free` | 128,000 |
| `openai/gpt-oss-120b:free` | 131,072 |
| `openai/gpt-oss-20b:free` | 131,072 |
| `qwen/qwen3-4b:free` | 40,960 |
| `qwen/qwen3-coder:free` | 262,000 |
| `qwen/qwen3-next-80b-a3b-instruct:free` | 262,144 |
| `stepfun/step-3.5-flash:free` | 256,000 |
| `upstage/solar-pro-3:free` | 128,000 |
| `z-ai/glm-4.5-air:free` | 131,072 |

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

1. **For code analysis**: Use `qwen/qwen3-coder:free` (optimized for code, 262K context)
2. **For long files**: Use `deepseek/deepseek-r1-0528:free` (163K context) or `qwen/qwen3-coder:free` (262K)
3. **For complex reasoning**: Use `deepseek/deepseek-r1-0528:free` or `nousresearch/hermes-3-llama-3.1-405b:free`
4. **For fast iteration**: Use smaller models like `google/gemma-3-4b-it:free` or `liquid/lfm-2.5-1.2b-instruct:free`
5. **For maximum quality**: Use `openai/gpt-oss-120b:free` or `nousresearch/hermes-3-llama-3.1-405b:free`

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
