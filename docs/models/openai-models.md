# OpenAI Models

OpenAI's current text and coding model IDs relevant to Vulnhuntr's `OPENAI_MODEL` setting. This page was verified against OpenAI's official model catalog on March 12, 2026.

## Primary Current Text Models

| Model ID | Positioning | Context Window | Max Output | Knowledge Cutoff |
|----------|-------------|----------------|------------|------------------|
| `gpt-5.4` | Best intelligence at scale for agentic, coding, and professional workflows | 1,050,000 | 128,000 | Aug 31, 2025 |
| `gpt-5-mini` | Near-frontier intelligence for lower-latency and cost-sensitive workloads | 400,000 | 128,000 | May 31, 2024 |
| `gpt-5-nano` | Fastest, cheapest GPT-5 model | 400,000 | 128,000 | May 31, 2024 |
| `gpt-4.1` | Strongest current non-reasoning GPT model | 1,047,576 | 32,768 | Jun 01, 2024 |

For Vulnhuntr, `gpt-5.4` is the best current default if you want the strongest OpenAI model without switching the repo to a different API style.

## Additional Current API Models

| Model ID | Notes | Context Window | Max Output | Knowledge Cutoff |
|----------|-------|----------------|------------|------------------|
| `gpt-4.1-mini` | Smaller, faster GPT-4.1 | 1,047,576 | 32,768 | Jun 01, 2024 |
| `gpt-4.1-nano` | Cheapest GPT-4.1 variant | 1,047,576 | 32,768 | Jun 01, 2024 |
| `o3` | Older reasoning model, now succeeded by GPT-5 | 200,000 | 100,000 | Jun 01, 2024 |
| `o4-mini` | Smaller reasoning model, now succeeded by GPT-5 mini | 200,000 | 100,000 | Jun 01, 2024 |

## Open-Weight Models

| Model ID | Notes | Context Window | Max Output | Knowledge Cutoff |
|----------|-------|----------------|------------|------------------|
| `gpt-oss-120b` | Largest OpenAI open-weight model; OpenAI's hosted API rate limits are effectively unavailable | 131,072 | 131,072 | Jun 01, 2024 |
| `gpt-oss-20b` | Smaller open-weight model for lower latency; not a good default for Vulnhuntr's hosted OpenAI path | 131,072 | 131,072 | Jun 01, 2024 |

## Aliases And Compatibility Notes

| Model ID | Status | Notes |
|----------|--------|-------|
| `gpt-5-chat-latest` | Current ChatGPT alias | 128K context, 16,384 max output, Sep 30, 2024 knowledge cutoff |
| `chatgpt-4o-latest` | Deprecated | Still appears in older Vulnhuntr docs and defaults, but OpenAI marks it deprecated |
| `gpt-5-codex` | Current, but special-case | OpenAI documents it as Responses-API-only, so it is not a safe default for Vulnhuntr's current `chat.completions` integration |

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | API key from [platform.openai.com](https://platform.openai.com/) | - |
| `OPENAI_MODEL` | OpenAI model identifier | `gpt-5.4` |
| `OPENAI_BASE_URL` | API endpoint | `https://api.openai.com/v1` |

## References

- [OpenAI Model Catalog](https://developers.openai.com/api/docs/models/all)
- [OpenAI GPT-5.4](https://developers.openai.com/api/docs/models/gpt-5.4)
- [OpenAI GPT-5-Codex](https://developers.openai.com/api/docs/models/gpt-5-codex)
- [OpenAI ChatGPT-4o Alias](https://developers.openai.com/api/docs/models/chatgpt-4o-latest)
