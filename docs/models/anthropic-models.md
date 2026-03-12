# Anthropic Models

Anthropic's current Claude API model IDs for direct Anthropic API use. This page was verified against Anthropic's official models overview on March 12, 2026.

## Current Claude API Models

| Family | Description | Claude API ID | Claude API Alias | Context Window | Max Output |
|--------|-------------|---------------|------------------|----------------|------------|
| Claude Opus 4.6 | Most intelligent Claude model for agents and coding | `claude-opus-4-6` | `claude-opus-4-6` | 200K / 1M beta | 128K |
| Claude Sonnet 4.6 | Best balance of speed and intelligence | `claude-sonnet-4-6` | `claude-sonnet-4-6` | 200K / 1M beta | 64K |
| Claude Haiku 4.5 | Fastest Claude model with near-frontier intelligence | `claude-haiku-4-5-20251001` | `claude-haiku-4-5` | 200K | 64K |

For Vulnhuntr, `claude-sonnet-4-6` is the safest current default for general code-analysis runs. Use the dated Haiku snapshot if you need a pinned version; use the alias if you want Anthropic-managed upgrades.

## Cloud Provider IDs

| Family | AWS Bedrock ID | GCP Vertex AI ID |
|--------|-----------------|------------------|
| Claude Opus 4.6 | `anthropic.claude-opus-4-6-v1` | `claude-opus-4-6` |
| Claude Sonnet 4.6 | `anthropic.claude-sonnet-4-6` | `claude-sonnet-4-6` |
| Claude Haiku 4.5 | `anthropic.claude-haiku-4-5-20251001-v1:0` | `claude-haiku-4-5@20251001` |

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `ANTHROPIC_API_KEY` | API key from [console.anthropic.com](https://console.anthropic.com/) | - |
| `ANTHROPIC_MODEL` | Claude model identifier | `claude-sonnet-4-6` |
| `ANTHROPIC_BASE_URL` | API endpoint | `https://api.anthropic.com` |

## References

- [Anthropic Models Overview](https://docs.anthropic.com/en/docs/about-claude/models/all-models)
- [Anthropic Model Names and IDs](https://docs.anthropic.com/en/docs/about-claude/models/overview)
