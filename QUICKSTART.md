# Quick Start

## Requirements

- Python 3.10-3.13
- API key from Anthropic, OpenAI, or OpenRouter

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Create `.env`:

```dotenv
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-sonnet-4-5
```

Or for free testing via OpenRouter:

```dotenv
OPENROUTER_API_KEY=sk-or-v1-...
OPENROUTER_MODEL=qwen/qwen3-coder:free
```

> Shell environment variables override `.env`. Run `unset ANTHROPIC_API_KEY OPENAI_API_KEY` if you have old keys exported.

## Run

```bash
vulnhuntr -r /path/to/repo -v
```

Target a specific file for faster, cheaper scans:

```bash
vulnhuntr -r /path/to/repo -a server.py --budget 3.0
```

## Troubleshooting

See [docs/troubleshooting.md](docs/troubleshooting.md) for common issues like JSON validation errors, model 404s, and rate limiting.

## CLI Reference

```
vulnhuntr -r ROOT [-a FILE] [-l {claude,gpt,ollama,openrouter}] [-v]
          [--dry-run] [--budget USD] [--resume] [--no-checkpoint]
          [--sarif PATH] [--html PATH] [--json PATH]
```

| Flag | Description |
|------|-------------|
| `-r` | Repository path (required) |
| `-a` | Specific file or directory to analyze |
| `-l` | LLM provider (default: claude) |
| `-v` | Verbose output |
| `--dry-run` | Estimate cost without running |
| `--budget` | Stop at USD limit |
| `--resume` | Resume from checkpoint |
