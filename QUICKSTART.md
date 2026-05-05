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

Common issues include JSON validation errors (use a model with sufficient context), model 404s (check the model name), and rate limiting (add delays between scans).

## CLI Reference

```
vulnhuntr -r ROOT [-a FILE] [-l PROVIDER] [-v]
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

## CLI Providers

If you do not have an API key, or prefer to run analysis locally, Vulnhuntr supports
four headless CLI providers. Each provider delegates to an external binary rather than
calling an API directly.

| `--llm` value | Binary | Install |
|---------------|--------|---------|
| `claude-code` | `claude` | `npm i -g @anthropic-ai/claude-code` |
| `gemini-cli` | `gemini` | `pip install gemini-cli` |
| `codex` | `codex` | `npm i -g @openai/codex` |
| `qwen-code` | `qwen` | `npm i -g @qwen-code/qwen-code` |

### Authentication

Each provider handles its own auth — run `claude login`, `gemini login`, etc. once before
using Vulnhuntr. Vulnhuntr strips its own API key env vars (`ANTHROPIC_API_KEY`,
`OPENAI_API_KEY`, `GOOGLE_API_KEY`, `DASHSCOPE_API_KEY`) from the subprocess environment
before spawning, so the provider uses its own stored credentials rather than any keys you
have exported for the API-based providers. If the provider's own auth fails, consult the
provider's documentation.

### Usage

```bash
vulnhuntr -l claude-code -r /path/to/repo
```

With a fallback to an API-based provider if the binary fails:

```bash
vulnhuntr -l codex --fallback1 claude:claude-sonnet-4-5 -r /path/to/repo
```

See the README for missing binary, timeout, and auth troubleshooting.

See [docs/example-config.yaml](docs/example-config.yaml) for the full set of configurable
CLI policy options.
