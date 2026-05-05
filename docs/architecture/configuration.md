# Configuration

## Environment Variables

```bash
# Anthropic Claude (Recommended)
ANTHROPIC_BASE_URL=https://api.anthropic.com
ANTHROPIC_API_KEY=sk-ant-api03-...
ANTHROPIC_MODEL=claude-sonnet-4-5

# OpenAI GPT
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_API_KEY=sk-proj-...
OPENAI_MODEL=chatgpt-4o-latest

# Ollama (Experimental)
OLLAMA_BASE_URL=http://127.0.0.1:11434/api/generate
OLLAMA_MODEL=llama3
# No API key required for Ollama
```

**Priority** (highest to lowest):

1. Shell environment variables
2. `.env` file in project root
3. Default values in code

Shell environment variables override `.env` because `dotenv.load_dotenv()` only sets variables that are not already set. If you have stale keys in ENV, unset them before running.

---

## CLI Arguments

```
vulnhuntr -r <root> [-a <analyze>] [-l PROVIDER] [-v] [--fallback1 PROVIDER:MODEL] [--fallback2 PROVIDER:MODEL]

Required:
  -r, --root PATH       Root directory of target repository

Optional:
  -a, --analyze PATH    Specific file or subdirectory to analyze
                        (relative to root or absolute path)

  -l, --llm PROVIDER    LLM provider to use (default: claude).
                        API providers: {claude,gpt,ollama,openrouter} — call HTTP APIs, require an API key.
                        CLI providers: {claude-code,gemini-cli,codex,qwen-code} — spawn local binaries, no API key needed.

  --fallback1 PROVIDER:MODEL
                        First fallback if primary provider fails
                        (e.g., openrouter:qwen/qwen3-coder:free)

  --fallback2 PROVIDER:MODEL
                        Second fallback LLM

  -v, --verbosity       Increase output verbosity
                        -v: Show verbose analysis output
                        -vv: Show context code details
```

---

## Token Limits

| Call | `max_tokens` |
|------|-------------|
| Initial analysis | 8192 |
| Secondary analysis | 8192 |
| Default in `LLM.chat()` | 4096 |

The 8192 limit was raised from the original 4096 after analysis responses consistently exceeded 15,000 characters and caused JSON truncation errors.

---

## Logging

```python
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)
```

Log output goes to stderr by default (stdlib integration).

**Log Levels**:

- `log.info()`: Major steps (file analysis, summaries)
- `log.debug()`: Detailed flow (context lookups, iterations)
- `log.warning()`: Validation failures, missing context
- `log.error()`: Exceptions, API errors

**Output Format**:

```json
{"event": "Summarizing project README", "level": "info", "timestamp": "..."}
{"event": "README summary complete", "summary": "...", "level": "info"}
{"event": "Performing initial analysis", "file": "/path/to/file.py", "level": "info"}
{"event": "Initial analysis complete", "report": {...}, "level": "info"}
```

---

## Jedi

```python
project = jedi.Project(repo_path)
# Uses default Python environment resolution
# No additional configuration
```

Jedi requires Python 3.10–3.13. Python 3.14+ breaks Parso parsing.
