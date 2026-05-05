# Troubleshooting

## JSON Validation Errors

```
ValidationError: Invalid JSON: EOF while parsing a list
```

LLM response is truncated. The code uses `max_tokens=8192`; if this still happens, check that [vulnhuntr/__main__.py](../vulnhuntr/__main__.py) has the correct value.

---

## Markdown-Wrapped JSON

```
ValidationError: Invalid JSON (markdown code blocks)
```

Claude sometimes wraps JSON in triple-backtick blocks. This is handled in [vulnhuntr/LLMs.py](../vulnhuntr/LLMs.py) with a regex strip. If you see this error, you may be on an older version.

---

## Wrong API Key

Shell environment variables override `.env`. Check with:

```bash
env | grep -E "ANTHROPIC_API_KEY|OPENAI_API_KEY"
```

Unset any stale exports:

```bash
unset ANTHROPIC_API_KEY OPENAI_API_KEY
```

---

## Model 404

```
APIStatusError: Received non-200 status code: 404
```

Model name is deprecated. Use current names:

```dotenv
ANTHROPIC_MODEL=claude-sonnet-4-5
OPENAI_MODEL=chatgpt-4o-latest
```

---

## Rate Limiting

```
RateLimitError: Request was rate-limited
```

Wait a few minutes or use a different API key. Consider a paid tier for higher limits.

---

## Python Version

```
ImportError or syntax errors in dependencies
```

Use Python 3.12 or 3.13. Upgrade jedi/parso:

```bash
pip install --upgrade jedi parso
```

---

## Debug Logs

Check `vulnhuntr.log` for detailed output:

```bash
tail -f vulnhuntr.log
```

---

## CLI Providers

### Binary not found

Vulnhuntr raises `CLIBinaryNotFoundError` when the provider binary is not on `PATH`.

Check with:

```bash
which claude
which gemini
which codex
which qwen
```

Fix by re-running the install command from [QUICKSTART.md](../QUICKSTART.md#cli-providers).
Note that adding the binary to `PATH` after installing sometimes requires opening a new shell.

### Subprocess timeout

Vulnhuntr kills the subprocess and raises `CLITimeoutError` after the configured timeout
(default 300 seconds). For large repositories or slow machines, increase the limit in
`.vulnhuntr.yaml`:

```yaml
cli:
  timeout: 600
```

### Auth failures

Shell environment variables take precedence over both `.env` and the provider's own stored
credentials. If `ANTHROPIC_API_KEY` is set in the shell, the `claude` binary ignores its
own stored auth and fails with an invalid-API-key error.

Vulnhuntr strips its own provider keys from the subprocess environment automatically, but
any variables set in your shell before Vulnhuntr starts are not stripped unless you
configure it explicitly. To force the provider to use its own stored auth:

```bash
unset ANTHROPIC_API_KEY
vulnhuntr -l claude-code -r /path/to/repo
```

Or configure Vulnhuntr to strip the variable:

```yaml
cli:
  strip_env_vars:
    - ANTHROPIC_API_KEY
```

### Provider auth reference

| Provider | Vulnhuntr strips | Provider's own auth mechanism |
|----------|-----------------|-------------------------------|
| `claude-code` | `ANTHROPIC_API_KEY` | `claude login` or `~/.claude/config.json` |
| `gemini-cli` | `GOOGLE_API_KEY`, `GEMINI_API_KEY` | `gemini login` or `~/.gemini/config.json` |
| `codex` | `OPENAI_API_KEY` | `OPENAI_API_KEY` in env or codex config |
| `qwen-code` | `DASHSCOPE_API_KEY` | `DASHSCOPE_API_KEY` or `qwen login` |

See also: [QUICKSTART.md](../QUICKSTART.md#cli-providers)
