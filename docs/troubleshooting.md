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
