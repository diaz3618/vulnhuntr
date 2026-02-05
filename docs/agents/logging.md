# Logging Guidelines for Vulnhuntr

**Project**: Vulnhuntr - LLM-Powered Vulnerability Scanner  
**Version**: 1.0.0  
**Last Updated**: 2026-02-04

---

## The Rule

Always use structlog with keyword arguments for context:

```python
import structlog

log = structlog.get_logger()
log.info("Analysis complete", file=str(file_path), vulnerabilities=len(results), cost_usd=round(cost, 4))
```

Structured logging provides:
- **JSON output** to vulnhuntr.log
- **Easy searching** and filtering
- **Security** - sensitive data can be sanitized
- **Metrics** - cost tracking, performance analysis

## Why This Matters

- **Security**: API keys, paths, and sensitive data must be redacted
- **Cost Tracking**: LLM API calls are expensive, must be logged
- **Debugging**: Structured logs make troubleshooting much easier
- **Analysis**: JSON logs can be parsed for metrics

## Correct Usage

```python
import structlog
from pathlib import Path

log = structlog.get_logger()

# Good - structured context
log.info(
    "LLM API call",
    model="claude-3-5-sonnet",
    prompt_tokens=2048,
    completion_tokens=512,
    cost_usd=0.0123
)

log.error(
    "Symbol resolution failed",
    symbol="fetch_user",
    file=str(file_path),
    error=str(exception)
)

log.debug(
    "Iteration complete",
    iteration=3,
    functions_fetched=["fetch_user", "validate_input"],
    complete=False
)
```

## Anti-Pattern

```python
# WRONG - string formatting loses structure
log.info(f"Analysis complete for {file_path}: {len(results)} vulnerabilities found")

# WRONG - exposes full API key
log.debug(f"Using API key: {api_key}")

# WRONG - no context for debugging
log.error("Analysis failed")
```

## Security: Sensitive Data Sanitization

**Always sanitize**:

```python
def sanitize_api_key(key: str) -> str:
    """Mask API key for logging."""
    if not key or len(key) < 12:
        return "[REDACTED]"
    return f"{key[:8]}...{key[-4:]}"

def sanitize_path(path: Path, repo_root: Path) -> str:
    """Log relative path only, not absolute."""
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return "<external>"

# Usage
log.info(
    "Using API key",
    provider="anthropic",
    key=sanitize_api_key(api_key)
)

log.debug(
    "Analyzing file",
    file=sanitize_path(file_path, repo_root)
)
```

## What to Sanitize

**Field patterns to redact** (case-insensitive):

| Category      | Patterns                                                                      |
| ------------- | ----------------------------------------------------------------------------- |
| API Keys      | `api_key`, `apiKey`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `token`          |
| Secrets       | `secret`, `password`, `passwd`, `credentials`                                 |
| Authentication| `authorization`, `bearer`, `auth_token`                                       |
| Paths         | Absolute paths (log relative to repo root only)                               |
| Code Content  | Large code blocks (truncate or summarize)                                     |

**Implementation**:

```python
import re
from typing import Any, Dict

def sanitize_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively sanitize sensitive fields."""
    sensitive_patterns = [
        r".*api[_-]?key.*",
        r".*token.*",
        r".*secret.*",
        r".*password.*",
        r".*auth.*"
    ]
    
    result = {}
    for key, value in data.items():
        key_lower = key.lower()
        
        # Check if key matches sensitive pattern
        if any(re.match(pattern, key_lower, re.IGNORECASE) for pattern in sensitive_patterns):
            result[key] = "[REDACTED]"
        elif isinstance(value, dict):
            result[key] = sanitize_dict(value)
        elif isinstance(value, str) and len(value) > 1000:
            result[key] = value[:100] + "...[truncated]"
        else:
            result[key] = value
    
    return result
```

## Log Levels

**Use appropriate levels**:

- `log.debug()` - Detailed flow, iterations, function fetches
- `log.info()` - Key events (analysis start/complete, LLM calls, cost)
- `log.warning()` - Recoverable issues (Jedi failures, validation errors)
- `log.error()` - Serious problems (API failures, crashes)

```python
# Debug - detailed flow
log.debug("Fetching functions", requested=["func1", "func2"], iteration=3)

# Info - key milestones
log.info("Analysis started", file=relative_path, target="api.py")

# Warning - recoverable
log.warning("Jedi resolution failed", symbol="unknown_func", fallback="skipped")

# Error - serious
log.error("LLM API call failed", provider="anthropic", error=str(e))
```

## Cost Tracking Pattern

**Always log LLM costs**:

```python
def track_llm_call(
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    cost_usd: float
):
    """Log LLM call with cost tracking."""
    log.info(
        "LLM API call",
        model=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=prompt_tokens + completion_tokens,
        cost_usd=round(cost_usd, 4),
        timestamp=datetime.now().isoformat()
    )
```

## Integration with Main Agent

This logging agent is consulted by COPILOT_AGENT.md for:
- Structlog usage patterns
- Sensitive data sanitization
- Cost tracking implementation
- Log level selection
- JSON logging best practices

**Version History**:
- 1.0.0 (2026-02-04): Adapted from TypeScript to Python structlog for Vulnhuntr
