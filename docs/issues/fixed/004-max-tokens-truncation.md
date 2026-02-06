# 004 — max_tokens Truncation (Upstream)

**Status:** Fixed (upstream, before fork)  
**Date Identified:** Pre-fork (documented in QUICKSTART.md)  
**Affected Component:** `vulnhuntr/__main__.py` — LLM `chat()` calls  

## Symptoms

LLM responses were truncated mid-JSON, producing validation errors like:

```
ValidationError: Invalid JSON: EOF while parsing a list
```

The response would cut off in the middle of a JSON object, leaving an incomplete structure that could not be parsed.

## Root Cause

The default `max_tokens` parameter in the base `LLM.chat()` method was `4096`. For complex analyses — especially secondary analysis with accumulated context code — the LLM's response frequently exceeded this limit. The API would silently truncate the output at the token boundary, resulting in broken JSON.

## Fix

The call sites in `__main__.py` (now `cli/runner.py`) were updated to pass `max_tokens=8192`:

```python
# Initial analysis
initial_analysis_report: Response = llm.chat(
    user_prompt, response_model=Response, max_tokens=8192
)

# Secondary analysis
secondary_analysis_report: Response = llm.chat(
    vuln_specific_user_prompt, response_model=Response, max_tokens=8192
)
```

The base `LLM.chat()` default remains `4096` for backward compatibility, but all analysis calls explicitly override it.

## Notes

- This fix was present in the codebase at the time of the initial fork commit (`b775307`)
- The QUICKSTART.md documents this as a known issue with the workaround
- `8192` tokens ≈ 32KB of text, which handles most analysis responses comfortably
- If analyses grow more complex (e.g., larger context windows), this may need to increase again
- Monitor `vulnhuntr.log` for truncation patterns: look for responses ending abruptly without a closing `}`
