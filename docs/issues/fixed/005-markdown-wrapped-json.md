# 005 — Markdown-Wrapped JSON Responses (Upstream)

**Status:** Fixed (upstream, before fork)  
**Affected Component:** `vulnhuntr/LLMs.py` — `_validate_response()`  

## Symptoms

LLM responses wrapped in markdown code fences fail JSON parsing:

````
```json
{"scratchpad": "...", "analysis": "...", ...}
```
````

The leading ` ```json ` and trailing ` ``` ` are not valid JSON and cause `json.loads()` / `model_validate_json()` to fail.

## Root Cause

Despite prompting for raw JSON output — and even using Claude's prefill technique or ChatGPT's `json_object` response format — LLMs occasionally wrap their JSON output in markdown code blocks. This is an inherent behavior of instruction-following models trained on markdown-heavy data.

## Fix

A regex extraction step in `_validate_response()` strips everything except the outermost JSON object:

```python
match = re.search(r'\{.*\}', response_text, re.DOTALL)
if match:
    response_text = match.group(0)
```

This runs before any other validation, so it handles both:
- `` ```json { ... } ``` `` — code-fenced JSON
- `Some preamble text { ... } Some trailing text` — JSON embedded in prose

## Notes

- This fix was present in the original upstream Protect AI code
- The `re.DOTALL` flag ensures the regex spans multiple lines
- The regex is greedy, matching from the *first* `{` to the *last* `}` in the response — this works because LLM responses contain a single top-level JSON object
- Claude's prefill technique (`{"scratchpad": "1.`) significantly reduces the frequency of markdown wrapping, but does not eliminate it entirely
- ChatGPT's `response_format={"type": "json_object"}` is the most reliable at preventing markdown wrapping
