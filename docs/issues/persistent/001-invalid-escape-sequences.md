# 001 — Invalid Escape Sequences in LLM JSON Responses

**Status:** Persistent (no complete fix)  
**Date First Seen:** 2026-02-05  
**Affected Component:** `vulnhuntr/LLMs.py` — `_validate_response()`  

## Symptoms

Analysis crashes with a JSON parse error referencing an invalid escape character:

```
Invalid JSON: invalid escape at line 1 column 2333
```

This typically occurs when the LLM includes code snippets containing backslashes (`\n`, `\t`, `\x`, `\u`, Windows paths like `C:\Users`, regex patterns like `\d+`, etc.) inside JSON string values.

## Root Cause

JSON has strict escaping rules. Inside a JSON string, only these escape sequences are valid:

```
\"  \\  \/  \b  \f  \n  \r  \t  \uXXXX
```

When Claude writes its analysis, it often includes code examples, file paths, or regex patterns verbatim inside the `scratchpad` or `analysis` fields. For example:

```json
{
  "scratchpad": "The regex pattern \d+ matches digits and \s matches whitespace"
}
```

Here `\d` and `\s` are not valid JSON escape sequences. A strict JSON parser like `jiter` (used by Pydantic) rejects these.

## Why This Is Hard to Fix

1. **Position-dependent**: The invalid escape could be anywhere in the response. A global regex replacement risks corrupting valid escapes (`\n` should stay as `\n`).

2. **Context-sensitive**: You can't blindly escape all backslashes — `\\n` (literal backslash + n) and `\n` (newline) have different meanings. You'd need to know whether the LLM *intended* a literal backslash or an escape sequence.

3. **Regex extraction already runs first**: The `re.search(r'\{.*\}', ...)` step works fine because the regex engine is more lenient than JSON parsers. But the extracted text still contains the invalid escapes.

4. **Prefill helps but doesn't prevent it**: Claude's prefill technique ensures the response starts as JSON, but doesn't control what goes inside string values.

## Current Mitigation

- **Debug file export** (issue fixed/006): When this error occurs, the raw response is saved to `/tmp/vulnhuntr_failed_response_<timestamp>.json` for inspection.
- **Error messaging**: The error handler detects "invalid escape" in the error message and prints guidance.
- **Re-running**: Since LLM outputs are non-deterministic, re-running the same analysis often produces a response without the problematic escapes.

## Potential Solutions (Not Yet Implemented)

### Option A: JSON Repair Library

Use a library like `json-repair` (PyPI) that can fix common JSON formatting issues including invalid escapes:

```python
import json_repair
fixed_json = json_repair.repair_json(response_text)
result = response_model.model_validate_json(fixed_json)
```

**Pros:** Handles many edge cases  
**Cons:** New dependency, may over-correct in some cases

### Option B: Custom Escape Fixer

Pre-process the JSON text to double-escape unrecognized escape sequences:

```python
import re

def fix_json_escapes(text: str) -> str:
    """Replace invalid JSON escapes with double-backslash equivalents."""
    valid_escapes = set('"\\/bfnrtu')
    result = []
    i = 0
    in_string = False
    while i < len(text):
        char = text[i]
        if char == '"' and (i == 0 or text[i-1] != '\\'):
            in_string = not in_string
            result.append(char)
        elif char == '\\' and in_string:
            if i + 1 < len(text) and text[i+1] not in valid_escapes:
                result.append('\\\\')  # Double-escape
            else:
                result.append(char)
        else:
            result.append(char)
        i += 1
    return ''.join(result)
```

**Pros:** No new dependency, targeted fix  
**Cons:** Complex string state tracking, edge cases with nested quotes

### Option C: Switch to `json.loads()` with Fallback

Python's `json.loads()` is also strict, but we could try a two-pass approach:

```python
try:
    return response_model.model_validate_json(response_text)
except ValidationError:
    # Fallback: parse with json.loads (same strictness) then validate dict
    data = json.loads(response_text)
    return response_model.model_validate(data)
```

This doesn't solve the escape issue but separates JSON parsing from Pydantic validation errors.

### Option D: Prompt Engineering

Add explicit instructions to the system prompt:

```
CRITICAL: All backslashes in your JSON response must be properly escaped.
Use \\n for literal backslash-n, \\d for literal backslash-d, etc.
```

**Pros:** Addresses root cause  
**Cons:** Uses tokens, LLMs don't always follow instructions perfectly

## Frequency

This occurs sporadically — approximately 1 in 5 analysis runs, depending on the target code. Files with heavy regex usage, Windows paths, or escape sequences in their source code are more likely to trigger it.

## Workaround

Re-run the analysis. LLM responses are non-deterministic, and the next run typically produces valid JSON. If it persists, try a different LLM provider (`-l gpt` instead of `-l claude`) — ChatGPT's `json_object` mode is slightly better at producing valid JSON escapes.
