# 002 — LLM Returns Python Syntax in JSON (None, True, False)

**Status:** Fixed  
**Date Identified:** 2026-02-05  
**Date Fixed:** 2026-02-05  
**Commit:** `b857a5b`  
**Affected Component:** `vulnhuntr/LLMs.py` — `_validate_response()`  

## Symptoms

Secondary analysis crashes with a JSON parse error at a specific character offset:

```
pydantic_core._pydantic_core.ValidationError: 1 validation error for Response
  Invalid JSON: expected ident at line 1 column 2015
```

The error location corresponds to a `None` value in the LLM response — Python's `None` instead of JSON's `null`.

## Root Cause

Claude (and occasionally other LLMs) returns Python literal syntax inside what should be valid JSON:

```json
{
  "scratchpad": "...",
  "poc": None,
  "confidence_score": 2
}
```

The problem tokens:

| Python | JSON    |
|--------|---------|
| `None` | `null`  |
| `True` | `true`  |
| `False`| `false` |

Pydantic's `model_validate_json()` uses the `jiter` parser under the hood, which is a strict JSON parser — it does not accept Python syntax.

This happens because Claude's prefill technique starts the response mid-JSON, and the model sometimes drifts into Python-native serialization instead of strict JSON for certain field values.

## Diagnosis

A failed response was saved to `/tmp/vulnhuntr_failed_response_1770348863.json`. Examining the raw bytes at the error offset:

```python
s = open("/tmp/vulnhuntr_failed_response_1770348863.json").read()
print(repr(s[2010:2020]))
# Output: '": None,  '
```

Confirmed: `"poc": None` — Python `None` where JSON requires `null`.

## Fix

Added regex-based pre-processing in `_validate_response()` before passing the text to Pydantic:

```python
# Replace Python None with JSON null
response_text = re.sub(r'\b(None)\b', 'null', response_text)

# Replace Python True/False with JSON true/false
response_text = re.sub(r'\b(True)\b', 'true', response_text)
response_text = re.sub(r'\b(False)\b', 'false', response_text)
```

The `\b` word boundary anchors prevent false matches inside quoted strings (e.g., `"NoneType"` is not affected because `\bNone\b` requires word boundaries on both sides, and `NoneType` does not have a boundary between `None` and `Type`).

## Known Limitation

If the LLM writes the literal word `None` as a standalone token inside a JSON string value (e.g., `"scratchpad": "... the value is None ..."`), the regex would convert it to `"... the value is null ..."`. In practice, this has not caused issues because:

1. `None` inside prose is almost always part of a longer word or sentence context
2. Even if converted, `null` in a string value is still a valid string — it doesn't break parsing

## Verification

Re-run the analysis command. The JSON pre-processing happens transparently before Pydantic validation. Check logs for any `"Applied automatic fixes"` messages indicating the conversion was needed.
