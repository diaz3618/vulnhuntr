# 006 — Debug File Export for Failed Responses

**Status:** Fixed (enhancement)  
**Date Implemented:** 2026-02-05  
**Commit:** `b857a5b`  
**Affected Component:** `vulnhuntr/LLMs.py` — `_validate_response()`  

## Context

When LLM response validation fails, the raw response text is lost — making it nearly impossible to diagnose why the JSON was malformed. The original code simply raised an exception with the Pydantic error message, which shows field-level issues but not the actual response content.

## Implementation

Added automatic debug file export on validation failure:

```python
except ValidationError as e:
    debug_file = os.path.join(
        tempfile.gettempdir(),
        f"vulnhuntr_failed_response_{int(time.time())}.json"
    )
    with open(debug_file, 'w') as f:
        f.write(response_text)
    log.error(f"Failed response saved to: {debug_file}")
```

Also added categorized error hints:
- **Invalid escape sequences** → "known issue when LLMs include code with backslashes"
- **Python syntax remnants** → "JSON contains Python syntax (None/True/False)"

## File Locations

Debug files are saved to `/tmp/vulnhuntr_failed_response_<unix_timestamp>.json`.

Example files from testing:
- `/tmp/vulnhuntr_failed_response_1770348863.json` — Python `None` in JSON (issue #002)
- `/tmp/vulnhuntr_failed_response_1770350803.json` — Same root cause, different file under analysis

## Usage

After a crash, examine the saved file:

```bash
# Pretty-print the response
cat /tmp/vulnhuntr_failed_response_*.json | python3 -m json.tool

# If JSON is broken, examine raw content
cat /tmp/vulnhuntr_failed_response_*.json | head -c 5000

# Find the problem area at a specific character offset
python3 -c "
s = open('/tmp/vulnhuntr_failed_response_TIMESTAMP.json').read()
col = 2015  # from the error message
print(f'Around column {col}:', repr(s[col-10:col+10]))
"
```

## Notes

- Files accumulate in `/tmp` — clean up periodically
- The timestamp in the filename prevents overwriting previous debug files
- The debug export is wrapped in a try/except to avoid interfering with the primary error flow
