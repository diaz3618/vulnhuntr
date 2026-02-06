# 001 — Symbol Resolution Loop: Repeated Context Requests

**Status:** Pending (under observation)  
**Date Identified:** 2026-02-05  
**Affected Component:** `vulnhuntr/cli/runner.py` — secondary analysis loop  

## Symptoms

During secondary analysis of `dsvpwa.py`, the LLM repeatedly requests the same symbols (`VulnHTTPRequestHandler`, `VulnHTTPServer`) across multiple iterations without receiving them. The analysis loop runs through multiple iterations before the termination condition triggers.

This was observed in the verbose output from the DSVPWA analysis run — the LLM requested `VulnHTTPRequestHandler` in the initial analysis, then again in iteration 1, 2, and 3 of the secondary analysis for the LFI vulnerability type.

## Likely Root Cause

The symbol extractor (`symbol_finder.py`) is searching within the target repository's files, but the Jedi project may not be properly resolving cross-module imports within the DSVPWA package structure. If `VulnHTTPRequestHandler` is defined in `dsvpwa/handlers.py` but Jedi can't locate it (e.g., missing `__init__.py`, incorrect project root, or the import path doesn't match file structure), the symbol fetch returns nothing.

When the symbol isn't found, it's not added to `stored_code_definitions`, so the LLM doesn't see it in the next iteration and requests it again.

The loop's termination logic catches this:
```python
if previous_context_amount >= len(stored_code_definitions):
    if same_context:
        break  # Requested same context twice
    same_context = True
```

But this allows 2–3 wasted iterations (and API calls) before breaking.

## Impact

- **Cost**: Each iteration is an LLM API call (~$0.10–$0.50 per call)
- **Time**: Each iteration adds 10–30 seconds of latency
- **Accuracy**: The LLM never gets the context it needs, so its analysis is incomplete

## Potential Improvements

1. **Early termination**: If a requested symbol can't be found, inform the LLM immediately rather than waiting for the next iteration. Inject a note like `"VulnHTTPRequestHandler: Symbol not found in repository"` into the context.

2. **Better Jedi project setup**: Ensure the target repository root is correctly set as the Jedi project path, and that Python path resolution includes the package root.

3. **Fallback to grep**: If Jedi can't resolve a symbol, fall back to a simple grep search for `class VulnHTTPRequestHandler` or `def VulnHTTPRequestHandler` across the repository files.

4. **Request deduplication**: Track previously-failed symbol requests and skip them in subsequent iterations.

## Current Status

This doesn't crash the analysis — it just wastes iterations. The loop terminates correctly, but the resulting analysis is incomplete because the LLM never sees the handler code it needs. This requires investigation into why Jedi isn't resolving the DSVPWA package symbols.
