# 002 — Network File Filtering: Limited File Coverage with `-a` Flag

**Status:** Pending (by design, but confusing)  
**Date Identified:** 2026-02-05  
**Affected Component:** `vulnhuntr/core/repo.py` — `get_network_related_files()`  

## Symptoms

When running vulnhuntr against its own codebase without the `-a` flag, only 1 out of 4 Python source files was analyzed. The other files were silently skipped because they didn't match the network entry point regex patterns.

```bash
# Only analyzes files matching 210+ network patterns
vulnhuntr -r /path/to/repo -l claude

# Analyzes ALL Python files under the given path
vulnhuntr -r /path/to/repo -a /path/to/repo -l claude
```

## Root Cause

Without `-a`, vulnhuntr uses `get_network_related_files()` which filters for files containing network entry point patterns (Flask routes, FastAPI endpoints, Django URLs, etc.). This is by design — the tool focuses on remotely exploitable vulnerabilities.

However, the behavior is surprising when:
1. The user expects all files to be scanned
2. The target repo doesn't use standard web frameworks (e.g., uses raw `http.server` like DSVPWA)
3. The entry point patterns don't cover the framework in use

## Workaround

Use the `-a` flag pointing to the repository root to scan all Python files:

```bash
vulnhuntr -r /path/to/repo -a /path/to/repo -l claude -v
```

## Potential Improvements

- Add a `--all-files` flag as a clearer alternative to `-a /same/path`
- Log which files were skipped and why during non-verbose runs
- Add a summary at the start: "Found N Python files, M match network patterns, analyzing M"
