# Issue Tracker

Tracking runtime issues, bugs, and fixes encountered during Vulnhuntr development and testing.

## Directory Structure

- **[fixed/](fixed/)** — Resolved issues with documented root causes and fixes
- **[persistent/](persistent/)** — Recurring issues without a complete fix
- **[pending/](pending/)** — Open issues still under investigation

## Naming Convention

Files follow the format: `NNN-short-description.md` where NNN is a sequential number.

## Related Resources

- Debug files are saved to `/tmp/vulnhuntr_failed_response_*.json` when LLM response parsing fails
- Structured logs: `vulnhuntr.log` (JSON format, created in the working directory)
- LLM API test script: `scripts/llm_api_test.py`
