---
phase: 04-claude-code-gemini-cli
fixed_at: 2026-05-03T00:00:00Z
review_path: .planning/phases/04-claude-code-gemini-cli/04-REVIEW.md
iteration: 1
findings_in_scope: 7
fixed: 7
skipped: 0
status: all_fixed
---

# Phase 04: Code Review Fix Report

**Fixed at:** 2026-05-03
**Source review:** .planning/phases/04-claude-code-gemini-cli/04-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 7 (2 Critical + 5 Warning)
- Fixed: 7
- Skipped: 0

## Fixed Issues

### CR-01: System prompt silently discarded for all CLI providers

**Files modified:** `vulnhuntr/cli_providers/claude_code.py`, `vulnhuntr/cli_providers/gemini_cli.py`
**Commit:** 6e023fe
**Applied fix:** Both `ClaudeCodeLLM.send_message()` and `GeminiCLILLM.send_message()` now
check `self.system_prompt` before building the subprocess command. When set, a `full_prompt`
is constructed as `"{system_prompt}\n\n{user_prompt}"` and passed to the `-p` flag instead
of the bare `user_prompt`. Claude Code supports `--system-prompt` in recent versions but
prompt-prepending works across all versions. Gemini CLI has no dedicated system-prompt flag
so prepending is the only portable approach.

---

### CR-02: `send_message` not declared `@abstractmethod` in `CLIProviderLLM`

**Files modified:** `vulnhuntr/cli_providers/base.py`
**Commit:** cb8f0c8
**Applied fix:** Added `@abstractmethod` decorators to both `send_message()` and
`_extract_usage()` in `CLIProviderLLM`. Also added `from vulnhuntr.core.models import
LLMUsage` to `base.py` so the abstract `_extract_usage` return type annotation resolves
correctly. Subclasses that omit either method now fail at instantiation rather than at
runtime inside `chat()`.

---

### WR-01: `workdir` stored but never passed as `cwd` to subprocess

**Files modified:** `vulnhuntr/cli_providers/base.py`
**Commit:** cb8f0c8
**Applied fix:** Added `cwd=self.workdir if self.workdir else None` to the `subprocess.run()`
call in `_run_subprocess()`. Also replaced `stdout=subprocess.PIPE, stderr=subprocess.PIPE`
with `capture_output=True` to satisfy the project's ruff UP022 rule (committed in the same
atomic commit as CR-02 since both touch `base.py`).

---

### WR-02: `binary_path` log field logs a boolean, not a path

**Files modified:** `vulnhuntr/cli/runner.py`
**Commit:** 9a6bdcd
**Applied fix:** Renamed the `binary_path=result.binary_found` keyword argument in the
probe success `log.info()` call to `binary_found=result.binary_found`. The field name now
accurately reflects that the value is a boolean, preventing operator confusion when
reading structured logs.

---

### WR-03: Config fallback condition too restrictive in runner.py

**Files modified:** `vulnhuntr/cli/runner.py`
**Commit:** 9a6bdcd
**Applied fix:** Replaced `if config.provider is None and config.budget is None` with a
two-step check: `if config.provider is None` triggers a target-repo config load, and the
result is applied only when `repo_config.provider is not None`. This ensures a CWD config
that sets `budget` (but not `provider`) no longer silently blocks the target-repo config
from supplying the provider value. (Committed in the same atomic commit as WR-02 since both
touch `runner.py`.)

---

### WR-04: Gemini version gate rejects valid 2-part version strings

**Files modified:** `vulnhuntr/cli_providers/gemini_cli.py`
**Commit:** 317e44c
**Applied fix:** Changed the version regex from `r"(\d+\.\d+\.\d+)"` (3-part only) to
`r"(\d+\.\d+(?:\.\d+)?)"` (2- or 3-part). After parsing the version string, the parts list
is padded to length 3 by appending 0s before converting to a tuple. This ensures `"0.6"`
becomes `(0, 6, 0)` which correctly compares as equal to the `_MIN_VERSION` `(0, 6, 0)` gate
rather than being incorrectly rejected as shorter-tuple-less-than.

---

### WR-05: Flaky test — `test_build_env_strips_gemini_vars` mutates `os.environ` without `try/finally`

**Files modified:** `tests/test_cli_providers.py`
**Commit:** 6f4c84b
**Applied fix:** Replaced the bare `os.environ["KEY"] = val` / `del os.environ["KEY"]`
pattern with `patch.dict(os.environ, {...})` as a context manager. The three env vars
(`GEMINI_API_KEY`, `GOOGLE_API_KEY`, `GOOGLE_GENAI_USE_VERTEXAI`) are now automatically
restored on context exit even when an assertion fails, matching the guarded pattern used in
`TestClaudeCodeLLMBuildEnv`.

---

## Test Suite Results

After all fixes: `python -m pytest tests/ -x -q -m "not live"` — **787 passed, 4 deselected** in 3.66s. No regressions.

---

_Fixed: 2026-05-03_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
