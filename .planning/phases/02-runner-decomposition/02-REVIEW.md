---
phase: 02-runner-decomposition
reviewed: 2026-04-10T00:00:00Z
depth: standard
files_reviewed: 2
files_reviewed_list:
  - vulnhuntr/cli/runner.py
  - tests/test_cli.py
findings:
  critical: 0
  warning: 0
  info: 3
  total: 3
status: clean
---

# Phase 02: Code Review Report

**Reviewed:** 2026-04-10
**Depth:** standard
**Files Reviewed:** 2
**Status:** clean (3 info-level items only)

## Summary

Reviewed the Phase 02 runner decomposition — extraction of 5 stage functions from `run_analysis()` in
`vulnhuntr/cli/runner.py`, plus the accompanying unit tests added to `tests/test_cli.py`.

All 5 extracted stages (`_collect_files`, `_init_providers`, `_analyze_files`, `_dispatch_reports`,
`_dispatch_integrations`) are behavior-preserving. No logic was dropped or reordered relative to the
original monolithic function. The 17 new unit tests (across 5 new test classes) all pass, and the full
suite of 82 tests passes cleanly in under 1 second.

No critical issues or warnings found. Three low-signal info items are noted below.

---

## Info

### IN-01: `llm_factory` positional call convention undocumented at call site

**File:** `vulnhuntr/cli/runner.py:~_init_providers`
**Issue:** When an `llm_factory` is supplied, `_init_providers` calls it as:
```python
llm = llm_factory(args.llm, system_prompt, cost_callback, config.model)
```
The fourth positional argument (`config.model`) acts as a `model_override`. This matches
`initialize_llm`'s signature positionally, but there is no comment or type hint at the call site
explaining the expected factory signature. A future implementor supplying a real factory could easily
get the argument order wrong.

**Fix:** Add an inline comment or a `Protocol` type alias for the factory callable:
```python
# llm_factory(llm_arg, system_prompt, cost_callback, model_override) -> LLMClient
llm = llm_factory(args.llm, system_prompt, cost_callback, config.model)
```
Or define a `Protocol`:
```python
class LLMFactory(Protocol):
    def __call__(
        self,
        llm_arg: str,
        system_prompt: str,
        cost_callback: Callable,
        model_override: str | None,
    ) -> LLMClient: ...
```

---

### IN-02: Redundant `MagicMock` re-imports inside test method bodies

**File:** `tests/test_cli.py` (multiple lines — e.g. 602, 618, 634, 648, 711, 801, 809, 832, 848, 870, 895)
**Issue:** `from unittest.mock import MagicMock` is imported at module level (line 27) and again
inside individual test method bodies. The re-imports are harmless but add noise and suggest the
module-level import was added after the method-local ones and the old imports were never cleaned up.

**Fix:** Remove the redundant in-method imports. The module-level import at line 27 is sufficient:
```python
# Remove all occurrences of this line inside test methods:
from unittest.mock import MagicMock
```

---

### IN-03: Missing compound-flag test in `TestDispatchIntegrations`

**File:** `tests/test_cli.py:TestDispatchIntegrations`
**Issue:** The three existing tests cover: no integrations, GitHub issues only, and webhook only.
The case where both `create_issues=True` AND a `webhook` URL are set simultaneously is not tested.
While each branch is individually covered, a compound call exercises both code paths in sequence
and would catch any accidental early-return or shared-state bug between them.

**Fix:** Add a fourth test:
```python
def test_both_integrations_called(self):
    args = MagicMock()
    args.create_issues = True
    args.webhook = "https://example.com/hook"
    findings = [MagicMock()]
    cost_tracker = MagicMock()
    files = ["f.py"]

    with patch("vulnhuntr.cli.runner._create_github_issues") as mock_issues, \
         patch("vulnhuntr.cli.runner._send_webhook") as mock_webhook:
        _dispatch_integrations(args, findings, cost_tracker, files)
        mock_issues.assert_called_once()
        mock_webhook.assert_called_once()
```

---

_Reviewed: 2026-04-10_
_Reviewer: gsd-code-reviewer agent_
_Depth: standard_
