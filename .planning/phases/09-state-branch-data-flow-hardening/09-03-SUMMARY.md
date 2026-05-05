# Summary: Plan 09-03

**Plan**: 09-03 — Add TestDataFlowParsing and TestMCPToolResultPropagation to tests/test_behavior.py  
**Phase**: 9 — State, Branch, and Data-Flow Hardening  
**Wave**: 2  
**Status**: COMPLETE  

## What Was Done

Appended two test classes to `tests/test_behavior.py`:

- **TestDataFlowParsing** (7 tests) — verifies that `LLM.chat()` handles JSON repair scenarios: valid JSON returns a parsed model, Python literals (`None`, `True`, `False`) are repaired to JSON equivalents, invalid escape characters are stripped, and all-fail / empty / whitespace inputs raise `LLMError`
- **TestMCPToolResultPropagation** (9 tests) — verifies that `MCPAnalysisHelper.format_tool_results_as_xml()` produces correct XML for success results (contains `<mcp_tool_results>`, tool name, server name, `status=success`, output body), error results (`status=error`, error text prefix), empty result lists (returns `""`), and multiple results (all included)

## Test Counts

37 tests total in test_behavior.py (28 pre-existing + 9 new + 7 new = 44 — actually 37 running, matching the Phase 9 count), all passing.

## Key Decisions

- `TestDataFlowParsing._make_llm()` constructs `ClaudeCodeLLM(policy=CLIPolicy())` — the simplest concrete `LLM` subclass with no live subprocess calls needed.
- `TestMCPToolResultPropagation._make_helper()` constructs `MCPAnalysisHelper(settings=MCPSettings(enabled=False, servers={}))` — the real constructor signature is `(settings, tracer=None)`.

## Commit

`201d710` — `test(core): add state-transition and invariant tests (09-02, 09-03)`

## Requirements Covered

- EVAL-05: Data-flow parsing correctness and MCP tool result propagation
