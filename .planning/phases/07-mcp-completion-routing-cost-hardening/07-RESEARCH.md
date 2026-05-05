# Phase 7 Research: MCP Completion, Routing, and Cost Hardening

**Researched:** 2026-05-04
**Domain:** Python async bridge, LLM fallback routing, cost tracking dataclasses
**Confidence:** HIGH — all findings verified from direct source code inspection

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- D-01: `VulnerabilityAnalyzer.__init__` gains `mcp_helper: MCPAnalysisHelper | None = None`
- D-02: Runner creates/initializes/shuts down helper; analyzer stays synchronous
- D-03: When `mcp_helper` is None or not active, zero behavioral change
- D-04: `MCPAnalysisHelper` gains `format_tool_results_for_prompt()` (see Q3 — already exists as `format_results_for_prompt()`)
- D-05: Tool call → result → XML block → prepend to next prompt, inside secondary loop
- D-06: Skip entirely when `mcp_tool_calls` is empty or `mcp_helper` is None
- D-07: Timeout enforcement inside `execute_tool_calls()` per call via `asyncio.wait_for()`
- D-08: Timeout produces `MCPToolCallResult(success=False, error="timeout after Xs")`
- D-09: `tool_timeout_seconds` default is 30 (already verified in config.py)
- D-10: `parse_fallback_spec` gains `config: VulnhuntrConfig | None = None`; CLI names delegate to `initialize_llm()`
- D-11: CLI prefixes: `claude-code`, `gemini-cli`, `codex`, `qwen-code`; no model sub-spec
- D-12: `CLIRuntimeError` is a subclass of `LLMError` — no FallbackLLM changes for error compatibility
- D-13: `wrap_with_fallbacks()` passes `config` to `parse_fallback_spec()`
- D-14: `usage_type: Literal["api","provider_reported","subscription"] = "api"` on `TokenUsage`
- D-15: `provider_note: str | None = None` on `TokenUsage`; in `to_dict()`/`from_dict()`
- D-16: `CostTracker.track_subscription_call()` — zero tokens, zero cost, `usage_type="subscription"`
- D-17: `get_summary()` gains `"usage_by_type"` key with api/provider_reported/subscription breakdowns
- D-18: Structured fallback log event with named fields
- D-19: `_diagnostics: list[dict[str, Any]] = []` initialized in `FallbackLLM.__init__`
- D-20: Print diagnostics to stderr when `--verbose` and diagnostics non-empty
- D-21/D-22: Integration tests in `tests/test_mcp_analysis.py`

### the agent's Discretion
- Whether `MCPAnalysisMode` guard lives in `execute_tool_calls` vs call site
- Whether `track_subscription_call()` should accept `tokens_estimate` optional param
- Exact field name — `usage_by_type` or `breakdown_by_type`

### Deferred Ideas (OUT OF SCOPE)
- Report-level integration of provider diagnostics (Phase 10)
- Per-provider cost budgets with CLI subscription cost estimation
- MCP server health probing before scan starts
- `asyncio.wait_for` session-level overall MCP timeout
</user_constraints>

---

## Executive Summary

Phase 7 has fewer net-new lines than it appears — several decisions are already partially or fully implemented. `execute_tool_calls()` already contains `asyncio.wait_for` with timeout and `asyncio.TimeoutError` handling (D-07, D-08 done). `format_results_for_prompt()` already exists on `MCPAnalysisHelper` under a slightly different name than D-04 specifies. `_analyze_files()` in `runner.py` already dispatches MCP calls after analysis results but discards them without feeding them back — that in-loop injection is the primary missing piece. The bulk of Phase 7 work is: (1) passing `mcp_helper` into `VulnerabilityAnalyzer` and wiring it inside `_secondary_analysis()` to actually close the feedback loop; (2) extending `parse_fallback_spec()` to detect CLI provider names; (3) adding `usage_type`/`provider_note` to `TokenUsage` and `track_subscription_call()` to `CostTracker`; (4) initializing `_diagnostics` in `FallbackLLM.__init__`.

---

## Q1: MCP Wiring Injection Point

**Finding: VERIFIED** — injection belongs inside `_secondary_analysis()`, not `_analyze_files()`.

### Current state

`_analyze_files()` in [vulnhuntr/cli/runner.py](vulnhuntr/cli/runner.py#L650) already has orphaned MCP dispatch code added in a prior pass:

```python
# Execute MCP tool calls from initial analysis (if any)
if mcp_helper is not None and mcp_helper.is_active and result.initial_report.mcp_tool_calls:
    mcp_results = run_async(mcp_helper.execute_tool_calls(result.initial_report.mcp_tool_calls))
    log.info("MCP tool calls executed (initial)", count=len(mcp_results))
```

This code fires *after* `analyze_file()` completes, discards `mcp_results`, and never feeds them back into any prompt. It is **dead code with respect to D-05**.

### Target injection point

[vulnhuntr/core/analysis.py](vulnhuntr/core/analysis.py) — `_secondary_analysis()` method, inside the `for iteration in range(self.config.max_iterations)` loop, **immediately after the `self.llm.chat()` call returns a `report`**:

```python
# Exact position (after line ~345 where report is assigned):
report = cast(Response, self.llm.chat(secondary_prompt, response_model=Response, max_tokens=8192))

# --- INSERT HERE (D-05) ---
if self.mcp_helper is not None and self.mcp_helper.is_active and report.mcp_tool_calls:
    from vulnhuntr.mcp.analysis import run_async
    mcp_results = run_async(self.mcp_helper.execute_tool_calls(report.mcp_tool_calls))
    mcp_block = self.mcp_helper.format_results_for_prompt(mcp_results)
    if mcp_block:
        secondary_prompt = mcp_block + "\n" + secondary_prompt  # prepend to next iteration
```

The prepend goes onto `secondary_prompt` which is rebuilt at the top of each loop iteration via `_build_secondary_prompt()`. Since `secondary_prompt` is reassigned at the start of each iteration body (before the chat call), the results XML survives into the very next iteration's user message.

### Secondary-loop structure (verified)

```
for iteration in range(max_iterations):
    if iteration > 0:
        expand context (resolve code definitions)
    secondary_prompt = _build_secondary_prompt(...)   ← rebuilt each iteration
    report = llm.chat(secondary_prompt, ...)           ← LLM call
    # INJECT MCP RESULTS HERE — prepend to secondary_prompt for NEXT iteration
    if self._on_iteration: ...
    if not report.context_code: break
    # stale-context termination check
```

### What to clean up

The orphaned block in `_analyze_files()` that dispatches and discards MCP results (around [runner.py L650-L680](vulnhuntr/cli/runner.py#L650)) should be **removed** once the injection lives inside `_secondary_analysis()`. Keeping it would execute tool calls twice and waste the first set of results.

---

## Q2: Async Bridge Pattern

**Finding: VERIFIED** — `run_async()` helper is the correct bridge; no event loop conflicts exist.

### run_async() location and behavior

`run_async()` is defined in [vulnhuntr/mcp/analysis.py](vulnhuntr/mcp/analysis.py) and re-exported from `vulnhuntr.mcp`. From `tests/test_mcp_analysis.py`:

```python
from vulnhuntr.mcp.analysis import run_async

# test confirms it wraps asyncio.run:
def test_runs_coroutine(self):
    async def simple():
        return 42
    assert run_async(simple()) == 42
```

### No event loop in the synchronous pipeline

`run_analysis()` → `_analyze_files()` → `analyzer.analyze_file()` → `_secondary_analysis()` is a fully synchronous call chain. There is no existing event loop running. `asyncio.run()` (inside `run_async()`) will work without raising `RuntimeError: This event loop is already running`.

The existing usages in `runner.py` confirm the pattern is established:

```python
run_async(mcp_helper.initialize())
# ...
run_async(mcp_helper.shutdown())
```

### Import path inside `_secondary_analysis()`

`_secondary_analysis()` is in `vulnhuntr/core/analysis.py`. The MCP module should be lazily imported to avoid introducing a hard dependency on the optional MCP stack:

```python
from vulnhuntr.mcp.analysis import run_async  # inside the if-block, not at module top
```

This matches the pattern already used in `_analyze_files()`.

### Thread-safety note

`asyncio.run()` creates a new event loop per call. With `max_iterations=7` and tool calls each iteration, this means up to 7 event loops created/destroyed per vuln type per file. This is acceptable overhead; no pooling is needed given analysis is inherently sequential.

---

## Q3: `execute_tool_calls` Signature and D-07/D-08 Status

**Finding: VERIFIED** — signature matches `Response.mcp_tool_calls` exactly; timeout handling already implemented.

### Signature (from [vulnhuntr/mcp/analysis.py](vulnhuntr/mcp/analysis.py))

```python
async def execute_tool_calls(
    self,
    requests: list[MCPToolCallRequest],
) -> list[MCPToolCallResult]:
```

`Response.mcp_tool_calls` is `list[MCPToolCallRequest]`. The types match exactly — no adapter needed.

### D-07 and D-08 already implemented

The existing code already contains:

```python
timeout = self._policy.tool_timeout_seconds or None
raw = await asyncio.wait_for(
    self._client.call_tool(req.server, req.tool, req.arguments),
    timeout=timeout if timeout and timeout > 0 else None,
)
```

And the `asyncio.TimeoutError` handler already produces:

```python
MCPToolCallResult(
    server=req.server,
    tool=req.tool,
    success=False,
    error=f"Timeout after {self._policy.tool_timeout_seconds}s",
)
```

**D-07 and D-08 are already done.** The planner should mark these as no-op tasks.

### D-04 method name discrepancy

CONTEXT.md D-04 calls for `format_tool_results_for_prompt()`. The actual method already in the codebase is:

```python
def format_results_for_prompt(self, results: list[MCPToolCallResult]) -> str:
```

Same signature, same return value, same XML-tag pattern. The planner has two options:
1. **Use the existing name** (`format_results_for_prompt`) — zero new code
2. **Add an alias** `format_tool_results_for_prompt = format_results_for_prompt` — fulfills D-04 letter

Option 1 is recommended to avoid over-engineering.

---

## Q4: CLI Provider Construction for Fallback Chain

**Finding: VERIFIED** — `initialize_llm()` already handles all four CLI providers; `parse_fallback_spec()` needs only a detection prefix check + delegation.

### Current `parse_fallback_spec()` structure

```python
providers: dict[str, type] = {
    "claude": Claude,
    "gpt": ChatGPT,
    "openrouter": OpenRouter,
    "ollama": Ollama,
}
# splits 'provider:model', constructs cls(model, base_url, system_prompt, cost_callback)
```

CLI providers are not in this dict and cannot be constructed with that positional signature — they take `policy: CLIPolicy`, not `model` + `base_url`.

### Required change (D-10)

Add a CLI prefix set and early-return path before the existing `providers` lookup:

```python
CLI_PROVIDERS = {"claude-code", "gemini-cli", "codex", "qwen-code"}

def parse_fallback_spec(
    spec: str,
    system_prompt: str = "",
    cost_callback: Callable | None = None,
    default_provider: str | None = None,
    config: Any | None = None,   # ← NEW (D-10)
):
    parts = spec.split(":", 1)
    provider_candidate = parts[0].lower()

    if provider_candidate in CLI_PROVIDERS:
        if len(parts) == 2:  # noqa: PLR2004
            log.warning("CLI providers do not accept model sub-spec; ignoring", spec=spec)
        return initialize_llm(
            provider_candidate,
            system_prompt=system_prompt,
            cost_callback=cost_callback,
            config=config,
        )
    # ... existing API provider logic unchanged ...
```

### What `initialize_llm()` needs (already handles it)

```python
elif llm_arg in ("claude-code", "gemini-cli", "codex", "qwen-code"):
    from vulnhuntr.config import CLIPolicy
    policy = getattr(config, "cli", None) or CLIPolicy()
    overrides = policy.overrides.get(llm_arg, {})
    timeout = overrides.get("timeout", policy.timeout)
    workdir = overrides.get("workdir", policy.workdir)
    return ClaudeCodeLLM(system_prompt=system_prompt, cost_callback=cost_callback,
                         timeout=timeout, workdir=workdir, policy=policy)
```

`initialize_llm()` already reads the `CLIPolicy` from `config.cli`, applies per-provider overrides, and constructs the right class. **No duplication needed.**

### `wrap_with_fallbacks()` change (D-13)

Currently passes no `config` to `parse_fallback_spec()`:

```python
fb1 = parse_fallback_spec(fallback1, system_prompt, cost_callback, default_provider)
```

Must become:

```python
fb1 = parse_fallback_spec(fallback1, system_prompt, cost_callback, default_provider, config=config)
```

The `config` is already in scope inside `wrap_with_fallbacks()` — it's a parameter.

---

## Q5: CLIRuntimeError Inheritance

**Finding: VERIFIED** — all CLI errors inherit from `LLMError`.

From [vulnhuntr/cli_providers/base.py](vulnhuntr/cli_providers/base.py):

```python
class LLMError(Exception): ...         # in llms.py

class CLIBinaryNotFoundError(LLMError): ...
class CLIAuthError(LLMError): ...
class CLITimeoutError(LLMError): ...
class CLIParseError(LLMError): ...
class CLISandboxError(LLMError): ...
class CLIRuntimeError(LLMError): ...
```

`FallbackLLM.chat()` catches `LLMError`:

```python
except LLMError as e:
    log.error(f"LLM {llm.model} failed: {e}", ...)
    if i == len(self._all_llms) - 1:
        raise LLMError(...)
    continue
```

Any CLI provider failure (binary missing, auth, timeout, parse, runtime) will be caught. **No changes to FallbackLLM needed for error type compatibility.**

---

## Q6: TokenUsage Backward Compatibility

**Finding: VERIFIED** — adding `usage_type` and `provider_note` with defaults is fully backward-compatible.

### Current `TokenUsage` (dataclass)

```python
@dataclass
class TokenUsage(LLMUsage):
    cost_usd: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    file_path: str | None = None
    call_type: str = "analysis"
```

`LLMUsage` is a `@dataclass` with `input_tokens: int`, `output_tokens: int`, `model: str` — no defaults.

### All construction sites use keyword arguments

`CostTracker.track_call()`:
```python
usage = TokenUsage(
    input_tokens=input_tokens,
    output_tokens=output_tokens,
    model=model,
    cost_usd=cost,
    file_path=file_path,
    call_type=call_type,
)
```

No positional-arg constructions found in the codebase. Adding new fields with defaults at the end of the dataclass will not break any construction site.

### `from_dict()` must be updated

Current `from_dict()` does not include `usage_type` or `provider_note`. It must add:

```python
usage_type=data.get("usage_type", "api"),
provider_note=data.get("provider_note"),
```

### `to_dict()` must be updated

Must add:

```python
"usage_type": self.usage_type,
"provider_note": self.provider_note,
```

### Checkpoint compatibility

Existing checkpoint files will not have `usage_type` or `provider_note`. The `data.get("usage_type", "api")` fallback ensures old checkpoints load correctly. No migration needed.

---

## Q7: CostTracker.get_summary() Structure

**Finding: VERIFIED** — adding `"usage_by_type"` is safe; no key conflicts.

### Current return shape

```python
{
    "total_cost_usd": float,
    "total_input_tokens": int,
    "total_output_tokens": int,
    "total_tokens": int,
    "api_calls": int,
    "costs_by_file": dict[str, float],
    "costs_by_model": dict[str, float],
    "elapsed_seconds": float,
    "start_time": str,    # ISO format
}
```

### Adding `"usage_by_type"` (D-17)

The new key fits cleanly alongside the existing breakdown keys. No existing key is named `usage_by_type`.

### Supporting data structure in `CostTracker.__init__`

To compute `usage_by_type`, the tracker needs a per-type counter. The cleanest approach is to add a private dict:

```python
self._counts_by_type: dict[str, dict[str, int | float]] = {
    "api": {"calls": 0, "cost_usd": 0.0, "tokens": 0},
    "provider_reported": {"calls": 0, "cost_usd": 0.0},
    "subscription": {"calls": 0, "providers": []},
}
```

`track_call()` and `track_subscription_call()` update this dict based on the `usage_type` of the `TokenUsage` being recorded. `get_summary()` then includes:

```python
"usage_by_type": {
    "api": {"calls": N, "cost_usd": X, "tokens": Y},
    "provider_reported": {"calls": N, "cost_usd": X},
    "subscription": {"calls": N, "providers": ["claude-code", ...]},
}
```

### `track_subscription_call()` placement

It should be a new public method on `CostTracker` (alongside `track_call()`). It creates a `TokenUsage` with `input_tokens=0, output_tokens=0, cost_usd=0.0, usage_type="subscription"` and appends it to `self._calls`. The `subscription` type entry in `_counts_by_type` accumulates the provider name.

---

## Q8: FallbackLLM `_diagnostics` Attribute Safety

**Finding: VERIFIED** — `_diagnostics` must be set in `__init__`; `__getattr__` will raise `AttributeError` for it otherwise.

### The `__getattr__` delegation

```python
def __getattr__(self, name: str) -> Any:
    if name.startswith("_"):
        raise AttributeError(name)  # ← does NOT delegate underscore names
    return getattr(self._active, name)
```

Any underscore-prefixed attribute lookup on `FallbackLLM` that was not set in `__init__` raises `AttributeError` immediately. Python's attribute lookup only calls `__getattr__` when the normal attribute lookup fails, so attributes set in `__init__` via `self._diagnostics = ...` are found without hitting `__getattr__`.

### Required change

Add to `FallbackLLM.__init__`:

```python
def __init__(self, primary: LLM, fallbacks: list[LLM]) -> None:
    self._primary = primary
    self._fallbacks = fallbacks
    self._active: LLM = primary
    self._all_llms: list[LLM] = [primary] + fallbacks
    self._diagnostics: list[dict[str, Any]] = []  # ← ADD (D-19)
```

The `from __future__ import annotations` is already at the top of `llms.py`. `Any` is already imported via `from typing import Any`.

### Diagnostic entry append in `chat()`

The diagnostic append replaces the existing informal log message (D-18):

```python
log.warning(
    "provider_failed_falling_back",
    failed_provider=type(self._active).__name__,
    failed_model=getattr(self._active, "model", "unknown"),
    error_class=type(e).__name__,
    failure_reason=str(e),
    fallback_provider=type(llm).__name__,
    fallback_index=i,
)
self._diagnostics.append({
    "failed_provider": type(self._active).__name__,
    "error_class": type(e).__name__,
    "failure_reason": str(e)[:200],
    "fallback_to": type(llm).__name__,
})
```

Note: the current log call uses `f"Primary LLM failed, falling back to {llm.model}"` with `extra={}`. D-18 upgrades this to structured fields.

---

## Q9: Test Pattern for Async Mocking

**Finding: VERIFIED** — the test suite uses `unittest.mock.AsyncMock`; direct `_tools`/`_initialized` injection for unit tests; `patch("vulnhuntr.mcp.client.MCPClientManager")` for integration tests.

### Pattern 1: unit tests with manual injection (existing pattern)

```python
helper = MCPAnalysisHelper(_make_settings("auto"))
helper._tools = [ToolDescriptor("test-server", "scan", "Scan code")]
helper._initialized = True
# call synchronous methods directly
prompt = helper.get_tool_prompt_section()
```

### Pattern 2: async test with AsyncMock (for execute_tool_calls tests)

```python
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

@pytest.mark.asyncio  # or use asyncio.run() in a sync test
async def test_execute_tool_calls_success():
    helper = MCPAnalysisHelper(_make_settings("auto"))
    helper._initialized = True

    mock_client = MagicMock()
    mock_client.call_tool = AsyncMock(return_value={"content": [{"text": "scan output"}]})
    helper._client = mock_client

    requests = [MCPToolCallRequest(server="s", tool="t", arguments={})]
    results = await helper.execute_tool_calls(requests)
    assert results[0].success is True
    assert "scan output" in results[0].output
```

### Pattern 3: timeout test

```python
async def test_execute_tool_calls_timeout():
    helper = MCPAnalysisHelper(_make_settings("auto"))
    helper._initialized = True
    helper._policy = MCPAnalysisPolicy(mode="auto", tool_timeout_seconds=1)

    mock_client = MagicMock()
    async def slow_call(*args, **kwargs):
        await asyncio.sleep(10)
    mock_client.call_tool = slow_call
    helper._client = mock_client

    requests = [MCPToolCallRequest(server="s", tool="t", arguments={})]
    results = await helper.execute_tool_calls(requests)
    assert results[0].success is False
    assert "Timeout" in results[0].error
```

### Pattern 4: integration flow test (D-21/D-22)

```python
@patch("vulnhuntr.mcp.client.MCPClientManager")
def test_full_mcp_flow(MockManager):
    """Tool discovered → call requested → result injected into next prompt."""
    mock_instance = MockManager.return_value
    mock_instance.connect_all = AsyncMock()
    mock_instance.disconnect_all = AsyncMock()
    mock_instance.list_all_tools = AsyncMock(return_value={
        "scanner": [MagicMock(name="scan", description="desc", inputSchema={})]
    })
    mock_instance.call_tool = AsyncMock(return_value="vuln found")

    helper = MCPAnalysisHelper(_make_settings("auto"))
    run_async(helper.initialize())
    assert helper.is_active
    # proceed with tool call dispatch, assert format_results_for_prompt output
```

### `run_async()` vs `asyncio.run()` in tests

Tests that call `execute_tool_calls` directly can use either `asyncio.run()` or `pytest-asyncio`. The existing test suite uses synchronous tests that call `run_async()` directly (see `TestRunAsync`). The same pattern works for new tests.

---

## Q10: Phase 6 Stub Location for `_build_mcp_config_args()`

**Finding: VERIFIED** — stub is at [vulnhuntr/cli_providers/claude_code.py](vulnhuntr/cli_providers/claude_code.py) `ClaudeCodeLLM._build_mcp_config_args()`.

### Current stub

```python
def _build_mcp_config_args(self) -> list[str]:
    """...Phase 6 writes {"mcpServers": {}} as a stub. Phase 7 populates real servers."""
    policy = self._policy
    if not policy:
        return []
    if policy.mcp_mode not in ("vulnhuntr", "both"):
        return []
    workdir = self.workdir or "/tmp/vulnhuntr"
    config_path = pathlib.Path(workdir) / "mcp_config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text('{"mcpServers": {}}', encoding="utf-8")
    return ["--mcp-config", str(config_path)]
```

### Phase 7 replacement

The method needs access to `MCPSettings` to build real server definitions. The `ClaudeCodeLLM` constructor does not currently receive `MCPSettings` directly — it receives `CLIPolicy`. Options:

**Option A (recommended):** Accept `mcp_settings: MCPSettings | None = None` in `ClaudeCodeLLM.__init__` and store it. The runner passes it when constructing the provider during `_init_providers()`.

**Option B:** Read `MCPSettings` via `load_mcp_config()` inside the method (lazy load). This avoids changing the constructor signature.

### Claude Code `mcpServers` JSON format

Claude Code's `--mcp-config` flag expects:

```json
{
  "mcpServers": {
    "server-name": {
      "command": "npx",
      "args": ["-y", "mcp-server-name"],
      "env": {}
    }
  }
}
```

For HTTP/SSE transports, Claude Code uses the `url` key. The Phase 7 implementation must iterate over `MCPSettings.servers.items()` and convert each `MCPServerConfig` to the appropriate format. Only enabled servers should be included.

---

## Validation Architecture

### MCP Wiring Tests (D-21, D-22) — `tests/test_mcp_analysis.py`

| Test | Type | What to assert |
|------|------|----------------|
| `test_mcp_helper_injected_into_analyzer` | Unit | `VulnerabilityAnalyzer(llm, extractor, mcp_helper=helper)` stores `self.mcp_helper` |
| `test_no_mcp_helper_no_calls` | Unit | When `mcp_helper=None`, `execute_tool_calls` is never called |
| `test_tool_calls_dispatched_in_secondary_loop` | Integration | Mock LLM returns `Response(mcp_tool_calls=[...])` on iter 0; assert mock `execute_tool_calls` called |
| `test_tool_results_prepended_to_next_prompt` | Integration | Capture prompt passed to `llm.chat()` on iter 1; assert `<mcp_tool_results>` block present |
| `test_timeout_result_injected_not_raised` | Integration | `call_tool` is slow; assert `success=False` result in next prompt, no exception |
| `test_empty_tool_calls_skips_dispatch` | Unit | `Response(mcp_tool_calls=[])` → `execute_tool_calls` not called |

### CLI Fallback Chain Tests — `tests/test_cli.py` (`TestParseFallbackSpec`)

| Test | What to assert |
|------|----------------|
| `test_cli_provider_prefix_claude_code` | `parse_fallback_spec("claude-code", config=mock_config)` calls `ClaudeCodeLLM` |
| `test_cli_provider_prefix_gemini_cli` | Same for `gemini-cli` → `GeminiCLILLM` |
| `test_cli_provider_prefix_codex` | Same for `codex` → `CodexLLM` |
| `test_cli_provider_prefix_qwen_code` | Same for `qwen-code` → `QwenCodeLLM` |
| `test_cli_provider_sub_spec_ignored` | `"claude-code:something"` — warning logged, model part discarded |
| `test_cli_provider_no_config_uses_defaults` | `config=None` → `CLIPolicy()` defaults apply |

### Cost Reporting Tests — `tests/test_cost_tracker.py`

| Test | What to assert |
|------|----------------|
| `test_tokenusage_usage_type_default` | `TokenUsage(input_tokens=1, output_tokens=1, model="m").usage_type == "api"` |
| `test_tokenusage_subscription_type` | `TokenUsage(..., usage_type="subscription")` stores correctly |
| `test_tokenusage_round_trip_with_new_fields` | `to_dict()` then `from_dict()` preserves `usage_type` and `provider_note` |
| `test_from_dict_old_format_defaults` | `from_dict()` on dict without `usage_type` defaults to `"api"` |
| `test_track_subscription_call` | `tracker.track_subscription_call("claude-code")` → `call_count` incremented, cost stays 0 |
| `test_get_summary_usage_by_type` | After mixed calls, `get_summary()["usage_by_type"]["api"]["calls"]` is correct |
| `test_get_summary_subscription_providers` | Subscription providers accumulate in list |

### FallbackLLM Diagnostics Tests — `tests/test_llms.py`

| Test | What to assert |
|------|----------------|
| `test_diagnostics_initialized_empty` | `FallbackLLM(p, [f1])._diagnostics == []` |
| `test_diagnostics_populated_on_fallback` | Primary fails → `_diagnostics` has 1 entry with correct keys |
| `test_diagnostics_not_delegated_to_active` | `getattr(fallback_llm, "_diagnostics")` returns the list, not delegated |

### Integration Test Scenarios

**Scenario 1: Full MCP tool call loop (D-21)**
1. Create `MCPAnalysisHelper` with mocked `MCPClientManager`
2. Mock client returns one tool in `list_all_tools`
3. Initialize helper
4. Create `VulnerabilityAnalyzer` with injected `mcp_helper`
5. Mock LLM: first secondary call returns `Response(mcp_tool_calls=[MCPToolCallRequest(...)])`
6. Assert `execute_tool_calls` is called
7. Assert second LLM call receives prompt with `<mcp_tool_results>` block

**Scenario 2: Timeout path (D-22)**
1. `call_tool` is an `AsyncMock` that raises `asyncio.TimeoutError` after brief sleep
2. Assert `MCPToolCallResult(success=False, error=...)` is returned
3. Assert second iteration prompt contains the error result block
4. Assert no exception propagated to `analyze_file()`

**Scenario 3: CLI fallback chain**
1. Primary is `ClaudeCodeLLM` mock that raises `CLIRuntimeError`
2. Fallback spec is `"openrouter:qwen/qwen3-coder:free"`
3. Assert `FallbackLLM.chat()` catches the error and delegates to `OpenRouter`
4. Assert `_diagnostics` has one entry with `error_class="CLIRuntimeError"`

---

## Implementation Risk Register

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| Orphaned MCP dispatch in `_analyze_files()` not removed → double execution | HIGH | Explicitly task the cleanup as a Wave 0 step before adding new wiring |
| `format_results_for_prompt` vs `format_tool_results_for_prompt` name mismatch causes AttributeError | MEDIUM | Use the existing method name; add alias only if tests reference D-04 name |
| `asyncio.run()` inside `_secondary_analysis()` fails if called from async context in future | LOW | Use `run_async()` helper consistently; document the sync-only contract on `analyze_file()` |
| `_diagnostics` accidentally delegated through `__getattr__` before `__init__` sets it | HIGH (without fix) | Test that `FallbackLLM(p, [f])._diagnostics == []` immediately after construction |
| `from_dict()` in `TokenUsage` breaks on old checkpoint files without `usage_type` | MEDIUM | `data.get("usage_type", "api")` default handles it; add a round-trip test with old-format dict |
| CLI providers in fallback chain constructed without `CLIPolicy` (config=None path) | MEDIUM | `initialize_llm()` already falls back to `CLIPolicy()` defaults; confirm with a test for `config=None` |
| `_build_mcp_config_args()` in `ClaudeCodeLLM` needs `MCPSettings` but constructor does not take it | HIGH if not planned | Plan explicitly: either add `mcp_settings` param to constructor or use `load_mcp_config()` lazy load |
| `usage_by_type` subscription providers list accumulates duplicate entries | LOW | Deduplicate on read in `get_summary()`: `list(set(self._subscription_providers))` |

---

## Sources

All findings are `[VERIFIED]` from direct source code inspection. No external documentation required for this phase.

| File | What was checked |
|------|-----------------|
| `vulnhuntr/core/analysis.py` | `VulnerabilityAnalyzer.__init__`, `analyze_file()`, `_secondary_analysis()` loop structure |
| `vulnhuntr/mcp/analysis.py` | `execute_tool_calls()` full implementation; `format_results_for_prompt()` existence; `run_async()` |
| `vulnhuntr/mcp/config.py` | `MCPAnalysisPolicy.tool_timeout_seconds` default=30 |
| `vulnhuntr/core/models.py` | `Response.mcp_tool_calls` type; `MCPToolCallRequest`/`MCPToolCallResult` fields |
| `vulnhuntr/cli/runner.py` | `parse_fallback_spec()`, `wrap_with_fallbacks()`, `_analyze_files()` MCP block, `run_analysis()` MCP init |
| `vulnhuntr/llms.py` | `FallbackLLM.__init__`, `__getattr__`, `chat()` fallback logic |
| `vulnhuntr/cost_tracker.py` | `TokenUsage` dataclass fields; `CostTracker.track_call()`, `get_summary()` return shape |
| `vulnhuntr/cli_providers/base.py` | Error hierarchy (`CLIRuntimeError(LLMError)`) |
| `vulnhuntr/cli_providers/claude_code.py` | `ClaudeCodeLLM.__init__` params; `_build_mcp_config_args()` stub |
| `tests/test_mcp_analysis.py` | Async mocking patterns; `run_async()` usage |
| `tests/test_cli.py` | `TestParseFallbackSpec` class structure |
