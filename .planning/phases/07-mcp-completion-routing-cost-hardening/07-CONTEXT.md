# Phase 7: MCP Completion, Routing, and Cost Hardening - Context

**Gathered:** 2026-05-04
**Status:** Ready for planning

<domain>
## Phase Boundary

Finish the three work streams that were deferred from earlier phases:

1. **MCP pipeline completion** — wire `MCPAnalysisHelper` into `VulnerabilityAnalyzer`
   so MCP tools actually participate in iterative analysis when `mcp_mode` is active.
   Includes timeout-bounded tool execution so a hung MCP call cannot block a scan.

2. **Mixed provider routing** — extend the fallback chain to support CLI providers
   alongside API providers so `FallbackLLM` can transparently fall through to
   `claude-code`, `codex`, etc. when an API provider fails.

3. **Cost and usage reporting** — distinguish exact API cost, provider-reported cost,
   and unattributable subscription usage so operators see meaningful numbers for CLI
   and subscription-backed backends.

Out of scope: behavioral evaluation (Phase 8), transition-aware tests (Phase 9),
report integration of diagnostics (Phase 10), new `CLIPolicy` fields.

</domain>

<decisions>
## Implementation Decisions

### MCP Wiring into VulnerabilityAnalyzer (MCP-01)

- **D-01:** `VulnerabilityAnalyzer.__init__` gains an optional parameter:
  ```python
  mcp_helper: MCPAnalysisHelper | None = None
  ```
  This is constructor injection — same pattern as `config` and `prompt_templates`. The
  caller (runner) creates and initializes the helper; the analyzer only calls it.

- **D-02:** The runner creates `MCPAnalysisHelper` when `mcp_mode != "none"` and
  `MCPSettings` is present. It calls `asyncio.run(helper.initialize())` before
  constructing `VulnerabilityAnalyzer`, passes the helper in, and calls
  `asyncio.run(helper.shutdown())` in the finally block after `analyze_file()` returns.
  `VulnerabilityAnalyzer` itself stays synchronous.

- **D-03:** When `mcp_helper` is `None` or `mcp_helper.is_active` is `False`,
  `analyze_file()` runs unchanged — zero behavioral difference for existing users.

### Tool Result Injection (MCP-02, MCP-03)

- **D-04:** `MCPAnalysisHelper` gains a new method:
  ```python
  def format_tool_results_for_prompt(self, results: list[MCPToolCallResult]) -> str:
  ```
  Returns an `<mcp_tool_results>...</mcp_tool_results>` XML block, parallel to the
  existing `<mcp_tools>` section from `get_tool_prompt_section()`. Empty string if
  `results` is empty.

- **D-05:** Inside the `analyze_file()` secondary-analysis loop, after receiving a
  `Response` that contains `mcp_tool_calls`, the analyzer:
  1. Calls `asyncio.run(mcp_helper.execute_tool_calls(response.mcp_tool_calls))` to get
     `list[MCPToolCallResult]`.
  2. Calls `format_tool_results_for_prompt(results)` to get the XML block.
  3. Prepends the XML block to the next iteration's user prompt string.
  No history manipulation — the results appear as part of the next user message.

- **D-06:** If `mcp_tool_calls` is empty or `mcp_helper` is `None`, step D-05 is
  skipped entirely. No extra prompting overhead.

### MCP Timeout Handling (MCP-04)

- **D-07:** Timeout enforcement lives inside `MCPAnalysisHelper.execute_tool_calls()`.
  Each individual tool call is wrapped with `asyncio.wait_for(call_coro, timeout=...)`.
  The timeout value comes from `MCPAnalysisPolicy.tool_timeout_seconds` (already on
  the policy dataclass).

- **D-08:** On `asyncio.TimeoutError`, the call produces:
  ```python
  MCPToolCallResult(
      server=request.server,
      tool=request.tool,
      success=False,
      error=f"timeout after {timeout}s",
  )
  ```
  Scan continues with the error result injected as context — never silently dropped,
  never fatal. The LLM sees that the tool timed out.

- **D-09:** If `MCPAnalysisPolicy.tool_timeout_seconds` is not set, default to `30`.
  Researcher confirms whether this field already has a default; if not, planner adds one.

### CLI Providers in Fallback Chains (ROUTING-01)

- **D-10:** `parse_fallback_spec` gains an optional `config: VulnhuntrConfig | None = None`
  parameter. When the provider prefix is a CLI provider name (`claude-code`, `gemini-cli`,
  `codex`, `qwen-code`), the function delegates to `initialize_llm(provider_name, ...)`,
  which already knows how to construct CLI providers from config. The `providers` dict
  fast-path is unchanged for API providers.

- **D-11:** Supported CLI prefixes in fallback specs:
  ```
  claude-code       → ClaudeCodeLLM (requires config for CLIPolicy)
  gemini-cli        → GeminiCLILLM
  codex             → CodexLLM
  qwen-code         → QwenCodeLLM
  ```
  Format: `claude-code` (no model sub-spec for CLI providers — they don't take a model
  name argument). If a user writes `claude-code:something`, the `something` part is
  ignored with a warning.

- **D-12:** `FallbackLLM.chat()` already catches `LLMError`. `CLIRuntimeError` is a
  subclass of `LLMError` (established Phase 3) — no changes to `FallbackLLM` needed
  for error type compatibility. The existing fallback logic works for CLI providers.

- **D-13:** `wrap_with_fallbacks()` in `runner.py` passes `config` down to
  `parse_fallback_spec` so CLI providers can be constructed with the correct `CLIPolicy`.

### Cost/Usage Reporting for Mixed Backends (ROUTING-02, ROUTING-03)

- **D-14:** Add `usage_type` field to `TokenUsage`:
  ```python
  usage_type: Literal["api", "provider_reported", "subscription"] = "api"
  ```
  - `"api"` — exact token counts from an API response (current behavior, all existing
    call sites default here).
  - `"provider_reported"` — token or cost estimate reported by the CLI tool itself
    (e.g., Claude Code outputs usage in its JSON envelope).
  - `"subscription"` — no token data available; provider is subscription-backed.

- **D-15:** Add an optional `provider_note: str | None = None` field to `TokenUsage`
  for human-readable context (e.g., `"claude-code subscription; no per-call cost"`).
  Serialized in `to_dict()` / loaded in `from_dict()`.

- **D-16:** `CostTracker` gains a new method:
  ```python
  def track_subscription_call(
      self,
      provider: str,
      file_path: str | None = None,
      call_type: str = "analysis",
      note: str | None = None,
  ) -> None:
  ```
  Records a `TokenUsage` with `usage_type="subscription"`, `input_tokens=0`,
  `output_tokens=0`, `cost_usd=0.0`. CLI provider `cost_callback` can call either
  `track_call()` (if it has usage data) or `track_subscription_call()` (if not).

- **D-17:** `CostTracker.get_summary()` returns a dict that adds a new
  `"usage_by_type"` key:
  ```python
  {
      "api": {"calls": N, "cost_usd": X, "tokens": Y},
      "provider_reported": {"calls": N, "cost_usd": X},
      "subscription": {"calls": N, "providers": ["claude-code", ...]},
  }
  ```
  The CLI output (`print_cost_summary`) reads this and renders each type with a
  distinct label so operators see the breakdown.

### Provider Diagnostic Events (ROUTING-04)

- **D-18:** `FallbackLLM.chat()` upgrades the existing informal log message to a
  structured structlog event:
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
  ```

- **D-19:** `FallbackLLM` gains a `_diagnostics: list[dict[str, Any]]` attribute
  initialized to `[]`. Each time a fallback occurs, append a diagnostic entry:
  ```python
  {
      "failed_provider": type(self._active).__name__,
      "error_class": type(e).__name__,
      "failure_reason": str(e)[:200],
      "fallback_to": type(llm).__name__,
  }
  ```

- **D-20:** The runner checks `getattr(llm, "_diagnostics", [])` after `run_analysis()`
  completes. When `--verbose` is set and diagnostics exist, it prints a compact
  provider-failure summary to stderr. No report integration — that's Phase 10.

### Integration Tests (MCP-05)

- **D-21:** Add tests verifying the full MCP tool call → result → next-iteration flow.
  Use `unittest.mock.patch("vulnhuntr.mcp.client.MCPClientManager")` (same patch
  pattern as existing provider tests). Tests live in `tests/test_mcp_analysis.py`
  (existing file already has model-level tests; add integration-flow tests there).

- **D-22:** The mock must simulate: tool discovered → tool call requested by LLM →
  `execute_tool_calls()` invoked → result injected → next iteration prompt contains the
  `<mcp_tool_results>` block. Test the timeout path too: mock raises `asyncio.TimeoutError`
  and assert that `success=False` result is returned, not an exception.

### the agent's Discretion

- Whether to add a `MCPAnalysisMode` guard in `analyze_file()` that checks
  `mcp_helper.mode` before calling `execute_tool_calls` — planner decides if the
  policy check is better placed in `execute_tool_calls` itself or at the call site.
- Whether `track_subscription_call()` should accept a `tokens_estimate` optional
  param for CLI tools that can report approximate usage — planner decides based on
  whether any current provider actually provides this.
- Exact field name for the cost summary `usage_by_type` key — planner may choose
  `breakdown_by_type` or similar if `usage_by_type` conflicts with existing keys.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### MCP Pipeline
- `vulnhuntr/mcp/analysis.py` — `MCPAnalysisHelper` lifecycle and `execute_tool_calls()`; `ToolDescriptor` and `get_tool_prompt_section()` pattern to follow for `format_tool_results_for_prompt()`
- `vulnhuntr/mcp/client.py` — `MCPClientManager`; note the module-level docstring "NOT integrated into analysis pipeline" — Phase 7 removes this caveat
- `vulnhuntr/mcp/config.py` — `MCPSettings`, `MCPAnalysisPolicy`, `MCPAnalysisMode`; `tool_timeout_seconds` field location
- `vulnhuntr/core/models.py` — `MCPToolCallRequest`, `MCPToolCallResult`, `MAX_TOOL_RESULT_CHARS`, `Response.mcp_tool_calls` field

### Core Analysis
- `vulnhuntr/core/analysis.py` — `VulnerabilityAnalyzer.__init__` signature and `analyze_file()` loop; injection point for `mcp_helper` parameter
- `vulnhuntr/cli/runner.py` — `_init_providers()`, `wrap_with_fallbacks()`, `parse_fallback_spec()`, `run_analysis()`; Phase 7 modifies all four

### Fallback + Cost
- `vulnhuntr/llms.py` — `FallbackLLM.chat()` (L494+); fallback failure logging and `_active` LLM tracking
- `vulnhuntr/cost_tracker.py` — `TokenUsage`, `CostTracker.track_call()`, `CostTracker.get_summary()`; D-14 through D-17 extend these

### Phase 6 Decisions (carry forward)
- `.planning/phases/06-sessions-native-tools-mcp-policy/06-CONTEXT.md` — D-12 (`mcp_mode` values), D-13 (`_build_mcp_config_args()` hook), D-14 (MCP warning for non-Claude providers), D-15 (stub → real content in Phase 7)

### Existing Tests (patterns to follow)
- `tests/test_mcp_analysis.py` — existing model-level tests; new integration tests go here (D-21, D-22)
- `tests/test_cli.py` — `TestParseFallbackSpec` class; D-10 adds CLI prefix tests here

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `MCPAnalysisHelper.execute_tool_calls()` — already implemented; just needs a
  `asyncio.wait_for()` wrapper per call for D-07/D-08
- `MCPAnalysisHelper.get_tool_prompt_section()` — exact model for
  `format_tool_results_for_prompt()` (D-04); XML-tag pattern, empty-string fallback
- `FallbackLLM` — already catches `LLMError`; `_diagnostics` attribute is purely additive
- `CostTracker.track_call()` — all call sites pass `input_tokens, output_tokens, model`;
  adding `usage_type` defaulting to `"api"` is backward-compatible

### Established Patterns
- `asyncio.run()` at call sites for async operations in the sync pipeline — already used
  for `_build_mcp_config_args()` in `ClaudeCodeLLM`; same bridge for MCP tool calls
- Constructor injection with `None` defaults — `VulnerabilityAnalyzer` already does this
  for `config`, `prompt_templates`, `vuln_specific_data`
- `unittest.mock.patch("subprocess.run")` for CLI provider tests — D-21/D-22 follows
  the same patch target style for `MCPClientManager`
- `structlog.get_logger()` structured events — every module already uses structlog;
  D-18 adds structured fields to an existing log call

### Integration Points
- `VulnerabilityAnalyzer.__init__` — add `mcp_helper` parameter (D-01)
- `analyze_file()` secondary loop — add MCP tool call → injection block (D-05)
- `runner.run_analysis()` — initialize/shutdown helper around analyzer call (D-02)
- `runner.wrap_with_fallbacks()` → `parse_fallback_spec()` — add CLI prefixes (D-10, D-13)
- `cost_tracker.TokenUsage` — add `usage_type` + `provider_note` fields (D-14, D-15)
- `cost_tracker.CostTracker` — add `track_subscription_call()` + extend `get_summary()` (D-16, D-17)
- `llms.FallbackLLM.chat()` — upgrade log + add `_diagnostics` list (D-18, D-19)
- `cli/runner.run_analysis()` — print diagnostic summary when `--verbose` (D-20)

</code_context>

<specifics>
## Specific Ideas

- Phase 6 left `_build_mcp_config_args()` returning `{"mcpServers": {}}` stub in
  `ClaudeCodeLLM`. Phase 7 makes it read from `MCPSettings` and write real server
  definitions (D-15 from Phase 6 explicitly calls this out).
- `MCPAnalysisHelper.execute_tool_calls()` currently has no timeout — D-07 adds it.
  The timeout should be per-call, not per-batch.
- `FallbackLLM._diagnostics` should be initialized in `__init__` (not `__getattr__`)
  to avoid the `__getattr__` delegation path.

</specifics>

<deferred>
## Deferred Ideas

- Report-level integration of provider diagnostics (fallback table in HTML/JSON report) — Phase 10
- Per-provider cost budgets with CLI subscription cost estimation — future enhancement
- MCP server health probing before scan starts — could land in Phase 10 or a future phase
- `asyncio.wait_for` session-level overall MCP timeout — not needed given per-call timeouts; park for if per-call proves insufficient
</deferred>
