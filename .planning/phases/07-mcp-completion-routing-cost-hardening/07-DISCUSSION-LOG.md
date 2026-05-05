# Phase 7 Discussion Log

**Mode:** `--all --auto --analyze` (fully autonomous, all gray areas, trade-off tables)
**Date:** 2026-05-04

---

## Area 1: MCP wiring into VulnerabilityAnalyzer

**Trade-off table reviewed.** Options:
- Constructor injection with `asyncio.run()` bridge at call sites
- Runner-level static context (tools baked in before analyzer builds)
- Full async `analyze_file()` (refactor)

**Selected:** Constructor injection + `asyncio.run()` bridge. Rationale: zero
change to `analyze_file()` synchronous contract; runner already uses `asyncio.run()`
for `_build_mcp_config_args()`; mockable in tests via same pattern as `config`.

**Decisions:** D-01, D-02, D-03

---

## Area 2: Tool result injection shape

**Trade-off table reviewed.** Options:
- XML prompt section (`<mcp_tool_results>` prepended to next iteration)
- New history message
- Append to code context dict

**Selected:** XML prompt section. Rationale: `get_tool_prompt_section()` already
defines the pattern in `MCPAnalysisHelper`; symmetric XML tag approach is clean;
no history mutation keeps the loop simple.

**Decisions:** D-04, D-05, D-06

---

## Area 3: MCP timeout architecture

**Trade-off table reviewed.** Options:
- `asyncio.wait_for()` per call inside `execute_tool_calls()`
- Session-level overall timeout
- Both

**Selected:** Per-call `asyncio.wait_for()`. Rationale: a single hung call should
not block other tools in the batch; `MCPAnalysisPolicy.tool_timeout_seconds` already
exists as the right config source; error result (not exception) keeps scan continuous.

**Decisions:** D-07, D-08, D-09

---

## Area 4: CLI providers in fallback chains

**Trade-off table reviewed.** Options:
- Extend `parse_fallback_spec` with `config` param + CLI provider prefixes
- Separate YAML fallback section for CLI providers
- Unified factory delegation to `initialize_llm`

**Selected:** Extend `parse_fallback_spec` with optional `config` parameter.
Rationale: minimal surface area change; `CLIRuntimeError ⊂ LLMError` so `FallbackLLM`
already handles CLI failures; `wrap_with_fallbacks` passes `config` through.

**Decisions:** D-10, D-11, D-12, D-13

---

## Area 5: Cost/usage reporting categories

**Trade-off table reviewed.** Options:
- `usage_type` Literal field on `TokenUsage` (`"api"` / `"provider_reported"` / `"subscription"`)
- Separate `SubscriptionUsage` dataclass
- New `track_subscription_call()` method only

**Selected:** `usage_type` literal + `provider_note` on `TokenUsage` + `track_subscription_call()`.
Rationale: backward-compatible (default `"api"`); all existing call sites unaffected;
`get_summary()` breakdown gives operators the three-way split without two different
data structures to maintain.

**Decisions:** D-14, D-15, D-16, D-17

---

## Area 6: Provider diagnostic events

**Trade-off table reviewed.** Options:
- Structured structlog events only
- `_diagnostics` list on `FallbackLLM` only
- Both

**Selected:** Both (structured log events + `_diagnostics` list). Rationale:
structured logs serve ops; `_diagnostics` list serves the runner's `--verbose` summary
without coupling the fallback class to output formatting.

**Decisions:** D-18, D-19, D-20

---

## Auto-mode pass complete

Single-pass cap enforced (--auto). No user questions asked. All 6 gray areas
resolved. Advancing to `gsd-plan-phase 07 --auto`.
