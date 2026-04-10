# Roadmap: Vulnhuntr

**Milestone:** 1.0 — Foundation & MCP Integration
**Created:** 2026-04-08
**Total phases:** 4
**v1 requirements:** 18 mapped, 18 covered ✓

---

## Standing Rules (all phases)

- **Comments**: no AI-pattern prose; follow `.github/skills/humanize-project/SKILL.md` before any commit
- **Commits**: natural, direct messages — no "This commit...", no bullet-list summaries, no AI attribution
- **MCP tools**: run `analyzer` (ruff + vulture) before committing; use `semgrep` on security-adjacent changes; use `context7` before asserting library API behavior; use `osv-scanner` before adding deps
- **Skills**: load the relevant `.github/skills/` or `.opencode/skills/` file before working in its domain
- **Ignored paths**: `.git/info/exclude` and `.gitignore` are hard stops — no force-adding, ever

---

## Phases Overview

| # | Phase | Goal | Requirements | Success Criteria |
|---|-------|------|--------------|------------------|
| 1 | Quick Wins & Test Infrastructure | Fix standalone bugs, enforce coverage, add integration test scaffold | INFRA-01–04 | 4 |
| 2 | Runner Decomposition | Break 714-line monolith into testable pipeline stages | RUNNER-01–06 | 5 |
| 3 | MCP Pipeline Integration | Wire MCPClientManager into analysis loop | MCP-01–05 | 5 |
| 4 | Analysis Quality | Externalize pricing, expand vuln types, test fallback chain | QUALITY-01–03 | 4 |

---

## Phase Details

### Phase 1: Quick Wins & Test Infrastructure

**Goal:** Fix standalone bugs (no risk to core pipeline), establish test coverage enforcer, and add an integration test entry point for the full analysis flow.

**Requirements:**
- INFRA-01: Checkpoint version uses actual package version
- INFRA-02: `--analyze` path validated within `--root`
- INFRA-03: Coverage threshold ≥72% enforced in CI
- INFRA-04: Full `run_analysis()` integration test passes with mocked LLM

**Plans:** 2 plans

Plans:
- [x] 01-01-PLAN.md — version fix (INFRA-01), traversal guard production code (INFRA-02), coverage threshold (INFRA-03)
- [x] 01-02-PLAN.md — traversal guard tests (INFRA-02) + run_analysis integration test (INFRA-04)

**Success Criteria:**
1. `pytest --cov=vulnhuntr` passes with ≥72% coverage without failures
2. `CheckpointData().vulnhuntr_version == "1.2.1"` (or current package version)
3. `vulnhuntr -r /tmp -a ../../etc/passwd` raises validation error or equivalent
4. Integration test for `run_analysis()` passes without any real API call
5. All 628 existing tests continue to pass

**Depends on:** (none — fully independent)
**UI hint:** no

---

### Phase 2: Runner Decomposition

**Goal:** Extract the 714-line `run_analysis()` monolith into 5 independently testable stage functions and add LLM factory injection, without changing external behavior.

**Requirements:**
- RUNNER-01: `_init_providers()` stage extracted and independently testable
- RUNNER-02: `_collect_files()` stage extracted and independently testable
- RUNNER-03: `_analyze_files()` stage extracted and independently testable
- RUNNER-04: `_dispatch_reports()` stage extracted and independently testable
- RUNNER-05: `_dispatch_integrations()` stage extracted and independently testable
- RUNNER-06: `run_analysis()` accepts optional `llm_factory` callable

**Plans:** 4 plans

Plans:
- [ ] 02-01-PLAN.md — extract _init_providers() (RUNNER-01) and _collect_files() (RUNNER-02)
- [ ] 02-02-PLAN.md — extract _analyze_files() (RUNNER-03) and add llm_factory param (RUNNER-06)
- [ ] 02-03-PLAN.md — add _dispatch_reports alias (RUNNER-04) and _dispatch_integrations() (RUNNER-05)
- [ ] 02-04-PLAN.md — per-stage unit tests and TestRunAnalysisIntegration refactor (RUNNER-01–06)

**Success Criteria:**
1. `runner.py` is ≤200 non-blank lines in the `run_analysis()` function itself
2. Each of the 5 stage functions has at least 2 unit tests
3. `_dispatch_integrations()` tested with mocked GitHub and webhook clients
4. Fallback LLM chain (`primary → fallback1 → fallback2`) covered by a test for `_init_providers()`
5. All 628+ existing tests continue to pass; coverage does not drop below 72%

**Depends on:** Phase 1 (coverage threshold must be set before refactor so regressions are caught)
**UI hint:** no

---

### Phase 3: MCP Pipeline Integration

**Goal:** Wire `MCPClientManager` into `VulnerabilityAnalyzer` so that LLM `mcp_tool_calls` in a `Response` actually invoke MCP server tools and inject results into the next analysis iteration.

**Requirements:**
- MCP-01: `VulnerabilityAnalyzer` accepts optional `MCPClientManager` parameter
- MCP-02: LLM `mcp_tool_calls` in `Response` cause actual MCP tool invocations
- MCP-03: MCP tool results injected as context into next LLM iteration
- MCP-04: MCP tool calls time out cleanly (no hang on slow/unresponsive server)
- MCP-05: Integration test verifies tool call → result → next-iteration flow

**Plans:**
1. Add `mcp_manager: MCPClientManager | None = None` to `VulnerabilityAnalyzer.__init__()` — backward-compatible; None = existing behavior
2. In `VulnerabilityAnalyzer` iteration loop: after receiving `Response`, check `response.mcp_tool_calls`; if non-empty and `mcp_manager` is not None, execute each call via `mcp_manager.call_tool()`
3. Wrap each MCP tool call with `asyncio.wait_for(coro, timeout=server_config.timeout)` — catch `asyncio.TimeoutError`, log warning, inject `MCPToolCallResult(success=False, error="timeout")`
4. Update `_analyze_files()` (from Phase 2) to create/pass `MCPClientManager` based on config
5. Write `tests/test_mcp_analysis.py` integration test: mock `MCPClientManager.call_tool()`, verify results appear in next LLM call's context

**Success Criteria:**
1. Analysis run with MCP config in `.vulnhuntr.yaml` passes tools to LLM without error
2. A test fixture with a stubbed MCP server confirms tool call results appear in the second LLM iteration context
3. Analysis with a non-responding MCP server times out within `server.timeout` seconds and continues (does not hang)
4. Analysis run without MCP config (`mcp_manager=None`) behaves identically to pre-Phase-3 behavior (no regression)
5. `vulnhuntr/mcp/client.py` docstring updated to remove "NOT integrated" notice

**Depends on:** Phase 2 (clean `_analyze_files()` stage makes MCP injection obvious)
**UI hint:** no

---

### Phase 4: Analysis Quality

**Goal:** Externalize the hardcoded pricing dict so users can override it, add at least one new OWASP Top 10 vulnerability type, and add an integration test proving the fallback LLM chain works correctly.

**Requirements:**
- QUALITY-01: Pricing data overridable via `.vulnhuntr.yaml` `pricing:` section
- QUALITY-02: At least one new vulnerability type (CSRF or auth bypass) with prompt template
- QUALITY-03: Fallback LLM chain integration test (primary fail → fallback1 invoked)

**Plans:**
1. Add `pricing` section parsing to `vulnhuntr/config.py` `VulnhuntrConfig` — dict of model → {input, output} overrides; merged with `PRICING_TABLE` at runtime
2. Update `cost_tracker.get_model_pricing()` to check config-supplied overrides first
3. Add `VulnType.CSRF = "CSRF"` (CWE-352) + `CSRF_TEMPLATE` prompt in `vulnhuntr/prompts.py` + wiring in `cli/runner.py` `vuln_specific_data`
4. Add integration test for fallback chain: mock primary LLM to raise `APIStatusError(429, ...)`, assert second `_init_providers()` pass uses `fallback1`

**Success Criteria:**
1. A `.vulnhuntr.yaml` with `pricing: { "my-model": { input: 0.001, output: 0.003 } }` is used in cost estimates
2. `vulnhuntr -r /path/to/project` with a CSRF-vulnerable endpoint produces a CSRF finding at confidence ≥ 1
3. Fallback chain test passes: primary 429 → fallback1 invoked → analysis completes
4. `PRICING_TABLE` in `cost_tracker.py` still works as default when no config override exists
5. All 628+ tests continue to pass; coverage stays ≥72%

**Depends on:** Phase 2 (`_init_providers()` must be extracted to test fallback chain cleanly)
**UI hint:** no

---

## Requirements Coverage

| Requirement | Phase | Description |
|-------------|-------|-------------|
| INFRA-01 | 1 | Checkpoint version fix |
| INFRA-02 | 1 | Path traversal guard |
| INFRA-03 | 1 | Coverage threshold |
| INFRA-04 | 1 | Integration test scaffold |
| RUNNER-01 | 2 | `_init_providers()` extraction |
| RUNNER-02 | 2 | `_collect_files()` extraction |
| RUNNER-03 | 2 | `_analyze_files()` extraction |
| RUNNER-04 | 2 | `_dispatch_reports()` extraction |
| RUNNER-05 | 2 | `_dispatch_integrations()` extraction |
| RUNNER-06 | 2 | LLM factory injection |
| MCP-01 | 3 | VulnerabilityAnalyzer MCP param |
| MCP-02 | 3 | Response mcp_tool_calls invocation |
| MCP-03 | 3 | Tool results → next iteration context |
| MCP-04 | 3 | Timeout safety |
| MCP-05 | 3 | MCP integration test |
| QUALITY-01 | 4 | Pricing override |
| QUALITY-02 | 4 | New vuln type (CSRF) |
| QUALITY-03 | 4 | Fallback chain test |

**Total v1:** 18 requirements, 18 mapped ✓

---
*Roadmap created: 2026-04-08*
