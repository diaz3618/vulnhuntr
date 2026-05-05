# Requirements: Vulnhuntr

**Defined:** 2026-04-08
**Revised:** 2026-05-01
**Milestone:** v1.0 — Foundation, MCP, AI CLI Integration, and Verification Hardening
**Core Value:** Find real, remotely-exploitable vulnerabilities that automated pattern-matching SAST tools miss, while giving operators flexible execution backends and bounded, understandable cost/runtime tradeoffs.

## v1.0 Requirements

### Foundation Completed

- [x] **INFRA-01**: Checkpoint files record the correct package version
- [x] **INFRA-02**: `--analyze` path argument is validated to stay within `--root`
- [x] **INFRA-03**: CLI test coverage threshold is enforced in CI/local pytest
- [x] **INFRA-04**: Full `run_analysis()` integration test passes with a mocked LLM provider
- [x] **RUNNER-01**: LLM initialization extracted into an independently testable stage
- [x] **RUNNER-02**: File collection extracted into an independently testable stage
- [x] **RUNNER-03**: Analysis loop extracted into an independently testable stage
- [x] **RUNNER-04**: Report dispatch extracted into an independently testable stage
- [x] **RUNNER-05**: Integration dispatch extracted into an independently testable stage
- [x] **RUNNER-06**: `run_analysis()` accepts optional LLM factory callable for test injection

### Vulnhuntr MCP Completion

- [ ] **MCP-01**: `VulnerabilityAnalyzer` accepts an optional `MCPClientManager` parameter
- [ ] **MCP-02**: LLM `mcp_tool_calls` in `Response` cause actual MCP tool invocations during analysis
- [ ] **MCP-03**: MCP tool results are injected as context into the next LLM iteration
- [ ] **MCP-04**: MCP tool calls time out cleanly and never hang the scan
- [ ] **MCP-05**: Integration tests verify tool call → result → next-iteration flow

### CLI Provider Contract

- [ ] **AICLI-01**: Vulnhuntr has a provider-neutral CLI transport layer that extends the current `LLM` abstraction without breaking API providers
- [ ] **AICLI-02**: Vulnhuntr probes CLI provider capabilities at startup and fails early with actionable diagnostics if required features are missing
- [ ] **AICLI-03**: CLI provider outputs are normalized into validated Vulnhuntr responses and usage metadata
- [ ] **AICLI-04**: CLI provider failures are classified into install, auth, timeout, parse, sandbox, and runtime errors with operator-friendly messages

### Supported CLI Providers

- [ ] **CLAUDECLI-01**: Claude Code works as a first-class Vulnhuntr backend in headless mode
- [ ] **GEMINI-CLI-01**: Gemini CLI works as a first-class Vulnhuntr backend in headless mode
- [ ] **CODEX-01**: Codex works as a first-class Vulnhuntr backend in headless mode
- [ ] **QWEN-01**: Qwen Code works as a first-class Vulnhuntr backend in headless mode

### Config and Environment

- [ ] **CONFIG-01**: `.vulnhuntr.yaml` supports selecting CLI providers anywhere `llm.provider` is used today
- [ ] **CONFIG-02**: `.vulnhuntr.yaml` supports CLI runtime policy fields for timeout, workdir, auth mode, session mode, approval mode, sandbox mode, max turns, and MCP mode
- [ ] **CONFIG-03**: Provider-specific overrides can be set without forcing every provider to share the same knobs
- [ ] **CONFIG-04**: `.env` and docs cover Vulnhuntr-specific CLI env vars and provider-owned auth/config precedence
- [ ] **CONFIG-05**: Example config generation includes the new CLI-tool sections

### Sessions and Native Tooling

- [ ] **SESSION-01**: Vulnhuntr supports stateless and resumable session modes wherever the selected provider supports them
- [ ] **SESSION-02**: Vulnhuntr records session identifiers and workdir context when scans resume provider sessions
- [ ] **SESSION-03**: Vulnhuntr has an explicit policy for provider-native tools and shell access during scans
- [ ] **SESSION-04**: Vulnhuntr has an explicit policy for provider-native MCP versus Vulnhuntr-managed MCP

### Routing, Cost, and Diagnostics

- [ ] **ROUTING-01**: API and CLI providers can coexist in the same fallback chain
- [ ] **ROUTING-02**: Pricing overrides remain configurable for API providers and can be extended without breaking CLI providers
- [ ] **ROUTING-03**: Usage and cost reporting distinguishes exact API cost, provider-reported cost, and unattributable subscription-backed usage
- [ ] **ROUTING-04**: Fallback and provider diagnostics make it obvious why a backend failed and which backend took over

### Behavioral Evaluation and Test Adequacy

- [ ] **EVAL-01**: Vulnhuntr records structured execution traces for critical provider flows, including probe results, response validation, tool calls, fallback decisions, and session decisions
- [ ] **EVAL-02**: Behavioral evaluations assert semantic and procedural correctness for multi-step provider flows, not just final output shape
- [ ] **EVAL-03**: Critical CLI config and provider-selection paths have equivalence-partition and boundary-focused tests
- [ ] **EVAL-04**: Critical fallback, resume, and MCP flows have explicit branch and state-transition coverage goals
- [ ] **EVAL-05**: High-risk parsing and context-propagation code has targeted data-flow-aware tests around definitions, uses, and propagation of results
- [ ] **EVAL-06**: Runtime invariants are defined and tested for provider progression, fallback ordering, session policy, and MCP/tool-result handling

### Verification and Docs

- [ ] **VERIFY-01**: Each CLI provider has mocked adapter tests covering success, timeout, parse failure, and missing-binary behavior
- [ ] **VERIFY-02**: Optional live tests exist for installed CLI providers and are clearly marked/documented
- [ ] **VERIFY-03**: QUICKSTART and architecture docs explain installation, auth, config, fallback, and troubleshooting for CLI providers
- [ ] **VERIFY-04**: Verification docs define the trace evidence and invariants required before declaring provider integration complete

## Future Requirements

### Post-CLI Expansion

- **QUALITY-02**: Add at least one new vulnerability type beyond the current 7
- **LANG-01**: Establish multi-language support foundation
- **AGENT-01**: Explore provider-native planning or agent workflows only after scan transport is stable

## Out of Scope

| Feature | Reason |
|---------|--------|
| Removing direct API providers | Explicitly out of scope for this milestone |
| Turning Vulnhuntr into a general coding agent | Product focus remains vulnerability analysis |
| Default write-capable provider execution | Too risky for a scanner default |
| Full provider SDK rewrite on day one | Headless CLI transport is the lower-maintenance path |
| Cross-host provider session portability guarantees | Not all tools guarantee this today |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| INFRA-01 | Phase 1 | Done |
| INFRA-02 | Phase 1 | Done |
| INFRA-03 | Phase 1 | Done |
| INFRA-04 | Phase 1 | Done |
| RUNNER-01 | Phase 2 | Done |
| RUNNER-02 | Phase 2 | Done |
| RUNNER-03 | Phase 2 | Done |
| RUNNER-04 | Phase 2 | Done |
| RUNNER-05 | Phase 2 | Done |
| RUNNER-06 | Phase 2 | Done |
| AICLI-01 | Phase 3 | Pending |
| AICLI-02 | Phase 3 | Pending |
| AICLI-03 | Phase 3 | Pending |
| AICLI-04 | Phase 3 | Pending |
| CONFIG-01 | Phase 3 | Pending |
| CONFIG-02 | Phase 3 | Pending |
| CONFIG-03 | Phase 3 | Pending |
| CLAUDECLI-01 | Phase 4 | Pending |
| GEMINI-CLI-01 | Phase 4 | Pending |
| CODEX-01 | Phase 5 | Pending |
| QWEN-01 | Phase 5 | Pending |
| SESSION-01 | Phase 6 | Pending |
| SESSION-02 | Phase 6 | Pending |
| SESSION-03 | Phase 6 | Pending |
| SESSION-04 | Phase 6 | Pending |
| MCP-01 | Phase 7 | Pending |
| MCP-02 | Phase 7 | Pending |
| MCP-03 | Phase 7 | Pending |
| MCP-04 | Phase 7 | Pending |
| MCP-05 | Phase 7 | Pending |
| ROUTING-01 | Phase 7 | Pending |
| ROUTING-02 | Phase 7 | Pending |
| ROUTING-03 | Phase 7 | Pending |
| ROUTING-04 | Phase 7 | Pending |
| EVAL-01 | Phase 8 | Pending |
| EVAL-02 | Phase 8 | Pending |
| EVAL-03 | Phase 8 | Pending |
| EVAL-04 | Phase 9 | Pending |
| EVAL-05 | Phase 9 | Pending |
| EVAL-06 | Phase 9 | Pending |
| VERIFY-01 | Phase 10 | Pending |
| VERIFY-02 | Phase 10 | Pending |
| VERIFY-03 | Phase 10 | Pending |
| VERIFY-04 | Phase 10 | Pending |
| CONFIG-04 | Phase 10 | Pending |
| CONFIG-05 | Phase 10 | Pending |

**Coverage:**
- total active v1.0 requirements: 43
- completed: 10
- mapped to phases: 43
- unmapped: 0 ✓

---
*Requirements revised: 2026-05-01 after milestone v1.0 scope expansion*
