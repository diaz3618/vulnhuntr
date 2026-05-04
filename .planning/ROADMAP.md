# Roadmap: Vulnhuntr

**Milestone:** v1.0 — Foundation, MCP, AI CLI Integration, and Verification Hardening
**Created:** 2026-04-08
**Revised:** 2026-05-01
**Total phases:** 10
**Mapped requirements:** 43 covered, 43 mapped ✓

---

## Standing Rules (all phases)

- **Comments**: no AI-pattern prose; follow the project's humanized style guidance before commits
- **Commits**: natural, direct messages only
- **Provider safety**: scan backends default to explicit, least-surprising approval/sandbox behavior
- **Structured output**: every provider path must end in validated Vulnhuntr response models
- **API compatibility**: existing API-provider workflows must remain intact while CLI providers land
- **Verification depth**: critical multi-step behavior requires trace and transition evidence, not final-output-only checks

---

## Phases Overview

| # | Phase | Goal | Requirements | Success Criteria |
|---|-------|------|--------------|------------------|
| 1 | Quick Wins & Test Infrastructure | Fix baseline bugs and create a test safety net | INFRA-01..04 | 5 |
| 2 | Runner Decomposition | Break orchestration into testable stages | RUNNER-01..06 | 5 |
| 3 | CLI Provider Contract & Config Schema | 3/3 | Complete   | 2026-05-02 |
| 4 | Claude Code & Gemini CLI | Implement and verify the first two account-capable CLI providers | CLAUDECLI-01, GEMINI-CLI-01 | 4 |
| 5 | Codex & Qwen Code | Implement and verify the remaining CLI providers | CODEX-01, QWEN-01 | 4 |
| 6 | Sessions, Native Tools, and MCP Policy | Make session handling and tool/MCP ownership explicit and testable | SESSION-01..04 | 4 |
| 7 | MCP Completion, Routing, and Cost Hardening | Finish Vulnhuntr-managed MCP plus mixed provider fallback/diagnostics | MCP-01..05, ROUTING-01..04 | 5 |
| 8 | Behavioral Evaluation & Trace Capture | Add trace-based behavioral evaluation and boundary-focused tests for critical provider flows | EVAL-01..03 | 4 |
| 9 | State, Branch, and Data-Flow Hardening | Add transition coverage, data-flow-aware tests, and runtime invariants for high-risk execution paths | EVAL-04..06 | 4 |
| 10 | Verification, Docs, and Release Hardening | Finish tests, live validation guidance, verification criteria, and user-facing docs/config examples | VERIFY-01..04, CONFIG-04..05 | 4 |

---

## Phase Details

### Phase 1: Quick Wins & Test Infrastructure

**Status:** Complete
**Goal:** Fix standalone bugs, enforce coverage, and add an integration-test entry point.

**Requirements:**
- INFRA-01
- INFRA-02
- INFRA-03
- INFRA-04

**Success Criteria:**
1. Coverage threshold enforced in CI/local pytest
2. Checkpoint version recorded correctly
3. `--analyze` path traversal blocked
4. `run_analysis()` integration test exists with mocked LLM
5. Existing test suite stays green

**Depends on:** none

---

### Phase 2: Runner Decomposition

**Status:** Complete
**Goal:** Extract `run_analysis()` into testable stages and add LLM construction injection.

**Requirements:**
- RUNNER-01
- RUNNER-02
- RUNNER-03
- RUNNER-04
- RUNNER-05
- RUNNER-06

**Success Criteria:**
1. Orchestration split into stage functions
2. Stage-level tests exist
3. `llm_factory` injection exists for integration tests
4. No user-facing CLI regression
5. Coverage stays at or above the enforced floor

**Depends on:** Phase 1

---

### Phase 3: CLI Provider Contract & Config Schema

**Goal:** Add the common abstractions needed for local CLI backends before implementing individual providers.

**Requirements:**
- AICLI-01
- AICLI-02
- AICLI-03
- AICLI-04
- CONFIG-01
- CONFIG-02
- CONFIG-03

**Plans:** 3/3 plans complete

Plans:
**Wave 1**
- [x] 03-01-PLAN.md — CLIProviderLLM base class, CapabilityResult, CLI*Error classes, and full test suite
- [x] 03-02-PLAN.md — CLIPolicy dataclass, VulnhuntrConfig.cli field, from_dict/to_dict extensions and config tests

**Wave 2** *(blocked on Wave 1 completion)*
- [x] 03-03-PLAN.md — Probe wiring in _init_providers() and CLI provider stubs in initialize_llm()

**Success Criteria:**
1. A new CLI provider can be added without editing unrelated HTTP-provider code paths
2. Vulnhuntr exits early with actionable diagnostics when a required binary or feature is missing
3. Config supports CLI provider selection plus runtime policy fields without breaking existing YAML files
4. Provider results and failures are normalized into a provider-neutral internal model
5. Existing API providers still pass current tests unchanged

**Depends on:** Phase 2

---

### Phase 4: Claude Code & Gemini CLI

**Goal:** Land the first two CLI backends, prioritizing the providers with the strongest account-auth and local-tool workflows.

**Requirements:**
- CLAUDECLI-01
- GEMINI-CLI-01

**Plans:** 3 plans

Plans:
**Wave 1** *(parallel)*
- [x] 04-01-PLAN.md — ClaudeCodeLLM adapter (CLIPolicy extension + claude_code.py + __init__.py update)
- [x] 04-02-PLAN.md — GeminiCLILLM adapter (gemini_cli.py + __init__.py update)

**Wave 2** *(blocked on Wave 1 completion)*
- [x] 04-03-PLAN.md — Runner wiring and mocked tests for both providers

**Success Criteria:**
1. `--llm claude-code` can run the Vulnhuntr pipeline in headless mode with validated output
2. `--llm gemini-cli` can run the Vulnhuntr pipeline in headless mode with validated output
3. Missing auth, missing binary, timeout, and malformed-output failures are distinguishable
4. Provider metadata includes version/capability context useful for debugging

**Depends on:** Phase 3

---

### Phase 5: Codex & Qwen Code

**Goal:** Add the remaining providers and cover the backend that can also bridge third-party APIs.

**Requirements:**
- CODEX-01
- QWEN-01

**Plans:**
1. Implement Codex adapter with explicit approval/sandbox handling
2. Implement Qwen Code adapter with headless JSON/stream-json support
3. Verify model selection and auth-mode behavior for both providers

**Success Criteria:**
1. `--llm codex` works as a Vulnhuntr backend in headless mode
2. `--llm qwen-code` works as a Vulnhuntr backend in headless mode
3. Qwen Code can be configured either as a direct model backend or as a bridge to compatible APIs
4. Provider-specific settings stay isolated behind shared runtime-policy interfaces

**Depends on:** Phase 3

---

### Phase 6: Sessions, Native Tools, and MCP Policy

**Goal:** Make provider-native state and tool access explicit instead of accidental.

**Requirements:**
- SESSION-01
- SESSION-02
- SESSION-03
- SESSION-04

**Plans:** 4 plans

Plans:
**Wave 1**
- [ ] 06-01-PLAN.md — Base class contracts: session_id, _last_probe_version, get_session_metadata(), _build_mcp_config_args(); CheckpointData.session_metadata; CLIPolicy docstring

**Wave 2** *(parallel)*
- [ ] 06-02-PLAN.md — Provider wire-up: session_mode flags in all 4 providers, ClaudeCodeLLM MCP override, probe() version capture
- [ ] 06-03-PLAN.md — Runner session metadata write to checkpoint after first successful call

**Wave 3** *(blocked on Wave 2)*
- [ ] 06-04-PLAN.md — Parametrized tests: session_mode, tool_mode, sandbox_mode, MCP, get_session_metadata, CheckpointData round-trip

**Success Criteria:**
1. Operators can choose stateless vs resumed execution through config
2. Resumed scans record enough metadata to explain which session/context was reused
3. Provider-native tool use is governed by explicit approval/sandbox settings
4. Native provider MCP and Vulnhuntr-managed MCP can be enabled/disabled without ambiguity

**Depends on:** Phases 4 and 5

---

### Phase 7: MCP Completion, Routing, and Cost Hardening

**Goal:** Finish the internal MCP pipeline and make mixed API/CLI provider routing safe and observable.

**Requirements:**
- MCP-01
- MCP-02
- MCP-03
- MCP-04
- MCP-05
- ROUTING-01
- ROUTING-02
- ROUTING-03
- ROUTING-04

**Plans:**
1. Wire `MCPClientManager` into `VulnerabilityAnalyzer`
2. Finish tool-result injection and timeout handling
3. Harden fallback behavior and provider diagnostics across API and CLI backends
4. Update cost/usage reporting for provider-reported versus unattributable subscription usage

**Success Criteria:**
1. Vulnhuntr-managed MCP actually participates in analysis when enabled
2. MCP timeouts cannot hang scans
3. Mixed fallback chains work across API and CLI providers
4. Reports and logs distinguish exact API cost, provider-reported cost, and unattributable usage
5. Operators can tell why a provider failed and which fallback took over

**Depends on:** Phases 3, 4, 5, and 6

---

### Phase 8: Behavioral Evaluation & Trace Capture

**Goal:** Add evidence that critical provider flows behave correctly, not just that they produce shaped output.

**Requirements:**
- EVAL-01
- EVAL-02
- EVAL-03

**Plans:**
1. Define a structured trace contract for probe, validation, tool, fallback, and session events
2. Add behavior-level tests that assert semantic and procedural correctness on representative multi-step flows
3. Add boundary-focused tests for config parsing, provider selection, and failure classification

**Success Criteria:**
1. Critical provider paths emit enough structured events to reconstruct what happened
2. Evaluation tests can distinguish tool execution success from semantic misuse of its result
3. Invalid and edge-case config/provider combinations are covered by boundary-focused tests
4. Failures can be localized to transport, parsing, routing, or semantic handling

**Depends on:** Phases 4, 5, 6, and 7

---

### Phase 9: State, Branch, and Data-Flow Hardening

**Goal:** Strengthen the most failure-prone execution paths with transition-aware tests and explicit invariants.

**Requirements:**
- EVAL-04
- EVAL-05
- EVAL-06

**Plans:**
1. Define explicit states and guarded transitions for provider selection, resume, fallback, and MCP execution
2. Add branch and state-transition coverage around those flows
3. Add targeted data-flow-aware tests for parse results, tool outputs, and propagated context
4. Encode and test runtime invariants for ordering and legality of transitions

**Success Criteria:**
1. Critical transitions have dedicated tests for allowed and forbidden paths
2. High-risk parsing and propagation paths are covered beyond line/statement coverage
3. Runtime invariants fail loudly when ordering or policy constraints are violated
4. Repeated-trial runs show stable behavior across the critical routing paths

**Depends on:** Phase 8

---

### Phase 10: Verification, Docs, and Release Hardening

**Goal:** Make the feature adoptable and supportable rather than experimental.

**Requirements:**
- VERIFY-01
- VERIFY-02
- VERIFY-03
- VERIFY-04
- CONFIG-04
- CONFIG-05

**Plans:**
1. Finish mocked tests for all adapters and config parsing
2. Add optional live test guidance/markers
3. Update QUICKSTART and config examples
4. Document the verification evidence required before declaring provider integration done

**Success Criteria:**
1. Every CLI provider has adapter tests covering the main failure classes
2. Live validation paths are documented without making CI depend on external tool accounts
3. Users can understand how `.env`, YAML config, and provider-owned auth/config interact
4. Example config generation includes the new CLI sections and provider examples
5. Completion criteria include trace evidence and invariant checks, not just green happy-path tests

**Depends on:** Phases 8 and 9

---

## Requirements Coverage

All active v1.0 requirements are mapped exactly once:

- Foundation work is captured in Phases 1 and 2
- common CLI infrastructure lands in Phase 3
- providers land in Phases 4 and 5
- session/tooling policy lands in Phase 6
- routing/MCP/cost hardening lands in Phase 7
- behavioral evaluation lands in Phase 8
- transition and invariant hardening lands in Phase 9
- verification/docs land in Phase 10

**Total v1.0 requirements:** 43
**Mapped:** 43
**Unmapped:** 0 ✓

---
*Roadmap revised: 2026-05-01 after milestone v1.0 scope expansion*
