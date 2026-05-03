# Vulnhuntr

## What This Is

Vulnhuntr is an LLM-powered autonomous static analysis tool that discovers complex, multi-step security vulnerabilities in codebases. It follows full attack chains from network entry points to dangerous sinks and is expanding from API-key-backed LLM providers into first-class local AI CLI backends such as Claude Code, Gemini CLI, Codex, and Qwen Code. The analysis pipeline stays centered on structured vulnerability discovery rather than becoming a general coding agent.

## Core Value

Find real, remotely-exploitable vulnerabilities that pattern-matching SAST tools miss, while giving operators flexible execution backends and bounded, understandable cost/runtime tradeoffs.

## Current Milestone: v1.0 Foundation, MCP, AI CLI Integration, and Verification Hardening

**Goal:** Finish the current foundation milestone by adding production-grade AI CLI backends as a first-class alternative to direct API providers, then harden the resulting system with stronger behavioral evaluation, state-aware verification, and execution-trace evidence.

**Target features:**

- CLI provider support for Claude Code, Gemini CLI, Codex, and Qwen Code
- Provider-neutral config for auth, sessions, sandbox/approval, and workdir control
- Clear ownership model for native CLI tools/MCP versus Vulnhuntr-managed MCP
- Mixed API/CLI fallback routing, diagnostics, and cost/usage reporting
- Trace-based verification and stronger transition- and boundary-focused testing

## Requirements

### Validated

- ✓ Checkpoint version uses actual package version via `importlib.metadata` (INFRA-01) — Validated in Phase 1: quick-wins-test-infrastructure
- ✓ `--analyze` path validated within `--root` via `Path.is_relative_to()` traversal guard (INFRA-02) — Validated in Phase 1: quick-wins-test-infrastructure
- ✓ Coverage threshold enforced in CI and local pytest (INFRA-03) — Validated in Phase 1: quick-wins-test-infrastructure
- ✓ Full `run_analysis()` integration test with mocked LLM provider (INFRA-04) — Validated in Phase 1: quick-wins-test-infrastructure
- ✓ `runner.py` decomposed into stage functions with injectable `llm_factory` (RUNNER-01..06) — Validated in Phase 2: runner-decomposition
- ✓ Multi-provider API support (Claude, ChatGPT, OpenRouter, Ollama) with fallback chain — existing
- ✓ Two-phase vulnerability analysis with iterative context expansion — existing
- ✓ Pydantic-validated response handling and output reporters — existing
- ✓ `.vulnhuntr.yaml` config file support with YAML + CLI merge — existing

### Active

- [ ] Vulnhuntr-managed MCP client wired into the analysis pipeline (MCP-01..05)
- ✓ `CLIPolicy` extended with `tool_mode` and `strip_env_vars` fields (CLAUDECLI-01, GEMINI-CLI-01) — Validated in Phase 4: claude-code-gemini-cli
- ✓ `ClaudeCodeLLM` and `GeminiCLILLM` production adapters wired into `initialize_llm()` (CLAUDECLI-01, GEMINI-CLI-01) — Validated in Phase 4: claude-code-gemini-cli
- [ ] AI CLI transport layer added without breaking existing API providers
- [ ] Claude Code, Gemini CLI, Codex, and Qwen Code supported as first-class backends
- [ ] `.vulnhuntr.yaml` and `.env` expanded for CLI auth, session, approval, sandbox, and workdir control
- [ ] Native CLI tools/MCP and Vulnhuntr-managed MCP have an explicit, testable ownership policy
- [ ] Mixed API/CLI fallback routing, usage reporting, and failure diagnostics hardened
- [ ] Behavioral evaluation and trace evidence added for multi-step provider execution
- [ ] Critical scan paths hardened with stronger state, branch, and boundary-focused tests
- [ ] Documentation and live-test guidance updated so users can adopt the feature intentionally

### Out of Scope

- Removing or deprecating direct API-key providers — this milestone is additive
- Rewriting Vulnhuntr into a generic multi-agent coding platform — the product remains an analyzer
- Defaulting scan backends to write-capable autonomous modes — analysis should stay read-focused unless users opt in
- Vendor-specific IDE/plugin ecosystems beyond what is needed for headless CLI execution
- New vulnerability-type expansion in this milestone — provider integration and verification depth now have higher priority

## Current State

Phase 4 complete (2026-05-03) — ClaudeCodeLLM and GeminiCLILLM adapters landed. `--llm claude-code` and `--llm gemini-cli` are now wired in `initialize_llm()`. 787 tests pass at 78% coverage. Next: Codex and Qwen Code adapters (Phase 5).

## Context

This is a brownfield Python project at v1.2.1 with a modularized CLI/core/reporting architecture and a partially completed `v1.0` milestone. Phases 1 and 2 are complete. On 2026-05-01, the scope of the remaining milestone was expanded twice: first to include AI CLI tools as a must-have alternative to direct API providers, and then to include stronger verification work around multi-step provider behavior, runtime state transitions, and execution traces.

The repo already contains a local Claude Code experiment under `internal/experiments/vulnhuntr_claude_code/`, which demonstrates that Vulnhuntr’s existing scan pipeline can survive a transport swap. The next wave of work is not just transport integration; it also needs stronger evidence that provider selection, fallback routing, resume behavior, tool invocation, and parsing semantics behave correctly under edge cases and repeated trials.

## Constraints

- **Python version:** 3.10–3.13 only
- **No breaking CLI:** current `--root`, `--analyze`, `--llm`, `--budget`, and existing provider flows must continue to work
- **Structured output:** Vulnhuntr still depends on validated structured responses, even when the backend is a local CLI tool
- **Security posture:** provider-native autonomy, shell access, and MCP must remain explicit and controllable
- **Statefulness:** sessions, workdirs, auth precedence, sandbox behavior, and fallback transitions must be visible in config, logs, and metadata
- **Cost clarity:** subscription-backed or account-auth runs must not be misreported as precise USD usage when that data is unavailable
- **Verification depth:** milestone completion requires more than happy-path output checks; it needs behavioral and trace evidence for critical paths

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Keep the existing analysis pipeline and expand the transport layer | Lowest-risk path; supported by the internal Claude Code experiment | Pending |
| Treat CLI tools as first-class backends, not hacks around existing API providers | Users want them as a real alternative | Pending |
| Add a dedicated capability probe before scans | Provider flags and JSON contracts drift over time | Pending |
| Make session, sandbox, auth, and MCP ownership explicit config | Hidden provider-native state will cause hard-to-debug failures | Pending |
| Preserve API providers and allow mixed fallback chains | User explicitly wants additive support | Pending |
| Require trace-based and state-aware verification for high-risk provider flows | Final-output-only tests are too weak for multi-step agent behavior | Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-05-01 — milestone v1.0 scope expanded for AI CLI integration and verification hardening*
