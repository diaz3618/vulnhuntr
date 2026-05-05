# Research Summary: AI CLI Tool Integration

**Domain:** AI CLI backends for Vulnhuntr
**Researched:** 2026-05-01
**Overall confidence:** HIGH for milestone direction, MEDIUM for some provider flag details because upstream CLI behavior changes quickly

## Executive Summary

Expanding Vulnhuntr to support Claude Code, Gemini CLI, Codex, and Qwen Code as first-class alternatives to API-key providers is technically aligned with the current architecture. The repo already proves the key idea with `internal/experiments/vulnhuntr_claude_code/`: the existing analysis pipeline can stay intact while only the LLM transport changes.

The feature is larger than “add four providers.” These tools are stateful local agents with their own auth models, session stores, sandbox/approval controls, MCP clients, and machine-readable output formats. A production-ready milestone therefore needs:

1. a dedicated CLI transport layer
2. runtime capability probes
3. explicit config for auth, sessions, sandbox/approval, and MCP ownership
4. strong parser and integration tests
5. trace-based evaluation and state-aware verification

## Key Findings

### What the user was right about

- CLI tools can reduce direct API-cost pressure and setup friction.
- They bring mature local tooling, agent workflows, session management, and native MCP ecosystems.
- Qwen Code is especially useful because it can operate both as a local agent and as a wrapper over external API providers.

### What was missing from the initial scope

- capability detection must be a first-class requirement
- session lifecycle must be configurable and logged
- native-tool/MCP ownership must be explicit
- cost accounting must handle “usage known, cost not attributable”
- `.env` precedence versus provider-owned config dirs must be documented
- output-only tests are insufficient for multi-step agent/tool behavior
- high-risk flows need stronger state, branch, and data-flow coverage

### Provider-specific conclusions

- **Claude Code** is the strongest first provider. Official docs confirm print mode, JSON output, permission modes, MCP config loading, and continue/resume support. Local repo experiment already validates the general pattern.
- **Gemini CLI** is valuable for keyless auth, built-in search, checkpointing, and MCP, but Vulnhuntr should not trust docs alone for JSON mode; probe actual support at runtime.
- **Codex** is a strong fit for local tool use and scripting, but sandbox and approval behavior should be explicit and user-controlled.
- **Qwen Code** is strategically important because it supports headless JSON/stream-json mode, resume/continue, MCP, and multiple authentication methods including BYO API providers.

### Verification conclusions

The milestone should not stop at adapter tests. The remaining work should apply:

- boundary-focused tests for config, CLI args, and provider error classes
- branch and transition coverage for fallback, resume, and MCP flows
- data-flow-aware checks around response parsing, trace propagation, and tool-result injection
- trace-based behavioral evaluation to validate semantic and procedural consistency
- explicit runtime invariants for retries, fallbacks, and state transitions

## Recommended Roadmap Shape

1. keep phases 1 and 2 as completed foundation work
2. build the common CLI provider contract and config schema next
3. implement providers in waves rather than all at once
4. integrate sessions/tool ownership/MCP policy after the common contract exists
5. finish mixed fallback, cost hardening, docs, and verification
6. add a final verification wave centered on traces, execution invariants, and state-aware tests

## Sources

- Internal experiment:
  - `internal/experiments/vulnhuntr_claude_code/README.md`
  - `internal/experiments/vulnhuntr_claude_code/claude_code_llm.py`
- Claude Code CLI reference: https://code.claude.com/docs/en/cli-reference
- Claude Code sessions: https://code.claude.com/docs/en/agent-sdk/sessions
- Codex CLI docs: https://developers.openai.com/codex/cli
- Gemini CLI repo/docs: https://github.com/google-gemini/gemini-cli
- Qwen Code auth: https://qwenlm.github.io/qwen-code-docs/en/users/configuration/auth/
- Qwen Code headless mode: https://qwenlm.github.io/qwen-code-docs/en/users/features/headless/
- Internal verification, testing, and orchestration notes reviewed on 2026-05-01
