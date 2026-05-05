# Feature Landscape

**Domain:** AI CLI tools as Vulnhuntr backends
**Researched:** 2026-05-01
**Milestone context:** Expand current `v1.0` milestone

## Table Stakes

| Feature | Why users expect it | Complexity | Notes |
|---------|---------------------|------------|-------|
| API and CLI providers coexist | This is an additive alternative, not a replacement | Medium | Must preserve current API-key workflows |
| Headless structured output | Vulnhuntr needs machine-parseable responses | High | Provider output formats differ materially |
| Clear install/auth diagnostics | Users should know whether failure is missing binary, auth, or unsupported feature | Low | Capability probe required |
| Configurable timeouts/workdir/session mode | CLI tools are stateful local programs, unlike HTTP SDKs | Medium | Belongs in config, not hardcoded flags |
| Test coverage for adapters | Parsing failures will otherwise show up only during live scans | Medium | Mocked + live optional tests |
| Strong behavioral oracles | Output-only checks miss many agent and tool-use failures | High | Need trace-aware assertions |
| Boundary-focused config and CLI validation | Most regressions live at edges and invalid combinations | Medium | Should drive test case design |

## Differentiators

| Feature | User value | Complexity | Notes |
|---------|------------|------------|-------|
| Account-auth local execution | Can reduce direct API cost and setup friction | Medium | Especially strong for Claude Code and Gemini CLI |
| Native MCP and tool use | Lets the reasoning backend use mature local tools | High | Must not conflict with Vulnhuntr-managed MCP |
| Session reuse and resume | Better long-running analysis and operator workflows | High | Provider semantics differ |
| Qwen Code as bridge backend | Gives users a mature CLI that can still drive third-party APIs | High | Unique value vs direct API-only providers |
| Mixed fallback chains | Route between API and CLI providers in one config | High | Requires provider-neutral error model |
| Trace-based evaluation | Exposes whether tools, fallbacks, and reasoning steps behaved correctly | High | More useful than final-output-only checks |
| State-aware orchestration testing | Catches bugs in resume, escalation, and handoff flows | High | Important for multi-step CLI scans |

## Anti-Features

| Anti-feature | Why avoid it now |
|--------------|------------------|
| Rewriting Vulnhuntr as a general multi-agent coding platform | The product remains a vulnerability scanner |
| Removing direct API providers | Violates the user’s explicit scope |
| Trusting provider JSON schemas blindly | Upstream CLI behavior drifts; validation and probes are mandatory |
| Defaulting to fully autonomous file-editing modes | Vulnhuntr needs analysis output, not repo mutation |
| Hiding provider-native state | Session, auth, and sandbox behavior must be explicit to the operator |
| Treating coverage as only a percentage | The critical risk is missing state, branch, and data-flow behaviors |

## What The Milestone Should Deliver

1. First-class CLI providers for Claude Code, Gemini CLI, Codex, and Qwen Code.
2. A provider-neutral contract for structured responses, usage metadata, failures, and capability detection.
3. Config and `.env` support for auth mode, session handling, sandbox/approval policy, and workdir control.
4. A clear policy for native CLI tools and MCP versus Vulnhuntr’s internal MCP manager.
5. Verification strong enough that users can choose CLI tools confidently, not experimentally.
6. Trace-based evaluation and state-aware testing for provider selection, resume flows, tool calls, and fallback routing.

## Sources

- Internal experiment: `internal/experiments/vulnhuntr_claude_code/`
- Claude Code CLI docs
- Codex CLI docs
- Gemini CLI docs/repo
- Qwen Code docs
- Internal verification and evaluation notes reviewed on 2026-05-01
