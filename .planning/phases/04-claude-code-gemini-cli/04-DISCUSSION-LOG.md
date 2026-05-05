# Phase 4: Claude Code & Gemini CLI - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-02
**Phase:** 04-claude-code-gemini-cli
**Areas discussed:** Claude Code adapter scope, Gemini CLI JSON envelope, probe() auth depth, env-var stripping, MCP/skill usage directives

---

## Claude Code Adapter Scope

| Option | Description | Selected |
|--------|-------------|----------|
| Base class only | Implement only probe(), send_message(), get_response(), _extract_usage() | ✓ |
| Override chat() in adapter | Keep experiment's 2-pass retry in ClaudeCodeLLM.chat() | |
| Move retry into base | Lift 2-pass retry into CLIProviderLLM.chat() | |

**User's choice:** Base class only
**Notes:** Keeps adapter thin. Base class CLIProviderLLM.chat() handles the full pipeline.

---

## Claude Code Permission Mode

| Option | Description | Selected |
|--------|-------------|----------|
| bypassPermissions | Required for headless scanning; matches experiment | ✓ |
| auto (default) | Would hang headless scans on tool-use prompts | |
| From CLIPolicy.approval_mode | Adds a mapping layer | |

**User's choice:** bypassPermissions

---

## Claude Code probe() Auth Check

| Option | Description | Selected |
|--------|-------------|----------|
| Binary + auth_valid=None | which claude + version; auth only fails at first real call | ✓ |
| Light config check | Run `claude config list` to detect login state | |

**User's choice:** Binary + auth_valid=None
**Notes:** Consistent with Phase 3 CapabilityResult design — auth_valid=None when static check isn't possible.

---

## Claude Code Prompt Passing

| Option | Description | Selected |
|--------|-------------|----------|
| -p argument | Matches experiment; simpler; no temp file management | ✓ |
| stdin pipe | Safer for very large prompts | |
| --input-file temp file | Unclear if Claude Code supports this flag | |

**User's choice:** -p argument

---

## Gemini CLI Token Usage Parsing

| Option | Description | Selected |
|--------|-------------|----------|
| Research + parse full breakdown | Researcher confirms stats field names; implements input/output split | ✓ |
| totalTokenCount only | Safe but less granular | |
| Zero stub + TODO | Fastest but violates cost-transparency intent | |

**User's choice:** Research + parse full breakdown

---

## Gemini CLI Version-Aware probe()

| Option | Description | Selected |
|--------|-------------|----------|
| Parse version + gate >= 0.6.0 | Fast, gives operators version in diagnostics | ✓ |
| grep --help for flag | Checks capability directly, avoids version parsing | |
| Binary check only | Poor DX — fails mid-scan with unhelpful error | |

**User's choice:** Parse version + gate >= 0.6.0

---

## Gemini CLI Tool Use

**User clarification:** Tool use (file reads, shell, web search) in the CLI backends should be an optional, configurable feature for ALL AI CLI providers — not just Gemini. Vulnhuntr runs OS-installed CLI tools as subprocesses; this question is about whether those tools can use their own built-in capabilities during analysis.

| Option | Description | Selected |
|--------|-------------|----------|
| Add tool_mode to CLIPolicy | Cross-provider field: none / read-only / full | ✓ |
| Use existing approval_mode | Different semantics, overloads the field | |
| Defer to Phase 6 | Loses useful capability for Phase 4 | |

**User's choice:** Add tool_mode to CLIPolicy (cross-provider)
**Notes:** Claude picked this option per user direction ("research and pick the best option"). Tool use applies to all CLI providers equally.

---

## Env-Var Stripping

| Option | Description | Selected |
|--------|-------------|----------|
| Hardcoded defaults + CLIPolicy override | Safe defaults per class; strip_env_vars for operator overrides | ✓ |
| Hardcoded only | No config surface | |
| Fully configurable | Too much operator burden | |

**User's choice:** Hardcoded defaults + CLIPolicy override
**Notes:** Claude picked this option per user direction ("research and pick the best option").

---

## MCP Server Usage (executor directive)

| Option | Selected |
|--------|----------|
| mcp__ripgrep / python-lsp | ✓ |
| mcp__analyzer (ruff/vulture) | ✓ |
| mcp__semgrep | ✓ |
| mcp__context7 | ✓ |

**Notes:** All four MCP server groups selected. Mandatory for executor agents.

---

## Skills Usage (executor directive)

| Option | Selected |
|--------|----------|
| python-guardian-orchestrator | ✓ |
| testing-strategy-enforcement | |
| api-integration | ✓ |
| secure-code-review + threat-modeling | ✓ |

---

## Claude's Discretion

- Exact `send_message()` parameter names/return type — follow experiment pattern
- Whether `GeminiCLILLM` needs a workdir or can use CWD — researcher checks docs
- How `tool_mode: "read-only"` maps to specific Gemini CLI flags — researcher documents
- Test file name (`test_cli_providers.py` vs extending `test_cli.py`) — planner decides

## Deferred Ideas

- Session modes (stateless/resume) — Phase 6
- Full native tool ownership policy — Phase 6 (Phase 4 adds field; Phase 6 adds semantics)
- Codex and Qwen Code adapters — Phase 5
- Mixed API/CLI fallback routing — Phase 7

---

## Post-Implementation Update — 2026-05-04

**Mode:** `--all --analyze --auto` (autonomous review of completed phase)
**Purpose:** Capture lessons from code review (REVIEW.md / REVIEW-FIX.md) and correct D-07.

### System Prompt Delivery (CR-01)

| Approach | Selected |
|---|---|
| Prepend to user prompt (`full_prompt = f"{system_prompt}\n\n{user_prompt}"`) | ✓ (auto) |
| `--system-prompt` flag (Claude Code only) | |
| Skip entirely | |

`[auto] Recommended: prepend — only portable approach across all CLI versions and providers.`

### Abstract Method Contract (CR-02)

| Approach | Selected |
|---|---|
| All four methods abstract (`probe`, `get_response`, `send_message`, `_extract_usage`) | ✓ (auto) |
| Only `probe` + `get_response` abstract (original) | |

`[auto] Recommended: all four abstract — fail fast at instantiation, not at runtime.`

### Gemini Token Usage Path (D-07 correction)

| Approach | Selected |
|---|---|
| `stats.models.<name>.tokens.{input,candidates}` (actual 0.40.1 format) | ✓ (auto) |
| `stats.inputTokenCount` / `stats.outputTokenCount` (original D-07) | |

`[auto] Recommended: iterate stats.models — confirmed against actual Gemini CLI 0.40.1 output.`

### Tool Mode Flag Mapping

| tool_mode | Claude Code | Gemini CLI | Selected |
|---|---|---|---|
| Document explicit per-provider mapping | ✓ (auto) | | |

`[auto] Documented in D-12 with verified flag combinations.`

### Version Tuple Normalization (WR-04)

| Approach | Selected |
|---|---|
| Pad to 3 elements before tuple comparison | ✓ (auto) |
| Raw split without padding | |

`[auto] Recommended: padding prevents false rejections of 2-part version strings.`
