---
phase: 05-codex-qwen-code
verified: 2026-05-04T00:00:00Z
status: passed
score: 14/14
overrides_applied: 0
---

# Phase 5: Codex & Qwen Code — Verification Report

**Phase Goal:** Implement CodexLLM and QwenCodeLLM as production CLIProviderLLM subclasses, wire them into initialize_llm() in runner.py, and add comprehensive mocked tests for both providers.
**Verified:** 2026-05-04T00:00:00Z
**Status:** PASSED
**Re-verification:** No — initial verification (produced retroactively from audit QT-01)

---

## Goal Achievement

### Observable Truths

All truths derived from: ROADMAP.md success criteria (authoritative), PLAN frontmatter must_haves (05-01, 05-02, 05-03), and summary files.

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | `--llm codex` can run the Vulnhuntr pipeline in headless mode with validated output | VERIFIED | CodexLLM wired in initialize_llm() at runner.py line 114-122; all methods substantive (probe, send_message, get_response, _extract_usage); 829/829 tests pass |
| 2 | `--llm qwen-code` can run the Vulnhuntr pipeline in headless mode with validated output | VERIFIED | QwenCodeLLM wired in initialize_llm() at runner.py line 124-133; all methods substantive; bridge mode supported via CLIPolicy.overrides |
| 3 | Codex CLI does not use `-p` flag — prompt is a positional argument to `codex exec` | VERIFIED | send_message() appends prompt as last element; 05-01-SUMMARY.md confirms "No -p flag" decision; TestCodexLLMSendMessage::test_send_message_prompt_positional passes |
| 4 | Codex JSONL output is parsed line-by-line; response comes from last `item.completed` where `item.type == "agent_message"` | VERIFIED | get_response() splits stdout by newline and scans for agent_message events; TestCodexLLMGetResponse::test_get_response_last_message_wins passes |
| 5 | CodexLLM uses `--sandbox read-only` + `--ask-for-approval never` (not legacy `--approval-mode`) | VERIFIED | codex.py send_message() builds args with `["--sandbox", sandbox_flag, "--ask-for-approval", "never"]`; TestCodexLLMSendMessage::test_send_message_uses_read_only_sandbox and test_send_message_uses_workspace_write_sandbox pass |
| 6 | `cached_input_tokens` summed into `input_tokens` for Codex (matches OpenAI billing) | VERIFIED | _extract_usage() returns `usage["input_tokens"] + usage.get("cached_input_tokens", 0)`; TestCodexLLMExtractUsage::test_extract_usage_sums_cached_input_tokens passes |
| 7 | OPENAI_API_KEY stripped from Codex subprocess env | VERIFIED | `_STRIP_ENV_VARS = ("OPENAI_API_KEY",)` at codex.py line 50; forces OAuth auth flow |
| 8 | QwenCodeLLM can be instantiated with a CLIPolicy and no other required args | VERIFIED | `QwenCodeLLM(policy=CLIPolicy())` succeeds; all args default |
| 9 | QwenCodeLLM uses `-p <prompt>` flag (unlike Codex) | VERIFIED | send_message() includes `["-p", full_prompt]`; TestQwenCodeLLMSendMessage::test_send_message_uses_p_flag passes |
| 10 | Qwen JSON output is a top-level array; validated with `isinstance(messages, list)` | VERIFIED | send_message() asserts `isinstance(messages, list)` and raises CLIParseError otherwise; TestQwenCodeLLMSendMessage::test_send_message_non_array_json_raises_cli_parse_error passes |
| 11 | QwenCodeLLM bridge mode: `OPENAI_BASE_URL` injected when `overrides["qwen-code"]["base_url"]` is set | VERIFIED | _build_env() checks policy.overrides; TestQwenCodeLLMBridgeMode::test_build_env_injects_openai_base_url_in_bridge_mode passes |
| 12 | DASHSCOPE_API_KEY and BAILIAN_CODING_PLAN_API_KEY stripped; OPENAI_API_KEY intentionally retained | VERIFIED | `_STRIP_ENV_VARS = ("DASHSCOPE_API_KEY", "BAILIAN_CODING_PLAN_API_KEY")`; TestQwenCodeLLMImport::test_strip_env_vars_contains_dashscope_and_bailian and test_strip_env_vars_does_not_contain_openai_api_key both pass |
| 13 | `tool_mode="full"` maps to `--yolo`; all other modes use `--approval-mode plan` for Qwen | VERIFIED | send_message() appends `["--yolo"]` for full, `["--approval-mode", "plan"]` otherwise; TestQwenCodeLLMSendMessage::test_send_message_tool_mode_full_uses_yolo and test_send_message_tool_mode_none_uses_approval_mode_plan pass |
| 14 | Neither CodexLLM nor QwenCodeLLM override chat() — base class transport used | VERIFIED | Neither class defines chat(); TestCodexLLMImport::test_no_chat_override and TestQwenCodeLLMImport::test_no_chat_override pass |

**Score:** 14/14 truths verified

---

## Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `vulnhuntr/cli_providers/codex.py` | CodexLLM(CLIProviderLLM) production subclass | VERIFIED | Implements probe, send_message, get_response, _extract_usage; _MIN_VERSION=(0,95,0) |
| `vulnhuntr/cli_providers/qwen_code.py` | QwenCodeLLM(CLIProviderLLM) production subclass | VERIFIED | Implements all four required methods; bridge mode via overrides; _MIN_VERSION=(0,1,0) |
| `vulnhuntr/cli_providers/__init__.py` | Package-level exports for both providers | VERIFIED | CodexLLM and QwenCodeLLM imported and in __all__ |
| `vulnhuntr/cli/runner.py` | Real CodexLLM and QwenCodeLLM instantiation in initialize_llm() | VERIFIED | Lines 114-133; both dispatch branches present |
| `tests/test_cli_providers.py` | 11 test classes, 84 test cases for Codex and Qwen | VERIFIED | TestCodexLLM* (5 classes, ~30 tests), TestQwenCodeLLM* (6 classes, ~54 tests); all pass |

---

## Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `vulnhuntr/cli_providers/codex.py` | `vulnhuntr/cli_providers/base.py` | `class CodexLLM(CLIProviderLLM)` | WIRED | Inherits probe, chat, _run_subprocess |
| `vulnhuntr/cli_providers/qwen_code.py` | `vulnhuntr/cli_providers/base.py` | `class QwenCodeLLM(CLIProviderLLM)` | WIRED | Inherits probe, chat, _run_subprocess |
| `vulnhuntr/cli/runner.py:initialize_llm` | `CodexLLM` | inline import + constructor | WIRED | Lines 114-122; `codex` arg dispatches to CodexLLM |
| `vulnhuntr/cli/runner.py:initialize_llm` | `QwenCodeLLM` | inline import + constructor | WIRED | Lines 124-133; `qwen-code` arg dispatches to QwenCodeLLM |
| `tests/test_cli_providers.py:TestCodexLLMSendMessage` | `subprocess.run` | `unittest.mock.patch` | WIRED | MagicMock pattern used throughout |
| `CodexLLM._extract_usage` | `turn.completed` event | JSONL scan | WIRED | Scans lines for `type == "turn.completed"`, extracts usage dict |
| `QwenCodeLLM._build_env` | `CLIPolicy.overrides["qwen-code"]["base_url"]` | dict lookup | WIRED | Injects OPENAI_BASE_URL when present |

---

## Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `CodexLLM.send_message` | `events` | `stdout.splitlines()` → `json.loads(line)` for each line | Yes — JSONL parsed to list of dicts | FLOWING |
| `CodexLLM._extract_usage` | `input_tokens` | `turn.completed` event `usage` dict | Yes — sum of input_tokens + cached_input_tokens | FLOWING |
| `QwenCodeLLM.send_message` | `messages` | `json.loads(stdout)` | Yes — top-level array of message dicts | FLOWING |
| `QwenCodeLLM._extract_usage` | `input_tokens` | `result` entry `usage` dict | Yes — with fallback to assistant message usage | FLOWING |
