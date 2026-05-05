# Phase 5: Codex & Qwen Code — Research

**Researched:** 2026-05-04
**Phase:** 5 — Codex & Qwen Code
**Requirements:** CODEX-01, QWEN-01

---

## Summary

Both providers follow the thin-adapter contract from Phase 4. The primary
research goal was to confirm the facts locked by D-04 and D-06 in CONTEXT.md:
binary names, JSON output flags, minimum version thresholds, env vars, and
prompt delivery flags. One critical discrepancy was found: D-02's
`--approval-mode` flag mapping assumes the legacy TypeScript Codex CLI. The
current Rust-based Codex CLI uses a different flag interface (`--sandbox` +
`--ask-for-approval`). The implementation must use the current flags.

---

## Codex CLI Research

### Binary Name and Installation

- **Binary:** `codex`
- **NPM package:** `@openai/codex` (`npm i -g @openai/codex`)
- **Homebrew:** `brew install --cask codex`
- **Current version:** 0.128.0 (Rust implementation — `codex-rs` in the repo)

### Non-Interactive (Headless) Mode

Codex headless mode uses the `exec` subcommand, **not** a `-p` flag:

```bash
codex exec "<task>"
```

This is fundamentally different from Claude Code and Gemini CLI which use `-p`.
`send_message()` for `CodexLLM` must use `codex exec` with the prompt as the
last positional argument.

```bash
codex exec --json --sandbox read-only --ask-for-approval never "<task prompt>"
```

### JSON Output Format

Enable machine-readable output with `--json`:

```bash
codex exec --json "<task>"
```

This emits **JSONL** (newline-delimited JSON) to stdout. Each line is one event
object. The stream is not a single JSON object — it is multiple objects, one
per line.

**Key event types:**

```jsonl
{"type":"thread.started","thread_id":"0199a213-81c0-7800-8aa1-bbab2a035a53"}
{"type":"turn.started"}
{"type":"item.started","item":{"id":"item_1","type":"command_execution","command":"...","status":"in_progress"}}
{"type":"item.completed","item":{"id":"item_3","type":"agent_message","text":"<response text>"}}
{"type":"turn.completed","usage":{"input_tokens":24763,"cached_input_tokens":24448,"output_tokens":122,"reasoning_output_tokens":0}}
```

**Parsing strategy for `get_response()` and `_extract_usage()`:**

- Response text: find the `item.completed` event where `item.type == "agent_message"` → return `item["text"]`
- Token usage: find the `turn.completed` event → `usage.input_tokens`, `usage.output_tokens`
- Multiple `item.completed` events are possible (tool calls, file changes, etc.); take the last `agent_message`
- The `turn.completed` event is always the last meaningful event before the JSONL stream ends

The raw stdout is multi-line JSONL. `_run_subprocess()` captures it as a
single string. Parse each line individually:

```python
import json

lines = result.stdout.strip().splitlines()
events = [json.loads(line) for line in lines if line.strip()]
```

This is what `send_message()` should return as the "payload" (a list of event dicts).
`get_response()` and `_extract_usage()` operate on that list.

### Sandbox and Approval System (CURRENT Rust CLI)

> **Critical Finding — D-02 Discrepancy:**
> CONTEXT.md D-02 maps `tool_mode` to `--approval-mode suggest|auto-edit|full-auto`.
> That was the **TypeScript CLI** (`codex-cli`) interface. The **current Rust CLI**
> (`codex-rs`, version ≥ 0.95) uses a different flag pair.

**Current Rust CLI sandbox flags:**

| Want | Flags |
|------|-------|
| Read-only, no prompts (safe for scanner) | `--sandbox read-only --ask-for-approval never` |
| Workspace write, prompt before running commands | `--sandbox workspace-write --ask-for-approval on-request` |
| Workspace write, fully autonomous (no prompts) | `--sandbox workspace-write --ask-for-approval never` |
| Full access, no sandbox | `--sandbox danger-full-access` (alias `--yolo`) |

**Old TypeScript compatibility flags (deprecated, still works but warns):**
- `codex exec --full-auto` — deprecated alias for `--sandbox workspace-write`
- There is no `--approval-mode` flag in the Rust CLI

**Mapping for `CodexLLM.send_message()` using CURRENT flags:**

| `tool_mode` | `--sandbox` | `--ask-for-approval` | Rationale |
|-------------|-------------|---------------------|-----------|
| `"none"` (default scanner) | `read-only` | `never` | No file changes, safest for a vulnerability scanner |
| `"read-only"` | `read-only` | `never` | Same — analyzer reads code, does not edit |
| `"full"` | `workspace-write` | `never` | Operator explicitly opted in; autonomous |

The planner should implement D-02's intent using the current flags rather than
the deprecated `--approval-mode` values.

### Authentication and `_STRIP_ENV_VARS`

- **ChatGPT session auth** (default, ChatGPT Pro/Plus): OAuth-based. Strip
  `OPENAI_API_KEY` so the binary uses its OAuth credentials instead of falling
  through to API key mode. This is consistent with D-01 and with
  `ClaudeCodeLLM`'s pattern.
- **API key auth** (operator opt-in): Set `CODEX_API_KEY` (separate from
  `OPENAI_API_KEY`). Operator sets `strip_env_vars: []` in `CLIPolicy` to
  keep `OPENAI_API_KEY` in the environment, **and** sets `CODEX_API_KEY`.
  Note: `CODEX_API_KEY` is only supported in `codex exec`, not interactive
  `codex`.

```python
_STRIP_ENV_VARS: ClassVar[tuple[str, ...]] = ("OPENAI_API_KEY",)
```

This matches D-01 exactly.

### Version Gate for `probe()`

`codex exec --json` is available starting from the Rust CLI era. The
TypeScript CLI did not have `--json`; it had `--output-format json`. The Rust
CLI was released in late 2025 and has been rapidly versioned.

- Minimum version for JSONL output: **0.95.0** (conservative floor; `--json`
  was added in the Rust port era before 0.95)
- Recommendation: `_MIN_VERSION: ClassVar[tuple[int, ...]] = (0, 95, 0)`
- Version string from `codex --version` output: e.g. `codex 0.128.0`
- Parse with regex `r"(\d+\.\d+(?:\.\d+)?)"`, same approach as `GeminiCLILLM`

### Prompt Delivery

Codex uses a **positional argument** for the prompt in `codex exec`, not `-p`:

```bash
codex exec --json --sandbox read-only --ask-for-approval never "YOUR PROMPT HERE"
```

The prompt must be the **last** argument and should be a single string. No
`--prompt` or `-p` flag exists in the Rust CLI. D-11 ("passes prompts via
`-p <text>`") applies to Qwen Code only, not Codex.

### System Prompt Handling

Codex has no `--system-prompt` flag in `codex exec`. Use the same
prefix-concatenation approach as Claude Code: prepend `self.system_prompt` to
the user prompt if set.

---

## Qwen Code Research

### Binary Name and Installation

- **Binary:** `qwen`
- **NPM package:** `@qwen-code/qwen-code` (`npm i -g @qwen-code/qwen-code`)
- **Quick install:** `bash -c "$(curl -fsSL https://qwen-code-assets.oss-cn-hangzhou.aliyuncs.com/installation/install-qwen.sh)"`
- **Homebrew:** `brew install qwen-code`
- **Current version:** 0.15.6

### Headless Mode and Prompt Flag

**Confirmed:** Qwen Code supports `-p` (short) and `--prompt` (long). D-11 is correct.

```bash
qwen -p "<task>"
# same as:
qwen --prompt "<task>"
```

### JSON Output Format

```bash
qwen -p "<task>" --output-format json
```

This produces a **JSON array** (buffered, all messages at end — batch mode).
This is confirmed for D-08 (batch JSON only, no streaming in Phase 5).

**Envelope format:**

```json
[
  {
    "type": "system",
    "subtype": "session_start",
    "uuid": "...",
    "session_id": "...",
    "model": "qwen3-coder-plus"
  },
  {
    "type": "assistant",
    "uuid": "...",
    "session_id": "...",
    "message": {
      "id": "...",
      "type": "message",
      "role": "assistant",
      "model": "qwen3-coder-plus",
      "content": [{"type": "text", "text": "<response text>"}],
      "usage": {"input_tokens": N, "output_tokens": N, ...}
    },
    "parent_tool_use_id": null
  },
  {
    "type": "result",
    "subtype": "success",
    "uuid": "...",
    "session_id": "...",
    "is_error": false,
    "duration_ms": 1234,
    "result": "<response text>",
    "usage": {"input_tokens": N, "output_tokens": N, ...}
  }
]
```

**Parsing strategy:**

- `get_response()`: find the entry with `type == "result"` and `subtype == "success"` → return `entry["result"]`
- `_extract_usage()`: from the `result` entry → `entry["usage"]` contains `input_tokens`, `output_tokens`, and potentially `model` info. Fall back to the `assistant` entry's `message.usage` if `result.usage` is absent.
- `model` name: from `result` entry's implicit model, or from `assistant.message.model`

> **Important:** Qwen Code's JSON envelope is **not the same** as Gemini CLI's.
> Gemini returns `{"response": "...", "stats": {"models": {...}}}`.
> Qwen returns a JSON array with a `result` entry. Do not copy Gemini's parsing.

### Approval Mode Flags

Qwen Code supports `--approval-mode` with these values:

| Value | What it does |
|-------|-------------|
| `plan` | Read-only; analysis only; no file changes or shell commands |
| (default) | Manual approval for all actions |
| `auto-edit` | Auto-approve file edits; manual approval for shell commands |
| `yolo` | Auto-approve everything (alias: `--yolo` flag) |

**Mapping for `QwenCodeLLM.send_message()`:**

| `tool_mode` | Flag | Rationale |
|-------------|------|-----------|
| `"none"` (default scanner) | `--approval-mode plan` | Read-only; safe for a scanner |
| `"read-only"` | `--approval-mode plan` | Same — file analysis only |
| `"full"` | `--yolo` | Operator explicitly opted in; autonomous |

This is a `--approval-mode` flag that Qwen Code **does** have (unlike the
current Rust Codex CLI). The CONTEXT.md was correct about `--approval-mode`
for Qwen Code but incorrect about it applying to Codex.

### System Prompt

Qwen Code supports `--system-prompt <text>` and `--append-system-prompt <text>`
in headless mode. However, the Phase 4 contract (D-10/D-11 base class pattern)
uses prompt-prepend for portability. Use the same approach as Claude Code
and Gemini: prepend `self.system_prompt` to `user_prompt` if set. This avoids
flag detection and works across all versions.

### Authentication and `_STRIP_ENV_VARS`

**Qwen OAuth was discontinued April 15, 2026.** There is no `QWEN_API_KEY` env
var to strip. Authentication is now:

1. **Alibaba Cloud Dashscope API key**: env var `DASHSCOPE_API_KEY`
2. **Alibaba Cloud Coding Plan API key**: env var `BAILIAN_CODING_PLAN_API_KEY`
3. **Bridge mode (OpenAI-compatible)**: env var `OPENAI_API_KEY` — do **NOT** strip (D-09)

For direct-Qwen mode (default), strip the Alibaba API keys so the operator
must explicitly provide them:

```python
_STRIP_ENV_VARS: ClassVar[tuple[str, ...]] = (
    "DASHSCOPE_API_KEY",
    "BAILIAN_CODING_PLAN_API_KEY",
)
```

In bridge mode (`CLIPolicy.overrides["qwen-code"]["base_url"]` is set), the
adapter injects `OPENAI_BASE_URL` into the subprocess env. `OPENAI_API_KEY`
stays in the env because the operator sets it for the bridge target. This
matches D-05 and D-09 exactly.

**Bridge mode env injection pattern:**

```python
def _build_env(self) -> dict[str, str]:
    env = super()._build_env()  # strips _STRIP_ENV_VARS + policy.strip_env_vars
    for var in (self._policy.strip_env_vars if self._policy else []):
        env.pop(var, None)
    # Inject OPENAI_BASE_URL for bridge mode
    if self._policy:
        qwen_overrides = self._policy.overrides.get("qwen-code", {})
        base_url = qwen_overrides.get("base_url")
        if base_url:
            env["OPENAI_BASE_URL"] = str(base_url)
    return env
```

### Version Gate (`_MIN_VERSION`)

Qwen Code was forked from Gemini CLI 0.8.2, which already had JSON output
support. The `--output-format json` flag has been available since Qwen Code's
first public release.

- **Minimum version for JSON output:** `(0, 1, 0)` — no documented cutoff
- Set `_MIN_VERSION: ClassVar[tuple[int, ...]] = (0, 1, 0)` as a conservative
  floor (effectively "any version works")
- Version string from `qwen --version`: e.g. `0.15.6`
- Parse with regex `r"(\d+\.\d+(?:\.\d+)?)"` (same as GeminiCLILLM)

---

## Standard Stack

| Concern | Decision |
|---------|----------|
| Codex headless mode | `codex exec --json --sandbox read-only --ask-for-approval never` |
| Qwen Code headless mode | `qwen -p "<prompt>" --output-format json --approval-mode plan` |
| Codex prompt delivery | Positional arg after all flags (`codex exec ... "<prompt>"`) |
| Qwen Code prompt delivery | `-p "<prompt>"` flag (confirmed) |
| Codex JSON parse | JSONL: parse each line, look for `item.completed/agent_message` and `turn.completed` |
| Qwen Code JSON parse | JSON array: look for `result` entry with `subtype == "success"` |
| Codex `_STRIP_ENV_VARS` | `("OPENAI_API_KEY",)` |
| Qwen Code `_STRIP_ENV_VARS` | `("DASHSCOPE_API_KEY", "BAILIAN_CODING_PLAN_API_KEY")` |
| Codex `_MIN_VERSION` | `(0, 95, 0)` |
| Qwen Code `_MIN_VERSION` | `(0, 1, 0)` |
| Approval flags — Codex | `--sandbox read-only --ask-for-approval never` (not `--approval-mode`) |
| Approval flags — Qwen Code | `--approval-mode plan` / `--yolo` |

---

## Architecture Patterns

### Don't Hand-Roll

- Do NOT replicate `_run_subprocess()` — it is already in `CLIProviderLLM`
- Do NOT override `chat()` — base class handles dispatch, validation, cost tracking
- Do NOT add streaming support in Phase 5 — D-08 says batch JSON only

### Patterns from Phase 4

Both adapters follow the Phase 4 thin-adapter contract (D-10):

```
CodexLLM / QwenCodeLLM
  ├── probe()          — binary + version check
  ├── send_message()   — build cmd + call _run_subprocess()
  ├── get_response()   — extract text from parsed payload
  └── _extract_usage() — extract LLMUsage from parsed payload
```

### Key Differences from GeminiCLILLM

| Aspect | GeminiCLILLM | CodexLLM | QwenCodeLLM |
|--------|-------------|----------|-------------|
| Prompt flag | `-p` | positional arg (no flag) | `-p` |
| Output flag | `--output-format json` | `--json` | `--output-format json` |
| JSON shape | single object | JSONL (one object per line) | JSON array |
| Response field | `response` | `item.text` (agent_message) | `result` (result entry) |
| Usage field | `stats.models.<name>.tokens` | `turn.completed.usage` | `result.usage` |
| Approval | `--approval-mode plan/yolo` | `--sandbox + --ask-for-approval` | `--approval-mode plan/yolo` |

---

## Validation Architecture

### Dimension 1 — Binary Check
`probe()` must verify the binary is on PATH with `shutil.which()`.

### Dimension 2 — Version Gate
`probe()` must parse the version string and compare using tuple comparison
(not string comparison). `_MIN_VERSION` set at `(0, 95, 0)` for Codex,
`(0, 1, 0)` for Qwen Code.

### Dimension 3 — JSON Parse Robustness
`send_message()` must handle:
- Empty stdout → `CLIParseError`
- Malformed JSON lines (Codex) → `CLIParseError`
- JSON array without expected entries (Qwen Code) → `CLIParseError`
- `is_error: true` in Qwen Code result entry → `CLIParseError` or `CLIRuntimeError`

### Dimension 4 — Approval Mode Coverage
Test cases must cover each `tool_mode` value and verify the correct flags
appear in the subprocess command (`mock_run_subprocess`).

### Dimension 5 — Env Var Stripping
Tests must verify `_STRIP_ENV_VARS` items are removed from the subprocess env.

### Dimension 6 — Bridge Mode (Qwen Code)
When `CLIPolicy.overrides["qwen-code"]["base_url"]` is set, `OPENAI_BASE_URL`
must appear in the subprocess env.

---

## Common Pitfalls

1. **Codex `-p` pitfall**: Codex does NOT accept `-p`. Using `-p` will fail.
   The prompt goes after `codex exec [flags]` as a bare positional string.

2. **Qwen Code JSON array pitfall**: `json.loads(stdout)` returns a list, not
   a dict. Accessing `payload["result"]` will raise `TypeError`. Must iterate.

3. **Codex JSONL pitfall**: `json.loads(stdout)` on multi-line JSONL raises
   `json.JSONDecodeError`. Must split on newlines first.

4. **`--approval-mode` on Codex**: The Rust Codex CLI has NO `--approval-mode`
   flag. Using it will cause Codex to exit with an error.

5. **`OPENAI_API_KEY` stripping for Qwen Code bridge mode**: Must NOT strip
   `OPENAI_API_KEY` from the subprocess env when bridge mode is in use.

6. **Qwen OAuth stripped**: Do NOT include `QWEN_API_KEY` in `_STRIP_ENV_VARS`
   — OAuth was discontinued April 2026; that env var no longer exists.
