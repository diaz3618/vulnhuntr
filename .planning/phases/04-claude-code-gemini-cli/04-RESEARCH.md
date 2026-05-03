# Phase 4: Claude Code & Gemini CLI - Research

**Researched:** 2026-05-02
**Domain:** CLI subprocess backends — Claude Code adapter (promote from experiment) and Gemini CLI adapter (new implementation), CLIPolicy extension, runner wiring
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Claude Code Adapter:**
- D-01: `ClaudeCodeLLM` is a thin adapter implementing only `probe()`, `send_message()`, `get_response()`, and `_extract_usage()`. No custom `chat()` override.
- D-02: `send_message()` passes prompts via `-p <text>` CLI argument.
- D-03: Default flags: `--output-format json`, `--permission-mode bypassPermissions`, `--no-session-persistence`.
- D-04: `probe()` checks binary via `shutil.which("claude")`, runs `claude --version`, sets `auth_valid=None`. Returns install hint if binary missing.
- D-05: `_STRIP_ENV_VARS = ["ANTHROPIC_API_KEY"]`.

**Gemini CLI Adapter:**
- D-06: `get_response()` returns `payload.get("response")`.
- D-07: `_extract_usage()` parses token counts from `stats` object. Researcher must confirm exact field names — see Gemini JSON Schema section below.
- D-08: `probe()` gates on `>= 0.6.0`. Version-too-old message: `"Gemini CLI {version} too old; --output-format json requires >= 0.6.0. Run: npm i -g @google/gemini-cli"`.
- D-09: `_STRIP_ENV_VARS = ["GEMINI_API_KEY", "GOOGLE_API_KEY"]`. Researcher to confirm completeness — see env var section.
- D-10: Default flags: `-p <prompt>`, `--output-format json`. Model override via `--model`.

**Tool Mode:**
- D-11: `CLIPolicy` gains `tool_mode: str = "none"` (values: `"none"` | `"read-only"` | `"full"`).
- D-12: Researcher documents per-provider flag mappings — see Tool Mode Mappings section.
- D-13: Default `tool_mode: "none"`.

**Env-Var Stripping:**
- D-14: Each provider class declares `_STRIP_ENV_VARS: ClassVar[list[str]]`. `CLIPolicy` gains `strip_env_vars: list[str] = field(default_factory=list)` appended to class defaults at subprocess build time.

**Runner Wiring:**
- D-15: Replace `NotImplementedError` stub in `_init_providers()` for `"claude-code"` and `"gemini-cli"` with real provider instantiation. Each receives its merged `CLIPolicy`.

**Testing:**
- D-16: Tests via `unittest.mock.patch("subprocess.run")`. Cover: success, `CLITimeoutError`, `CLIParseError`, `CLIBinaryNotFoundError`, and probe version gate.
- D-17: Live tests marked `@pytest.mark.live`, excluded from CI.

**MCP/Skills Directives (executor tooling):**
- D-18: Executor MUST use `mcp__ripgrep__*`, `mcp__python-lsp-mcp__*`, `mcp__analyzer__*`, `mcp__semgrep__*`, `mcp__context7__*`.
- D-19: Executor MUST invoke `python-guardian-orchestrator`, `api-integration`, `secure-code-review`, `threat-modeling`.

### Claude's Discretion

- Exact abstract method signatures for `send_message()` — follow experiment's `send_message(self, messages, max_tokens, response_model)` pattern.
- Whether `GeminiCLILLM` needs a workdir or can run from CWD.
- How `tool_mode: "read-only"` maps to Gemini CLI flags.
- Test file name (`test_cli_providers.py` vs extending `test_cli.py`).

### Deferred Ideas (OUT OF SCOPE)

- Session modes (stateless/resume) — Phase 6
- Native tool ownership policy (full semantics) — Phase 6
- Codex and Qwen Code adapters — Phase 5
- Mixed API/CLI fallback routing — Phase 7
- `strip_env_vars` confirmation for Codex/Qwen — Phases 5/6
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| CLAUDECLI-01 | Claude Code works as a first-class Vulnhuntr backend in headless mode | Experiment promoted to CLIProviderLLM subclass; subprocess flags verified; env stripping confirmed |
| GEMINI-CLI-01 | Gemini CLI works as a first-class Vulnhuntr backend in headless mode | JSON schema verified via live run; version gate logic documented; auth env vars confirmed from source |
</phase_requirements>

---

## Summary

Phase 4 promotes the existing Claude Code experiment to a production-grade `CLIProviderLLM` subclass and adds a new `GeminiCLILLM` peer class. Both adapters implement four methods (`probe`, `send_message`, `get_response`, `_extract_usage`) against the base class contract from Phase 3. The base class already owns all subprocess execution, env-stripping, timeout enforcement, and cost-tracking wiring — subclasses stay thin.

The primary research task was verifying the Gemini CLI JSON output schema (the CONTEXT.md contained a wrong field path — see below). A live run of `gemini -p ... --output-format json` confirmed the actual schema. The Claude Code JSON schema was also confirmed with a live run. Both CLIs are installed on the development machine (Claude Code 2.1.126, Gemini CLI 0.40.1), so tests with `@pytest.mark.live` will work locally.

The `CLIPolicy` extension (`tool_mode`, `strip_env_vars`) is a small dataclass change with corresponding updates to `from_dict()` and `_build_env()`. The runner stub replacement is a targeted swap in `initialize_llm()`.

**Primary recommendation:** Implement in four sequential tasks — (1) CLIPolicy extension, (2) ClaudeCodeLLM subclass, (3) GeminiCLILLM subclass, (4) runner wiring + tests.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Subprocess execution, env stripping, timeout | `CLIProviderLLM` base (Phase 3) | — | Already implemented; subclasses inherit without override |
| Claude Code JSON envelope parsing | `ClaudeCodeLLM` (`get_response`, `_extract_usage`) | — | Provider-specific field names (`result`, `usage`) |
| Gemini CLI JSON envelope parsing | `GeminiCLILLM` (`get_response`, `_extract_usage`) | — | Provider-specific nested path (`response`, `stats.models.*`) |
| Binary availability and version gating | `probe()` on each provider | `_init_providers()` (runner) | Provider knows its own binary name and version contract |
| Runtime policy (`tool_mode`, `strip_env_vars`) | `CLIPolicy` dataclass | `CLIProviderLLM._build_env()` | Config-level declaration, transport-level enforcement |
| Provider registration and instantiation | `initialize_llm()` in runner.py | — | Existing routing table; CLI providers slot into the same map |

---

## Standard Stack

### Core (already present — no new dependencies)

| Library | Version | Purpose | Notes |
|---------|---------|---------|-------|
| `subprocess` (stdlib) | Python 3.x | Spawn CLI processes | `_run_subprocess()` already uses list-form, `shell=False` |
| `shutil` (stdlib) | Python 3.x | `shutil.which()` for binary detection in `probe()` | No new install |
| `packaging` (optional) | any | Semver comparison in `probe()` | Alternative: manual tuple split (see Pitfalls) |

### External CLIs (operator-installed, not pip dependencies)

| Tool | Min Version | Install | Auth Mechanism |
|------|-------------|---------|---------------|
| `claude` (Claude Code) | any (no gate) | `npm i -g @anthropic-ai/claude-code` | OAuth via keychain; strips `ANTHROPIC_API_KEY` to force CLI auth |
| `gemini` (Gemini CLI) | 0.6.0 | `npm i -g @google/gemini-cli` | OAuth via Google account; strips `GEMINI_API_KEY`+`GOOGLE_API_KEY` to force CLI auth |

**Installed on dev machine:** `claude` 2.1.126 [VERIFIED: `claude --version`], `gemini` 0.40.1 [VERIFIED: `gemini --version`]

**Version verification:**
```bash
npm view @anthropic-ai/claude-code version  # not verified in this session
npm view @google/gemini-cli version         # not verified in this session
```

---

## Gemini CLI JSON Output Schema

**CRITICAL CORRECTION:** The CONTEXT.md (D-07) mentions `stats.inputTokenCount` and `stats.outputTokenCount`. These field names **do not exist** in the actual Gemini CLI JSON output. [VERIFIED: live run on gemini 0.40.1]

**Actual verified JSON structure:**

```json
{
  "session_id": "f38b9ca3-...",
  "response": "Hello",
  "stats": {
    "models": {
      "<model-name>": {
        "api": {
          "totalRequests": 1,
          "totalErrors": 0,
          "totalLatencyMs": 681
        },
        "tokens": {
          "input": 2289,
          "prompt": 2289,
          "candidates": 40,
          "total": 2364,
          "cached": 0,
          "thoughts": 35,
          "tool": 0
        },
        "roles": { ... }
      }
    },
    "tools": { ... },
    "files": { ... }
  }
}
```

**Field path for token extraction in `_extract_usage()`:**
- Input tokens: `stats.models.<first_model>.tokens.input`
- Output tokens: `stats.models.<first_model>.tokens.candidates`
- Total tokens: `stats.models.<first_model>.tokens.total`

Multiple models may appear (e.g., `gemini-2.5-flash-lite` for routing + `gemini-3-flash-preview` for main response). For usage purposes, sum across all models or pick the first one with the highest token count. A safe implementation:

```python
def _extract_usage(self, response: Any) -> LLMUsage:
    stats = response.get("stats") or {}
    models = stats.get("models") or {}
    input_tokens = 0
    output_tokens = 0
    model_name = self.model or "gemini"
    for name, mdata in models.items():
        tokens = mdata.get("tokens") or {}
        input_tokens += int(tokens.get("input", 0))
        output_tokens += int(tokens.get("candidates", 0))
        model_name = name  # last model name wins; acceptable
    return LLMUsage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        model=model_name,
    )
```

**`get_response()` implementation:**
```python
def get_response(self, response: Any) -> str:
    result = response.get("response")
    if result is None:
        raise CLIParseError(
            "Gemini CLI response did not contain a 'response' field"
        )
    return str(result)
```

---

## Claude Code JSON Output Schema

**Confirmed fields from live run:** [VERIFIED: `claude -p "..." --output-format json --permission-mode bypassPermissions --no-session-persistence`]

```
Keys: type, subtype, is_error, api_error_status, duration_ms, duration_api_ms,
      num_turns, result, stop_reason, session_id, total_cost_usd, usage,
      modelUsage, permission_denials, terminal_reason, fast_mode_state, uuid
```

**Key field paths:**
- Response text: `payload["result"]`
- Input tokens: `usage["input_tokens"]` + `usage["cache_creation_input_tokens"]` + `usage["cache_read_input_tokens"]`
- Output tokens: `usage["output_tokens"]`
- Model name: `next(iter(modelUsage.keys()))` (e.g., `"claude-sonnet-4-6"`)
- Cost: `total_cost_usd`

The experiment's `_extract_usage()` and `_build_call_record()` match this schema exactly and can be promoted directly. [VERIFIED: live run confirms schema]

---

## Abstract Interface Contract

`CLIProviderLLM` exposes 2 formal `@abstractmethod` decorators (`probe`, `get_response`) plus 2 de-facto required overrides (`send_message`, `_extract_usage`) that raise `NotImplementedError` in `LLM` base. Phase 4 subclasses must implement all four. [VERIFIED: `base.py` source read]

| Method | Decorator | Signature | Notes |
|--------|-----------|-----------|-------|
| `probe(self) -> CapabilityResult` | `@abstractmethod` | No args | Returns `CapabilityResult`; `auth_valid=None` for both Claude Code and Gemini CLI |
| `get_response(self, response: Any) -> str` | `@abstractmethod` | Takes raw subprocess JSON payload dict | Raises `CLIParseError` if field missing |
| `send_message(self, messages: Any, max_tokens: int, response_model: Any) -> Any` | NotImplementedError in `LLM` base | Same signature as experiment | Builds CLI command, calls `_run_subprocess()`, JSON-parses stdout |
| `_extract_usage(self, response: Any) -> LLMUsage` | NotImplementedError in `LLM` base | Takes raw payload dict | Returns `LLMUsage(input_tokens, output_tokens, model)` |

**`send_message()` must also set `self.model`** before returning, since `_extract_usage()` may fall back to `self.model` when model name is absent from payload.

---

## Tool Mode Flag Mappings

**D-12 deliverable — per-provider flag mappings for `tool_mode`.** [VERIFIED: `claude --help`, `gemini --help`, Gemini bundle docs]

### Claude Code

| `tool_mode` | CLI Flag(s) | Notes |
|-------------|------------|-------|
| `"none"` | `--tools ""` | Disables all built-in tools; passes empty string to `--tools` |
| `"read-only"` | `--tools "Read"` (or `--permission-mode plan`) | `plan` mode is read-only per Claude Code docs; `--tools "Read"` restricts to file read only |
| `"full"` | (omit `--tools` flag) | Default built-in tool set is active |

**Confirmed flags from `claude --help`:** [VERIFIED]
- `--tools <tools...>` — specify list from built-in set; `""` disables all; `"default"` enables all
- `--allowed-tools <tools...>` — comma/space-separated list of tools to allow
- `--disallowed-tools <tools...>` — comma/space-separated list of tools to deny
- `--permission-mode plan` — read-only mode (one of: `acceptEdits`, `auto`, `bypassPermissions`, `default`, `dontAsk`, `plan`)

**Recommended implementation for `tool_mode`:**
- `"none"` → append `--tools` `""` to cmd
- `"read-only"` → append `--permission-mode` `plan` (overrides D-03 `bypassPermissions`)
- `"full"` → omit `--tools` flag (default behavior)

### Gemini CLI

| `tool_mode` | CLI Flag(s) | Notes |
|-------------|------------|-------|
| `"none"` | `--approval-mode plan` | `plan` = read-only mode per Gemini docs: "Plan Mode for read-only safety during planning" |
| `"read-only"` | `--approval-mode plan` | Same as `"none"` — Gemini's `plan` mode restricts to read-only tool use |
| `"full"` | `--approval-mode yolo` | Auto-approves all tools |

**IMPORTANT:** `--allowed-tools` is deprecated in Gemini CLI 0.40.1 — use the Policy Engine or `--approval-mode` instead. [VERIFIED: `gemini --help` output shows `[DEPRECATED: Use Policy Engine instead]`]

**`approval-mode` values confirmed:** `default` (prompt for approval), `auto_edit` (auto-approve edit tools), `yolo` (auto-approve all), `plan` (read-only mode). [VERIFIED: Gemini CLI bundle source and CLI reference]

For default headless operation (`tool_mode: "none"`), use `--approval-mode plan` for Gemini CLI. This is the safest headless default and prevents Gemini from making file edits or running shell commands.

---

## Env-Var Stripping Analysis

### Claude Code — `_STRIP_ENV_VARS`

`["ANTHROPIC_API_KEY"]` is correct per experiment and D-05. [VERIFIED: experiment source + Claude Code `--bare` flag docs note `ANTHROPIC_API_KEY` is the API-key auth path in bare mode]

**Why:** Claude Code uses keychain/OAuth by default. If `ANTHROPIC_API_KEY` is set, the binary uses API key auth instead of OAuth. Stripping forces CLI-native auth.

### Gemini CLI — `_STRIP_ENV_VARS`

[VERIFIED: Gemini CLI bundle source `chunk-F73F75XM.js`]

The `getApiKeyFromEnv()` function in Gemini CLI core reads:
1. `GOOGLE_API_KEY` (checked first; if both set, uses this and warns)
2. `GEMINI_API_KEY` (fallback)

Both trigger API key auth instead of OAuth. Strip both.

Additionally, Vertex AI path is triggered by:
- `GOOGLE_GENAI_USE_VERTEXAI` (boolean env) — routes to Vertex AI instead of Gemini API
- `GOOGLE_CLOUD_PROJECT` + `GOOGLE_CLOUD_LOCATION` — used with Vertex AI

**Recommended `_STRIP_ENV_VARS` for `GeminiCLILLM`:**
```python
_STRIP_ENV_VARS: ClassVar[tuple[str, ...]] = (
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_GENAI_USE_VERTEXAI",  # prevents Vertex AI routing
)
```

`GOOGLE_CLOUD_PROJECT` and `GOOGLE_CLOUD_LOCATION` are probably safe to leave unless the operator specifically uses Vertex AI — stripping them would break legitimate Vertex setups. Include only `GOOGLE_GENAI_USE_VERTEXAI` as the gating flag.

**Note:** D-09 in CONTEXT.md only lists `["GEMINI_API_KEY", "GOOGLE_API_KEY"]`. Adding `GOOGLE_GENAI_USE_VERTEXAI` is a research-driven addition; planner should include it.

---

## Gemini CLI Version Gate

**Current installed version:** 0.40.1 [VERIFIED: `gemini --version`]

**Version gate in D-08:** `>= 0.6.0`. This is already satisfied by 0.40.1. The semver comparison `(0, 40, 1) >= (0, 6, 0)` is True. [VERIFIED: local arithmetic]

**Parsing `gemini --version`:** The binary outputs just `0.40.1` (no additional text like Claude Code does). Parse with a simple split:

```python
import re
raw = completed.stdout.strip()  # "0.40.1"
match = re.search(r"(\d+\.\d+\.\d+)", raw)
if match:
    version_str = match.group(1)
```

**Claude Code `--version` output format:** `"2.1.126 (Claude Code)"` [VERIFIED: live run]. Parse with the same regex `r"(\d+\.\d+\.\d+)"`.

---

## Architecture Patterns

### System Architecture Diagram

```
Vulnhuntr CLI
    │
    ├─ initialize_llm("claude-code" | "gemini-cli")
    │       │
    │       └─ ClaudeCodeLLM / GeminiCLILLM (new Phase 4)
    │               │
    │               ├─ __init__(policy: CLIPolicy)
    │               │       └─ self.timeout, self.workdir from policy
    │               │
    │               ├─ probe()
    │               │       ├─ shutil.which("claude"|"gemini")
    │               │       ├─ run --version → parse semver
    │               │       └─ → CapabilityResult
    │               │
    │               └─ chat(prompt, response_model) ← CLIProviderLLM.chat() (Phase 3)
    │                       │
    │                       ├─ send_message(prompt, max_tokens, model) [PROVIDER IMPL]
    │                       │       ├─ build cmd list with flags
    │                       │       ├─ _run_subprocess(cmd) ← CLIProviderLLM (Phase 3)
    │                       │       │       └─ subprocess.run(shell=False, env=_build_env())
    │                       │       └─ json.loads(stdout) → payload dict
    │                       │
    │                       ├─ _log_response(payload) → _extract_usage() [PROVIDER IMPL]
    │                       │
    │                       └─ get_response(payload) [PROVIDER IMPL] → text
    │                               └─ _validate_response(text, model) ← LLM (Phase 1)
    │
    └─ _init_providers() probe call → CapabilityResult.ok=False → SystemExit(1)
```

### Recommended Project Structure

```
vulnhuntr/
├── cli_providers/
│   ├── __init__.py          # add ClaudeCodeLLM, GeminiCLILLM exports
│   ├── base.py              # unchanged (Phase 3)
│   ├── claude_code.py       # NEW — ClaudeCodeLLM subclass
│   └── gemini_cli.py        # NEW — GeminiCLILLM subclass
├── config.py                # add tool_mode + strip_env_vars to CLIPolicy
└── cli/
    └── runner.py            # replace NotImplementedError stub in initialize_llm()

tests/
└── test_cli_providers.py    # EXTEND (file exists from Phase 3)
```

### Pattern 1: Thin Subclass Structure (ClaudeCodeLLM)

```python
# Source: promoted from internal/experiments/vulnhuntr_claude_code/claude_code_llm.py
from __future__ import annotations

import json
import re
import shutil
from typing import Any, ClassVar

import structlog

from vulnhuntr.cli_providers.base import (
    CLIBinaryNotFoundError,
    CLIParseError,
    CLIProviderLLM,
    CapabilityResult,
)
from vulnhuntr.core.models import LLMUsage

log = structlog.get_logger(__name__)


class ClaudeCodeLLM(CLIProviderLLM):
    """Claude Code headless adapter."""

    _STRIP_ENV_VARS: ClassVar[tuple[str, ...]] = ("ANTHROPIC_API_KEY",)

    def probe(self) -> CapabilityResult:
        binary = shutil.which("claude")
        if not binary:
            return CapabilityResult(
                ok=False,
                binary_found=False,
                version=None,
                auth_valid=None,
                diagnostic_message=(
                    "Claude Code binary not found. "
                    "Install with: npm i -g @anthropic-ai/claude-code"
                ),
            )
        try:
            result = self._run_subprocess(["claude", "--version"])
        except Exception as exc:
            return CapabilityResult(
                ok=False,
                binary_found=True,
                version=None,
                auth_valid=None,
                diagnostic_message=f"Failed to run claude --version: {exc}",
            )
        match = re.search(r"(\d+\.\d+\.\d+)", result.stdout)
        version = match.group(1) if match else result.stdout.strip()
        return CapabilityResult(
            ok=True,
            binary_found=True,
            version=version,
            auth_valid=None,  # auth only verifiable at first real call
            diagnostic_message="",
        )

    def send_message(self, messages: Any, max_tokens: int, response_model: Any) -> dict[str, Any]:
        cmd = [
            "claude", "-p", str(messages),
            "--output-format", "json",
            "--permission-mode", self._permission_mode(),
            "--no-session-persistence",
        ]
        # tool_mode applied via _permission_mode() helper
        result = self._run_subprocess(cmd)
        stdout = result.stdout.strip()
        if not stdout:
            raise CLIParseError("Claude Code returned empty stdout")
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise CLIParseError(
                f"Claude Code returned invalid JSON: {stdout[:500]}"
            ) from exc
        # Set model name for _extract_usage
        model_usage = payload.get("modelUsage") or {}
        self.model = next(iter(model_usage.keys()), "claude-code")
        return payload

    def get_response(self, response: Any) -> str:
        result = response.get("result")
        if result is None:
            raise CLIParseError(
                "Claude Code response did not contain a 'result' field"
            )
        return str(result)

    def _extract_usage(self, response: Any) -> LLMUsage:
        usage = response.get("usage") or {}
        model_usage = response.get("modelUsage") or {}
        model_name = next(iter(model_usage.keys()), self.model or "claude-code")
        input_tokens = (
            int(usage.get("input_tokens", 0))
            + int(usage.get("cache_creation_input_tokens", 0))
            + int(usage.get("cache_read_input_tokens", 0))
        )
        output_tokens = int(usage.get("output_tokens", 0))
        return LLMUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=model_name,
        )

    def _permission_mode(self) -> str:
        """Map tool_mode → Claude Code --permission-mode flag."""
        # tool_mode is accessed via self._policy if passed in __init__
        # Phase 4 default: bypassPermissions (D-03)
        return "bypassPermissions"
```

### Pattern 2: GeminiCLILLM Structure

```python
# Source: research-documented JSON schema from live verification
class GeminiCLILLM(CLIProviderLLM):
    """Gemini CLI headless adapter."""

    _STRIP_ENV_VARS: ClassVar[tuple[str, ...]] = (
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_GENAI_USE_VERTEXAI",
    )
    _MIN_VERSION = (0, 6, 0)

    def probe(self) -> CapabilityResult:
        binary = shutil.which("gemini")
        if not binary:
            return CapabilityResult(
                ok=False, binary_found=False, version=None, auth_valid=None,
                diagnostic_message=(
                    "Gemini CLI binary not found. "
                    "Install with: npm i -g @google/gemini-cli"
                ),
            )
        try:
            result = self._run_subprocess(["gemini", "--version"])
        except Exception as exc:
            return CapabilityResult(
                ok=False, binary_found=True, version=None, auth_valid=None,
                diagnostic_message=f"Failed to run gemini --version: {exc}",
            )
        match = re.search(r"(\d+\.\d+\.\d+)", result.stdout)
        version_str = match.group(1) if match else result.stdout.strip()
        parsed = tuple(int(x) for x in version_str.split(".", 2))
        if parsed < self._MIN_VERSION:
            min_s = ".".join(str(x) for x in self._MIN_VERSION)
            return CapabilityResult(
                ok=False, binary_found=True, version=version_str,
                auth_valid=None,
                diagnostic_message=(
                    f"Gemini CLI {version_str} too old; "
                    f"--output-format json requires >= {min_s}. "
                    "Run: npm i -g @google/gemini-cli"
                ),
            )
        return CapabilityResult(
            ok=True, binary_found=True, version=version_str,
            auth_valid=None, diagnostic_message="",
        )

    def send_message(self, messages: Any, max_tokens: int, response_model: Any) -> dict[str, Any]:
        cmd = ["gemini", "-p", str(messages), "--output-format", "json"]
        # tool_mode: apply --approval-mode
        # default "none" → "--approval-mode" "plan"
        cmd.extend(["--approval-mode", "plan"])
        result = self._run_subprocess(cmd)
        stdout = result.stdout.strip()
        if not stdout:
            raise CLIParseError("Gemini CLI returned empty stdout")
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise CLIParseError(
                f"Gemini CLI returned invalid JSON: {stdout[:500]}"
            ) from exc
        return payload

    def get_response(self, response: Any) -> str:
        result = response.get("response")
        if result is None:
            raise CLIParseError(
                "Gemini CLI response did not contain a 'response' field"
            )
        return str(result)

    def _extract_usage(self, response: Any) -> LLMUsage:
        stats = response.get("stats") or {}
        models = stats.get("models") or {}
        input_tokens = 0
        output_tokens = 0
        model_name = self.model or "gemini"
        for name, mdata in models.items():
            tokens = (mdata or {}).get("tokens") or {}
            input_tokens += int(tokens.get("input", 0))
            output_tokens += int(tokens.get("candidates", 0))
            model_name = name
        self.model = model_name
        return LLMUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=model_name,
        )
```

### Pattern 3: CLIPolicy Extension

```python
# Add to vulnhuntr/config.py CLIPolicy dataclass
@dataclass
class CLIPolicy:
    # ... existing fields ...
    tool_mode: str = "none"             # "none" | "read-only" | "full"
    strip_env_vars: list[str] = field(default_factory=list)

# Update from_dict() to parse these new fields:
if "tool_mode" in cli_data:
    cli.tool_mode = str(cli_data["tool_mode"])
if "strip_env_vars" in cli_data and isinstance(cli_data["strip_env_vars"], list):
    cli.strip_env_vars = list(cli_data["strip_env_vars"])
```

### Pattern 4: Updated `_build_env()` for strip_env_vars merging

The base class `_build_env()` only reads `_STRIP_ENV_VARS` from the class. To support the `strip_env_vars` policy field, the provider `__init__` should store the policy and `send_message()` (or an override of `_build_env()`) must merge them.

**Option A** (recommended): Override `_build_env()` in each provider to merge class-level and policy-level strips:
```python
def _build_env(self) -> dict[str, str]:
    env = super()._build_env()  # strips class _STRIP_ENV_VARS
    for var in (self._policy.strip_env_vars if self._policy else []):
        env.pop(var, None)
    return env
```

**Option B**: Add `_extra_strip_vars: tuple[str, ...]` to `CLIProviderLLM` and populate it in `__init__`. The planner can choose.

### Pattern 5: Runner Wiring

```python
# In initialize_llm(), replace the NotImplementedError block:
elif llm_arg in ("claude-code", "gemini-cli", "codex", "qwen-code"):
    from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM
    from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM

    policy = getattr(config, "cli", None) or CLIPolicy()
    overrides = policy.overrides.get(llm_arg, {})

    if llm_arg == "claude-code":
        timeout = overrides.get("timeout", policy.timeout)
        workdir = overrides.get("workdir", policy.workdir)
        return ClaudeCodeLLM(
            system_prompt=system_prompt,
            cost_callback=cost_callback,
            timeout=timeout,
            workdir=workdir,
            policy=policy,
        )
    elif llm_arg == "gemini-cli":
        timeout = overrides.get("timeout", policy.timeout)
        workdir = overrides.get("workdir", policy.workdir)
        return GeminiCLILLM(
            system_prompt=system_prompt,
            cost_callback=cost_callback,
            timeout=timeout,
            workdir=workdir,
            policy=policy,
        )
    else:
        raise NotImplementedError(
            f"CLI provider '{llm_arg}' lands in Phase 5."
        )
```

### Anti-Patterns to Avoid

- **Calling `probe()` after wrapping in `FallbackLLM`:** Runner already guards against this (calls `probe()` on the unwrapped instance before wrapping). Don't change this order.
- **Using `shell=True` in subprocess:** `_run_subprocess()` already enforces `shell=False`. Subclasses must never bypass this.
- **Prompt injection via `-p` argument:** Prompts passed as list elements (not shell-interpolated) are safe. Never build `cmd` as a string.
- **Overriding `chat()`:** Phase 4 subclasses must NOT override `chat()` — D-01 is explicit. The base class `chat()` wires everything correctly.
- **Importing `ClaudeCodeLLM` from `llms.py`:** The provider lives in `cli_providers/`, not `llms.py`. Only runner imports it.
- **Manual semver string comparison:** `"0.40.1" >= "0.6.0"` is lexicographic and wrong. Use tuple comparison: `tuple(int(x) for x in v.split("."))`.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| JSON parsing with repair | Custom regex | `LLM._validate_response()` already does multi-pass JSON repair + Pydantic validation | Handles markdown fences, partial JSON, etc. |
| Subprocess safety | `os.system()` or shell=True | `_run_subprocess()` in base class | Already handles timeout, env, error taxonomy |
| Version comparison | String sort | `tuple(int(x) for x in v.split("."))` comparison | Lexicographic string comparison fails for `"0.9.0" > "0.40.1"` |
| Binary detection | `os.path.exists("/usr/bin/claude")` | `shutil.which("claude")` | Searches full PATH, handles symlinks |

---

## Common Pitfalls

### Pitfall 1: Semver String Comparison (Gemini version gate)
**What goes wrong:** `"0.40.1" < "0.6.0"` evaluates True in lexicographic order.
**Why it happens:** Python `"4" < "6"` is correct but `"40" < "6"` is wrong as string.
**How to avoid:** Always parse to `tuple(int(x) for x in version.split("."))` before comparing.
**Warning signs:** Gate rejects valid 0.40.x installs.

### Pitfall 2: Gemini CLI `--allowed-tools` is Deprecated
**What goes wrong:** Using `--allowed-tools` in Gemini CLI 0.40.1 produces a deprecation warning and may be removed in future releases.
**Why it happens:** Gemini migrated to Policy Engine for tool control.
**How to avoid:** Use `--approval-mode plan` for read-only/none mode; `--approval-mode yolo` for full mode. [VERIFIED: Gemini CLI help output]
**Warning signs:** Deprecation warning in stderr; `CLIRuntimeError` if future Gemini version removes the flag.

### Pitfall 3: `stats.inputTokenCount` Field Path (Gemini)
**What goes wrong:** `payload["stats"]["inputTokenCount"]` raises `KeyError`.
**Why it happens:** The actual schema uses `stats.models.<name>.tokens.input`. The CONTEXT.md suggested `inputTokenCount` which doesn't exist.
**How to avoid:** Use the verified path: `stats.models.<first_model>.tokens.input`.
**Warning signs:** `_extract_usage()` returns 0 tokens silently if using `.get()` with wrong key.

### Pitfall 4: Gemini CLI Exits Non-Zero on Approval-Mode Prompt
**What goes wrong:** `CLIRuntimeError` raised even on successful response.
**Why it happens:** In `default` approval mode, Gemini CLI may prompt for tool approval when running headlessly, causing it to hang or exit non-zero.
**How to avoid:** Always use `--approval-mode plan` (or `yolo`) in headless mode. Never omit `--approval-mode`.
**Warning signs:** Subprocess hangs; stderr contains "approve" or tool confirmation messages.

### Pitfall 5: Multiple Model Names in Gemini Stats
**What goes wrong:** Using only `stats.models[first_key]` misses token counts from routing/utility models.
**Why it happens:** Gemini CLI uses multiple models (e.g., `gemini-2.5-flash-lite` for routing + `gemini-3-flash-preview` for main). Both appear in `stats.models`.
**How to avoid:** Sum token counts across all models in the dict, as shown in the `_extract_usage()` pattern above.
**Warning signs:** Reported token counts much lower than expected; single model name in response but two in stats.

### Pitfall 6: `_STRIP_ENV_VARS` Type Mismatch
**What goes wrong:** `base.py` declares `_STRIP_ENV_VARS: tuple[str, ...] = ()`. If a subclass uses `list[str]`, `_build_env()` iterates fine but the `ClassVar[list[str]]` type annotation in D-14 is inconsistent with base class declaration.
**How to avoid:** Use `tuple[str, ...]` in subclasses to match base class type. The merge with `CLIPolicy.strip_env_vars` (a `list`) happens at `_build_env()` runtime, not at class definition.
**Warning signs:** mypy/pyright type errors; runtime works but CI type checks fail.

### Pitfall 7: Subprocess Env on Linux — Inherited `HOME` and `USER` Needed
**What goes wrong:** Over-stripping the environment removes `HOME` and `USER`, causing CLI tools to fail finding their credential stores.
**Why it happens:** `_build_env()` starts from `os.environ.copy()` and removes named vars. This is safe — only named vars are stripped, not the whole environment. Don't add `HOME` or `USER` to `_STRIP_ENV_VARS`.
**How to avoid:** Only strip the specific auth-forcing vars listed; preserve `HOME`, `PATH`, `USER`, `NODE_PATH` for the binary to function.
**Warning signs:** `claude --version` succeeds but `claude -p` fails with "could not load keychain" or "HOME not set".

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `--yolo` flag in Gemini CLI | `--approval-mode yolo` | ~v0.30+ | `--yolo` deprecated; use `--approval-mode` |
| `--allowed-tools` in Gemini CLI | Policy Engine (`.toml` files) | v0.30+ | `--allowed-tools` deprecated; CLI flag still works but discouraged |
| Manual `subprocess.run()` with `capture_output=True` (experiment) | `CLIProviderLLM._run_subprocess()` (Phase 3) | Phase 3 | Promotes to shared transport with proper error taxonomy |
| `ClaudeCodeLLM(LLM)` direct subclass (experiment) | `ClaudeCodeLLM(CLIProviderLLM)` | Phase 4 | Gets shared transport, error taxonomy, cost wiring for free |

---

## Existing Test Infrastructure

**File:** `tests/test_cli_providers.py` — already exists from Phase 3 [VERIFIED: `ls tests/`]

Phase 3 tests cover AICLI-01..04 (base class contract). Phase 4 must add provider-specific tests to this file (or a separate `test_claude_code.py` / `test_gemini_cli.py` depending on volume).

**Existing `@pytest.mark.live` setup:** Not yet in the file — must be added. The pyproject.toml `markers` block already declares `live: marks tests that hit real LLM APIs`. [VERIFIED: `pyproject.toml`]

**Existing conftest fixtures:** `tmp_repo`, `tmp_checkpoint_dir`, `mock_llm`, `sample_response_json` — available for reuse.

**CI exclusion already configured:** `addopts = "-m \"not live\""` in pyproject.toml — live tests auto-excluded from CI. [VERIFIED: `pyproject.toml`]

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest (existing) |
| Config file | `pyproject.toml` `[tool.pytest.ini_options]` |
| Quick run command | `pytest tests/test_cli_providers.py -x -m "not live"` |
| Full suite command | `pytest -m "not live" --cov-fail-under=72` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| CLAUDECLI-01 | `ClaudeCodeLLM.probe()` returns ok=True when binary present | unit | `pytest tests/test_cli_providers.py::TestClaudeCodeLLM::test_probe_ok -x` | ❌ Wave 0 |
| CLAUDECLI-01 | `ClaudeCodeLLM.probe()` returns ok=False when binary missing | unit | `pytest tests/test_cli_providers.py::TestClaudeCodeLLM::test_probe_missing_binary -x` | ❌ Wave 0 |
| CLAUDECLI-01 | `ClaudeCodeLLM.send_message()` parses `result` field | unit | `pytest tests/test_cli_providers.py::TestClaudeCodeLLM::test_send_message_success -x` | ❌ Wave 0 |
| CLAUDECLI-01 | `ClaudeCodeLLM.send_message()` raises `CLITimeoutError` on timeout | unit | `pytest tests/test_cli_providers.py::TestClaudeCodeLLM::test_send_message_timeout -x` | ❌ Wave 0 |
| CLAUDECLI-01 | `ClaudeCodeLLM.send_message()` raises `CLIParseError` on invalid JSON | unit | `pytest tests/test_cli_providers.py::TestClaudeCodeLLM::test_send_message_parse_error -x` | ❌ Wave 0 |
| CLAUDECLI-01 | Live: `claude -p "hello" --output-format json` returns valid response | live | `pytest tests/test_cli_providers.py -m live -k claude` | ❌ Wave 0 |
| GEMINI-CLI-01 | `GeminiCLILLM.probe()` returns ok=True when binary >= 0.6.0 | unit | `pytest tests/test_cli_providers.py::TestGeminiCLILLM::test_probe_ok -x` | ❌ Wave 0 |
| GEMINI-CLI-01 | `GeminiCLILLM.probe()` returns ok=False when version too old | unit | `pytest tests/test_cli_providers.py::TestGeminiCLILLM::test_probe_version_too_old -x` | ❌ Wave 0 |
| GEMINI-CLI-01 | `GeminiCLILLM.get_response()` extracts `response` field | unit | `pytest tests/test_cli_providers.py::TestGeminiCLILLM::test_get_response -x` | ❌ Wave 0 |
| GEMINI-CLI-01 | `GeminiCLILLM._extract_usage()` sums tokens across models | unit | `pytest tests/test_cli_providers.py::TestGeminiCLILLM::test_extract_usage_multi_model -x` | ❌ Wave 0 |
| GEMINI-CLI-01 | Live: `gemini -p "hello" --output-format json` returns valid response | live | `pytest tests/test_cli_providers.py -m live -k gemini` | ❌ Wave 0 |

### Sampling Rate

- **Per task commit:** `pytest tests/test_cli_providers.py -x -m "not live"`
- **Per wave merge:** `pytest -m "not live" --cov-fail-under=72`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `tests/test_cli_providers.py` — extend with `TestClaudeCodeLLM` and `TestGeminiCLILLM` classes (file exists from Phase 3, add new test classes)
- [ ] No new conftest fixtures required — existing `tmp_repo` and mock patterns are sufficient

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | `_STRIP_ENV_VARS` prevents API-key auth bypass; auth is CLI-native OAuth |
| V3 Session Management | no | `--no-session-persistence` (Claude Code); stateless per call |
| V4 Access Control | yes | `tool_mode` controls what the CLI binary can do during a scan run |
| V5 Input Validation | yes | `shutil.which()` + list-form subprocess; no shell injection vector |
| V6 Cryptography | no | No crypto operations; auth delegated to CLI binary |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Prompt injection via `-p` flag | Tampering | List-form `subprocess.run` (already implemented in base); `-p` as a separate list element, not shell-interpolated |
| API key leakage via inherited env | Information Disclosure | `_build_env()` strips designated API key vars before spawn |
| Subprocess escape via crafted prompt | Elevation of Privilege | `shell=False` enforced in `_run_subprocess()`; no shell metacharacter risk |
| CLI tool side effects during scan | Tampering | `tool_mode: "none"` → `--approval-mode plan` (Gemini) / `--tools ""` (Claude Code) prevents write operations |
| Vertex AI routing via env leak | Information Disclosure | `GOOGLE_GENAI_USE_VERTEXAI` included in strip list |

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `claude` binary | CLAUDECLI-01 | ✓ | 2.1.126 | — (operator must install) |
| `gemini` binary | GEMINI-CLI-01 | ✓ | 0.40.1 | — (operator must install) |
| `node` / `npm` | Install path for both CLIs | ✓ | node 25.8.1, npm 11.12.0 | — |
| `pytest` | Testing | ✓ | (existing) | — |

**Missing dependencies with no fallback:** None — both CLIs are installed.

**Note:** Live tests (`@pytest.mark.live`) require both binaries to be installed and authenticated. CI runs with `-m "not live"` so CI is unblocked regardless.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `gemini --version` outputs just the semver string (e.g., `0.40.1`) with no additional prefix text | Gemini Version Gate | Regex `r"(\d+\.\d+\.\d+)"` still matches; low risk |
| A2 | `--approval-mode plan` in headless mode (`-p`) prevents all file write and shell execution | Tool Mode Mappings | Gemini tool calls could still make writes if `plan` mode is bypassed; verify with live test |
| A3 | `ClaudeCodeLLM.__init__` should accept a `policy: CLIPolicy` parameter for `tool_mode` and `strip_env_vars` merging | Runner Wiring pattern | If not passed, `tool_mode` defaults to `"none"` (safe) but `strip_env_vars` overrides won't work |
| A4 | `GOOGLE_GENAI_USE_VERTEXAI` stripping prevents Vertex AI routing without breaking normal OAuth flow | Env-Var Stripping | If operator legitimately uses Vertex, stripping this var would break their setup; planner should document in `.env` |

**If this table is empty:** All claims in this research were verified or cited — no user confirmation needed.

The A1–A4 assumptions above are LOW risk but flagged for the planner's awareness.

---

## Open Questions (RESOLVED)

1. **`CLIProviderLLM.__init__` signature for `policy` parameter**
   - What we know: The base class `__init__` takes `(system_prompt, cost_callback, timeout, workdir)` — no `policy` parameter.
   - What's unclear: Should `ClaudeCodeLLM.__init__` add `policy: CLIPolicy` as a parameter and store it on `self`, or should `tool_mode` and `strip_env_vars` be extracted and stored separately?
   - **RESOLVED:** Add `policy: CLIPolicy | None = None` to each provider `__init__`, store as `self._policy`. Override `_build_env()` to merge `_STRIP_ENV_VARS` + `policy.strip_env_vars`.

2. **`send_message` first argument name: `user_prompt` vs `messages`**
   - What we know: `LLM.send_message(self, messages, max_tokens, response_model)` uses `messages`. `CLIProviderLLM.chat()` calls `self.send_message(user_prompt, max_tokens, response_model)` — passing a string as first arg.
   - What's unclear: Whether the parameter should be named `user_prompt: str` or `messages: Any` in subclasses.
   - **RESOLVED:** Name it `user_prompt: str` in provider subclasses (it's always a single string for CLI providers, not a list of dicts). Match the experiment's pattern.

3. **Gemini CLI workdir**
   - What we know: `CLIProviderLLM.__init__` has `workdir: str | None = None` and base class passes it to `_run_subprocess` via `cwd`.
   - What's unclear: Whether `GeminiCLILLM` needs a specific workdir or can run from the current directory.
   - **RESOLVED:** Default to `None` (inherits CWD) for Gemini CLI; only set workdir if operator specifies in `CLIPolicy`.

---

## Sources

### Primary (HIGH confidence)
- Live `claude -p ... --output-format json` run — Claude Code JSON schema keys confirmed
- Live `gemini -p ... --output-format json` run — Gemini CLI JSON schema, nested `stats.models.<name>.tokens.input` path confirmed
- `claude --help` output — all Claude Code CLI flags confirmed (--tools, --allowed-tools, --disallowed-tools, --permission-mode, etc.)
- `gemini --help` output — all Gemini CLI flags confirmed (--approval-mode choices, --output-format, -p, etc.)
- `vulnhuntr/cli_providers/base.py` — abstract interface, 2 `@abstractmethod` decorators (probe, get_response), class structure
- `vulnhuntr/cli_providers/__init__.py` — exports; needs ClaudeCodeLLM and GeminiCLILLM added
- `vulnhuntr/config.py` — CLIPolicy fields; needs tool_mode and strip_env_vars added
- `vulnhuntr/cli/runner.py` — NotImplementedError stub location, probe wiring already present
- `internal/experiments/vulnhuntr_claude_code/claude_code_llm.py` — experiment implementation confirmed promotable
- `tests/test_cli_providers.py` — existing test structure, mock patterns
- `/home/diaz/.nvm/versions/node/v25.8.1/lib/node_modules/@google/gemini-cli/bundle/chunk-F73F75XM.js` — `getApiKeyFromEnv()` function; confirms `GOOGLE_API_KEY` checked first, `GEMINI_API_KEY` fallback
- `/home/diaz/.nvm/versions/node/v25.8.1/lib/node_modules/@google/gemini-cli/bundle/chunk-DMTQDMOD.js` — `approval-mode` plan = "read-only mode" confirmed from source comment
- `pyproject.toml` — pytest markers, CI exclusion, coverage threshold

### Secondary (MEDIUM confidence)
- `https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/headless.md` — confirms `response`, `stats`, `error` as top-level fields (no stats subfields shown; verified via live run)
- `https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/tutorials/automation.md` — `.response` field access pattern for jq

### Tertiary (LOW confidence — training knowledge)
- Minimum Gemini CLI version for `--output-format json`: CONTEXT.md says `>= 0.6.0`; this research could not find the release where it was introduced. Dev machine has 0.40.1 and it works. Version gate `>= 0.6.0` is from CONTEXT.md decision D-08, not independently verified.

---

## Metadata

**Confidence breakdown:**
- Gemini JSON schema: HIGH — confirmed via live run on gemini 0.40.1
- Claude Code JSON schema: HIGH — confirmed via live run on claude 2.1.126
- Claude Code CLI flags: HIGH — confirmed via `claude --help`
- Gemini CLI flags (approval-mode): HIGH — confirmed via `gemini --help` + bundle source
- Env var stripping for Gemini: HIGH — confirmed from Gemini CLI bundle JavaScript source
- Tool mode flag mapping: HIGH for Claude Code (from help output); MEDIUM for Gemini CLI (approval-mode plan semantics confirmed from bundle source comment)
- Version gate minimum (0.6.0): LOW — carried from CONTEXT.md, not independently verified via changelog

**Research date:** 2026-05-02
**Valid until:** 2026-06-02 (stable CLI APIs; Gemini CLI updates frequently — re-verify `--approval-mode` flag if using version >1.0)
