# Phase 4: Claude Code & Gemini CLI - Pattern Map

**Mapped:** 2026-05-02
**Files analyzed:** 7
**Analogs found:** 7 / 7

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `vulnhuntr/cli_providers/claude_code.py` | service | request-response | `internal/experiments/vulnhuntr_claude_code/claude_code_llm.py` | exact |
| `vulnhuntr/cli_providers/gemini_cli.py` | service | request-response | `internal/experiments/vulnhuntr_claude_code/claude_code_llm.py` | role-match |
| `vulnhuntr/cli_providers/__init__.py` | config | — | `vulnhuntr/cli_providers/__init__.py` (current) | exact |
| `vulnhuntr/config.py` | config | — | `vulnhuntr/config.py` (current CLIPolicy) | exact |
| `vulnhuntr/cli/runner.py` | controller | request-response | `vulnhuntr/cli/runner.py` (current `initialize_llm`) | exact |
| `tests/test_cli_providers.py` | test | — | `tests/test_cli_providers.py` (Phase 3 tests) | exact |

---

## Pattern Assignments

### `vulnhuntr/cli_providers/claude_code.py` (service, request-response)

**Analog:** `internal/experiments/vulnhuntr_claude_code/claude_code_llm.py`
**Secondary analog:** `vulnhuntr/cli_providers/base.py` — base class contract

**Imports pattern** (experiment lines 1-10, adjusted for new base):
```python
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
```

**Class declaration and `_STRIP_ENV_VARS`** (adapt from experiment line 13 + D-05):
```python
class ClaudeCodeLLM(CLIProviderLLM):
    """Claude Code headless adapter (CLIProviderLLM subclass)."""

    _STRIP_ENV_VARS: ClassVar[tuple[str, ...]] = ("ANTHROPIC_API_KEY",)
```

**`probe()` pattern** — no analog in experiment; build from base class `_run_subprocess`:
```python
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
```

**`send_message()` pattern** (experiment lines 34-84, adapted to use base `_run_subprocess`):
```python
# Experiment: lines 34-84
def send_message(self, messages: str, max_tokens: int, response_model: Any = None) -> dict[str, Any]:
    del max_tokens, response_model

    cmd = [
        "claude",
        "-p",
        messages,           # prompt via -p flag (D-02)
        "--output-format", "json",
        "--permission-mode", "bypassPermissions",  # D-03
        "--no-session-persistence",                # D-03
    ]

    # env stripping handled by CLIProviderLLM._build_env() via _STRIP_ENV_VARS
    result = self._run_subprocess(cmd)   # NOT subprocess.run directly
    stdout = result.stdout.strip()
    if not stdout:
        raise CLIParseError("Claude Code returned empty stdout")
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise CLIParseError(
            f"Claude Code returned invalid JSON: {stdout[:500]}"
        ) from exc
    # Set self.model so _extract_usage can fall back to it
    model_usage = payload.get("modelUsage") or {}
    self.model = next(iter(model_usage.keys()), "claude-code")
    return payload
```

Key difference from experiment: replace `subprocess.run(...)` with `self._run_subprocess(cmd)` — base class handles timeout, env, and error taxonomy.

**`get_response()` pattern** (experiment lines 86-90):
```python
def get_response(self, response: Any) -> str:
    result = response.get("result")
    if result is None:
        raise CLIParseError(
            "Claude Code response did not contain a 'result' field"
        )
    return str(result)
```

**`_extract_usage()` pattern** (experiment lines 127-142):
```python
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
```

**`_build_env()` override for `CLIPolicy.strip_env_vars` merging** (RESEARCH.md Pattern 4):
```python
def _build_env(self) -> dict[str, str]:
    env = super()._build_env()  # strips class-level _STRIP_ENV_VARS
    for var in (self._policy.strip_env_vars if self._policy else []):
        env.pop(var, None)
    return env
```

**`__init__` signature** — add `policy` parameter; base class does NOT have it (RESEARCH.md open question 1):
```python
def __init__(
    self,
    system_prompt: str = "",
    cost_callback: Any | None = None,
    timeout: int = 300,
    workdir: str | None = None,
    policy: CLIPolicy | None = None,
) -> None:
    super().__init__(system_prompt, cost_callback, timeout, workdir)
    self._policy = policy
```

**Do NOT override `chat()`** — D-01 is explicit; base class `CLIProviderLLM.chat()` handles everything.

---

### `vulnhuntr/cli_providers/gemini_cli.py` (service, request-response)

**Analog:** `internal/experiments/vulnhuntr_claude_code/claude_code_llm.py` (same shape, different JSON envelope)

**Imports pattern** (same as ClaudeCodeLLM):
```python
from __future__ import annotations

import json
import re
import shutil
from typing import Any, ClassVar

import structlog

from vulnhuntr.cli_providers.base import (
    CLIParseError,
    CLIProviderLLM,
    CapabilityResult,
)
from vulnhuntr.core.models import LLMUsage

log = structlog.get_logger(__name__)
```

**Class declaration, `_STRIP_ENV_VARS`, and `_MIN_VERSION`** (RESEARCH.md D-09 + env-var analysis):
```python
class GeminiCLILLM(CLIProviderLLM):
    """Gemini CLI headless adapter (CLIProviderLLM subclass)."""

    _STRIP_ENV_VARS: ClassVar[tuple[str, ...]] = (
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_GENAI_USE_VERTEXAI",   # prevents Vertex AI routing
    )
    _MIN_VERSION: tuple[int, ...] = (0, 6, 0)
```

**`probe()` with version gate** (RESEARCH.md D-08, Gemini version gate section):
```python
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
    # MUST use tuple comparison — string comparison is wrong for semver (Pitfall 1)
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
```

**`send_message()` pattern** (RESEARCH.md Pattern 2 + tool mode flags):
```python
def send_message(self, messages: str, max_tokens: int, response_model: Any = None) -> dict[str, Any]:
    del max_tokens, response_model

    cmd = ["gemini", "-p", messages, "--output-format", "json"]
    # tool_mode: default "none" → --approval-mode plan (safe headless default)
    # NEVER use --allowed-tools — deprecated in Gemini CLI 0.40.1 (Pitfall 2)
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
```

**`get_response()` pattern** (RESEARCH.md D-06 + verified JSON schema):
```python
def get_response(self, response: Any) -> str:
    result = response.get("response")
    if result is None:
        raise CLIParseError(
            "Gemini CLI response did not contain a 'response' field"
        )
    return str(result)
```

**`_extract_usage()` pattern** (RESEARCH.md verified schema — NOT `stats.inputTokenCount`, Pitfall 3):
```python
def _extract_usage(self, response: Any) -> LLMUsage:
    stats = response.get("stats") or {}
    models = stats.get("models") or {}
    input_tokens = 0
    output_tokens = 0
    model_name = self.model or "gemini"
    # Sum across ALL models — Gemini uses multiple models per call (Pitfall 5)
    for name, mdata in models.items():
        tokens = (mdata or {}).get("tokens") or {}
        input_tokens += int(tokens.get("input", 0))
        output_tokens += int(tokens.get("candidates", 0))
        model_name = name  # last model name wins
    self.model = model_name
    return LLMUsage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        model=model_name,
    )
```

**`_build_env()` override** — same pattern as ClaudeCodeLLM (see above).

**`__init__` signature** — same as ClaudeCodeLLM (add `policy: CLIPolicy | None = None`).

---

### `vulnhuntr/cli_providers/__init__.py` (config)

**Analog:** `vulnhuntr/cli_providers/__init__.py` (current, lines 1-28)

**Current exports** (lines 8-28) — add `ClaudeCodeLLM` and `GeminiCLILLM`:
```python
from vulnhuntr.cli_providers.base import (
    CLIAuthError,
    CLIBinaryNotFoundError,
    CLIParseError,
    CLIProviderLLM,
    CLIRuntimeError,
    CLISandboxError,
    CLITimeoutError,
    CapabilityResult,
)
from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM
from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM

__all__ = [
    "CLIProviderLLM",
    "CapabilityResult",
    "CLIBinaryNotFoundError",
    "CLIAuthError",
    "CLITimeoutError",
    "CLIParseError",
    "CLISandboxError",
    "CLIRuntimeError",
    "ClaudeCodeLLM",
    "GeminiCLILLM",
]
```

---

### `vulnhuntr/config.py` — `CLIPolicy` extension (config)

**Analog:** `vulnhuntr/config.py` lines 16-48 (current CLIPolicy dataclass)

**New fields to add after `mcp_mode`** (after line 47 in current file):
```python
# Existing fields (lines 40-48) remain unchanged:
#   timeout, workdir, auth_mode, session_mode, approval_mode,
#   sandbox_mode, max_turns, mcp_mode, overrides

# Add two new fields (D-11, D-14):
tool_mode: str = "none"                           # "none" | "read-only" | "full"
strip_env_vars: list[str] = field(default_factory=list)
```

**`from_dict()` additions** — copy the pattern from current lines 183-201, add after `mcp_mode` block:
```python
# Copy pattern from config.py lines 198-200:
if "mcp_mode" in cli_data:
    cli.mcp_mode = str(cli_data["mcp_mode"])
# Add these two new blocks:
if "tool_mode" in cli_data:
    cli.tool_mode = str(cli_data["tool_mode"])
if "strip_env_vars" in cli_data and isinstance(cli_data["strip_env_vars"], list):
    cli.strip_env_vars = list(cli_data["strip_env_vars"])
```

**`to_dict()` note** — `dataclasses.asdict(self.cli)` at line 223 auto-includes new fields; no manual change required.

---

### `vulnhuntr/cli/runner.py` — `initialize_llm()` stub replacement (controller)

**Analog:** `vulnhuntr/cli/runner.py` lines 63-97 (`initialize_llm()` function)

**Current stub** (lines 83-90) to replace:
```python
elif llm_arg in ("claude-code", "gemini-cli", "codex", "qwen-code"):
    from vulnhuntr.cli_providers import CLIProviderLLM  # noqa: F401

    raise NotImplementedError(
        f"CLI provider '{llm_arg}' is not yet implemented. ..."
    )
```

**Replacement pattern** (RESEARCH.md Pattern 5; follow `elif llm_arg == "ollama"` style at line 79):
```python
elif llm_arg in ("claude-code", "gemini-cli", "codex", "qwen-code"):
    from vulnhuntr.config import CLIPolicy

    policy = getattr(config, "cli", None) or CLIPolicy()
    overrides = policy.overrides.get(llm_arg, {})
    timeout = overrides.get("timeout", policy.timeout)
    workdir = overrides.get("workdir", policy.workdir)

    if llm_arg == "claude-code":
        from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM
        return ClaudeCodeLLM(
            system_prompt=system_prompt,
            cost_callback=cost_callback,
            timeout=timeout,
            workdir=workdir,
            policy=policy,
        )
    elif llm_arg == "gemini-cli":
        from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM
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

Note: `initialize_llm` signature is `(llm_arg, system_prompt, cost_callback, model_override)` — but CLI providers don't take `model_override` via env; they use `CLIPolicy.overrides`. The `config` parameter is not currently in the signature. Planner must choose: either pass `config` in or access it through the call chain. RESEARCH.md Pattern 5 passes `config` as a local in `_init_providers()` at line 302.

The actual call at runner.py line 302 is:
```python
llm = initialize_llm(args.llm, system_prompt, cost_callback, model_override=config.model)
```

**The planner must add `config` to `initialize_llm`'s signature** or load it internally for the CLI branch. Simplest approach: add `config: Any | None = None` as a keyword argument to `initialize_llm`, defaulting to None, and call `CLIPolicy()` as fallback.

---

### `tests/test_cli_providers.py` — extension with new test classes (test)

**Analog:** `tests/test_cli_providers.py` lines 37-334 (existing Phase 3 test structure)

**Mock pattern** (lines 195-212 — use verbatim for new tests):
```python
# Pattern: patch subprocess.run, set returncode=0, provide stdout
with patch("subprocess.run") as mock_run:
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = '{"result": "hello", "usage": {}, "modelUsage": {}}'
    mock_result.stderr = ""
    mock_run.return_value = mock_result

    # call provider method here
```

**CLITimeoutError test pattern** (lines 248-251):
```python
with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="x", timeout=1)):
    with pytest.raises(CLITimeoutError):
        provider._run_subprocess(["claude", "-p", "test"])
```

**CLIBinaryNotFoundError test pattern** (lines 241-244):
```python
with patch("subprocess.run", side_effect=FileNotFoundError("no such file")):
    with pytest.raises(CLIBinaryNotFoundError):
        provider._run_subprocess(["claude", "..."])
```

**probe() missing binary pattern** — mock `shutil.which` to return `None`:
```python
with patch("shutil.which", return_value=None):
    result = provider.probe()
    assert result.ok is False
    assert result.binary_found is False
```

**probe() binary found pattern** — mock `shutil.which` + `subprocess.run`:
```python
with patch("shutil.which", return_value="/usr/bin/claude"):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="2.1.126 (Claude Code)", stderr="")
        result = provider.probe()
        assert result.ok is True
        assert result.version == "2.1.126"
```

**`@pytest.mark.live` pattern** (RESEARCH.md D-17; pyproject.toml already declares the marker):
```python
@pytest.mark.live
def test_claude_code_live_round_trip():
    """Requires `claude` binary installed and authenticated.
    Run locally: pytest tests/test_cli_providers.py -m live -k claude
    Excluded from CI via pyproject.toml addopts = '-m "not live"'
    """
    from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM
    provider = ClaudeCodeLLM()
    result = provider.send_message("Say hello in one word.", 256, None)
    assert "result" in result
```

**Test class structure** — follow the `class TestSubprocessDispatch:` shape at line 194:
```python
class TestClaudeCodeLLM:
    def test_probe_ok(self): ...
    def test_probe_missing_binary(self): ...
    def test_send_message_success(self): ...
    def test_send_message_timeout(self): ...
    def test_send_message_parse_error(self): ...
    def test_get_response_extracts_result_field(self): ...
    def test_extract_usage_sums_cache_tokens(self): ...

class TestGeminiCLILLM:
    def test_probe_ok(self): ...
    def test_probe_missing_binary(self): ...
    def test_probe_version_too_old(self): ...
    def test_send_message_success(self): ...
    def test_get_response_extracts_response_field(self): ...
    def test_extract_usage_multi_model(self): ...
    def test_extract_usage_missing_stats(self): ...
```

---

## Shared Patterns

### `from __future__ import annotations`
**Source:** Every existing source file in the project (`base.py` line 13, `config.py` line 3, `llms.py` line 1)
**Apply to:** `claude_code.py`, `gemini_cli.py`
```python
from __future__ import annotations
```

### structlog logger
**Source:** `vulnhuntr/cli_providers/base.py` line 25; `vulnhuntr/config.py` line 12
**Apply to:** `claude_code.py`, `gemini_cli.py`
```python
import structlog
log = structlog.get_logger(__name__)
```

### Error taxonomy (re-raise as CLI errors)
**Source:** `vulnhuntr/cli_providers/base.py` lines 33-54 + `_run_subprocess()` lines 188-208
**Apply to:** `claude_code.py`, `gemini_cli.py` — raise `CLIParseError` for JSON issues; the base class already raises `CLIBinaryNotFoundError`, `CLITimeoutError`, `CLIRuntimeError` from `_run_subprocess()`.
```python
# CLIParseError raised in send_message() when json.loads fails or stdout is empty
raise CLIParseError(f"... returned invalid JSON: {stdout[:500]}") from exc
```

### `LLMUsage` return type
**Source:** `vulnhuntr/core/models.py` lines 15-25
**Apply to:** Both `_extract_usage()` implementations
```python
from vulnhuntr.core.models import LLMUsage
# ...
return LLMUsage(input_tokens=..., output_tokens=..., model=...)
```

### `ClassVar` for class-level constants
**Source:** `vulnhuntr/cli_providers/base.py` line 101 (`_STRIP_ENV_VARS: tuple[str, ...] = ()`)
**Apply to:** Both provider classes — use `ClassVar[tuple[str, ...]]` to match base class type (avoid Pitfall 6)
```python
from typing import Any, ClassVar
_STRIP_ENV_VARS: ClassVar[tuple[str, ...]] = ("ANTHROPIC_API_KEY",)
```

### dataclass field additions
**Source:** `vulnhuntr/config.py` lines 40-48 + `from_dict()` lines 183-202
**Apply to:** `CLIPolicy` additions — follow the `if "field" in cli_data:` pattern for `from_dict()`

### `unittest.mock.patch` for subprocess
**Source:** `tests/test_cli_providers.py` lines 15-16, 199-211
**Apply to:** All new test methods — always patch `"subprocess.run"` (not `"vulnhuntr.cli_providers.base.subprocess.run"`)
```python
from unittest.mock import MagicMock, patch
import subprocess
with patch("subprocess.run") as mock_run:
    mock_run.return_value = MagicMock(returncode=0, stdout="...", stderr="")
```

---

## No Analog Found

All files have close analogs. No entries in this section.

---

## Critical Implementation Notes (for planner)

1. **Do NOT override `chat()`** in either provider (D-01). The base class `CLIProviderLLM.chat()` at `base.py` lines 216-247 is the full pipeline.

2. **Semver tuple comparison** required in `GeminiCLILLM.probe()` — `"0.9.0" > "0.40.0"` is True as strings but False as version. Use `tuple(int(x) for x in v.split("."))`.

3. **`--allowed-tools` is deprecated** in Gemini CLI 0.40.1. Use `--approval-mode plan` for `tool_mode: "none"` and `"read-only"`. Never use `--allowed-tools`.

4. **Gemini JSON schema correction** — `stats.inputTokenCount` does NOT exist. Use `stats.models.<name>.tokens.input` and `stats.models.<name>.tokens.candidates`. Sum across all model entries.

5. **`initialize_llm` needs `config` access** for CLI branch. The function currently receives `model_override` but not the full `config`. Either add `config: Any | None = None` kwarg, or extract `CLIPolicy` from a module-level config load.

6. **`_build_env()` override pattern** for `CLIPolicy.strip_env_vars` merging — call `super()._build_env()` first, then pop additional vars from `self._policy.strip_env_vars`.

7. **Test file:** Extend `tests/test_cli_providers.py` (add new classes at the bottom) — do not create a separate file, as the volume fits within the existing file and the mock infrastructure is already imported.

---

## Metadata

**Analog search scope:** `vulnhuntr/`, `internal/experiments/`, `tests/`
**Files scanned:** 8 source files read in full
**Pattern extraction date:** 2026-05-02
