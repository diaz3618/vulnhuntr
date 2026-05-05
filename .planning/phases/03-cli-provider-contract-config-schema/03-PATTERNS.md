# Phase 3: CLI Provider Contract & Config Schema - Pattern Map

**Mapped:** 2026-05-01
**Files analyzed:** 5 new/modified files
**Analogs found:** 5 / 5

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `vulnhuntr/cli_providers/__init__.py` | config/re-export | — | `vulnhuntr/__init__.py` | role-match (package re-export) |
| `vulnhuntr/cli_providers/base.py` | service/provider | request-response (subprocess) | `internal/experiments/vulnhuntr_claude_code/claude_code_llm.py` | exact (promoted pattern) |
| `vulnhuntr/config.py` (extend) | config | CRUD/transform | `vulnhuntr/config.py` itself | self (additive extension) |
| `vulnhuntr/cli/runner.py` (extend) | controller/factory | request-response | `vulnhuntr/cli/runner.py` itself | self (additive extension) |
| `tests/test_cli_providers.py` | test | — | `tests/test_llms.py` | role-match (LLM provider tests) |
| `tests/test_config.py` (extend) | test | — | `tests/test_config.py` itself | self (additive extension) |

---

## Pattern Assignments

### `vulnhuntr/cli_providers/__init__.py` (package init, re-export)

**Analog:** `vulnhuntr/__init__.py` (lines 1-17) and `vulnhuntr/cli/__init__.py`

**Re-export pattern** — copy the `from __future__ import annotations` convention and explicit `__all__`. The package init must re-export `CLIProviderLLM` and `CapabilityResult` so callers use `from vulnhuntr.cli_providers import CLIProviderLLM`:

```python
from __future__ import annotations

from vulnhuntr.cli_providers.base import (
    CapabilityResult,
    CLIAuthError,
    CLIBinaryNotFoundError,
    CLIParseError,
    CLIProviderLLM,
    CLIRuntimeError,
    CLISandboxError,
    CLITimeoutError,
)

__all__ = [
    "CLIProviderLLM",
    "CapabilityResult",
    "CLIBinaryNotFoundError",
    "CLIAuthError",
    "CLITimeoutError",
    "CLIParseError",
    "CLISandboxError",
    "CLIRuntimeError",
]
```

---

### `vulnhuntr/cli_providers/base.py` (service, request-response via subprocess)

**Analog:** `internal/experiments/vulnhuntr_claude_code/claude_code_llm.py` (lines 1-163) — this is the proof-of-concept being promoted. Extract shared patterns; make abstract what varies per provider.

**Imports pattern** — copy from experiment (lines 1-10), extend with `abc`, `shutil`, `dataclass`:

```python
from __future__ import annotations

import json
import os
import shutil
import subprocess
from abc import abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from vulnhuntr.core.models import LLMUsage
from vulnhuntr.llms import LLM, LLMError

log = structlog.get_logger()
```

**Error hierarchy pattern** — mirrors existing `llms.py` lines 31-43. New subclasses use the same bare-`pass` body convention:

```python
# Source: vulnhuntr/llms.py lines 31-43
class RateLimitError(LLMError):
    pass

class APIConnectionError(LLMError):
    pass
```

Apply the same pattern to all six CLI-specific subclasses:
```python
class CLIBinaryNotFoundError(LLMError):
    pass

class CLIAuthError(LLMError):
    pass

class CLITimeoutError(LLMError):
    pass

class CLIParseError(LLMError):
    pass

class CLISandboxError(LLMError):
    pass

class CLIRuntimeError(LLMError):
    pass
```

**CapabilityResult dataclass pattern** — mirrors `config.py` dataclass style (lines 23-64): `@dataclass` with typed fields and defaults, no `field()` needed because all fields are immutable scalars or `None`-able:

```python
@dataclass
class CapabilityResult:
    ok: bool
    binary_found: bool
    version: str | None
    auth_valid: bool | None   # None = cannot check statically
    diagnostic_message: str
```

**CLIProviderLLM `__init__` pattern** — copy `ClaudeCodeLLM.__init__` (experiment lines 16-29) but add `cost_callback` param (from `LLM.__init__` at `llms.py` lines 47-68) and `env_strip_keys` hook:

```python
# Source: internal/experiments/vulnhuntr_claude_code/claude_code_llm.py lines 16-29
def __init__(
    self,
    model: str | None = None,
    system_prompt: str = "",
    workdir: str | Path = "/tmp/vulnhuntr",
    timeout_seconds: int = 300,
) -> None:
    super().__init__(system_prompt=system_prompt)
    self.model = model or "claude-code"
    self._workdir = Path(workdir)
    self._timeout_seconds = timeout_seconds
    self._workdir.mkdir(parents=True, exist_ok=True)
```

Extended version for `CLIProviderLLM` adds `cost_callback` and `env_strip_keys`:
```python
def __init__(
    self,
    model: str | None = None,
    system_prompt: str = "",
    workdir: str | Path = "/tmp/vulnhuntr",
    timeout_seconds: int = 300,
    cost_callback=None,
    env_strip_keys: frozenset[str] | None = None,
) -> None:
    super().__init__(system_prompt=system_prompt, cost_callback=cost_callback)
    self.model = model or self.binary_name
    self._workdir = Path(workdir)
    self._timeout_seconds = timeout_seconds
    if env_strip_keys is not None:
        self._env_strip_keys = env_strip_keys
    self._workdir.mkdir(parents=True, exist_ok=True)
```

**`_run_subprocess` core pattern** — extracted and promoted from `ClaudeCodeLLM.send_message` (experiment lines 34-84). Critical additions over the experiment: `stdin=subprocess.DEVNULL`, typed error classification into `CLI*Error` subclasses instead of bare `LLMError`, and JSON parsing moved here:

```python
# Source: internal/experiments/vulnhuntr_claude_code/claude_code_llm.py lines 52-84
env = os.environ.copy()
env.pop("ANTHROPIC_API_KEY", None)

try:
    completed = subprocess.run(
        cmd,
        capture_output=True,
        cwd=self._workdir,
        env=env,
        text=True,
        timeout=self._timeout_seconds,
        check=False,
    )
except subprocess.TimeoutExpired as exc:
    raise LLMError(f"Claude Code timed out after {self._timeout_seconds}s") from exc

if completed.returncode != 0:
    stderr = completed.stderr.strip() or "No stderr captured"
    raise LLMError(f"Claude Code exited with status {completed.returncode}: {stderr}")

stdout = completed.stdout.strip()
if not stdout:
    raise LLMError("Claude Code returned empty stdout")

try:
    payload = json.loads(stdout)
except json.JSONDecodeError as exc:
    snippet = stdout[:500]
    raise LLMError(f"Claude Code returned invalid JSON envelope: {snippet}") from exc
```

In `CLIProviderLLM._run_subprocess`, generalize: replace `LLMError` with the specific `CLI*Error` subclasses, use `self.binary_name` instead of `"Claude Code"`, pop `self._env_strip_keys` instead of hardcoding `ANTHROPIC_API_KEY`, and add `stdin=subprocess.DEVNULL`.

**`chat()` override pattern** — copy from experiment lines 92-125 almost verbatim. Key invariants to preserve:
1. `self._add_to_history("user", prompt)` before subprocess call
2. `self._log_response(payload)` immediately after `_run_subprocess` returns (cost tracking)
3. `self.get_response(payload)` to unwrap envelope (abstract)
4. `self._validate_response(response_text, response_model)` for Pydantic validation
5. Two-attempt retry with JSON repair suffix on attempt 1

```python
# Source: internal/experiments/vulnhuntr_claude_code/claude_code_llm.py lines 92-125
def chat(self, user_prompt, response_model=None, max_tokens=8192):
    base_prompt = user_prompt
    repair_suffix = (
        "\n\nIMPORTANT: Return only valid JSON that conforms to the schema in "
        "<response_format>. Do not wrap the JSON in markdown fences or add prose."
    )

    last_error: Exception | None = None
    for attempt in range(2):
        prompt = base_prompt if attempt == 0 else base_prompt + repair_suffix
        self._add_to_history("user", prompt)

        response = self.send_message(prompt, max_tokens, response_model)
        self._log_response(response)

        response_text = self.get_response(response)
        if response_model is not None:
            try:
                parsed = self._validate_response(response_text, response_model)
            except Exception as exc:
                last_error = exc
                continue
            self._add_to_history("assistant", str(parsed))
            return parsed

        self._add_to_history("assistant", response_text)
        return response_text

    raise LLMError("Claude Code failed to return valid structured output") from last_error
```

In `CLIProviderLLM.chat()`, replace `self.send_message(prompt, ...)` with `self._run_subprocess(self._build_cmd(prompt, max_tokens))`. The `get_response()` and `_extract_usage()` calls remain abstract.

**`_extract_usage` pattern** — copy from experiment lines 127-142; make abstract in base, keep the cache-token summing logic as a reference for the Phase 4 Claude Code subclass:

```python
# Source: internal/experiments/vulnhuntr_claude_code/claude_code_llm.py lines 127-142
def _extract_usage(self, response: Any) -> LLMUsage:
    usage = response.get("usage") or {}
    model_usage = response.get("modelUsage") or {}
    model_name = next(iter(model_usage.keys()), self._model_alias or self.model)
    input_tokens = (
        int(usage.get("input_tokens", 0))
        + int(usage.get("cache_creation_input_tokens", 0))
        + int(usage.get("cache_read_input_tokens", 0))
    )
    output_tokens = int(usage.get("output_tokens", 0))
    return LLMUsage(input_tokens=input_tokens, output_tokens=output_tokens, model=model_name)
```

In `CLIProviderLLM`, declare `_extract_usage` as `@abstractmethod`. The above excerpt is the Phase 4 ClaudeCodeLLM implementation (not the base).

**`create_messages` / `send_message` stub pattern** — these exist on `LLM` base (lines 185-195) as `raise NotImplementedError`. `CLIProviderLLM.chat()` fully bypasses them; override both to raise a clear `NotImplementedError` that explains why:

```python
# Source: vulnhuntr/llms.py lines 185-195
def create_messages(self, user_prompt: str) -> Any:
    """Create messages for the LLM API. Override in subclasses."""
    raise NotImplementedError

def send_message(self, messages: Any, max_tokens: int, response_model: Any = None) -> Any:
    """Send messages to the LLM API. Override in subclasses."""
    raise NotImplementedError
```

Override in `CLIProviderLLM` with a message that redirects to `_run_subprocess`.

---

### `vulnhuntr/config.py` (extend — additive)

**Analog:** `vulnhuntr/config.py` itself. Copy the existing `@dataclass` pattern and `from_dict()` extension pattern.

**Dataclass field pattern** — copy from `VulnhuntrConfig` lines 23-64. Use `field(default_factory=...)` for the mutable `overrides` dict (matches `vuln_types` at line 58):

```python
# Source: vulnhuntr/config.py lines 23-64
@dataclass
class VulnhuntrConfig:
    ...
    vuln_types: list[str] = field(default_factory=list)   # <-- mutable default pattern
    exclude_paths: list[str] = field(default_factory=list)
```

Apply same pattern to `CLIPolicy.overrides`:
```python
@dataclass
class CLIPolicy:
    timeout: int = 300
    workdir: str = "/tmp/vulnhuntr"
    auth_mode: str = "auto"
    session_mode: str = "stateless"
    approval_mode: str = "auto"
    sandbox_mode: str = "none"
    max_turns: int = 10
    mcp_mode: str = "none"
    overrides: dict[str, dict] = field(default_factory=dict)
```

Add `cli: CLIPolicy = field(default_factory=CLIPolicy)` to `VulnhuntrConfig`.

**`from_dict()` extension pattern** — copy the nested-section block structure from lines 107-139. Each section uses `if "key" in data and isinstance(data["key"], dict):` then `int()`/`str()`/`bool()` casts per field:

```python
# Source: vulnhuntr/config.py lines 107-139
if "cost" in data and isinstance(data["cost"], dict):
    cost = data["cost"]
    if "budget" in cost:
        config.budget = float(cost["budget"]) if cost["budget"] is not None else None
    if "checkpoint" in cost:
        config.checkpoint = bool(cost["checkpoint"])
    if "checkpoint_interval" in cost:
        config.checkpoint_interval = int(cost["checkpoint_interval"])
```

Apply the same pattern for the `cli:` section. The `overrides` sub-dict gets special handling: `{k: dict(v) for k, v in cli_data["overrides"].items()}`.

**`to_dict()` extension pattern** — copy from lines 142-159. Add `"cli": dataclasses.asdict(self.cli)` to the returned dict. Requires adding `import dataclasses` to `config.py` if not already present (it is not currently imported — only `from dataclasses import dataclass, field`):

```python
# Source: vulnhuntr/config.py lines 142-159
def to_dict(self) -> dict[str, Any]:
    return {
        "budget": self.budget,
        ...
        "confidence_threshold": self.confidence_threshold,
    }
```

New version adds: `"cli": dataclasses.asdict(self.cli)` — requires `import dataclasses` at module level (not just `from dataclasses import dataclass, field`).

---

### `vulnhuntr/cli/runner.py` (extend — two additive changes)

**Analog:** `vulnhuntr/cli/runner.py` itself. Copy the `initialize_llm` `elif` branch pattern and the `_init_providers` probe pattern.

**`initialize_llm()` branch pattern** — copy from lines 63-84. New `elif` branches for CLI providers follow the same `elif llm_arg == "..."` structure:

```python
# Source: vulnhuntr/cli/runner.py lines 63-84
elif llm_arg == "claude":
    model = model_override or os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
    base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
    return Claude(model, base_url, system_prompt, cost_callback)

...

else:
    raise ValueError(f"Invalid LLM argument: {llm_arg}\nValid options are: claude, gpt, ollama, openrouter")
```

New Phase 3 stubs use `raise NotImplementedError(...)` instead of returning an instance:
```python
elif llm_arg == "claude-code":
    from vulnhuntr.cli_providers import CLIProviderLLM  # noqa: F401
    raise NotImplementedError(
        "claude-code provider will be implemented in Phase 4. "
        "Use --llm claude for API-based Claude."
    )
```

Update the `else` branch `ValueError` message to list CLI providers with a "coming soon" note.

**`_init_providers()` probe pattern** — copy from lines 265-290. After `llm = llm_factory(...)` or `llm = initialize_llm(...)`, add the probe check BEFORE `wrap_with_fallbacks`:

```python
# Source: vulnhuntr/cli/runner.py lines 265-290
def _init_providers(args, config, cost_callback=None, system_prompt="", llm_factory=None):
    if llm_factory is not None:
        llm = llm_factory(args.llm, system_prompt, cost_callback, config.model)
    else:
        llm = initialize_llm(args.llm, system_prompt, cost_callback, model_override=config.model)
    return wrap_with_fallbacks(llm, args, cost_callback, system_prompt, config=config)
```

New version inserts probe check between instantiation and `wrap_with_fallbacks`:
```python
    # Probe CLI providers before wrapping (must run on the unwrapped instance)
    if hasattr(llm, "probe"):
        result = llm.probe()
        if not result.ok:
            log.error(
                "CLI provider capability check failed",
                provider=args.llm,
                binary_found=result.binary_found,
                diagnostic=result.diagnostic_message,
            )
            raise SystemExit(1)
    return wrap_with_fallbacks(llm, args, cost_callback, system_prompt, config=config)
```

Note: structlog call uses keyword arguments as established throughout `runner.py` (e.g., lines 141, 204, 210).

---

### `tests/test_cli_providers.py` (test, new file)

**Analog:** `tests/test_llms.py` (lines 1-607)

**File header / import pattern** — copy from `test_llms.py` lines 1-27. Docstring + stdlib imports + `unittest.mock` + `pytest` + project imports:

```python
# Source: tests/test_llms.py lines 1-27
"""
Tests for vulnhuntr.llms
...
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel, Field

from vulnhuntr.llms import (
    LLM,
    ...
)
```

**Concrete subclass helper pattern** — copy the `_subclass` inner-class pattern from `test_llms.py` lines 207-223. For `CLIProviderLLM` tests, create a minimal concrete subclass `_FakeCLIProvider` that implements the three abstract methods:

```python
# Source: tests/test_llms.py lines 207-223
class TestLLMChatOrchestration:
    def _subclass(self, raw_response_text, response_obj=None):
        class _Fake(LLM):
            def create_messages(self, user_prompt):
                return [{"role": "user", "content": user_prompt}]
            def send_message(self, messages, max_tokens, response_model):
                return response_obj or SimpleNamespace()
            def get_response(self, response):
                return raw_response_text
            def _extract_usage(self, response):
                return LLMUsage(input_tokens=10, output_tokens=5, model="fake")
        return _Fake()
```

**Error hierarchy test pattern** — copy from `test_llms.py` lines 188-198:

```python
# Source: tests/test_llms.py lines 188-198
class TestErrors:
    def test_llm_error_is_base(self):
        assert issubclass(RateLimitError, LLMError)
        assert issubclass(APIConnectionError, LLMError)
        assert issubclass(APIStatusError, LLMError)
```

Apply same structure for CLI error subclasses:
```python
class TestCLIErrors:
    def test_all_subclass_llm_error(self):
        from vulnhuntr.llms import LLMError
        assert issubclass(CLIBinaryNotFoundError, LLMError)
        # ... repeat for all six
```

**`patch` + `MagicMock` for subprocess** — copy `patch` usage from `test_llms.py` lines 439-466. Use `patch("subprocess.run")` with `MagicMock` return values to test `_run_subprocess` without real processes:

```python
# Source: tests/test_llms.py lines 439-458
@patch("vulnhuntr.llms.requests.post")
def test_sends_correct_payload(self, mock_post):
    mock_post.return_value = MagicMock(
        json=lambda: {"response": "ok"},
        status_code=200,
    )
```

**Cost callback test pattern** — copy from `test_llms.py` lines 244-269 directly:

```python
# Source: tests/test_llms.py lines 244-269
class TestCostCallback:
    def test_callback_invoked(self):
        calls = []
        def cb(inp, out, model, fp, ct):
            calls.append((inp, out, model, fp, ct))
        ...
        fake.set_context(file_path="app.py", call_type="initial")
        fake.chat("go")
        assert len(calls) == 1
        assert calls[0] == (100, 50, "m", "app.py", "initial")
```

Apply same structure to verify `CLIProviderLLM._log_response()` fires the cost callback.

---

### `tests/test_config.py` (extend — additive test classes)

**Analog:** `tests/test_config.py` itself (existing file).

**Test class naming pattern** — copy from existing class names (`TestVulnhuntrConfigDefaults`, `TestFromDictFlat`, `TestFromDictNested`, `TestToDict`). New classes follow same naming:
- `TestCLIPolicyDefaults`
- `TestCLIPolicy` (tests `from_dict()` parsing of the `cli:` section)
- `TestCLIPolicyOverrides` (tests `overrides` dict access)
- `TestFromDictFlat` (extend with `test_cli_provider_string` — tests `provider: "claude-code"` round-trips)

**Default test pattern** — copy from `TestVulnhuntrConfigDefaults` lines 20-50:

```python
# Source: tests/test_config.py lines 20-50
class TestVulnhuntrConfigDefaults:
    def test_budget_is_none(self):
        cfg = VulnhuntrConfig()
        assert cfg.budget is None

    def test_checkpoint_enabled(self):
        assert VulnhuntrConfig().checkpoint is True
```

Apply same pattern to `CLIPolicy`:
```python
class TestCLIPolicyDefaults:
    def test_timeout_default(self):
        assert CLIPolicy().timeout == 300

    def test_workdir_default(self):
        assert CLIPolicy().workdir == "/tmp/vulnhuntr"
    # ... one test per field
```

**Round-trip test pattern** — copy from `TestToDict` lines 97-104:

```python
# Source: tests/test_config.py lines 97-104
class TestToDict:
    def test_round_trip(self):
        original = VulnhuntrConfig(budget=42.0, provider="claude", max_iterations=5)
        d = original.to_dict()
        restored = VulnhuntrConfig.from_dict(d)
        assert restored.budget == original.budget
```

Apply to verify `cli` field survives `to_dict()` / `from_dict()` round-trip.

---

## Shared Patterns

### `from __future__ import annotations` — top of every file
**Source:** `vulnhuntr/llms.py` line 1, `vulnhuntr/config.py` line 3, `internal/experiments/vulnhuntr_claude_code/claude_code_llm.py` line 1
**Apply to:** All new source files: `cli_providers/__init__.py`, `cli_providers/base.py`
```python
from __future__ import annotations
```

### structlog logger — module-level
**Source:** `vulnhuntr/llms.py` line 18, `vulnhuntr/config.py` line 11, `vulnhuntr/cli/runner.py` line 36
**Apply to:** `cli_providers/base.py`
```python
# Source: vulnhuntr/llms.py line 18
log = structlog.get_logger()
```
Note: `config.py` uses `log = structlog.get_logger(__name__)` with the module name argument — match whichever form the target file's neighbors use. `runner.py` and `llms.py` use the no-arg form.

### LLMError inheritance — bare-pass subclass body
**Source:** `vulnhuntr/llms.py` lines 31-43
**Apply to:** All six `CLI*Error` classes in `cli_providers/base.py`
```python
# Source: vulnhuntr/llms.py lines 31-43
class RateLimitError(LLMError):
    pass

class APIConnectionError(LLMError):
    pass
```

### `field(default_factory=...)` for mutable dataclass defaults
**Source:** `vulnhuntr/config.py` lines 57-61
**Apply to:** `CLIPolicy.overrides` and the `VulnhuntrConfig.cli` field
```python
# Source: vulnhuntr/config.py lines 57-61
vuln_types: list[str] = field(default_factory=list)
exclude_paths: list[str] = field(default_factory=list)
include_paths: list[str] = field(default_factory=list)
```

### structlog keyword-argument logging
**Source:** `vulnhuntr/cli/runner.py` lines 141, 204, 210, 364
**Apply to:** All `log.*()` calls in `cli_providers/base.py` and `runner.py` additions
```python
# Source: vulnhuntr/cli/runner.py line 204
log.info("Fallback 1 configured", spec=fallback1)
log.info("Wrapping LLM with fallback support", fallback_count=len(fallbacks))
```

### Private helper prefix convention
**Source:** `vulnhuntr/cli/runner.py` (all private helpers: `_collect_files`, `_init_providers`, `_analyze_files`, `_generate_reports`, `_dispatch_integrations`)
**Apply to:** `_run_subprocess`, `_build_cmd`, `_env_strip_keys`, `_extract_usage` in `CLIProviderLLM`

### unittest.mock patterns for tests
**Source:** `tests/test_llms.py` lines 9-10, 274, 300, 439
**Apply to:** `tests/test_cli_providers.py` — use `patch("subprocess.run")`, `MagicMock`, `patch.dict("os.environ", ...)` for environment stripping tests
```python
# Source: tests/test_llms.py lines 274-277
@patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
@patch("vulnhuntr.llms.anthropic.Anthropic")
def test_readme_prompt_has_no_prefill(self, mock_cls):
```

---

## No Analog Found

All files in this phase have close analogs. No "no analog" entries.

---

## Metadata

**Analog search scope:** `vulnhuntr/`, `internal/experiments/`, `tests/`
**Files scanned:** 7 source files, 2 test files
**Canonical experiment:** `internal/experiments/vulnhuntr_claude_code/claude_code_llm.py` — the primary promotion source for `CLIProviderLLM`
**Pattern extraction date:** 2026-05-01
