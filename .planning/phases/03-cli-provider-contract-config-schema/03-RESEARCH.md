# Phase 3: CLI Provider Contract & Config Schema - Research

**Researched:** 2026-05-01
**Domain:** Python subprocess-based LLM transport, abstract base class design, dataclass config extension
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**CLI Base Class Architecture (AICLI-01)**
- D-01: Add an intermediate `CLIProviderLLM(LLM)` base class (not direct `LLM` subclasses per provider). Shared logic — subprocess execution, timeout, env-stripping, output parsing, and capability probe — lives in `CLIProviderLLM`. `get_response()` and `_extract_usage()` are abstract, implemented per provider in Phases 4/5.
- D-02: `CLIProviderLLM` lives in `vulnhuntr/cli_providers/base.py`. New `vulnhuntr/cli_providers/__init__.py` re-exports `CLIProviderLLM` and `CapabilityResult`. `llms.py` is untouched — existing `Claude`, `ChatGPT`, `OpenRouter`, `Ollama` classes are not modified.

**Capability Probe (AICLI-02)**
- D-03: `CLIProviderLLM.probe()` is called from the runner's `_init_providers()` stage (Phase 2 pattern), not inside `__init__`. Runner calls `probe()` for each CLI provider before scan starts; if `CapabilityResult.ok` is False, runner logs the `diagnostic_message` via structlog and exits with error.
- D-04: `CapabilityResult` is a dataclass with fields: `ok: bool`, `binary_found: bool`, `version: str | None`, `auth_valid: bool | None` (None = cannot check statically), `diagnostic_message: str`.

**Response Normalization & Failure Taxonomy (AICLI-03, AICLI-04)**
- D-05: Failure classes extend the existing `LLMError` hierarchy. New CLI-specific subclasses: `CLIBinaryNotFoundError`, `CLIAuthError`, `CLITimeoutError`, `CLIParseError`, `CLISandboxError`, `CLIRuntimeError`. These live in `cli_providers/base.py`.
- D-06: Response normalization: `CLIProviderLLM.chat()` calls `get_response()` (abstract) to extract the raw text from the provider's JSON envelope, then feeds it into the existing `_validate_response()` path. Each provider subclass implements `get_response()` to handle its own envelope format.

**Config Schema (CONFIG-01, CONFIG-02, CONFIG-03)**
- D-07: Add a `CLIPolicy` dataclass to `vulnhuntr/config.py` with fields: `timeout: int = 300`, `workdir: str = "/tmp/vulnhuntr"`, `auth_mode: str = "auto"`, `session_mode: str = "stateless"`, `approval_mode: str = "auto"`, `sandbox_mode: str = "none"`, `max_turns: int = 10`, `mcp_mode: str = "none"`, `overrides: dict[str, dict] = field(default_factory=dict)`.
- D-08: `VulnhuntrConfig` gains a `cli: CLIPolicy = field(default_factory=CLIPolicy)` field. In YAML, this maps to a `cli:` sub-section. Existing `.vulnhuntr.yaml` files without a `cli:` section are unaffected.
- D-09: `VulnhuntrConfig.from_dict()` is extended to parse the nested `cli:` dict into a `CLIPolicy`. Per-provider overrides are accessed as `config.cli.overrides.get("claude-code", {})`.
- D-10: CLI provider selection: `--llm claude-code`, `--llm gemini-cli`, etc. map to CLI providers. Provider registration maps string → class, including CLI providers.

### Claude's Discretion
- Exact abstract method signatures for `get_response()` and `_extract_usage()` in `CLIProviderLLM`.
- Whether `CLIProviderLLM.chat()` fully overrides `LLM.chat()` or calls `super().chat()`.
- Exact env-stripping logic (which vars to remove per provider type).
- Test file location: new `tests/test_cli_providers.py` vs. extending `tests/test_cli.py`.

### Deferred Ideas (OUT OF SCOPE)
None — discussion stayed within phase scope.
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| AICLI-01 | Provider-neutral CLI transport layer extending `LLM` without breaking API providers | `CLIProviderLLM(LLM)` intermediate base class in `vulnhuntr/cli_providers/base.py`; `llms.py` untouched |
| AICLI-02 | Probe CLI provider capabilities at startup and fail early with actionable diagnostics | `probe()` method returning `CapabilityResult` dataclass; called from `_init_providers()` |
| AICLI-03 | Normalize CLI provider outputs into validated `Response` and usage metadata | `CLIProviderLLM.chat()` feeds `get_response()` (abstract) into existing `_validate_response()` pipeline |
| AICLI-04 | Classify CLI provider failures into install, auth, timeout, parse, sandbox, runtime errors | Six new `LLMError` subclasses: `CLIBinaryNotFoundError`, `CLIAuthError`, `CLITimeoutError`, `CLIParseError`, `CLISandboxError`, `CLIRuntimeError` |
| CONFIG-01 | `.vulnhuntr.yaml` supports selecting CLI providers anywhere `llm.provider` is used | `provider: claude-code` works via provider registration map; `initialize_llm()` extended |
| CONFIG-02 | `.vulnhuntr.yaml` supports CLI runtime policy fields | `CLIPolicy` dataclass nested as `config.cli`; YAML key `cli:` |
| CONFIG-03 | Provider-specific overrides without forcing shared knobs | `config.cli.overrides: dict[str, dict]`; per-provider merge at instantiation time |
</phase_requirements>

---

## Summary

Phase 3 adds the pure-abstraction layer that makes CLI-based LLM providers a first-class citizen alongside the existing API providers (`Claude`, `ChatGPT`, `OpenRouter`, `Ollama`). It does NOT implement any real provider — those land in Phases 4 and 5. The design goal is to make adding a new CLI backend a matter of subclassing `CLIProviderLLM` and implementing three methods: `probe()` hook (binary check), `get_response()` (envelope unwrap), and `_extract_usage()` (usage extraction), without touching any API-provider code path.

The existing codebase already has a working proof-of-concept — `internal/experiments/vulnhuntr_claude_code/claude_code_llm.py` — that directly subclasses `LLM`. Phase 3 extracts the shared patterns from that experiment (subprocess dispatch, env-stripping, JSON envelope parsing, retry-on-bad-JSON) into `CLIProviderLLM`, so each future provider subclass is thin. The experiment's `ClaudeCodeLLM` will become a Phase 4 thin subclass with minimal changes.

The config extension is purely additive: `CLIPolicy` is a new dataclass with all fields defaulted, added as an optional nested sub-object on `VulnhuntrConfig`. Existing YAML files that do not contain a `cli:` section continue to work unchanged because `field(default_factory=CLIPolicy)` supplies defaults at construction time — the same pattern used by `CheckpointData` in the existing codebase.

**Primary recommendation:** Write `vulnhuntr/cli_providers/base.py` first (the invariant), then extend `config.py` (additive), then wire `runner.py` (`_init_providers()` probe call and registration stub). Keep `llms.py` read-only throughout.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| CLI subprocess execution | LLM Layer (`cli_providers/base.py`) | — | Transport is an LLM concern; runners are provider-agnostic |
| Capability probe at startup | CLI Layer (`runner.py`) | LLM Layer (probe() method lives here) | Runner orchestrates startup; probe logic lives in provider |
| Error taxonomy (CLIBinaryNotFoundError etc.) | LLM Layer (`cli_providers/base.py`) | — | Mirrors existing `LLMError` hierarchy in `llms.py` |
| Config schema (CLIPolicy) | Infrastructure (`config.py`) | — | Same file as `VulnhuntrConfig`; additive extension |
| Provider registration map | CLI Layer (`runner.py` or new `providers.py`) | — | Runner is the factory; currently holds `initialize_llm()` |
| Response normalization | LLM Layer (`cli_providers/base.py`) | — | Reuses `_validate_response()` already in `LLM` base |
| Env-stripping per provider | LLM Layer (`cli_providers/base.py`) | — | Each provider defines which keys to strip; hook lives in base |

---

## Standard Stack

### Core (all already present in project)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `subprocess` | stdlib | CLI process execution | Standard Python approach for shelling out; used in experiment |
| `dataclasses` | stdlib | `CapabilityResult`, `CLIPolicy` | Matches existing `VulnhuntrConfig`, `CheckpointData` pattern |
| `structlog` | >=24.2.0 | Probe failure logging | Project-wide logging standard; all modules use it |
| `pydantic` | >=2.8.0 | `_validate_response()` reuse | Already handles JSON repair pipeline |
| `pyyaml` | >=6.0.3 | `cli:` section parsing | Already used in `config.py` |

[VERIFIED: npm registry] — N/A (Python project; pyproject.toml confirms all versions above)
[VERIFIED: codebase grep] — All libraries above are imported in existing source files

### No New Dependencies Required
Phase 3 adds zero new package dependencies. `subprocess`, `dataclasses`, and `shutil.which()` (for binary detection in `probe()`) are all stdlib. [VERIFIED: codebase grep of pyproject.toml]

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `subprocess.run()` | `asyncio.create_subprocess_exec` | Async not needed — analysis is already synchronous; adds complexity for no benefit in this phase |
| `dataclass` for CLIPolicy | Pydantic `BaseModel` | Dataclass matches all other config objects in the project; pydantic would be inconsistent |
| New `providers.py` registry file | Extend `runner.py` in-place | Both are valid; in-place is lower churn for a stub-only registration map |

---

## Architecture Patterns

### System Architecture Diagram

```
CLI args / .vulnhuntr.yaml
         |
         v
   runner._init_providers()
         |
         +-- [API provider string] -------> initialize_llm() -> Claude/ChatGPT/OpenRouter/Ollama
         |
         +-- [CLI provider string] -------> CLIProviderLLM subclass (Phase 4/5)
                    |
                    v
             probe()  (called here, before scan starts)
                    |
              CapabilityResult.ok?
              /           \
           False           True
             |               |
          log + exit     VulnerabilityAnalyzer.analyze_file()
                               |
                         CLIProviderLLM.chat()
                               |
                    +-- get_response() [abstract, provider-specific]
                    |         |
                    |    raw text string
                    |         |
                    +-- _validate_response() [inherited from LLM]
                               |
                         validated Response model
```

### Recommended Project Structure
```
vulnhuntr/
├── cli_providers/          # NEW - Phase 3 scope
│   ├── __init__.py         # re-exports CLIProviderLLM, CapabilityResult
│   └── base.py             # CLIProviderLLM, CapabilityResult, CLI*Error classes
├── config.py               # EXTEND - add CLIPolicy dataclass + VulnhuntrConfig.cli field
├── cli/
│   └── runner.py           # EXTEND - _init_providers() probe call + CLI provider registration stub
└── llms.py                 # READ-ONLY - zero changes
```

### Pattern 1: CLIProviderLLM Intermediate Base Class

**What:** An abstract `LLM` subclass that provides shared subprocess execution, timeout, env-stripping, and probe logic. Per-provider differences (envelope format, usage extraction) are abstract methods.

**When to use:** Every CLI-based provider in Phases 4/5 inherits from this, not from `LLM` directly.

**Example (based on experiment + locked decisions):**
```python
# Source: internal/experiments/vulnhuntr_claude_code/claude_code_llm.py (promoted pattern)
# vulnhuntr/cli_providers/base.py
from __future__ import annotations

import os
import shutil
import subprocess
from abc import abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from vulnhuntr.llms import LLM, LLMError

log = structlog.get_logger()


# ---------- Failure taxonomy (AICLI-04) ----------

class CLIBinaryNotFoundError(LLMError):
    """Required CLI binary is not installed or not on PATH."""

class CLIAuthError(LLMError):
    """CLI provider authentication failed (bad key, missing login, etc.)."""

class CLITimeoutError(LLMError):
    """CLI process exceeded the configured timeout."""

class CLIParseError(LLMError):
    """CLI provider returned output that could not be parsed as expected JSON."""

class CLISandboxError(LLMError):
    """CLI provider sandbox policy rejected the operation."""

class CLIRuntimeError(LLMError):
    """CLI process exited with a non-zero return code for an unclassified reason."""


# ---------- Capability probe result (AICLI-02) ----------

@dataclass
class CapabilityResult:
    ok: bool
    binary_found: bool
    version: str | None
    auth_valid: bool | None   # None = cannot check statically
    diagnostic_message: str


# ---------- Abstract base ----------

class CLIProviderLLM(LLM):
    """Intermediate base class for all CLI-invoked LLM providers.

    Subclasses MUST implement:
      - binary_name: str  (class attribute, e.g. "claude")
      - get_response(response: dict) -> str
      - _extract_usage(response: dict) -> LLMUsage
      - probe() -> CapabilityResult

    Subclasses MAY override:
      - _env_strip_keys: frozenset[str]  (env vars to remove before subprocess)
      - _build_cmd(prompt, max_tokens) -> list[str]
    """

    binary_name: str = ""          # override in subclass, e.g. "claude"
    _env_strip_keys: frozenset[str] = frozenset()

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

    # ---------- Abstract interface ----------

    @abstractmethod
    def probe(self) -> CapabilityResult:
        """Check binary presence, version, and (optionally) auth before scan."""

    @abstractmethod
    def get_response(self, response: Any) -> str:
        """Extract the text answer from provider's JSON envelope."""

    @abstractmethod
    def _extract_usage(self, response: Any) -> "LLMUsage":
        """Extract token counts from provider's JSON envelope."""

    # ---------- Shared subprocess dispatch ----------

    def _run_subprocess(self, cmd: list[str]) -> dict[str, Any]:
        """Run cmd in a sanitised env, return parsed JSON payload."""
        env = os.environ.copy()
        for key in self._env_strip_keys:
            env.pop(key, None)

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
            raise CLITimeoutError(
                f"{self.binary_name} timed out after {self._timeout_seconds}s"
            ) from exc

        if completed.returncode != 0:
            stderr = completed.stderr.strip() or "no stderr"
            # Classify common failure patterns
            if "permission" in stderr.lower() or "sandbox" in stderr.lower():
                raise CLISandboxError(f"{self.binary_name} sandbox rejection: {stderr}")
            if "auth" in stderr.lower() or "login" in stderr.lower() or "401" in stderr:
                raise CLIAuthError(f"{self.binary_name} auth failure: {stderr}")
            raise CLIRuntimeError(
                f"{self.binary_name} exited {completed.returncode}: {stderr}"
            )

        stdout = completed.stdout.strip()
        if not stdout:
            raise CLIParseError(f"{self.binary_name} returned empty stdout")

        import json
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as exc:
            snippet = stdout[:500]
            raise CLIParseError(
                f"{self.binary_name} returned non-JSON: {snippet}"
            ) from exc

    # ---------- Shared chat() override ----------

    def chat(self, user_prompt, response_model=None, max_tokens=8192):
        """Override LLM.chat() — uses _run_subprocess instead of HTTP client."""
        # Subclasses define _build_cmd(); fallback to NotImplementedError
        cmd = self._build_cmd(user_prompt, max_tokens)
        self._add_to_history("user", user_prompt)

        last_error = None
        for attempt in range(2):
            prompt = user_prompt if attempt == 0 else (
                user_prompt + "\n\nIMPORTANT: Return only valid JSON conforming to the schema."
            )
            cmd = self._build_cmd(prompt, max_tokens)
            payload = self._run_subprocess(cmd)
            self._log_response(payload)

            response_text = self.get_response(payload)
            if response_model is not None:
                try:
                    parsed = self._validate_response(response_text, response_model)
                    self._add_to_history("assistant", str(parsed))
                    return parsed
                except LLMError as exc:
                    last_error = exc
                    continue

            self._add_to_history("assistant", response_text)
            return response_text

        raise LLMError(f"{self.binary_name} failed structured output after 2 attempts") from last_error

    def _build_cmd(self, prompt: str, max_tokens: int) -> list[str]:
        raise NotImplementedError(
            f"{type(self).__name__} must implement _build_cmd()"
        )
```

### Pattern 2: CLIPolicy Dataclass and Config Extension

**What:** A new `CLIPolicy` dataclass in `config.py`; `VulnhuntrConfig` gains a `cli` field; `from_dict()` parses a `cli:` YAML section.

**When to use:** Any time a CLI provider is configured — but because all fields default, existing YAML files need no changes.

**Example:**
```python
# Source: vulnhuntr/config.py (to be extended — matched to existing dataclass pattern)
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


@dataclass
class VulnhuntrConfig:
    # ... existing fields unchanged ...
    cli: CLIPolicy = field(default_factory=CLIPolicy)  # NEW — all defaults apply
```

And in `from_dict()`:
```python
if "cli" in data and isinstance(data["cli"], dict):
    cli_data = data["cli"]
    cli = CLIPolicy()
    # ... parse each field with same int()/str() pattern as existing sections ...
    if "overrides" in cli_data and isinstance(cli_data["overrides"], dict):
        cli.overrides = {k: dict(v) for k, v in cli_data["overrides"].items()}
    config.cli = cli
```

### Pattern 3: Provider Registration Stub in `_init_providers()`

**What:** Extend `initialize_llm()` in `runner.py` to accept CLI provider strings (`"claude-code"`, `"gemini-cli"`). Phase 3 adds the registration branches with a stub that raises a clear "not yet implemented" error for Phase 3; Phases 4/5 fill in the real classes.

**Why in `runner.py`:** `initialize_llm()` is already the provider factory; this is an additive `elif` branch.

```python
# runner.py — initialize_llm() extension (Phase 3 stub)
elif llm_arg == "claude-code":
    from vulnhuntr.cli_providers import CLIProviderLLM  # noqa: F401
    raise NotImplementedError(
        "claude-code provider will be implemented in Phase 4. "
        "Use --llm claude for API-based Claude."
    )
```

**When Phase 4 lands:** The stub `raise` is replaced with the real `ClaudeCodeLLM(...)` instantiation.

### Pattern 4: Capability Probe Wiring in `_init_providers()`

**What:** After instantiating a CLI provider, call `probe()` and exit early if `ok` is False.

```python
# runner.py — _init_providers() addition (pseudocode)
if hasattr(llm, "probe"):   # only CLI providers have probe()
    result = llm.probe()
    if not result.ok:
        log.error(
            "CLI provider capability check failed",
            provider=args.llm,
            binary_found=result.binary_found,
            diagnostic=result.diagnostic_message,
        )
        raise SystemExit(1)
```

### Anti-Patterns to Avoid

- **Modifying `llms.py`:** The locked decisions forbid this. Never add CLI-related code to `llms.py`. All CLI logic belongs in `vulnhuntr/cli_providers/`.
- **Calling `probe()` from `__init__`:** This makes unit-testing hard (instantiation always hits the filesystem). Call `probe()` from `_init_providers()` only.
- **Catching broad `Exception` in `_run_subprocess`:** The experiment does `if completed.returncode != 0: raise LLMError(...)`. Phase 3 must classify these into the specific `CLI*Error` subclasses so downstream handlers can distinguish "binary missing" from "auth expired" from "process crashed".
- **Hardcoding env var names in `CLIProviderLLM`:** Use the `_env_strip_keys` class attribute pattern — each provider subclass declares what to strip. This avoids the base class needing to know about `ANTHROPIC_API_KEY`.
- **Merging `overrides` at parse time:** Per D-09, per-provider override dicts should be merged at provider instantiation time (`__init__`), not during YAML parsing. Parsing just stores the raw dict.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| JSON repair for CLI output | Custom parser | `LLM._validate_response()` already exists | Multi-pass repair + Pydantic validation already handles all known LLM JSON quirks |
| Binary detection | Custom `os.path` traversal | `shutil.which(self.binary_name)` | stdlib, returns `None` cleanly when not found |
| Subprocess timeout | Manual signal handling | `subprocess.run(..., timeout=N)` | stdlib handles SIGKILL; raises `subprocess.TimeoutExpired` which we map to `CLITimeoutError` |
| History management | Re-implement in `CLIProviderLLM` | Inherited `_add_to_history()` and `_log_response()` from `LLM` | Already present — no re-implementation needed |
| Cost callback plumbing | New field on `CLIProviderLLM` | Inherited `_cost_callback`, `set_context()`, `_log_response()` from `LLM` | All inherited at zero cost |

**Key insight:** The `LLM` base class provides the full scaffolding (history, cost tracking, validation pipeline). `CLIProviderLLM` only needs to replace the HTTP transport (`send_message`/`create_messages`) with subprocess dispatch.

---

## Common Pitfalls

### Pitfall 1: `chat()` Call Signature Mismatch
**What goes wrong:** `LLM.chat()` calls `self.create_messages()` then `self.send_message()`. If `CLIProviderLLM.chat()` fully overrides `LLM.chat()` but forgets to call `_log_response()`, cost tracking silently stops working.
**Why it happens:** The experiment's `ClaudeCodeLLM.chat()` calls `self._log_response(response)` explicitly — this is easy to miss when extracting the pattern.
**How to avoid:** Always call `self._log_response(payload)` after `_run_subprocess()` returns. The `_log_response()` method in `LLM` calls `_extract_usage()` and fires `_cost_callback`.
**Warning signs:** Cost tracker always reports 0 tokens for CLI provider calls.

### Pitfall 2: `CapabilityResult.ok = False` Swallowed by `FallbackLLM`
**What goes wrong:** If a CLI provider is wrapped in `FallbackLLM` and `probe()` is called on the wrapper (not the inner provider), the probe result is meaningless.
**Why it happens:** `FallbackLLM.__getattr__` delegates to the active LLM — but `probe()` is a CLI-only method. Calling `wrapper.probe()` reaches the inner provider via delegation.
**How to avoid:** In `_init_providers()`, call `probe()` BEFORE wrapping with `FallbackLLM`. Check `hasattr(llm, "probe")` on the unwrapped instance.
**Warning signs:** Probe succeeds but the scan later fails with a `CLIBinaryNotFoundError`.

### Pitfall 3: Existing YAML Config Broken by `to_dict()` Change
**What goes wrong:** `VulnhuntrConfig.to_dict()` is used by `AnalysisCheckpoint` to serialize config. If `to_dict()` is not updated to include `cli`, checkpoint files become inconsistent.
**Why it happens:** Developers add a field to `__init__` (via `@dataclass`) and `from_dict()` but forget `to_dict()` because Python dataclasses don't auto-generate it.
**How to avoid:** Add `"cli": dataclasses.asdict(self.cli)` to `to_dict()` when extending it.
**Warning signs:** Tests that round-trip config through `to_dict()` / `from_dict()` fail on the `cli` field.

### Pitfall 4: `CLIPolicy.overrides` Dict Mutation Across Instances
**What goes wrong:** Two `CLIProviderLLM` instances share the same `overrides` dict because `field(default_factory=dict)` is not used.
**Why it happens:** If a developer writes `overrides: dict = {}` instead of `overrides: dict[str, dict] = field(default_factory=dict)`, all `CLIPolicy` instances share the same mutable default.
**How to avoid:** Use `field(default_factory=dict)` — exactly as `VulnhuntrConfig.vuln_types` already does.
**Warning signs:** Overrides set for one provider appear on all providers.

### Pitfall 5: `subprocess.run()` Hanging on Interactive Prompts
**What goes wrong:** Some CLI tools (e.g., `claude --version` in certain auth states) prompt for user input on stdin. `subprocess.run()` with default stdin hangs indefinitely.
**Why it happens:** `capture_output=True` only captures stdout/stderr — it does not set stdin to `/dev/null`.
**How to avoid:** Pass `stdin=subprocess.DEVNULL` in `_run_subprocess()`. The experiment does not do this — Phase 3 should add it as a defensive measure.
**Warning signs:** `probe()` hangs indefinitely on a machine where the binary prompts for first-time auth.

### Pitfall 6: Provider Registration Map Accepts Unknown Strings
**What goes wrong:** `initialize_llm("claude-code")` currently falls through to the `else: raise ValueError(...)` branch. The error message lists only the old providers. After Phase 3, the error message should list CLI providers too (even if marked "coming soon").
**Why it happens:** `initialize_llm()` has a hardcoded error string.
**How to avoid:** Update the error message in the `else` branch to include `"claude-code"`, `"gemini-cli"` with a note about Phase 4.
**Warning signs:** Users get `"Invalid LLM argument: claude-code\nValid options are: claude, gpt, ollama, openrouter"` — confusing when Phase 3 config docs mention `claude-code`.

---

## Code Examples

### Binary Detection in `probe()` (standard pattern)
```python
# Source: shutil.which() stdlib documentation + experiment pattern
import shutil

def probe(self) -> CapabilityResult:
    binary_path = shutil.which(self.binary_name)
    if binary_path is None:
        return CapabilityResult(
            ok=False,
            binary_found=False,
            version=None,
            auth_valid=None,
            diagnostic_message=(
                f"'{self.binary_name}' binary not found on PATH. "
                f"Install it and ensure it is executable."
            ),
        )
    # Try --version to confirm it is runnable
    try:
        result = subprocess.run(
            [self.binary_name, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            stdin=subprocess.DEVNULL,
        )
        version = result.stdout.strip() or result.stderr.strip() or "unknown"
    except Exception:
        version = None

    return CapabilityResult(
        ok=True,
        binary_found=True,
        version=version,
        auth_valid=None,   # CLI auth only fails at first real call
        diagnostic_message=f"'{self.binary_name}' found: {version}",
    )
```

### Extending `VulnhuntrConfig.from_dict()` (additive pattern)
```python
# Source: vulnhuntr/config.py existing from_dict() structure
if "cli" in data and isinstance(data["cli"], dict):
    cli_data = data["cli"]
    cli = CLIPolicy()
    if "timeout" in cli_data:
        cli.timeout = int(cli_data["timeout"])
    if "workdir" in cli_data:
        cli.workdir = str(cli_data["workdir"])
    if "auth_mode" in cli_data:
        cli.auth_mode = str(cli_data["auth_mode"])
    if "session_mode" in cli_data:
        cli.session_mode = str(cli_data["session_mode"])
    if "approval_mode" in cli_data:
        cli.approval_mode = str(cli_data["approval_mode"])
    if "sandbox_mode" in cli_data:
        cli.sandbox_mode = str(cli_data["sandbox_mode"])
    if "max_turns" in cli_data:
        cli.max_turns = int(cli_data["max_turns"])
    if "mcp_mode" in cli_data:
        cli.mcp_mode = str(cli_data["mcp_mode"])
    if "overrides" in cli_data and isinstance(cli_data["overrides"], dict):
        cli.overrides = {k: dict(v) for k, v in cli_data["overrides"].items()}
    config.cli = cli
```

### Per-Provider Override Merge (at instantiation)
```python
# Source: D-09 (CONTEXT.md) — merge at provider __init__, not at parse time
class ClaudeCodeLLM(CLIProviderLLM):  # Phase 4 example
    binary_name = "claude"
    _env_strip_keys = frozenset({"ANTHROPIC_API_KEY"})

    def __init__(self, ..., config: VulnhuntrConfig | None = None):
        overrides = (config.cli.overrides.get("claude-code", {})
                     if config else {})
        timeout = overrides.get("timeout", config.cli.timeout if config else 300)
        workdir = overrides.get("workdir", config.cli.workdir if config else "/tmp/vulnhuntr")
        super().__init__(timeout_seconds=timeout, workdir=workdir, ...)
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Direct `LLM` subclasses per provider (experiment) | `CLIProviderLLM` intermediate base | Phase 3 | Shared subprocess code lives in one place |
| `initialize_llm()` only handles API providers | `initialize_llm()` extended with CLI provider stubs | Phase 3 | `--llm claude-code` no longer crashes with unhelpful error |
| `LLMError` hierarchy covers only API failures | Six new `CLI*Error` subclasses added | Phase 3 | Operator can distinguish install from auth from timeout failures |
| `VulnhuntrConfig` has no CLI policy fields | `cli: CLIPolicy` sub-object added | Phase 3 | CLI runtime knobs configurable from YAML without breaking existing configs |

**Not deprecated in this phase:**
- `llms.py` — untouched; existing API providers remain primary path
- `_validate_response()` — reused by CLI path, not replaced

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `_init_providers()` is the correct injection point for `probe()` — called before scan starts and has access to `args.llm` and `config` | Architecture Patterns, Pattern 4 | If probe must be called after README summarization pass, wiring point changes; LOW risk given CONTEXT.md D-03 is explicit |
| A2 | `shutil.which()` is a reliable binary detector on all target platforms (Linux/macOS/Windows) | Code Examples | Unlikely to fail on Linux/macOS; Windows PATH quirks possible; LOW risk for a security scanner used in developer/CI environments |
| A3 | `stdin=subprocess.DEVNULL` does not break any CLI provider's normal stdout/stderr flow | Common Pitfalls, Pitfall 5 | If a provider reads stdin for input (e.g., piping code context), this would break it. All CLI tools in scope use `-p`/`--prompt` flags, not stdin. LOW risk. |

---

## Open Questions (RESOLVED)

1. **`create_messages` / `send_message` on `CLIProviderLLM`**
   - What we know: `LLM.chat()` calls `create_messages()` then `send_message()`. `CLIProviderLLM.chat()` fully overrides `LLM.chat()`, bypassing both.
   - What's unclear: Should `create_messages()` and `send_message()` be implemented as `NotImplementedError` stubs or omitted entirely?
   - Recommendation: Implement both as `raise NotImplementedError("CLIProviderLLM uses _run_subprocess; create_messages/send_message not applicable")`. This prevents accidental calls via `super().chat()` and makes the intent explicit.

2. **`FallbackLLM` compatibility with CLI providers**
   - What we know: `FallbackLLM.__getattr__` delegates to the active LLM; `probe()` would be accessible via delegation if called on the wrapper.
   - What's unclear: Phase 3 does not implement real CLI providers, so `FallbackLLM` wrapping a CLI provider is not tested yet.
   - Recommendation: In `_init_providers()`, probe BEFORE wrapping; document this constraint in a code comment.

3. **`to_dict()` usage of `CLIPolicy`**
   - What we know: `VulnhuntrConfig.to_dict()` is used by `AnalysisCheckpoint.start()` for checkpoint metadata.
   - What's unclear: Whether checkpoint metadata needs to round-trip the full `CLIPolicy` or just the top-level config fields.
   - Recommendation: Use `dataclasses.asdict(self.cli)` in `to_dict()`. If `dataclasses` is not already imported in `config.py`, add the import.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python 3.10+ | Phase 3 code | ✓ | 3.14.4 | — |
| pytest 8+ | Test suite | ✓ | 9.0.2 | — |
| `subprocess` (stdlib) | `_run_subprocess()` | ✓ | stdlib | — |
| `shutil.which` (stdlib) | `probe()` binary detection | ✓ | stdlib | — |
| `dataclasses` (stdlib) | `CapabilityResult`, `CLIPolicy` | ✓ | stdlib | — |
| pydantic ≥2.8.0 | `_validate_response()` reuse | ✓ | in venv | — |
| pyyaml ≥6.0.3 | `cli:` section parsing | ✓ | in venv | — |

[VERIFIED: Bash — `python3 --version` = 3.14.4, `pytest --version` = 9.0.2, stdlib modules always available]

**Missing dependencies with no fallback:** None.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest 9.0.2 |
| Config file | `pyproject.toml` `[tool.pytest.ini_options]` |
| Quick run command | `pytest tests/test_cli_providers.py tests/test_config.py -x -q` |
| Full suite command | `pytest -m "not live" -q` |
| Coverage threshold | 72% (enforced via `--cov-fail-under=72`) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| AICLI-01 | `CLIProviderLLM` inherits from `LLM`; does not break API providers | unit | `pytest tests/test_cli_providers.py::TestCLIProviderLLMInheritance -x` | ❌ Wave 0 |
| AICLI-01 | `llms.py` existing classes unchanged (API providers still pass) | unit | `pytest tests/test_llms.py -x` | ✅ exists |
| AICLI-02 | `probe()` returns `CapabilityResult(ok=False)` when binary missing | unit | `pytest tests/test_cli_providers.py::TestProbe::test_binary_missing -x` | ❌ Wave 0 |
| AICLI-02 | Runner exits with error when `probe().ok` is False | unit | `pytest tests/test_cli.py::TestInitProviders::test_probe_failure_exits -x` | ❌ Wave 0 |
| AICLI-03 | `chat()` feeds `get_response()` output into `_validate_response()` | unit | `pytest tests/test_cli_providers.py::TestCLIProviderChat -x` | ❌ Wave 0 |
| AICLI-03 | `_log_response()` is called (cost tracking works for CLI providers) | unit | `pytest tests/test_cli_providers.py::TestCostTracking -x` | ❌ Wave 0 |
| AICLI-04 | `CLIBinaryNotFoundError` raised when returncode != 0 + "not found" in stderr | unit | `pytest tests/test_cli_providers.py::TestErrorClassification -x` | ❌ Wave 0 |
| AICLI-04 | `CLITimeoutError` raised on `subprocess.TimeoutExpired` | unit | `pytest tests/test_cli_providers.py::TestErrorClassification::test_timeout -x` | ❌ Wave 0 |
| CONFIG-01 | `config.provider = "claude-code"` accepted by `from_dict()` | unit | `pytest tests/test_config.py::TestFromDictFlat::test_cli_provider_string -x` | ❌ Wave 0 |
| CONFIG-02 | `CLIPolicy` fields parsed from YAML `cli:` section | unit | `pytest tests/test_config.py::TestCLIPolicy -x` | ❌ Wave 0 |
| CONFIG-02 | YAML without `cli:` section still loads with defaults | unit | `pytest tests/test_config.py::TestCLIPolicyDefaults -x` | ❌ Wave 0 |
| CONFIG-03 | `config.cli.overrides.get("claude-code", {})` accessible per-provider | unit | `pytest tests/test_config.py::TestCLIPolicyOverrides -x` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `pytest tests/test_cli_providers.py tests/test_config.py tests/test_llms.py -x -q`
- **Per wave merge:** `pytest -m "not live" -q`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `tests/test_cli_providers.py` — covers AICLI-01, AICLI-02, AICLI-03, AICLI-04
- [ ] `tests/test_config.py` additions — covers CONFIG-01, CONFIG-02, CONFIG-03 (file exists; new test classes needed)

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | — (auth is delegated to CLI tool's own auth mechanism) |
| V3 Session Management | no | — (stateless subprocess calls; no session tokens in this phase) |
| V4 Access Control | no | — (scanner is a developer tool; no multi-user access model) |
| V5 Input Validation | yes | User-controlled `workdir`, `binary_name` must not be injected into subprocess command unsanitized |
| V6 Cryptography | no | — (no crypto operations in this phase) |

### Known Threat Patterns for CLI Subprocess Transport

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Command injection via `workdir` or config string fields | Tampering | Never interpolate config strings into shell command via `shell=True`; always use list-form `subprocess.run([...])` |
| Environment variable leakage to subprocess | Information Disclosure | Use `env = os.environ.copy()` + explicit pop of sensitive keys; never pass raw `os.environ` |
| Untrusted binary on PATH shadowing real tool | Elevation of Privilege | Phase 3 notes: `probe()` logs the resolved binary path from `shutil.which()`; operators should verify. Full path pinning is a Phase 10 hardening item. |
| Subprocess stdout exceeding memory | Denial of Service | `capture_output=True` buffers in memory; `CLIProviderLLM` inherits the `max_tokens` cap from `LLM.chat()` which limits prompt size, but output is unbounded. Document limit; full fix is Phase 10. |

**Key constraint:** `subprocess.run()` MUST always be called with a list argument (`cmd: list[str]`), never with `shell=True`. This is a hard requirement — `shell=True` with any user-controlled input creates command injection. [ASSUMED — standard Python subprocess security guidance; risk is HIGH if violated]

---

## Sources

### Primary (HIGH confidence)
- [VERIFIED: codebase] `vulnhuntr/llms.py` — full `LLM` base class, `LLMError` hierarchy, `_validate_response()`, `_log_response()`, `chat()` orchestration
- [VERIFIED: codebase] `internal/experiments/vulnhuntr_claude_code/claude_code_llm.py` — working `ClaudeCodeLLM(LLM)` proof-of-concept; `subprocess.run()` pattern, env-stripping, JSON envelope parsing
- [VERIFIED: codebase] `vulnhuntr/config.py` — `VulnhuntrConfig` dataclass, `from_dict()` parsing pattern, `to_dict()` structure
- [VERIFIED: codebase] `vulnhuntr/cli/runner.py` — `_init_providers()` interface, `initialize_llm()`, `FallbackLLM` wrapping, `parse_fallback_spec()`
- [VERIFIED: codebase] `pyproject.toml` — all dependency versions confirmed; pytest configuration confirmed
- [VERIFIED: Bash] pytest 9.0.2 installed; Python 3.14.4; existing test suite passes (85 tests green)

### Secondary (MEDIUM confidence)
- [CITED: Python docs — subprocess] `subprocess.run()` with list-form args for injection safety; `timeout` parameter; `DEVNULL` stdin
- [CITED: Python docs — shutil.which] Binary detection cross-platform behavior

### Tertiary (LOW confidence)
- None — all phase-critical claims verified from codebase or stdlib documentation

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all libraries already in project; no new dependencies
- Architecture: HIGH — derived directly from locked decisions in CONTEXT.md + code audit of canonical files
- Pitfalls: HIGH — derived from experiment code analysis + standard Python subprocess patterns
- Security: MEDIUM — subprocess injection risk is well-documented; specific CLI tool behaviors are ASSUMED

**Research date:** 2026-05-01
**Valid until:** 2026-06-01 (stable Python stdlib; project dependencies unlikely to change)
