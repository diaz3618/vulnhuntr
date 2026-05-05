# Phase 8: Behavioral Evaluation & Trace Capture - Pattern Map

**Mapped:** 2026-05-04
**Files analyzed:** 13
**Analogs found:** 13 / 13

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `vulnhuntr/core/trace.py` (NEW) | model/accumulator | event-driven | `vulnhuntr/core/models.py` (dataclass pattern) | role-match |
| `vulnhuntr/cli_providers/base.py` (MODIFY) | middleware | request-response | `vulnhuntr/mcp/analysis.py` (`MCPAnalysisHelper.__init__` injection) | role-match |
| `vulnhuntr/cli_providers/claude_code.py` (MODIFY) | provider | request-response | `vulnhuntr/cli_providers/gemini_cli.py` (probe rename pattern) | exact |
| `vulnhuntr/cli_providers/gemini_cli.py` (MODIFY) | provider | request-response | `vulnhuntr/cli_providers/claude_code.py` | exact |
| `vulnhuntr/cli_providers/codex.py` (MODIFY) | provider | request-response | `vulnhuntr/cli_providers/claude_code.py` | exact |
| `vulnhuntr/cli_providers/qwen_code.py` (MODIFY) | provider | request-response | `vulnhuntr/cli_providers/claude_code.py` | exact |
| `vulnhuntr/llms.py` (MODIFY) | service | event-driven | self — `FallbackLLM._diagnostics.append()` pattern | exact |
| `vulnhuntr/core/analysis.py` (MODIFY) | service | CRUD | self — `VulnerabilityAnalyzer.__init__` `mcp_helper=` kwarg | exact |
| `vulnhuntr/mcp/analysis.py` (MODIFY) | service | event-driven + async | self — `execute_tool_calls()` try/except structure | exact |
| `tests/test_trace.py` (NEW) | test | event-driven | `tests/test_mcp_analysis.py` (model + helper unit tests) | role-match |
| `tests/test_behavior.py` (NEW) | test | request-response | `tests/test_cli_providers.py` `TestClaudeCodeSessionMode` | role-match |
| `tests/test_config.py` (MODIFY) | test | CRUD | self — `TestCLIPolicy` / `TestCLIPolicyDefaults` classes | exact |
| `tests/test_cli_providers.py` (MODIFY) | test | request-response | self — `TestClaudeCodeMCPConfig` / `TestErrorTaxonomy` parametrize | exact |

---

## Pattern Assignments

### `vulnhuntr/core/trace.py` (NEW — model/accumulator, event-driven)

**Analog:** `vulnhuntr/core/models.py` — stdlib-only dataclass leaf module; `vulnhuntr/mcp/analysis.py` — accumulator class with `list` state and single-method append.

**Imports pattern** (model from `core/models.py` lines 1–8; no vulnhuntr imports in this file):
```python
from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from typing import Any, Literal
```

**Core dataclass pattern** (from CONTEXT.md D-01 — copy verbatim):
```python
TraceEventType = Literal[
    "probe_result",
    "response_validated",
    "tool_call",
    "fallback_triggered",
    "session_decision",
]

@dataclasses.dataclass
class TraceEvent:
    event_type: TraceEventType
    provider: str          # class name or provider key
    timestamp: datetime    # UTC; set to datetime.now(timezone.utc) at emission
    data: dict[str, Any]   # event-specific payload
```

**Accumulator class pattern** (from CONTEXT.md D-02 — copy verbatim):
```python
class ExecutionTracer:
    def __init__(self) -> None:
        self.events: list[TraceEvent] = []

    def emit(
        self,
        event_type: TraceEventType,
        provider: str,
        **data: Any,
    ) -> None:
        self.events.append(
            TraceEvent(
                event_type=event_type,
                provider=provider,
                timestamp=datetime.now(timezone.utc),
                data=data,
            )
        )

    def filter(self, event_type: TraceEventType) -> list[TraceEvent]:
        return [e for e in self.events if e.event_type == event_type]
```

**No error handling needed** — `emit()` is append-only with no I/O or external calls.

---

### `vulnhuntr/cli_providers/base.py` (MODIFY — middleware, request-response)

**Analog:** `vulnhuntr/mcp/analysis.py` lines 67–74 — optional-kwarg injection pattern (`mcp_helper=None`); `vulnhuntr/core/analysis.py` lines 112–130 — same optional-kwarg injection `mcp_helper: Any | None = None`.

**Import addition** (add after existing `vulnhuntr.core.models` import):
```python
from vulnhuntr.core.trace import ExecutionTracer
```
*Use `TYPE_CHECKING` guard if preferred to avoid circular import risk — none exists here since `trace.py` is stdlib-only.*

**`__init__` injection pattern** (from `VulnerabilityAnalyzer.__init__` lines 112–130; `MCPAnalysisHelper.__init__` lines 67–74 — follow same style):
```python
def __init__(
    self,
    system_prompt: str = "",
    cost_callback: Any | None = None,
    timeout: int = 300,
    workdir: str | None = None,
    tracer: ExecutionTracer | None = None,   # ADD
) -> None:
    super().__init__(system_prompt, cost_callback)
    self.timeout = timeout
    self.workdir = workdir
    self.session_id: str | None = None
    self._last_probe_version: str | None = None
    self._tracer = tracer                    # ADD (private, underscore prefix)
```

**Template method pattern** (from RESEARCH.md Finding 1 — probe hook):
```python
@abstractmethod
def _do_probe(self) -> CapabilityResult:
    """Provider-specific probe implementation."""

def probe(self) -> CapabilityResult:
    """Check capability and emit probe_result trace event."""
    result = self._do_probe()
    if self._tracer is not None:
        self._tracer.emit(
            "probe_result",
            provider=self.__class__.__name__,
            ok=result.ok,
            binary_found=result.binary_found,
            version=result.version,
            auth_valid=result.auth_valid,
            diagnostic_message=result.diagnostic_message,
        )
    return result
```
*`probe()` was previously `@abstractmethod`. After this change it becomes a concrete method; `_do_probe()` becomes the new abstract.*

**None-guard pattern** (apply consistently for all emit sites):
```python
if self._tracer is not None:
    self._tracer.emit("event_type", provider=self.__class__.__name__, ...)
```

---

### `vulnhuntr/cli_providers/claude_code.py` (MODIFY — provider, request-response)

**Analog:** `vulnhuntr/cli_providers/gemini_cli.py` lines 67–128 — identical `probe()` structure to rename.

**`__init__` tracer pass-through** (add `tracer` kwarg, forward to `super()`):
```python
def __init__(
    self,
    system_prompt: str = "",
    cost_callback: Any | None = None,
    timeout: int = 300,
    workdir: str | None = None,
    policy: CLIPolicy | None = None,
    tracer: ExecutionTracer | None = None,   # ADD
) -> None:
    super().__init__(system_prompt, cost_callback, timeout, workdir, tracer=tracer)  # PASS
    self._policy = policy
```

**`probe()` → `_do_probe()` rename** (from `claude_code.py` lines 143–173):
```python
# BEFORE:
def probe(self) -> CapabilityResult:
    """Check binary availability..."""
    binary = shutil.which("claude")
    ...

# AFTER:
def _do_probe(self) -> CapabilityResult:
    """Check binary availability..."""
    binary = shutil.which("claude")
    ...
```
*Body is unchanged — only the method name changes.*

**`session_decision` emit in `send_message()`** (co-locate with session flag logic in `send_message()` — follow same `if self._tracer is not None:` guard pattern):
```python
# After building session flags (flags_added list), before cmd construction:
if self._tracer is not None:
    self._tracer.emit(
        "session_decision",
        provider=self.__class__.__name__,
        session_mode=session_mode,
        flags_added=flags_added,   # list of str, e.g. ["--resume", "sess-123"]
        warned=warned,             # bool — True if a log.warning was emitted
    )
```

**`response_validated` emit in `send_message()`** (after Pydantic parse; `CLIParseError` path):
```python
# Success path:
if self._tracer is not None:
    self._tracer.emit(
        "response_validated",
        provider=self.__class__.__name__,
        vuln_type="",       # not known at send_message level; pass "" or omit
        confidence=0,
        valid=True,
        error=None,
    )

# On CLIParseError (in except block, before re-raise):
if self._tracer is not None:
    self._tracer.emit(
        "response_validated",
        provider=self.__class__.__name__,
        vuln_type="",
        confidence=0,
        valid=False,
        error=str(exc),
    )
raise
```

---

### `vulnhuntr/cli_providers/gemini_cli.py` (MODIFY — provider, request-response)

**Analog:** `vulnhuntr/cli_providers/claude_code.py` — identical rename pattern.

**Changes are mechanical** — same as claude_code.py:
1. Add `tracer: ExecutionTracer | None = None` to `__init__`, forward to `super()`
2. Rename `probe()` → `_do_probe()` (lines 67–128); body unchanged
3. No `session_decision` emit needed (GeminiCLI logs a warning for non-stateless modes but doesn't change flags — if `log.warning()` is called for unsupported session_mode, emit `session_decision` with `warned=True`)

**Import addition** (after existing `vulnhuntr.cli_providers.base` import block):
```python
from vulnhuntr.core.trace import ExecutionTracer
```

---

### `vulnhuntr/cli_providers/codex.py` (MODIFY — provider, request-response)

**Analog:** `vulnhuntr/cli_providers/claude_code.py` — same rename.

**`probe()` → `_do_probe()` location:** `codex.py` line ~75 (`def probe(self) -> CapabilityResult:`). Same mechanical rename, body unchanged. Same `__init__` tracer kwarg addition.

---

### `vulnhuntr/cli_providers/qwen_code.py` (MODIFY — provider, request-response)

**Analog:** `vulnhuntr/cli_providers/claude_code.py` — same rename.

**`probe()` → `_do_probe()` location:** `qwen_code.py` line ~80 (`def probe(self) -> CapabilityResult:`). Same mechanical rename, body unchanged. Same `__init__` tracer kwarg addition.

---

### `vulnhuntr/llms.py` (MODIFY — service, event-driven)

**Analog:** `vulnhuntr/llms.py` `FallbackLLM._diagnostics.append()` at lines 539–547 — emit co-located with append.

**`FallbackLLM.__init__` tracer injection** (lines 476–480 — add `tracer` alongside `_diagnostics`):
```python
def __init__(self, primary: LLM, fallbacks: list[LLM], tracer: ExecutionTracer | None = None) -> None:
    self._primary = primary
    self._fallbacks = fallbacks
    self._active: LLM = primary
    self._all_llms: list[LLM] = [primary] + fallbacks
    self._diagnostics: list[dict[str, Any]] = []
    self._tracer = tracer    # ADD
```

**Import addition** (at top of `llms.py` — already imports from `vulnhuntr.core.models`):
```python
from vulnhuntr.core.trace import ExecutionTracer
```

**`fallback_triggered` emit** (lines 539–547 — co-locate immediately after `self._diagnostics.append(...)`):
```python
# Existing:
self._diagnostics.append(
    {
        "failed_provider": type(llm).__name__,
        "error_class": type(e).__name__,
        "failure_reason": str(e)[:200],
        "fallback_to": type(self._all_llms[i + 1]).__name__ if i + 1 < len(self._all_llms) else "none",
    }
)
# ADD immediately after:
if self._tracer is not None:
    self._tracer.emit(
        "fallback_triggered",
        provider=type(llm).__name__,
        failed_provider=type(llm).__name__,
        error_class=type(e).__name__,
        fallback_to=type(self._all_llms[i + 1]).__name__ if i + 1 < len(self._all_llms) else "none",
        fallback_index=i + 1,
    )
```

---

### `vulnhuntr/core/analysis.py` (MODIFY — service, CRUD)

**Analog:** `vulnhuntr/core/analysis.py` lines 112–130 — existing `mcp_helper: Any | None = None` injection; follow the exact same kwarg/attribute pattern.

**`VulnerabilityAnalyzer.__init__` addition** (add `tracer` after `mcp_helper` — lines 112–130):
```python
def __init__(
    self,
    llm: LLMClient,
    code_extractor: SymbolExtractor,
    config: AnalysisConfig | None = None,
    prompt_templates: dict[str, str] | None = None,
    vuln_specific_data: dict[VulnType, dict] | None = None,
    mcp_helper: Any | None = None,
    tracer: Any | None = None,    # ADD (use Any to avoid circular import; type as ExecutionTracer)
) -> None:
    ...
    self.mcp_helper = mcp_helper
    self.tracer = tracer          # ADD
```

**Import** (at top of `core/analysis.py` — it IS in `vulnhuntr.core`, so use relative):
```python
from .trace import ExecutionTracer   # or: TYPE_CHECKING guard + string annotation
```
*Per RESEARCH Finding 7, there is zero circular-import risk — `trace.py` has no back-imports.*

---

### `vulnhuntr/mcp/analysis.py` (MODIFY — service, event-driven + async)

**Analog:** self — `execute_tool_calls()` lines 197–270 — emit fits into each existing try/except branch.

**`MCPAnalysisHelper.__init__` addition** (line 67 — add `tracer` after `settings`):
```python
def __init__(self, settings: MCPSettings, tracer: ExecutionTracer | None = None) -> None:
    self._settings = settings
    self._policy: MCPAnalysisPolicy = settings.analysis
    self._tools: list[ToolDescriptor] = []
    self._client: Any = None
    self._initialized = False
    self._tracer = tracer    # ADD
```

**Import addition** (at top of `mcp/analysis.py` — already imports from `vulnhuntr.core.models`):
```python
from vulnhuntr.core.trace import ExecutionTracer
```

**`tool_call` emit pattern** (in `execute_tool_calls()` — add `time` import at module top; add `t0` before each `wait_for` call):
```python
import time   # ADD at module top

# Inside execute_tool_calls(), before the try block for each req:
t0 = time.monotonic()
try:
    raw = await asyncio.wait_for(
        self._client.call_tool(req.server, req.tool, req.arguments),
        timeout=timeout if timeout and timeout > 0 else None,
    )
    duration_ms = int((time.monotonic() - t0) * 1000)
    output_str = _extract_text(raw)
    results.append(MCPToolCallResult(server=req.server, tool=req.tool,
                                     success=True, output=output_str[:MAX_TOOL_RESULT_CHARS]))
    log.info("MCP tool call succeeded", ...)
    if self._tracer is not None:                                    # ADD
        self._tracer.emit("tool_call", provider="MCPAnalysisHelper",
                          server=req.server, tool=req.tool,
                          success=True, error=None, duration_ms=duration_ms)
except asyncio.TimeoutError:
    duration_ms = int((time.monotonic() - t0) * 1000)
    results.append(MCPToolCallResult(..., success=False,
                   error=f"Timeout after {self._policy.tool_timeout_seconds}s"))
    log.warning(...)
    if self._tracer is not None:                                    # ADD
        self._tracer.emit("tool_call", provider="MCPAnalysisHelper",
                          server=req.server, tool=req.tool,
                          success=False,
                          error=f"Timeout after {self._policy.tool_timeout_seconds}s",
                          duration_ms=duration_ms)
except Exception as e:
    duration_ms = int((time.monotonic() - t0) * 1000)
    ...
    if self._tracer is not None:                                    # ADD
        self._tracer.emit("tool_call", provider="MCPAnalysisHelper",
                          server=req.server, tool=req.tool,
                          success=False, error=str(e)[:512], duration_ms=duration_ms)
```

**Blocked tool emit** (in the `is_tool_allowed` branch — emit with `duration_ms=0`):
```python
# After the results.append(MCPToolCallResult(...blocked...)):
if self._tracer is not None:
    self._tracer.emit("tool_call", provider="MCPAnalysisHelper",
                      server=req.server, tool=req.tool,
                      success=False, error="blocked by destructive-tool policy",
                      duration_ms=0)
```

---

### `tests/test_trace.py` (NEW — test, event-driven)

**Analog:** `tests/test_mcp_analysis.py` lines 1–100 — model unit tests pattern: direct construction, field assertions, no fixtures needed.

**File header pattern** (from `test_mcp_analysis.py` lines 1–18):
```python
"""
Tests for vulnhuntr.core.trace

Covers TraceEvent dataclass shape, ExecutionTracer emit/filter, and per-event
data schema requirements from EVAL-01.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from vulnhuntr.core.trace import ExecutionTracer, TraceEvent, TraceEventType
```

**Dataclass shape test pattern** (from `test_mcp_analysis.py` `TestMCPToolCallResult`):
```python
class TestTraceEvent:
    def test_fields_present(self):
        evt = TraceEvent(
            event_type="probe_result",
            provider="ClaudeCodeLLM",
            timestamp=datetime.now(timezone.utc),
            data={"ok": True, "binary_found": True, "version": "2.1.0",
                  "auth_valid": None, "diagnostic_message": ""},
        )
        assert evt.event_type == "probe_result"
        assert evt.provider == "ClaudeCodeLLM"
        assert isinstance(evt.timestamp, datetime)
        assert evt.data["ok"] is True
```

**Emit/filter pattern** (no fixtures; pure method calls):
```python
class TestExecutionTracer:
    def test_emit_appends_event(self):
        tracer = ExecutionTracer()
        tracer.emit("probe_result", provider="X", ok=True, binary_found=True,
                    version="1.0", auth_valid=None, diagnostic_message="")
        assert len(tracer.events) == 1

    def test_filter_returns_subset(self):
        tracer = ExecutionTracer()
        tracer.emit("probe_result", provider="A", ok=True, binary_found=True,
                    version=None, auth_valid=None, diagnostic_message="")
        tracer.emit("tool_call", provider="B", server="s", tool="t",
                    success=True, error=None, duration_ms=10)
        probe_events = tracer.filter("probe_result")
        assert len(probe_events) == 1
        assert probe_events[0].provider == "A"

    def test_empty_filter_returns_empty_list(self):
        tracer = ExecutionTracer()
        assert tracer.filter("fallback_triggered") == []
```

---

### `tests/test_behavior.py` (NEW — test, request-response)

**Analog:** `tests/test_cli_providers.py` `TestClaudeCodeSessionMode` (lines 1663–1744) — construct real provider with mocked subprocess; assert on side effects.

**File header and imports** (from `test_cli_providers.py` lines 1–30 and `TestClaudeCodeSessionMode`):
```python
"""
Tests for behavioral flows with ExecutionTracer (EVAL-02).

Each class drives a complete multi-step flow with mocked subprocesses
and asserts that trace events were emitted with correct semantic content.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM
from vulnhuntr.config import CLIPolicy
from vulnhuntr.core.trace import ExecutionTracer
from vulnhuntr.llms import FallbackLLM, LLMError
```

**`_make_fake()` helper pattern** (from `TestClaudeCodeSessionMode` lines 1666–1673):
```python
def _make_fake(session_id: str | None = None) -> MagicMock:
    payload: dict[str, Any] = {"result": "ok", "usage": {}, "modelUsage": {}}
    if session_id:
        payload["session_id"] = session_id
    fake = MagicMock()
    fake.stdout = json.dumps(payload)
    fake.returncode = 0
    return fake
```

**`TestProbeToSendTrace` class** (from RESEARCH Finding 4):
```python
class TestProbeToSendTrace:
    """Flow 1: probe() → send_message() emits probe_result + response_validated."""

    def test_probe_and_send_emit_expected_trace_events(self):
        tracer = ExecutionTracer()
        policy = CLIPolicy(session_mode="stateless", mcp_mode="none", tool_mode="none")
        llm = ClaudeCodeLLM(policy=policy, workdir="/tmp", tracer=tracer)

        with patch("shutil.which", return_value="/usr/bin/claude"):
            with patch("subprocess.run") as m:
                m.return_value = MagicMock(returncode=0, stdout="2.1.126", stderr="")
                llm.probe()

        with patch("subprocess.run", return_value=_make_fake()):
            llm.send_message("test prompt", 1024)

        probe_events = tracer.filter("probe_result")
        assert len(probe_events) == 1
        assert probe_events[0].data["ok"] is True
        assert probe_events[0].provider == "ClaudeCodeLLM"

        validated = tracer.filter("response_validated")
        assert len(validated) == 1
        assert validated[0].data["valid"] is True
        assert validated[0].data["error"] is None
```

**`TestFallbackChainTrace` class** (from RESEARCH Finding 4 + `FallbackLLM` pattern):
```python
class TestFallbackChainTrace:
    """Flow 2: FallbackLLM emits fallback_triggered when primary fails."""

    def test_fallback_triggered_event_has_correct_fields(self):
        from vulnhuntr.cli_providers.base import CLIRuntimeError

        tracer = ExecutionTracer()
        # Primary: a CLI provider that always fails
        primary = MagicMock()
        primary.chat.side_effect = CLIRuntimeError("binary crash")
        # Fallback: a provider that succeeds
        fallback = MagicMock()
        fallback.chat.return_value = "ok"
        fallback.history = []
        fallback.system_prompt = ""
        fallback.prev_prompt = ""
        fallback.prev_response = ""

        llm = FallbackLLM(primary, [fallback], tracer=tracer)
        llm.chat("test prompt")

        events = tracer.filter("fallback_triggered")
        assert len(events) == 1
        assert events[0].data["error_class"] == "CLIRuntimeError"
        assert events[0].data["fallback_index"] == 1
```

**`TestSessionResumeTrace` class** (from `TestClaudeCodeSessionMode.test_resume_with_session_id_passes_resume_flag`):
```python
class TestSessionResumeTrace:
    """Flow 3: session_mode='resume' emits session_decision with correct flags."""

    def test_session_resume_emits_session_decision_event(self):
        tracer = ExecutionTracer()
        policy = CLIPolicy(session_mode="resume", mcp_mode="none", tool_mode="none")
        llm = ClaudeCodeLLM(policy=policy, workdir="/tmp", tracer=tracer)
        llm.session_id = "stored-session-123"

        with patch("subprocess.run", return_value=_make_fake("stored-session-123")):
            llm.send_message("test", 1024)

        events = tracer.filter("session_decision")
        assert len(events) == 1
        assert events[0].data["session_mode"] == "resume"
        flags = events[0].data["flags_added"]
        assert any("--resume" in f for f in flags)
        assert events[0].data["warned"] is False
```

**`TestValidationFailureTrace` class** (from RESEARCH Finding 4 — malformed JSON path):
```python
class TestValidationFailureTrace:
    """Flow 4: malformed subprocess output → response_validated(valid=False) + CLIParseError."""

    def test_parse_failure_emits_invalid_response_validated(self):
        from vulnhuntr.cli_providers.base import CLIParseError

        tracer = ExecutionTracer()
        policy = CLIPolicy(session_mode="stateless", mcp_mode="none", tool_mode="none")
        llm = ClaudeCodeLLM(policy=policy, workdir="/tmp", tracer=tracer)

        bad = MagicMock()
        bad.stdout = "not-valid-json{{{"
        bad.returncode = 0

        with pytest.raises(CLIParseError):
            with patch("subprocess.run", return_value=bad):
                llm.send_message("test", 1024)

        events = tracer.filter("response_validated")
        assert len(events) == 1
        assert events[0].data["valid"] is False
        assert events[0].data["error"] != ""
```

---

### `tests/test_config.py` (MODIFY — test, CRUD)

**Analog:** `tests/test_config.py` `TestCLIPolicy` and `TestCLIPolicyDefaults` (lines 215–270) — `VulnhuntrConfig.from_dict()` construction, field assertion, no fixtures.

**Class doc with partition table pattern** (from CONTEXT.md D-11/D-12, with D-14 IDs):
```python
class TestCLIPolicyBoundaries:
    """Equivalence-partition and boundary tests for CLIPolicy field validation (EVAL-03).

    Partition table:
      session_mode  : valid={stateless,continue,resume}  invalid={unknown}
      mcp_mode      : valid={none,vulnhuntr,provider,both}  invalid={auto}
      tool_mode     : valid={none,read-only,full}  invalid={""} (empty string)
      timeout       : boundary={0,1,300,sys.maxsize}  invalid={-1}
      max_turns     : boundary={1,10,100}  invalid={0}
    """

    @pytest.mark.parametrize(
        "session_mode,should_raise",
        [
            pytest.param("stateless", False, id="valid-stateless"),
            pytest.param("continue",  False, id="valid-continue"),
            pytest.param("resume",    False, id="valid-resume"),
            pytest.param("unknown",   True,  id="invalid-unknown"),
        ],
    )
    def test_session_mode_validation(self, session_mode, should_raise):
        if should_raise:
            with pytest.raises(ValueError, match="session_mode"):
                CLIPolicy(session_mode=session_mode)
        else:
            p = CLIPolicy(session_mode=session_mode)
            assert p.session_mode == session_mode
```
*Note: per RESEARCH Finding 3, `CLIPolicy` currently has no `__post_init__` validation. The Phase 8 plan must add `__post_init__` to `CLIPolicy` in `config.py` before these tests will pass. See Shared Patterns > Validation below.*

**Boundary int test pattern** (from `TestCLIPolicyDefaults` + RESEARCH D-12):
```python
    @pytest.mark.parametrize(
        "timeout,should_raise",
        [
            pytest.param(0,            False, id="boundary-zero"),
            pytest.param(1,            False, id="boundary-one"),
            pytest.param(300,          False, id="boundary-default"),
            pytest.param(sys.maxsize,  False, id="boundary-maxsize"),
            pytest.param(-1,           True,  id="invalid-negative"),
        ],
    )
    def test_timeout_boundary(self, timeout, should_raise):
        if should_raise:
            with pytest.raises(ValueError, match="timeout"):
                CLIPolicy(timeout=timeout)
        else:
            assert CLIPolicy(timeout=timeout).timeout == timeout
```

---

### `tests/test_cli_providers.py` (MODIFY — test, request-response)

**Analog:** `tests/test_cli_providers.py` `TestClaudeCodeMCPConfig` (lines 1767–1810) — tempdir + patch("subprocess.run") + assert on cmd list; `TestErrorTaxonomy` (lines 87–110) — `@pytest.mark.parametrize` with `id=` on every case.

**Class doc with partition table** (from CONTEXT.md D-13, with D-14 IDs):
```python
class TestProviderSelectionBoundaries:
    """Equivalence-partition tests for initialize_llm() and probe capability checks (EVAL-03).

    Partition table:
      Valid CLI provider name ("claude-code")  → ClaudeCodeLLM instance
      Valid API provider name ("claude")        → Claude instance
      Unknown provider name ("gpt-99")          → ValueError with name in message
      CLI provider binary_found=False           → CLIBinaryNotFoundError
      CLI provider auth_valid=False             → CLIAuthError
      Fallback spec "claude-code,claude"        → FallbackLLM wrapping both
      Fallback with unknown CLI name            → ValueError at spec parse time
    """
```

**Probe error mock pattern** (from `TestClaudeCodeSessionMode` approach — mock `probe()` directly; reference `_check_cli_provider_capabilities` per RESEARCH RISK-06):
```python
    def test_binary_not_found_raises_cli_binary_error(self):
        from vulnhuntr.cli_providers import ClaudeCodeLLM, CLIBinaryNotFoundError
        from vulnhuntr.config import CLIPolicy

        policy = CLIPolicy(session_mode="stateless")
        llm = ClaudeCodeLLM(policy=policy, workdir="/tmp")
        with patch.object(llm, "_do_probe", return_value=CapabilityResult(
            ok=False, binary_found=False, version=None, auth_valid=None,
            diagnostic_message="not found",
        )):
            result = llm.probe()
        assert result.binary_found is False
        # The runner's _check_cli_provider_capabilities() raises on ok=False:
        # test that path separately, targeting runner._check_cli_provider_capabilities
```

**Parametrize with IDs** (from `TestErrorTaxonomy` lines 87–110 + D-14):
```python
    @pytest.mark.parametrize(
        "provider_name,expected_type",
        [
            pytest.param("claude-code", "ClaudeCodeLLM", id="valid-claude-code"),
            pytest.param("gemini-cli",  "GeminiCLILLM",  id="valid-gemini-cli"),
            pytest.param("codex",       "CodexLLM",       id="valid-codex"),
            pytest.param("qwen-code",   "QwenCodeLLM",    id="valid-qwen-code"),
        ],
    )
    def test_valid_cli_provider_returns_correct_type(self, provider_name, expected_type):
        from vulnhuntr.cli import initialize_llm
        ...
```

---

## Shared Patterns

### Optional Keyword Injection (None = no-op)
**Source:** `vulnhuntr/core/analysis.py` lines 112–130 (`mcp_helper: Any | None = None`)
**Apply to:** All `__init__` additions — `CLIProviderLLM`, `FallbackLLM`, `VulnerabilityAnalyzer`, `MCPAnalysisHelper`
```python
tracer: ExecutionTracer | None = None   # in __init__ signature
self._tracer = tracer                    # stored as _tracer (private)

# At every emit site:
if self._tracer is not None:
    self._tracer.emit(...)
```

### Structlog Co-location
**Source:** `vulnhuntr/llms.py` lines 539–547 (`log.error(...)` then `self._diagnostics.append(...)`)
**Apply to:** All emit sites — place `if self._tracer is not None: self._tracer.emit(...)` immediately after the existing `log.*()` call at each emission site. Never emit without the adjacent `log.*()` for structured observability.

### CLIPolicy Validation (must be added as part of Phase 8)
**Source:** No existing analog — `CLIPolicy` has no `__post_init__` today (RESEARCH Finding 3)
**Apply to:** `vulnhuntr/config.py` `CLIPolicy` dataclass

Add `__post_init__` with frozenset guards before boundary tests will pass:
```python
_VALID_SESSION_MODES = frozenset({"stateless", "continue", "resume"})
_VALID_MCP_MODES = frozenset({"none", "vulnhuntr", "provider", "both"})
_VALID_TOOL_MODES = frozenset({"none", "read-only", "full"})

@dataclass
class CLIPolicy:
    ...

    def __post_init__(self) -> None:
        if self.session_mode not in _VALID_SESSION_MODES:
            raise ValueError(
                f"Invalid session_mode {self.session_mode!r}. "
                f"Must be one of: {sorted(_VALID_SESSION_MODES)}"
            )
        if self.mcp_mode not in _VALID_MCP_MODES:
            raise ValueError(
                f"Invalid mcp_mode {self.mcp_mode!r}. "
                f"Must be one of: {sorted(_VALID_MCP_MODES)}"
            )
        if self.tool_mode not in _VALID_TOOL_MODES:
            raise ValueError(
                f"Invalid tool_mode {self.tool_mode!r}. "
                f"Must be one of: {sorted(_VALID_TOOL_MODES)}"
            )
        if self.timeout < 0:
            raise ValueError(f"timeout must be >= 0, got {self.timeout}")
        if self.max_turns < 1:
            raise ValueError(f"max_turns must be >= 1, got {self.max_turns}")
```
⚠️ **Validation scope risk:** Adding `__post_init__` may break existing tests that use `CLIPolicy(mcp_mode="auto")` or other invalid values. Run `pytest tests/test_config.py tests/test_cli_providers.py -x` immediately after adding validation.

### Parametrize with IDs (D-14)
**Source:** `tests/test_cli_providers.py` `TestErrorTaxonomy` lines 87–110
**Apply to:** All new `@pytest.mark.parametrize` calls in `TestCLIPolicyBoundaries` and `TestProviderSelectionBoundaries`
```python
@pytest.mark.parametrize(
    "field_value,expected",
    [
        pytest.param("valid_value", expected_result, id="descriptive-id"),
        # Every case gets an explicit id= — never rely on numeric index
    ],
)
```

### `_FakeCLIProvider` Update
**Source:** `tests/test_cli_providers.py` lines 38–62
**Apply to:** `tests/test_cli_providers.py` top-level `_FakeCLIProvider` class
```python
# BEFORE:
def probe(self) -> CapabilityResult:
    return CapabilityResult(ok=True, ...)

# AFTER:
def _do_probe(self) -> CapabilityResult:
    return CapabilityResult(ok=True, ...)
```
*No other body changes. Existing tests that call `_FakeCLIProvider().probe()` continue to work because `probe()` now lives in the base class.*

---

## No Analog Found

All 13 files have analogs or direct self-referential patterns. No files lack a pattern source.

---

## Critical Implementation Order

The following ordering constraint applies — it is NOT captured in the file classification table:

| Step | Action | Reason |
|------|--------|--------|
| 1 | Create `vulnhuntr/core/trace.py` | All other files import from it |
| 2 | Add `tracer` to `CLIProviderLLM.__init__`; rename `probe()` → `_do_probe()` in base | Blocks concrete providers and `_FakeCLIProvider` |
| 3 | Rename `probe()` → `_do_probe()` in all 4 providers | Must happen atomically with step 2 |
| 4 | Update `_FakeCLIProvider.probe()` → `_do_probe()` in tests | Must happen in same commit as steps 2–3 |
| 5 | Add `CLIPolicy.__post_init__` validation | Must precede `TestCLIPolicyBoundaries` tests |
| 6 | All other emission wiring + new test files | Can proceed in parallel after steps 1–5 |

---

## Metadata

**Analog search scope:** `vulnhuntr/`, `tests/`
**Files scanned:** 13 source files read directly; cross-referenced with 08-RESEARCH.md findings
**Pattern extraction date:** 2026-05-04
