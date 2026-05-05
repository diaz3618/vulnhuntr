# Phase 8 Research: Behavioral Evaluation & Trace Capture

**Researched:** 2026-05-04
**Domain:** Python testing patterns, execution tracing, equivalence-partition test design
**Confidence:** HIGH — all findings are from direct codebase inspection, no external sources needed

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- D-01 through D-14 as specified in 08-CONTEXT.md
- New module `vulnhuntr/core/trace.py` with `TraceEvent` dataclass and `ExecutionTracer`
- Five event types: `probe_result`, `response_validated`, `tool_call`, `fallback_triggered`, `session_decision`
- Tracer injected as optional keyword arg; `None` means no-op
- `run_analysis()` returns `tuple[list[AnalysisResult], ExecutionTracer | None]`
- Two new test files: `tests/test_trace.py` and `tests/test_behavior.py`
- Boundary tests land in existing `test_config.py` and `test_cli_providers.py`
- In-memory only; no file I/O in Phase 8

### Agent's Discretion
- Which base-class method or hook is cleanest for emitting `probe_result`
- Exact `run_analysis()` return-type handling (tuple vs named struct)
- Whether `CLIPolicy` invalid-value tests assert `ValueError` or a structlog warning

### Deferred Ideas (OUT OF SCOPE)
- State-transition invariants (Phase 9)
- Report integration of trace output (Phase 10)
- `--trace-output` flag and `CheckpointData` attachment (Phase 10)
- Any new `CLIPolicy` fields
- Changes to Phase 7 MCP wiring
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| EVAL-01 | Structured execution traces for critical provider flows (probe, validation, tool calls, fallback, session) | Findings 1, 5, 6, 7 |
| EVAL-02 | Behavioral evaluations assert semantic/procedural correctness for multi-step flows | Finding 4 |
| EVAL-03 | CLI config and provider-selection paths have equivalence-partition and boundary tests | Findings 3, 4 |
</phase_requirements>

---

## Summary

Phase 8 adds a thin `ExecutionTracer` accumulator to five emission sites across the codebase, then uses it in new behavioral tests that drive multi-step flows and assert event ordering and content. The codebase is well-structured for this: `trace.py` can be a standalone leaf module with no vulnhuntr imports, the injection pattern (optional kwarg, None = no-op) matches the existing `mcp_helper` pattern from Phase 7, and all five emission sites are already well-identified in CONTEXT.md.

There are two decision-critical findings the planner must address before writing plans: (1) the probe hook approach — the template method pattern (rename `probe()` → `_do_probe()`) is cleanest but requires updating five concrete implementations and several test classes; (2) D-05's `run_analysis()` signature conflicts with the existing `runner.run_analysis()` which returns `int`. Both are solvable; the resolutions are proposed below.

**Primary recommendation:** Use the template method for probe emission; for D-05, create `VulnerabilityAnalyzer.run_analysis()` as a new method rather than changing `runner.run_analysis()`.

---

## Findings

### 1. Probe Emission Hook — Recommended Approach

**Current state:** `probe()` is declared `@abstractmethod` in `CLIProviderLLM` (base.py line ~104). All four concrete providers (`ClaudeCodeLLM`, `GeminiCLILLM`, `CodexLLM`, `QwenCodeLLM`) implement it directly. The test helper `_FakeCLIProvider` also implements `probe()` directly.

**Three options evaluated:**

| Option | Mechanism | Requires subclass change? | Risk |
|--------|-----------|--------------------------|------|
| (a) Template method | Rename abstract to `_do_probe()`, base `probe()` calls it then emits | Yes — 4 providers + `_FakeCLIProvider` + test mocks of `.probe()` | Medium — mechanical rename, but many files touched |
| (b) Post-call hook in `chat()` | `chat()` calls `probe()` lazily before first `send_message()` | No | Breaks existing probe-without-send tests; wrong conceptually |
| (c) Require `super().probe()` | Each subclass calls `super().probe()` | Yes — 4 providers | High — forgotten `super()` = silent no-op; hard to enforce |

**Recommendation: Option (a) — Template method.**

```python
# In CLIProviderLLM:
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

**Files that need `probe()` renamed to `_do_probe()`:**
- `vulnhuntr/cli_providers/claude_code.py` — `ClaudeCodeLLM.probe()` → `_do_probe()`
- `vulnhuntr/cli_providers/gemini_cli.py` — `GeminiCLILLM.probe()` → `_do_probe()`
- `vulnhuntr/cli_providers/codex.py` — `CodexLLM.probe()` → `_do_probe()`
- `vulnhuntr/cli_providers/qwen_code.py` — `QwenCodeLLM.probe()` → `_do_probe()`
- `tests/test_cli_providers.py` — `_FakeCLIProvider.probe()` → `_do_probe()`

**Test classes that patch or call `.probe()` directly (must be updated):**
- `TestClaudeCodeLLMProbe`, `TestClaudeCodeLLM.test_probe_ok/test_probe_missing_binary`
- `TestGeminiCLILLM.test_probe_*` (7 tests)
- `TestCodexLLMProbe` (3 tests)
- `TestQwenCodeLLMProbe` (2 tests)
- `TestProbeAbstract` — tests that `_do_probe()` is abstract
- `runner.py` calls `llm.probe()` at line ~370; that call continues to work unchanged

**Note:** The `_FakeCLIProvider` in tests currently returns a hardcoded `CapabilityResult`. After rename it becomes `_do_probe()`. Existing tests that construct `_FakeCLIProvider()` and call `.probe()` will continue to work — they call the new non-abstract `probe()` which calls `_do_probe()` internally. The tracer will be `None` (no tracer injected), so emit is skipped.

---

### 2. run_analysis() Return Type Impact

**Current state:** `run_analysis()` lives in `vulnhuntr/cli/runner.py` at line 393. Its current signature and return type:

```python
def run_analysis(args: argparse.Namespace, llm_factory: Callable | None = None) -> int:
```

It returns an integer exit code (0 on success, non-zero on error). The internal `_analyze_files()` helper returns `tuple[list[AnalysisResult], bool]`.

**Call sites that would break if `runner.run_analysis()` returned a tuple:**
- `tests/test_cli.py` — 4 tests: `test_run_analysis_produces_finding`, `test_run_analysis_returns_zero_exit_code`, `test_run_analysis_does_not_call_real_api`, `test_run_analysis_no_checkpoint_file_created` — all use `exit_code = run_analysis(...)` and compare to int
- `vulnhuntr/__main__.py` — entry point, calls `sys.exit(run_analysis(args))`

**Conflict with D-05:** D-05 specifies `def run_analysis(...) -> tuple[list[AnalysisResult], ExecutionTracer | None]`. This cannot apply to `runner.run_analysis()` without breaking the exit-code contract and all existing callers.

**Recommended resolution (for planner):** D-05 should apply to a NEW method `VulnerabilityAnalyzer.run_analysis()` (or `VulnerabilityAnalyzer.run_batch()`), not to `runner.run_analysis()`. The runner's internal `_analyze_files()` can be modified to return the tracer alongside findings as a private implementation detail. The runner's public `run_analysis()` continues to return `int`.

Alternative: If the intent is truly to expose the tracer from the runner, create a new `runner.run_analysis_with_trace()` variant that returns the tuple, keeping the original `run_analysis()` unchanged for backward compatibility.

**Decision needed from planner:** Choose resolution before writing plans for D-05.

---

### 3. CLIPolicy Validation Behavior

**Current state:** `VulnhuntrConfig.from_dict()` (config.py lines ~167–230) does **no validation** on `CLIPolicy` string fields. The implementation for each field is:

```python
if "session_mode" in cli_data:
    cli.session_mode = str(cli_data["session_mode"])
```

Invalid values like `"unknown"` (for `session_mode`) or `"auto"` (for `mcp_mode`) are **silently accepted and stored**. No `ValueError` is raised, no structlog warning is emitted. The invalid string simply becomes the field value.

**What D-12 tests should assert (given current behavior):**

Since the current implementation silently accepts anything, two valid approaches for the planner:

1. **Test current behavior (no validation):** Assert that `VulnhuntrConfig.from_dict({"cli": {"session_mode": "unknown"}}).cli.session_mode == "unknown"` — the value is stored, no exception raised. This documents a known gap (no guard at parse time).

2. **Add validation as part of Phase 8 (extend the implementation):** Add a validation step inside `from_dict()` or `CLIPolicy.__post_init__()` that raises `ValueError` for out-of-range values, then test that. This is a small implementation addition.

**Recommendation:** Since D-12 says "either ValueError or a structlog warning — whichever the implementation chooses", and Phase 8 is an evaluation/hardening phase, the planner should **add validation** (option 2) as part of the boundary test work. This makes the tests non-trivially assertable and closes a real correctness gap. Validation could be in `CLIPolicy.__post_init__()` or a `validate()` class method called from `from_dict()`.

**Proposed validation constants to add to CLIPolicy:**
```python
_VALID_SESSION_MODES = frozenset({"stateless", "continue", "resume"})
_VALID_MCP_MODES = frozenset({"none", "vulnhuntr", "provider", "both"})
_VALID_TOOL_MODES = frozenset({"none", "read-only", "full"})
```

**For boundary values (timeout, max_turns):** The current code blindly does `cli.timeout = int(cli_data["timeout"])`. Negative values like `-1` are silently stored. D-12 calls these "invalid" — the tests should either assert `ValueError` (if validation is added) or assert the value is stored without error (if testing current behavior).

---

### 4. Existing Test Patterns to Follow

**`_FakeCLIProvider` pattern (tests/test_cli_providers.py lines 38–62):**

```python
class _FakeCLIProvider(CLIProviderLLM):
    def probe(self) -> CapabilityResult:          # becomes _do_probe() after Phase 8
        return CapabilityResult(ok=True, binary_found=True, version="1.0.0",
                                auth_valid=True, diagnostic_message="")
    def get_response(self, response: Any) -> str:
        return response.stdout
    def _extract_usage(self, response: Any) -> Any:
        from vulnhuntr.core.models import LLMUsage
        return LLMUsage(input_tokens=0, output_tokens=0, model=self.model)
    def send_message(self, user_prompt: str, max_tokens: int, response_model: Any) -> Any:
        return self._run_subprocess(["echo", user_prompt])
```

**`TestClaudeCodeSessionMode` pattern** (lines 1663–1744) — the closest match for `TestSessionResumeTrace`:
- Construct `ClaudeCodeLLM(policy=CLIPolicy(session_mode="resume", ...), workdir="/tmp")`
- Set `llm.session_id = "stored-session-123"`
- Use `_make_fake()` helper to produce a `MagicMock` with `.stdout`, `.returncode=0`
- `with patch("subprocess.run", return_value=self._make_fake()) as m: llm.send_message("test", 1024)`
- Assert on `m.call_args[0][0]` (the cmd list) and provider state

**For `TestProbeToSendTrace` (new behavior test with tracer):**
```python
# Pattern to follow in tests/test_behavior.py:
def test_probe_and_send_emit_expected_trace_events(self):
    from vulnhuntr.core.trace import ExecutionTracer
    from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM
    from vulnhuntr.config import CLIPolicy

    tracer = ExecutionTracer()
    policy = CLIPolicy(session_mode="stateless", mcp_mode="none", tool_mode="none")
    llm = ClaudeCodeLLM(policy=policy, workdir="/tmp", tracer=tracer)

    with patch("shutil.which", return_value="/usr/bin/claude"):
        with patch("subprocess.run") as m:
            m.return_value = MagicMock(returncode=0, stdout="2.1.126", stderr="")
            llm.probe()
    # patch for send_message...
    assert len(tracer.filter("probe_result")) == 1
    assert tracer.filter("probe_result")[0].data["ok"] is True
```

**For `TestFallbackChainTrace`:**
- Construct `FallbackLLM(primary_cli_provider, [fake_api_provider])` where primary raises `CLIRuntimeError`
- Drive through `FallbackLLM.chat()`
- Assert `tracer.filter("fallback_triggered")` has 1 event with correct `failed_provider`, `error_class`, `fallback_to`

**For parametrize with IDs (D-14):**
```python
@pytest.mark.parametrize(
    "session_mode,expected_valid",
    [
        pytest.param("stateless", True, id="valid-stateless"),
        pytest.param("continue", True, id="valid-continue"),
        pytest.param("resume", True, id="valid-resume"),
        pytest.param("unknown", False, id="invalid-unknown"),
    ],
)
def test_session_mode_validation(self, session_mode, expected_valid):
    ...
```

**`TestCLIPolicyDefaults` and `TestCLIPolicy` patterns (test_config.py lines 215–270):**
- Simple `VulnhuntrConfig.from_dict({...})` construction
- Assertion on `.cli.<field>`
- No fixtures needed; pure function call

---

### 5. FallbackLLM fallback_triggered Wiring

**Location:** `vulnhuntr/llms.py`, `FallbackLLM.chat()`, the `except LLMError as e:` block starting at approximately line 540.

**Current code in the except block:**
```python
except LLMError as e:
    log.error("llm_failed", provider=..., error_class=type(e).__name__, ...)
    self._diagnostics.append({
        "failed_provider": type(llm).__name__,
        "error_class": type(e).__name__,
        "failure_reason": str(e)[:200],
        "fallback_to": type(self._all_llms[i + 1]).__name__ if i + 1 < len(self._all_llms) else "none",
    })
```

**Data already available for the trace event** (maps directly to D-03 schema):
- `failed_provider` → `type(llm).__name__`
- `error_class` → `type(e).__name__`
- `fallback_to` → `type(self._all_llms[i + 1]).__name__ if i + 1 < len(self._all_llms) else "none"`
- `fallback_index` → `i + 1` (index of the fallback, matches D-03)

**Emit site (co-locate with `self._diagnostics.append()`):**
```python
except LLMError as e:
    ...
    self._diagnostics.append({...})
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

**`FallbackLLM.__init__`** currently takes `primary: LLM, fallbacks: list[LLM]`. Needs `tracer: ExecutionTracer | None = None` added per D-04.

**Note on the `provider_failed_falling_back` log warning:** That warning fires in the `if llm is not self._active:` branch *before* the try block — it fires for the second provider onward. The trace event should fire in the `except` block instead, which correctly captures the failing provider regardless of whether it's primary or a fallback.

---

### 6. MCP tool_call Event Location

**File:** `vulnhuntr/mcp/analysis.py`, `MCPAnalysisHelper.execute_tool_calls()` (line 197–269).

**Current structure per tool call:**
1. Blocked-tool check (early `continue`) → no call made
2. `asyncio.wait_for(self._client.call_tool(...), timeout=...)` → success path
3. `except asyncio.TimeoutError` → timeout path
4. `except Exception` → general error path

**Emit after each resolution.** D-03 requires `duration_ms` — needs `time.monotonic()` before/after the `wait_for`:

```python
import time
...
t0 = time.monotonic()
try:
    raw = await asyncio.wait_for(
        self._client.call_tool(req.server, req.tool, req.arguments),
        timeout=timeout if timeout and timeout > 0 else None,
    )
    duration_ms = int((time.monotonic() - t0) * 1000)
    output_str = _extract_text(raw)
    results.append(MCPToolCallResult(server=req.server, tool=req.tool, success=True, output=...))
    if self._tracer is not None:
        self._tracer.emit("tool_call", provider="MCPAnalysisHelper",
                          server=req.server, tool=req.tool,
                          success=True, error=None, duration_ms=duration_ms)
except asyncio.TimeoutError:
    duration_ms = int((time.monotonic() - t0) * 1000)
    results.append(MCPToolCallResult(..., success=False, error=...))
    if self._tracer is not None:
        self._tracer.emit("tool_call", provider="MCPAnalysisHelper",
                          server=req.server, tool=req.tool,
                          success=False, error=f"Timeout after {self._policy.tool_timeout_seconds}s",
                          duration_ms=duration_ms)
except Exception as e:
    duration_ms = int((time.monotonic() - t0) * 1000)
    ...emit similarly...
```

**For blocked tools:** D-07 doesn't explicitly require a trace event for blocked tools, only for tool calls that resolve. Blocked-tool events could use `success=False, error="blocked by policy"` or be omitted. Planner should decide — recommend emitting them with `duration_ms=0` and `error="blocked by destructive-tool policy"` for full observability.

**`MCPAnalysisHelper.__init__`** currently takes `settings: MCPSettings`. Needs `tracer: ExecutionTracer | None = None` per D-04. The tracer must be propagated from `VulnerabilityAnalyzer` → `MCPAnalysisHelper`.

---

### 7. Import Boundary for trace.py

**`trace.py` imports:** stdlib only — `dataclasses`, `datetime`, `typing`. **Zero vulnhuntr imports.** It is a leaf module.

**Modules that will import from `trace.py`:**

| Module | What it imports | Currently imports from `vulnhuntr.core`? |
|--------|----------------|----------------------------------------|
| `vulnhuntr/cli_providers/base.py` | `ExecutionTracer` (for `__init__` param, emit calls) | Yes — already `from vulnhuntr.core.models import LLMUsage` |
| `vulnhuntr/llms.py` | `ExecutionTracer` (for `FallbackLLM.__init__`) | Yes — `from vulnhuntr.core.models import LLMUsage` |
| `vulnhuntr/mcp/analysis.py` | `ExecutionTracer` (for `MCPAnalysisHelper.__init__`) | Yes — `from vulnhuntr.core.models import ...` |
| `vulnhuntr/core/analysis.py` | `ExecutionTracer` (for `VulnerabilityAnalyzer.__init__`) | It IS in `vulnhuntr.core` — local import from `.trace` |
| `vulnhuntr/cli/runner.py` | `ExecutionTracer` (to instantiate per scan) | Yes — already imports from `vulnhuntr.core` |

**Circular import risk: None.** `trace.py` has no back-imports into any of the above modules. The import direction is strictly one-way:

```
trace.py (stdlib only)
    ↑ imported by
cli_providers/base.py, llms.py, mcp/analysis.py, core/analysis.py, cli/runner.py
```

**`__init__.py` update:** `vulnhuntr/core/__init__.py` should export `ExecutionTracer` and `TraceEvent` alongside the existing exports. This matches the pattern of `core/__init__.py` re-exporting everything in the `core` package.

**One edge case:** `vulnhuntr/__init__.py` imports `from vulnhuntr.core import (...)`. Adding `ExecutionTracer` to the top-level exports is optional but consistent. The planner can defer this to Phase 10 docs work.

---

## Validation Architecture

**Test infrastructure:** pytest, existing suite at `tests/`. Running: `python -m pytest tests/test_trace.py tests/test_behavior.py -v`.

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| EVAL-01 | `TraceEvent` dataclass shape, 5 required fields each type | unit | `pytest tests/test_trace.py -x` | ❌ Wave 0 |
| EVAL-01 | `ExecutionTracer.emit()` appends event; `filter()` returns subset | unit | `pytest tests/test_trace.py -x` | ❌ Wave 0 |
| EVAL-01 | `probe_result` event emitted from base `probe()` | behavior | `pytest tests/test_behavior.py::TestProbeToSendTrace -x` | ❌ Wave 0 |
| EVAL-01 | `fallback_triggered` emitted in `FallbackLLM.chat()` | behavior | `pytest tests/test_behavior.py::TestFallbackChainTrace -x` | ❌ Wave 0 |
| EVAL-01 | `session_decision` emitted on resume session path | behavior | `pytest tests/test_behavior.py::TestSessionResumeTrace -x` | ❌ Wave 0 |
| EVAL-01 | `response_validated` emitted with `valid=False` on parse error | behavior | `pytest tests/test_behavior.py::TestValidationFailureTrace -x` | ❌ Wave 0 |
| EVAL-02 | Trace events assert semantic content not just presence | behavior | Full test_behavior.py suite | ❌ Wave 0 |
| EVAL-03 | `CLIPolicy` field boundary and invalid-value cases | unit | `pytest tests/test_config.py::TestCLIPolicyBoundaries -x` | ❌ Wave 0 |
| EVAL-03 | Provider selection: valid/unknown/binary-missing/auth-fail partitions | unit | `pytest tests/test_cli_providers.py::TestProviderSelectionBoundaries -x` | ❌ Wave 0 |

### Wave 0 Gaps

- [ ] `tests/test_trace.py` — `TraceEvent` and `ExecutionTracer` unit tests
- [ ] `tests/test_behavior.py` — 4 behavior test classes (`TestProbeToSendTrace`, `TestFallbackChainTrace`, `TestSessionResumeTrace`, `TestValidationFailureTrace`)
- [ ] `vulnhuntr/core/trace.py` — module itself (must exist before tests run)
- [ ] `TestCLIPolicyBoundaries` class added to `tests/test_config.py`
- [ ] `TestProviderSelectionBoundaries` class added to `tests/test_cli_providers.py`

### Sampling Rate

- Per task commit: `python -m pytest tests/test_trace.py tests/test_behavior.py tests/test_config.py::TestCLIPolicyBoundaries tests/test_cli_providers.py::TestProviderSelectionBoundaries -x`
- Per wave merge: `python -m pytest tests/ -x --timeout=60`
- Phase gate: full suite green before `/gsd-verify-work`

---

## Risks and Unknowns

### RISK-01 (Medium): Template method rename touches many files
Renaming `probe()` → `_do_probe()` across 4 provider files and updating ~15 test methods is mechanical but high-surface. A missed rename causes `AttributeError` at runtime (easy to catch in tests). Mitigation: do it in a single atomic Wave 0 task before any other implementation.

### RISK-02 (High): D-05 conflicts with existing runner.run_analysis()
`runner.run_analysis()` currently returns `int`. Changing it breaks `__main__.py` and 4 test_cli.py tests. The CONTEXT.md D-05 description must be interpreted as either:
- A new `VulnerabilityAnalyzer.run_analysis()` method (does not exist yet — safe to create), OR
- A change to `runner._analyze_files()` (private, internal — caller can adapt)

**Decision required before Wave 1:** Planner must choose. Recommend option A (new VulnerabilityAnalyzer method) as it avoids touching runner.py's public API.

### RISK-03 (Low): CLIPolicy validation scope
D-12 boundary tests for invalid values are currently unverifiable without adding validation code first. The planner must explicitly include a "add CLIPolicy.__post_init__ validation" task in the same wave as the boundary test task. If omitted, the tests will assert behavior (silent accept) that may conflict with future validation intent.

### RISK-04 (Low): duration_ms in tool_call events
`MCPAnalysisHelper.execute_tool_calls()` is async. `time.monotonic()` works in async context but the blocked-tool path skips the actual call. Blocked tools should emit `duration_ms=0`. This is a minor schema consistency issue with no functional impact.

### RISK-05 (Low): tracer propagation chain
`VulnerabilityAnalyzer` constructs `MCPAnalysisHelper` externally (in `runner.py`) and receives it via `mcp_helper=` injection. The tracer must be injected into `MCPAnalysisHelper` at construction time in `runner.py`, not inside `VulnerabilityAnalyzer`. This means `runner.py` must thread the tracer through both `VulnerabilityAnalyzer(tracer=tracer)` and `MCPAnalysisHelper(tracer=tracer)`. The planner must add both injection sites in the same task.

### RISK-06 (Low): TestProviderSelectionBoundaries and probe mocking
D-13 requires testing `CLIBinaryNotFoundError` and `CLIAuthError` from a mocked probe. However, `initialize_llm()` in runner.py does NOT call `probe()` — it only constructs the provider. The probe is called in `_check_cli_provider_capabilities()` (runner.py ~line 370). The boundary tests for "CLI provider with `binary_found=False`" must target `_check_cli_provider_capabilities()` or test the probe path directly, not `initialize_llm()`.

---

## RESEARCH COMPLETE

**Phase:** 8 — Behavioral Evaluation & Trace Capture
**Confidence:** HIGH

### Key Findings

1. **Template method is the right probe hook** — rename abstract `probe()` to `_do_probe()`, 5 concrete impls to update, zero subclass `super()` calls required
2. **D-05 conflicts with existing runner.run_analysis()** — must be resolved as a new `VulnerabilityAnalyzer` method or private helper; planner decision required before Wave 1
3. **CLIPolicy.from_dict() silently accepts all values** — no validation today; Phase 8 must add it (small `__post_init__`) before boundary tests are meaningful
4. **`FallbackLLM._diagnostics` already has all D-03 fields** — emit just needs to mirror the append call with `tracer.emit()`
5. **No circular import risk** — `trace.py` is stdlib-only, safe to import from any layer

### File Created
`.planning/phases/08-behavioral-evaluation-trace-capture/08-RESEARCH.md`

### Confidence Assessment

| Area | Level | Reason |
|------|-------|--------|
| Probe hook pattern | HIGH | Direct code inspection of abstract method and all 4 concrete impls |
| run_analysis() conflict | HIGH | Verified runner.py signature and all test_cli.py callers |
| CLIPolicy validation behavior | HIGH | Read all from_dict() branches; no validation code found |
| FallbackLLM wiring | HIGH | Read full chat() method; _diagnostics fields match D-03 exactly |
| MCP tool_call site | HIGH | Read execute_tool_calls() in full; duration_ms is the only addition needed |
| Import boundary | HIGH | Traced all vulnhuntr.core imports across affected modules |

### Open Questions

1. **D-05 resolution** — Should `run_analysis(...)` returning `tuple[list[AnalysisResult], ExecutionTracer | None]` be a new `VulnerabilityAnalyzer` method, or should `runner._analyze_files()` be modified? Planner decides.
2. **Blocked-tool trace emission** — Should blocked MCP tool calls emit a `tool_call` event? Recommend yes (with `duration_ms=0, error="blocked by policy"`) but not locked by CONTEXT.md.
3. **session_decision emit site** — `send_message()` in `ClaudeCodeLLM` currently applies session flags but emits no event. The emit should go in `send_message()` immediately after the session-mode branch adds flags to `cmd`. Only `ClaudeCodeLLM` needs this in Phase 8; other providers don't have session-mode flag logic yet.

### Ready for Planning
Research complete. Planner can now create PLAN.md files for all three workstreams: trace module + wiring, behavioral tests, and boundary tests.
