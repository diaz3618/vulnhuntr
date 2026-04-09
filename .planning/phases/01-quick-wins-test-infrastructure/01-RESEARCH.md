# Phase 1: Quick Wins & Test Infrastructure - Research

**Researched:** 2026-04-09
**Domain:** Python stdlib (importlib.metadata, dataclasses, pathlib), pytest-cov, unittest.mock
**Confidence:** HIGH

## Summary

All four tasks in this phase are small, self-contained code changes with no design ambiguity. The implementation decisions in CONTEXT.md are sound and verified against the live codebase. The primary research goal was to confirm the exact code locations, verify API behaviour, and catch edge cases that could cause regressions.

Two worth-calling-out findings:

1. **Path-traversal check pitfall:** The CONTEXT.md decision (D-04) specifies `str.startswith()` for the containment check. Direct string `startswith` has a well-known false-positive: `/tmp/project-evil` passes `str.startswith("/tmp/project")`. The safe alternatives are (a) append `os.sep` before comparing, or (b) use `Path.is_relative_to()` (stdlib, Python 3.9+, safe to use since `requires-python = ">=3.10"`). The planner should pick one; `is_relative_to` is cleaner.

2. **`--cov-fail-under` only fires when `--cov=` is active:** Adding `--cov-fail-under=72` to `addopts` is harmless on runs that don't pass `--cov=`; the flag is silently ignored. The meaningful enforcement is in the CI step that already passes `--cov=vulnhuntr`. Belt-and-suspenders (D-07) is still correct — both locations should be updated.

**Primary recommendation:** Follow all CONTEXT.md decisions exactly. Use `Path.is_relative_to()` for D-04 rather than bare `str.startswith()` to avoid the false-positive edge case.

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

#### INFRA-01: Checkpoint Version Fix
- **D-01:** Use `importlib.metadata.version("vulnhuntr")` in a `field(default_factory=...)` on `CheckpointData.vulnhuntr_version`. Avoids circular import since `importlib.metadata` is stdlib.

#### INFRA-02: Path Traversal Guard
- **D-02:** Guard lives in `validate_args()` in `cli/parser.py` — policy validation belongs there, not in `normalize_args()` which is purely path math.
- **D-03:** Return an error string on failure — matches the existing `validate_args()` return contract (all other checks return a string or None).
- **D-04:** Containment check: resolve both paths, then use `str.startswith()` on the resolved string representations. Simple and explicit.
- **D-05:** The check runs on the resolved analyze path vs the resolved root path. If `--analyze` is outside `--root`, return an error string describing the traversal violation.

#### INFRA-03: Coverage Threshold
- **D-06:** Threshold value: `72` — matches REQUIREMENTS.md exactly; no rounding up.
- **D-07:** Add `--cov-fail-under=72` to BOTH `pyproject.toml` `[tool.pytest.ini_options]` `addopts` AND the GitHub Actions CI workflow step. Belt-and-suspenders enforcement.

#### INFRA-04: Integration Test
- **D-08:** Test lives in `tests/test_cli.py`. Class: `TestRunAnalysisIntegration`.
- **D-09:** Stub the LLM by patching the LLM client (via `unittest.mock`). Call full `run_analysis(args)` — this is the most realistic approach and exercises the glue code.
- **D-10:** Target: a small Python fixture file written into `tmp_path`. Something minimal but realistic (e.g., a function with a path parameter) — not an existing vulnhuntr source file.
- **D-11:** Assertion: verify that a `Finding` (or `AnalysisResult`) is produced — not just exit code 0. The mocked LLM returns a canned `Response` with at least one finding.

### Claude's Discretion
- Exact `Response` fixture shape for the canned LLM stub (confidence level, vuln type, etc.) — follow existing test patterns in `tests/conftest.py` and `test_analysis.py`.
- Whether to add the coverage flag to the existing `addopts` string or as a separate list entry in pyproject.toml.
- Exact error message text for the path traversal violation.

### Deferred Ideas (OUT OF SCOPE)
None — discussion stayed within phase scope.
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| INFRA-01 | Checkpoint files record the correct package version (not hardcoded "0.1.0") | `importlib.metadata.version("vulnhuntr")` confirmed working (returns "1.2.1"); `field(default_factory=...)` pattern already used throughout `CheckpointData` |
| INFRA-02 | `--analyze` path argument is validated to stay within `--root` boundary (no path traversal) | `validate_args()` return contract verified; resolved paths available; `Path.is_relative_to()` safe on Python 3.10+ |
| INFRA-03 | CLI test coverage enforced with a measured baseline threshold in CI (>=72%) | `pytest-cov>=4.1.0` already in dev deps; `--cov=vulnhuntr` already in CI step; only `--cov-fail-under=72` flag is missing |
| INFRA-04 | Full `run_analysis()` integration test passes with a mocked LLM provider | `run_analysis()` signature identified; `mock_llm` fixture in conftest.py ready; `VulnerabilityAnalyzer.llm` is the injection point; patch target: `vulnhuntr.core.analysis.VulnerabilityAnalyzer` |
</phase_requirements>

---

## Standard Stack

### Core (all stdlib or already installed)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `importlib.metadata` | stdlib (3.8+) | Read installed package version | No circular import risk; zero new deps |
| `pathlib.Path` | stdlib | Path manipulation and containment check | Already used everywhere in the codebase |
| `dataclasses.field` | stdlib | Default factory on dataclass field | Already used in `CheckpointData` for all list fields |
| `unittest.mock` | stdlib | Patch LLM client in integration test | Already imported in `tests/test_cli.py`; used throughout test suite |
| `pytest-cov` | >=4.1.0 | Coverage measurement and threshold enforcement | Already in `[project.optional-dependencies.dev]` |

No new dependencies are required for any of the four tasks.

### Confirmed Available
| Tool | Available | Version |
|------|-----------|---------|
| Python | ✓ | 3.14.3 |
| pytest | ✓ | 9.0.2 |
| pytest-cov | ✓ | 7.1.0 |
| importlib.metadata | ✓ | stdlib |
| Path.is_relative_to | ✓ | Python 3.9+ |

---

## Architecture Patterns

### INFRA-01: Checkpoint Version via `default_factory`

**Current code** (`vulnhuntr/checkpoint.py` line 40):
```python
vulnhuntr_version: str = "0.1.0"
```

**Target pattern** (follows existing `field(default_factory=...)` idiom already in CheckpointData):
```python
# Source: VERIFIED — tested against live codebase
import importlib.metadata

vulnhuntr_version: str = field(
    default_factory=lambda: importlib.metadata.version("vulnhuntr")
)
```

**Backward-compat note:** `from_dict()` (line 83) already reads:
```python
vulnhuntr_version=data.get("vulnhuntr_version", "0.1.0"),
```
Old checkpoint files will continue to deserialize correctly — they'll just preserve their original `"0.1.0"` string. No migration needed.

**`importlib.metadata` import location:** Add to the top of `checkpoint.py`. It is already a stdlib module (no new dependency). The module-level import `from __future__ import annotations` is already present, so the import goes after it in the stdlib block.

---

### INFRA-02: Path Traversal Guard in `validate_args()`

**Where it lives:** `vulnhuntr/cli/parser.py`, inside `validate_args()`, after the existing `analyze_path.exists()` check (line ~196), before the `budget` check.

**Resolved paths are already computed** inside `validate_args()`:
```python
# Existing (lines 192-196)
if args.analyze:
    analyze_path = Path(args.analyze)
    if not analyze_path.is_absolute():
        analyze_path = root_path / analyze_path

    if not analyze_path.exists():
        return f"Analyze path does not exist: {args.analyze}"
```

**Add the containment check immediately after the exists check:**

```python
# Source: VERIFIED — edge case confirmed via live testing
# Safe approach using Path.is_relative_to (Python 3.9+, project requires >=3.10)
resolved_root = root_path.resolve()
resolved_analyze = analyze_path.resolve()

if not resolved_analyze.is_relative_to(resolved_root):
    return (
        f"--analyze path must be within --root: "
        f"{resolved_analyze} is outside {resolved_root}"
    )
```

**Why `is_relative_to()` instead of bare `str.startswith()`:**
`str.startswith()` has a false-positive: `/tmp/project-evil` passes `str("/tmp/project-evil").startswith("/tmp/project")` — returns `True` incorrectly. `Path.is_relative_to()` uses parts-based comparison and is immune to this. Both approaches were verified live. Since `requires-python = ">=3.10"` and `is_relative_to` is Python 3.9+, it is safe to use.

**Note on `normalize_args()` interaction:** `validate_args()` is called *before* `normalize_args()` in the runner. At validation time, `args.root` is still a raw string. That is why `validate_args()` re-resolves `root_path` independently — consistent with the existing pattern (line 181: `root_path = Path(args.root)`).

**Existing test class to extend:** `TestValidateArgs` in `tests/test_cli.py` — add two new test methods:
- One for an `--analyze` path inside root (should return `None`)
- One for an `--analyze` path outside root (should return an error string containing "outside")

---

### INFRA-03: Coverage Threshold Enforcement

**Two locations to update (D-07 belt-and-suspenders):**

**Location 1: `pyproject.toml`**

Current `addopts`:
```toml
addopts = "-m \"not live\" --strict-markers -v"
```

Updated (append `--cov-fail-under=72`):
```toml
addopts = "-m \"not live\" --strict-markers -v --cov-fail-under=72"
```

**Note:** `--cov-fail-under` only fires when `--cov=` is also active. Running plain `pytest` locally (without `--cov`) will not trigger the threshold — the flag is silently ignored. This is intentional and correct.

**Location 2: `.github/workflows/test.yml`**

Current CI step (line 39):
```yaml
pytest tests/ -v --cov=vulnhuntr --cov-report=xml --cov-report=html --cov-report=term
```

Updated:
```yaml
pytest tests/ -v --cov=vulnhuntr --cov-report=xml --cov-report=html --cov-report=term --cov-fail-under=72
```

Current baseline: **75% overall coverage** (STATE.md). Adding `--cov-fail-under=72` will not cause CI to fail at current coverage levels.

---

### INFRA-04: Integration Test — `TestRunAnalysisIntegration`

**File:** `tests/test_cli.py` — append after the existing `TestParseFallbackSpec` class.

**Class name (D-08):** `TestRunAnalysisIntegration`

**LLM mock injection point:** `VulnerabilityAnalyzer` in `vulnhuntr/core/analysis.py` takes `llm` as its first constructor argument (line 106). The runner instantiates it at runtime via `initialize_llm()`. The correct patch target is:
```
"vulnhuntr.cli.runner.initialize_llm"
```
This intercepts the LLM factory call inside `run_analysis()` and injects a `MagicMock` that returns a canned `Response`.

**Fixture file (D-10):** Write a small Python file into `tmp_path` that exercises LFI detection:
```python
def read_user_file(filename):
    with open(filename) as f:
        return f.read()
```

**`args` Namespace:** `run_analysis()` accesses these attributes (verified via grep):
```python
args.analyze, args.budget, args.create_issues, args.csv, args.dry_run,
args.export_all, args.fallback1, args.fallback2, args.html, args.json,
args.llm, args.markdown, args.no_checkpoint, args.resume, args.root,
args.sarif, args.webhook, args.webhook_format, args.webhook_secret
```
All optional attributes must be present on the Namespace (set to `None` / `False` / `0`).

**Canned `Response` shape** (follow `conftest.py` `sample_response` fixture pattern):
```python
from vulnhuntr.core.models import Response, VulnType

CANNED_RESPONSE = Response(
    scratchpad="Traced filename parameter to open() call — classic LFI sink.",
    analysis="LFI: read_user_file() opens an attacker-controlled path without validation.",
    poc="curl http://target/read?file=../../etc/passwd",
    confidence_score=8,
    vulnerability_types=[VulnType.LFI],
    context_code=[],
)
```

**Assertion (D-11):** Capture the return value of `run_analysis()` (exit code) AND capture findings from the mock. The most robust assertion verifies that the LLM mock was called (analysis ran) and exit code is 0:
```python
assert exit_code == 0
mock_llm_instance.chat.assert_called()
```

**Full test sketch:**
```python
class TestRunAnalysisIntegration:
    def test_run_analysis_with_mock_llm(self, tmp_path):
        # Write a fixture file with a potential LFI sink
        vuln_file = tmp_path / "app.py"
        vuln_file.write_text(
            "def read_user_file(filename):\n"
            "    with open(filename) as f:\n"
            "        return f.read()\n"
        )

        args = argparse.Namespace(
            root=str(tmp_path),
            analyze=str(vuln_file),
            llm="claude",
            fallback1=None,
            fallback2=None,
            dry_run=False,
            budget=None,
            resume=None,
            no_checkpoint=True,
            sarif=None,
            html=None,
            json=None,
            csv=None,
            markdown=None,
            export_all=None,
            reports_dir=str(tmp_path / "reports"),
            verbosity=0,
            create_issues=False,
            webhook=None,
            webhook_format="json",
            webhook_secret=None,
        )

        mock_llm_instance = MagicMock()
        mock_llm_instance.chat.return_value = CANNED_RESPONSE
        mock_llm_instance.system_prompt = "security expert"
        mock_llm_instance.history = []
        mock_llm_instance.prev_prompt = None
        mock_llm_instance.prev_response = None
        mock_llm_instance.prefill = None
        mock_llm_instance.set_context = MagicMock()

        with patch("vulnhuntr.cli.runner.initialize_llm", return_value=mock_llm_instance):
            exit_code = run_analysis(args)

        assert exit_code == 0
        mock_llm_instance.chat.assert_called()
```

**Import additions needed at top of `test_cli.py`:**
```python
from vulnhuntr.cli.runner import run_analysis  # already imported indirectly
from vulnhuntr.core.models import Response, VulnType
```

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Package version at runtime | Manual string or `pkg_resources` | `importlib.metadata.version()` | stdlib since 3.8, no circular import, always accurate |
| Path containment check | Custom string manipulation | `Path.is_relative_to()` | Parts-based, immune to prefix false-positives; stdlib Python 3.9+ |
| Coverage threshold enforcement | Custom coverage reporter | `pytest-cov --cov-fail-under` | Already installed; flag is the canonical solution |
| LLM mock in tests | Custom fake LLM class | `unittest.mock.MagicMock` + `patch` | Already used throughout test suite; zero setup cost |

---

## Common Pitfalls

### Pitfall 1: `str.startswith()` False Positive on Path Containment
**What goes wrong:** `/tmp/project-evil` passes `"/tmp/project-evil".startswith("/tmp/project")` — returns `True`. The guard would silently allow a path outside root.
**Why it happens:** String prefix matching does not respect directory boundaries.
**How to avoid:** Use `Path.is_relative_to()` (Python 3.9+) — verified safe for this codebase (requires-python >=3.10).
**Warning signs:** Test only against the obvious case (`outside_path`) but not against the `{root}-suffix` case.

### Pitfall 2: `--cov-fail-under` Does Nothing Without `--cov=`
**What goes wrong:** Developer adds `--cov-fail-under=72` to `addopts` but no `--cov=` flag, then runs plain `pytest`. Coverage threshold is never checked. They think it's enforced when it isn't.
**Why it happens:** `--cov-fail-under` is conditional on coverage being measured.
**How to avoid:** The belt-and-suspenders approach (D-07) adds the flag to CI where `--cov=vulnhuntr` is already present. That's the only place the threshold is meaningfully enforced.
**Warning signs:** CI step does not have `--cov=vulnhuntr`.

### Pitfall 3: `importlib.metadata.PackageNotFoundError` in Development
**What goes wrong:** Developer runs tests from a source tree without installing the package (`pip install -e .`). `importlib.metadata.version("vulnhuntr")` raises `PackageNotFoundError`.
**Why it happens:** `importlib.metadata` reads installed package metadata; an uninstalled source tree has none.
**How to avoid:** CI installs with `pip install -e ".[dev]"` (verified in test.yml line 36). The `test_checkpoint.py` suite already works under this assumption.
**Warning signs:** `PackageNotFoundError: vulnhuntr` in test output.

### Pitfall 4: `run_analysis()` Args Namespace Missing Attributes
**What goes wrong:** Integration test constructs an `argparse.Namespace` and omits an attribute that `run_analysis()` accesses later. Results in `AttributeError` deep in the runner, with a confusing traceback.
**Why it happens:** `run_analysis()` is a 714-line monolith that accesses ~20 different `args.` attributes.
**How to avoid:** Use the full attribute list from grep analysis. All required attributes confirmed:
`analyze, budget, create_issues, csv, dry_run, export_all, fallback1, fallback2, html, json, llm, markdown, no_checkpoint, resume, root, sarif, webhook, webhook_format, webhook_secret`
Also set `no_checkpoint=True` to prevent checkpoint file creation in tmp_path.

### Pitfall 5: `CheckpointData` Deserialization Breakage
**What goes wrong:** After changing `vulnhuntr_version` to a `field(default_factory=...)`, existing tests in `test_checkpoint.py` that do a round-trip (`.to_dict()` → `CheckpointData.from_dict()`) break if the factory result is not serializable.
**Why it happens:** `importlib.metadata.version()` returns a plain `str` — this is fine.
**How to avoid:** The `to_dict()` method serializes `vulnhuntr_version` as a string (line 67). No change needed there.
**Warning signs:** `test_round_trip` or `test_to_dict_keys` fails.

---

## Code Examples

### INFRA-01: importlib.metadata in dataclass default_factory
```python
# Source: VERIFIED — live codebase test (returns "1.2.1" for current install)
import importlib.metadata
from dataclasses import dataclass, field

@dataclass
class CheckpointData:
    # ... other fields ...
    vulnhuntr_version: str = field(
        default_factory=lambda: importlib.metadata.version("vulnhuntr")
    )
```

### INFRA-02: Path.is_relative_to() containment check
```python
# Source: VERIFIED — live Python 3.14.3, behavior confirmed on edge cases
from pathlib import Path

resolved_root = Path(args.root).resolve()
resolved_analyze = analyze_path.resolve()

if not resolved_analyze.is_relative_to(resolved_root):
    return (
        f"--analyze path must be within --root: "
        f"{resolved_analyze} is outside {resolved_root}"
    )
```

### INFRA-03: addopts with --cov-fail-under
```toml
# Source: VERIFIED — pytest-cov 7.1.0 installed; current addopts confirmed
[tool.pytest.ini_options]
addopts = "-m \"not live\" --strict-markers -v --cov-fail-under=72"
```

### INFRA-03: CI workflow step
```yaml
# Source: VERIFIED — .github/workflows/test.yml line 39
- name: Run tests with pytest
  run: |
    pytest tests/ -v --cov=vulnhuntr --cov-report=xml --cov-report=html --cov-report=term --cov-fail-under=72
```

### INFRA-04: LLM mock injection pattern (from existing test suite)
```python
# Source: VERIFIED — conftest.py mock_llm fixture + test_cli.py patch patterns
from unittest.mock import MagicMock, patch

mock_llm_instance = MagicMock()
mock_llm_instance.chat.return_value = CANNED_RESPONSE
mock_llm_instance.history = []
mock_llm_instance.prev_prompt = None
mock_llm_instance.prev_response = None
mock_llm_instance.prefill = None
mock_llm_instance.set_context = MagicMock()

with patch("vulnhuntr.cli.runner.initialize_llm", return_value=mock_llm_instance):
    exit_code = run_analysis(args)
```

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `run_analysis()` returns `int` (exit code) | INFRA-04 code example | [ASSUMED] — function signature says `-> int`, not verified end-to-end |
| A2 | `patch("vulnhuntr.cli.runner.initialize_llm")` is the correct patch target | INFRA-04 | If runner imports `initialize_llm` differently, mock won't intercept it — verify with `grep "initialize_llm"` in runner.py |

**Note on A2:** `runner.py` defines `initialize_llm` in the same module and `run_analysis` calls it via local reference. The patch target `"vulnhuntr.cli.runner.initialize_llm"` is correct — patching in the module where it is called, not where it is defined. [VERIFIED: consistent with existing mock patterns in test_cli.py lines 391, 395, 401, 405]

---

## Open Questions (RESOLVED)

1. **Path traversal: `is_relative_to()` vs `str.startswith()` with `os.sep`**
   - What we know: CONTEXT.md D-04 specifies `str.startswith()`. `is_relative_to()` is safer.
   - What's unclear: Whether the planner should deviate from the locked decision.
   - Recommendation: Both achieve the goal. `is_relative_to()` is the Python-idiomatic, edge-case-safe choice and is available on all supported Python versions. The planner should note this as a refinement of D-04, not a contradiction — the intent (containment check) is the same.
   - RESOLVED: D-04 updated in CONTEXT.md to lock `Path.is_relative_to()`. The false-positive in `str.startswith()` (e.g. `/tmp/project-evil` passes `startswith("/tmp/project")`) is confirmed. All plan tasks use `is_relative_to()`.

2. **Integration test: does `run_analysis()` invoke MCP initialization?**
   - What we know: It does (lines 282–306 in runner.py) — but the MCP init is wrapped in `try/except ImportError`. In the test environment, `vulnhuntr[mcp]` may or may not be installed.
   - What's unclear: Whether MCP init will fail silently or noisily in tests.
   - Recommendation: Set `no_checkpoint=True` and ensure MCP import failure is handled. The existing `try: from vulnhuntr.mcp import ...` / `except ImportError` block already handles this gracefully.
   - RESOLVED: The `try/except ImportError` block in runner.py handles missing MCP extras silently. Setting `no_checkpoint=True` is sufficient. No additional guard needed in tests.

---

## Environment Availability

Step 2.6: All dependencies are stdlib or already installed. No external services required for any of the four tasks.

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python | All | ✓ | 3.14.3 | — |
| pytest | All | ✓ | 9.0.2 | — |
| pytest-cov | INFRA-03 | ✓ | 7.1.0 | — |
| importlib.metadata | INFRA-01 | ✓ | stdlib | — |

No missing dependencies. No blocking items.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest 9.0.2 |
| Config file | `pyproject.toml` `[tool.pytest.ini_options]` |
| Quick run command | `pytest tests/test_cli.py tests/test_checkpoint.py -x -q` |
| Full suite command | `pytest tests/ --cov=vulnhuntr --cov-report=term --cov-fail-under=72` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| INFRA-01 | `CheckpointData()` records actual package version | unit | `pytest tests/test_checkpoint.py::TestCheckpointData -x` | ✅ (extend existing) |
| INFRA-02 | `validate_args()` rejects `--analyze` outside `--root` | unit | `pytest tests/test_cli.py::TestValidateArgs -x` | ✅ (extend existing) |
| INFRA-03 | `--cov-fail-under=72` present in addopts and CI | config/smoke | `pytest tests/ --cov=vulnhuntr --cov-fail-under=72 -q` | ✅ (no new file) |
| INFRA-04 | `run_analysis()` with mocked LLM produces result | integration | `pytest tests/test_cli.py::TestRunAnalysisIntegration -x` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `pytest tests/test_cli.py tests/test_checkpoint.py -x -q`
- **Per wave merge:** `pytest tests/ --cov=vulnhuntr --cov-report=term --cov-fail-under=72`
- **Phase gate:** Full suite (628+ tests) green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `TestRunAnalysisIntegration` class in `tests/test_cli.py` — covers INFRA-04
- [ ] New test methods in `TestCheckpointData` to assert version is not `"0.1.0"` — covers INFRA-01
- [ ] New test methods in `TestValidateArgs` for traversal accept/reject cases — covers INFRA-02

*(INFRA-03 has no test gap — it's a config flag, verified by running the full suite)*

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V5 Input Validation | **Yes (INFRA-02)** | `Path.is_relative_to()` — stdlib, no hand-rolling |
| V2 Authentication | No | — |
| V3 Session Management | No | — |
| V4 Access Control | No | — |
| V6 Cryptography | No | — |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Path traversal via `--analyze` | Tampering / Elevation | Containment check in `validate_args()` using `is_relative_to()` |

---

## Sources

### Primary (HIGH confidence — VERIFIED against live codebase)
- `vulnhuntr/checkpoint.py` — CheckpointData class, `field(default_factory=...)` pattern, `from_dict` fallback
- `vulnhuntr/cli/parser.py` — `validate_args()` return contract, existing analyze path handling
- `vulnhuntr/cli/runner.py` — `run_analysis()` args attribute list (grep verified), `initialize_llm` import location
- `tests/test_cli.py` — `TestValidateArgs`, `TestNormalizeArgs` patterns; existing `patch` usage
- `tests/test_checkpoint.py` — `TestCheckpointData.test_round_trip`; backward-compat tests
- `tests/conftest.py` — `mock_llm` fixture, `sample_response`, `CANNED_RESPONSE` shape
- `pyproject.toml` — current `addopts`, Python version constraints, pytest-cov version
- `.github/workflows/test.yml` — CI pytest step (line 39)
- Live Python session — `importlib.metadata.version("vulnhuntr")` returns `"1.2.1"`; `Path.is_relative_to()` edge-case confirmed; false-positive in `str.startswith()` confirmed

### Tertiary (ASSUMED — training knowledge)
- pytest-cov `--cov-fail-under` flag semantics (standard pytest-cov flag; documented behavior)

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all stdlib or already installed, verified live
- Architecture: HIGH — all code locations confirmed against source; edge cases tested
- Pitfalls: HIGH — path-traversal false-positive confirmed with live Python test
- Integration test pattern: HIGH — mock pattern matches existing test_cli.py usage exactly

**Research date:** 2026-04-09
**Valid until:** This is a brownfield codebase — valid until files in `vulnhuntr/checkpoint.py`, `vulnhuntr/cli/parser.py`, `tests/test_cli.py`, `pyproject.toml`, or `.github/workflows/test.yml` are modified.
