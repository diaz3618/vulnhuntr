# Testing Patterns

**Analysis Date:** 2026-04-08

## Test Framework

**Runner:**
- `pytest >= 8.0.0`
- Config: `pyproject.toml` `[tool.pytest.ini_options]`

**Async support:**
- `pytest-asyncio >= 0.23.0`
- Mode: `asyncio_mode = "auto"` (all async tests run automatically without `@pytest.mark.asyncio`)

**Coverage:**
- `pytest-cov >= 4.1.0`

**Run Commands:**
```bash
pytest                          # Run all non-live tests (default marker filter applied)
pytest -v                       # Verbose output (default in config)
pytest -x                       # Stop on first failure
pytest tests/test_llms.py       # Run single test file
pytest --cov=vulnhuntr --cov-report=html  # Coverage report
```

## Test File Organization

**Location:**
- All tests in top-level `tests/` directory (separate from source)

**Naming:**
- `test_<module>.py` — mirrors source module name
- `test_mcp_client.py`, `test_mcp_config.py`, `test_mcp_analysis.py` — one file per MCP sub-module

**Structure:**
```
tests/
├── conftest.py          # Shared fixtures
├── test_analysis.py     # Core VulnerabilityAnalyzer
├── test_checkpoint.py   # Checkpoint save/load/resume
├── test_cli.py          # Parser + runner
├── test_config.py       # Config loading
├── test_cost_tracker.py # CostTracker + BudgetEnforcer
├── test_integrations.py # GitHub + webhook
├── test_llms.py         # LLM validation pipeline (most comprehensive)
├── test_mcp_analysis.py
├── test_mcp_client.py
├── test_mcp_config.py
├── test_models.py       # Domain models
├── test_prompts.py      # Prompt templates
├── test_reporters.py    # All reporter formats
├── test_repo.py         # RepoOps file discovery
├── test_symbol_finder.py # SymbolExtractor
├── test_xml_models.py   # XML prompt wrappers
└── test_results/        # Stored test artifacts (HTML reports, etc.)
```

## Test Structure

**Suite Organization (class-based grouping):**
```python
class TestValidateResponseJSONExtraction:
    """Group related tests under a class with a descriptive docstring."""

    def test_clean_json(self):
        llm = _make_llm()
        result = llm._validate_response(_valid_json(), _Stub)
        assert result.scratchpad == "step 1"

    def test_markdown_wrapped(self):
        raw = "```json\n" + _valid_json() + "\n```"
        result = _make_llm()._validate_response(raw, _Stub)
        assert result.value == 42
```

**Patterns:**
- Classes group related tests (not required — many tests use free functions too)
- No `setup_method` / `teardown_method` in most tests; `tmp_path` fixture used for filesystem
- `pytest.raises` for exception testing
- Private helper functions prefixed with `_` (e.g., `_make_llm()`, `_valid_json()`, `_build_response_json()`)

## Mocking

**Framework:** `unittest.mock` — `MagicMock`, `patch` (no third-party mock library)

**Patterns:**
```python
from unittest.mock import MagicMock, patch

def test_llm_call():
    llm = MagicMock()
    llm.chat.return_value = Response(...)

# Context manager patching
with patch("vulnhuntr.llms.anthropic.Anthropic") as mock_client:
    mock_client.return_value.messages.create.return_value = mock_response
    ...
```

**What to Mock:**
- All LLM API calls (Anthropic, OpenAI clients) — no real network calls in unit tests
- `requests.Session.post` for HTTP integrations
- System-level calls (file system via `tmp_path` fixture, not mocked)

**What NOT to Mock:**
- Pydantic validation — always test real `model_validate_json()`
- `structlog` — let it log normally in tests
- Filesystem operations — use `tmp_path` pytest fixture for temp directories

## Fixtures and Factories

**Key fixtures in `tests/conftest.py`:**
```python
@pytest.fixture()
def tmp_repo(tmp_path):
    """Create minimal Python repo with Flask app for analysis tests."""
    # Creates: README.md, myapp/views.py, myapp/utils.py, tests/test_views.py
    return tmp_path

@pytest.fixture()
def tmp_checkpoint_dir(tmp_path):
    """Clean temp directory for checkpoint files."""
    return tmp_path / "checkpoints"

@pytest.fixture()
def sample_response_json():
    """Valid JSON string matching the Response schema."""
    return _build_response_json()  # helper function in conftest

@pytest.fixture()
def sample_response():
    """Pre-validated Response object."""
    return Response(confidence_score=8, vulnerability_types=["SQLI"], ...)
```

**Factory function pattern (non-fixture helpers):**
```python
def _build_response_json(
    scratchpad="...",
    analysis="...",
    confidence=8,
    vuln_types=None,
) -> str:
    """Return valid JSON string for Response model — used by fixtures."""
    payload = {...}
    return json.dumps(payload)
```

**Location:**
- All shared fixtures in `tests/conftest.py`
- Per-file helpers defined locally with `_` prefix

## Coverage

**Requirements:** Not enforced with `--fail-under` in pyproject.toml

**View Coverage:**
```bash
pytest --cov=vulnhuntr --cov-report=html
# Open htmlcov/index.html
```

## Test Types

**Unit Tests:**
- Most tests — test a single function/class in isolation
- LLM clients mocked, filesystem uses `tmp_path`
- Files: `test_llms.py`, `test_models.py`, `test_cost_tracker.py`, `test_checkpoint.py`, `test_config.py`

**Integration Tests:**
- Tests that exercise multiple components together with test fixtures
- Files: `test_analysis.py`, `test_reporters.py`, `test_integrations.py`

**Live Tests (excluded by default):**
- Tests making real API calls; require API keys
- Marked with `@pytest.mark.live`
- Excluded by default: `addopts = "-m "not live""` in `pyproject.toml`
- Run with: `pytest -m live` (requires credentials)

## Common Patterns

**Async Testing:**
```python
# asyncio_mode = "auto" in pyproject.toml — no decorator needed
async def test_connect_all():
    manager = MCPClientManager(settings)
    result = await manager.connect_all()
    assert result["server_name"] is True
```

**Error Testing:**
```python
def test_raises_on_empty_response():
    llm = LLM()
    with pytest.raises(LLMError, match="empty response"):
        llm._validate_response("", Response)

def test_api_status_error():
    with pytest.raises(APIStatusError) as exc_info:
        ...
    assert exc_info.value.status_code == 429
```

**Filesystem Testing:**
```python
def test_checkpoint_saves(tmp_checkpoint_dir):
    checkpoint = AnalysisCheckpoint(checkpoint_dir=tmp_checkpoint_dir)
    checkpoint.save()
    assert (tmp_checkpoint_dir / "checkpoint.json").exists()
```

---

*Testing analysis: 2026-04-08*
