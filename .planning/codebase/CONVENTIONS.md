# Coding Conventions

**Analysis Date:** 2026-04-08

## Naming Patterns

**Files:**
- `snake_case.py` — all module files (e.g., `symbol_finder.py`, `cost_tracker.py`, `github_issues.py`)
- `test_<module>.py` — test files mirror source module names

**Functions:**
- `snake_case` — all function and method names (e.g., `get_relevant_py_files`, `analyze_file`, `track_call`)
- Private methods prefixed with `_` (e.g., `_validate_response`, `_extract_usage`, `_log_response`)
- Async functions follow same pattern (e.g., `connect_all`, `_connect_server`)

**Variables:**
- `snake_case` for all variables and parameters
- Constants: `UPPER_SNAKE_CASE` (e.g., `PRICING_TABLE`, `DEFAULT_PRICING`, `GITHUB_API_BASE`, `MAX_TOOL_RESULT_CHARS`)

**Types/Classes:**
- `PascalCase` for all classes (e.g., `VulnerabilityAnalyzer`, `SymbolExtractor`, `CostTracker`)
- `PascalCase` for Pydantic models (e.g., `Response`, `ContextCode`, `MCPServerConfig`)
- `PascalCase` for enums and dataclasses (e.g., `VulnType`, `FindingSeverity`, `CheckpointData`)

**Exceptions:**
- `PascalCase` ending with `Error` where applicable (e.g., `LLMError`, `RateLimitError`, `APIConnectionError`)

## Code Style

**Formatting:**
- Tool: `ruff format` (configured in `pyproject.toml`)
- Line length: 120 characters (`line-length = 120`)

**Linting:**
- Tool: `ruff check` (configured in `pyproject.toml`)
- Selected rules: `E` (pycodestyle), `F` (pyflakes), `I` (isort), `N` (pep8-naming), `W` (warnings), `UP` (pyupgrade)
- Ignored: `E501` (line length — handled by formatter, often too strict for docstrings/URLs)
- Target: `py310` (uses `pyupgrade` to enforce modern syntax)

**Type checking:**
- Tool: `mypy` (non-strict mode)
- Python version: 3.10
- Key settings: `disallow_untyped_defs = false`, `warn_return_any = false`, `ignore_missing_imports = true`
- `type: ignore[...]` used minimally in a few places (e.g., `requests` import guards, `openai` overloads)

## Import Organization

**Standard pattern (all files):**
```python
from __future__ import annotations  # ← ALWAYS first line in source files

import json                          # stdlib
import os
from pathlib import Path

import structlog                     # third-party
from pydantic import BaseModel

from vulnhuntr.core.models import Response  # local package
```

**Order:**
1. `from __future__ import annotations` (mandatory in all `.py` source files)
2. stdlib imports (alphabetical)
3. Third-party imports (alphabetical)
4. Local package imports (`from vulnhuntr.*`)

**Lazy / optional imports:**
- Optional dependencies (e.g., `requests`, `yaml`, `mcp`) are guarded with `try/except ImportError`
- The guard sets a boolean flag (e.g., `REQUESTS_AVAILABLE = True`) and a log warning on failure
- Example pattern from `vulnhuntr/integrations/github_issues.py`:
  ```python
  try:
      import requests
      REQUESTS_AVAILABLE = True
  except ImportError:
      REQUESTS_AVAILABLE = False
  ```

**TYPE_CHECKING imports:**
- Used in `vulnhuntr/core/analysis.py` to break circular imports:
  ```python
  from typing import TYPE_CHECKING
  if TYPE_CHECKING:
      from ..llms import ChatGPT, Claude, Ollama
  ```

## Error Handling

**Patterns:**
- LLM layer: typed exception hierarchy (`LLMError` → subclasses) raised from provider clients
- All LLM errors propagate to the caller; no silent swallowing at provider level
- CLI runner: top-level `except Exception` logs via structlog and returns non-zero exit code
- Soft-dependency failures: logged as warnings, raise `ImportError` or `RuntimeError` at call site

## Logging

**Framework:** `structlog` (JSON renderer, configured in `__main__.py`)

**Patterns:**
- Always use `log = structlog.get_logger()` or `log = structlog.get_logger(__name__)` at module level
- Log structured key-value pairs, not f-string messages:
  ```python
  log.debug("Connecting to MCP server", server=name, transport=transport)
  log.error("Failed to connect MCP server", server=name, error=str(outcome))
  ```
- Use `log.warning()` for recoverable issues, `log.error()` for failures, `log.debug()` for tracing

## Comments

**When to Comment:**
- Complex algorithms and edge cases (e.g., `SymbolExtractor.extract()` documents known edge cases inline)
- Non-obvious design decisions at class/method level
- Known limitations or corner cases

**Docstrings:**
- All public classes and methods have Google-style docstrings with `Args:`, `Returns:`, `Raises:`
- `Example:` blocks used for classes frequently (e.g., `VulnerabilityAnalyzer`, `CostTracker`, `RepoOps`)

## Function Design

**Size:** No strict limit; `runner.py` has large functions due to orchestration complexity
**Parameters:** Constructor injection preferred for dependencies (LLM, extractor passed to `VulnerabilityAnalyzer.__init__`)
**Return Values:**
- Prefer typed returns; use `None` for void
- Optional values: `X | None` (Python 3.10+ union syntax, enabled by `from __future__ import annotations`)

## Module Design

**Exports:**
- Each sub-package `__init__.py` re-exports public symbols explicitly
- Root `__init__.py` defines `__all__` with complete public API

**Barrel Files:**
- Used: `vulnhuntr/__init__.py`, `vulnhuntr/cli/__init__.py`, `vulnhuntr/core/__init__.py`, `vulnhuntr/reporters/__init__.py`
- All use explicit import lists — no wildcard re-exports

## Dataclass vs Pydantic

**Use Pydantic `BaseModel` for:**
- All LLM input/output schemas (`Response`, `ContextCode`, `MCPToolCallRequest`, etc.)
- MCP server/settings config (`MCPServerConfig`, `MCPSettings`)

**Use `@dataclass` for:**
- Internal data containers not validated from external input (`FindingResult`, `CheckpointData`, `VulnhuntrConfig`, `GitHubConfig`, `WebhookConfig`)
- Value objects with `to_dict()` / `from_dict()` for JSON serialization

---

*Convention analysis: 2026-04-08*
