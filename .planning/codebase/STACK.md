# Technology Stack

**Analysis Date:** 2026-04-08

## Languages

**Primary:**
- Python 3.10–3.13 — entire codebase (3.14+ explicitly blocked by `requires-python = ">=3.10,<3.14"` due to Jedi/Parso compatibility)

## Runtime

**Environment:**
- CPython 3.10–3.13 (pinned in `pyproject.toml`)

**Package Manager:**
- pip / setuptools 70+
- Lockfile: `requirements.txt` present (pinned extras)

## Frameworks

**Core:**
- `pydantic >= 2.8.0` — LLM response validation, config models, MCP config schemas
- `pydantic-xml >= 2.11.0` — XML-based prompt context models (`vulnhuntr/core/xml_models.py`)
- `structlog >= 24.2.0` — structured JSON logging throughout
- `rich >= 13.7.1` — terminal output, progress display
- `jinja2 >= 3.1.0` — prompt template rendering

**Analysis / AST:**
- `jedi >= 0.19.2` — Python symbol resolution for context expansion (`vulnhuntr/symbol_finder.py`)
- `parso >= 0.8.5` — Jedi dependency, Python AST parsing

**Networking:**
- `requests >= 2.32.4` — GitHub API, webhook delivery, OpenRouter/Ollama HTTP calls

**LLM SDKs:**
- `anthropic >= 0.78.0` — Claude provider (`vulnhuntr/llms.py` `Claude` class)
- `openai >= 1.51.2` — ChatGPT and OpenRouter providers (`ChatGPT`, `OpenRouter` classes)

**Dev / Test:**
- `pytest >= 8.0.0` — test runner
- `pytest-asyncio >= 0.23.0` — async test support
- `pytest-cov >= 4.1.0` — coverage reports
- `ruff >= 0.2.0` — linting + formatting
- `mypy >= 1.8.0` — type checking
- `python-semantic-release >= 9.0.0` — versioned releases

**Build:**
- `build >= 1.0.0` + `twine >= 5.0.0` — PyPI packaging

**Optional (extras):**
- `mcp >= 1.0.0` — MCP client support (install via `pip install vulnhuntr[mcp]`)

## Key Dependencies

**Critical:**
- `anthropic` — primary LLM SDK; `Claude` class uses prefill trick to reduce JSON wrapping
- `pydantic` — all LLM output passes through `model_validate_json()`; required for correctness
- `jedi` — powers iterative context expansion (MUST stay ≤ Python 3.13)
- `structlog` — all internal logging uses `structlog.get_logger()`

**Infrastructure:**
- `python-dotenv >= 1.0.0` — loads `.env` at entry point (`__main__.py`)
- `pyyaml >= 6.0.3` — config file parsing (`vulnhuntr/config.py`, `vulnhuntr/mcp/config.py`)

## Configuration

**Environment:**
- `.env` file loaded at startup via `dotenv.load_dotenv()` in `vulnhuntr/__main__.py`
- Key env vars: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_MODEL`, `OPENAI_MODEL`, `OPENROUTER_MODEL`, `OLLAMA_BASE_URL`
- **Note:** Shell env vars override `.env` (standard dotenv behaviour)

**Build:**
- `pyproject.toml` — single source of truth for project metadata, dependencies, tool config
- `setup.cfg` not used; setuptools configured via `pyproject.toml` `[tool.setuptools]`

## Platform Requirements

**Development:**
- Python 3.10–3.13 strictly enforced
- No Node.js or OS-specific dependencies

**Production:**
- Docker image available (`Dockerfile`)
- CI: GitHub Actions (`.github/workflows/`) — test, codeql, semgrep, trivy, publish
- PyPI distribution via `twine`

---

*Stack analysis: 2026-04-08*
