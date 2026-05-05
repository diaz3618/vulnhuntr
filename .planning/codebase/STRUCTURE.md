# Codebase Structure

**Analysis Date:** 2026-04-08

## Directory Layout

```
vulnhuntr/                    # Project root
├── vulnhuntr/                # Main package (flat layout)
│   ├── __init__.py           # Public API re-exports + __version__
│   ├── __main__.py           # CLI entry point (logging setup, delegates to CLI)
│   ├── llms.py               # LLM provider clients (Claude, ChatGPT, OpenRouter, Ollama)
│   ├── symbol_finder.py      # Jedi-based Python symbol resolver (SymbolExtractor)
│   ├── prompts.py            # Vuln-type-specific prompt templates (string constants)
│   ├── config.py             # YAML config loader (VulnhuntrConfig dataclass)
│   ├── checkpoint.py         # Checkpoint save/resume (AnalysisCheckpoint)
│   ├── cost_tracker.py       # Token usage + cost calculation (CostTracker, BudgetEnforcer)
│   ├── cli/                  # CLI sub-package
│   │   ├── __init__.py       # Re-exports: run_analysis, initialize_llm, get_model_name
│   │   ├── parser.py         # argparse setup + validation
│   │   ├── runner.py         # Full run orchestration (run_analysis function)
│   │   └── output.py         # Rich console display helpers
│   ├── core/                 # Core domain sub-package
│   │   ├── __init__.py       # Re-exports domain types
│   │   ├── models.py         # Domain models: VulnType, Response, ContextCode, LLMUsage
│   │   ├── xml_models.py     # Pydantic-XML prompt context wrappers
│   │   ├── analysis.py       # VulnerabilityAnalyzer (two-phase iterative analysis)
│   │   └── repo.py           # RepoOps (file discovery + network pattern detection)
│   ├── reporters/            # Output format reporters
│   │   ├── __init__.py       # Re-exports all reporters
│   │   ├── base.py           # BaseReporter (ABC), Finding dataclass, FindingSeverity
│   │   ├── html.py           # HTMLReporter (inline Jinja2 template)
│   │   ├── sarif.py          # SARIFReporter (SARIF 2.1.0)
│   │   ├── json_reporter.py  # JSONReporter
│   │   ├── csv_reporter.py   # CSVReporter
│   │   └── markdown_reporter.py  # MarkdownReporter
│   ├── integrations/         # External push integrations (opt-in)
│   │   ├── __init__.py
│   │   ├── github_issues.py  # GitHubIssueCreator (REST API)
│   │   └── webhook.py        # WebhookNotifier (HMAC-signed, multi-format)
│   └── mcp/                  # MCP client sub-package
│       ├── __init__.py
│       ├── config.py         # MCPServerConfig, MCPSettings Pydantic models
│       ├── client.py         # MCPClientManager (async context manager)
│       └── analysis.py       # MCP analysis integration helpers
├── tests/                    # Test suite (co-located at root)
│   ├── conftest.py           # Shared fixtures (tmp_repo, sample_response, etc.)
│   ├── test_llms.py          # LLM validation pipeline tests
│   ├── test_analysis.py      # VulnerabilityAnalyzer tests
│   ├── test_cli.py           # CLI parser + runner tests
│   ├── test_repo.py          # RepoOps tests
│   ├── test_symbol_finder.py # SymbolExtractor tests
│   ├── test_checkpoint.py    # Checkpoint save/load tests
│   ├── test_cost_tracker.py  # CostTracker + BudgetEnforcer tests
│   ├── test_config.py        # Config loading tests
│   ├── test_models.py        # Domain model tests
│   ├── test_prompts.py       # Prompt template tests
│   ├── test_xml_models.py    # XML model tests
│   ├── test_reporters.py     # Reporter output tests
│   ├── test_integrations.py  # GitHub + webhook integration tests
│   ├── test_mcp_*.py         # MCP client/config/analysis tests
│   └── test_results/         # Stored test output artifacts
├── docs/                     # Project documentation
├── .github/                  # GitHub Actions + Copilot config
├── pyproject.toml            # Project metadata, deps, tool config
├── requirements.txt          # Pinned dev dependencies
├── Makefile                  # Dev shortcuts
└── Dockerfile                # Container build
```

## Directory Purposes

**`vulnhuntr/cli/`:**
- Purpose: Everything the user touches directly — argument parsing, execution orchestration, display
- Contains: `create_argument_parser()`, `run_analysis()`, Rich console output helpers
- Key files: `vulnhuntr/cli/runner.py` (714 lines — largest file, complex orchestration)

**`vulnhuntr/core/`:**
- Purpose: Business logic; no direct user I/O
- Contains: The `VulnerabilityAnalyzer`, domain models, file scanner
- Key files: `vulnhuntr/core/analysis.py`, `vulnhuntr/core/models.py`

**`vulnhuntr/reporters/`:**
- Purpose: Output format adapters — each takes a list of `Finding` objects
- Contains: One file per format; all inherit from `BaseReporter`
- Key files: `vulnhuntr/reporters/base.py` (defines `Finding` and `BaseReporter`)

**`vulnhuntr/integrations/`:**
- Purpose: Opt-in outbound push after analysis completes
- Contains: GitHub REST API client, webhook sender

**`vulnhuntr/mcp/`:**
- Purpose: MCP gateway support (standalone client, not yet in main pipeline)
- Key files: `vulnhuntr/mcp/config.py` (Pydantic schemas), `vulnhuntr/mcp/client.py`

## Key File Locations

**Entry Points:**
- `vulnhuntr/__main__.py` — `python -m vulnhuntr` entry; sets up logging + delegates
- `vulnhuntr/cli/runner.py` — `run_analysis(args)` — main analysis orchestration

**Configuration:**
- `pyproject.toml` — all project settings (deps, ruff, mypy, pytest)
- `vulnhuntr/config.py` — runtime config from `.vulnhuntr.yaml`

**Core Logic:**
- `vulnhuntr/core/analysis.py` — iterative LLM analysis
- `vulnhuntr/llms.py` — all LLM provider clients + validation pipeline
- `vulnhuntr/symbol_finder.py` — Jedi-powered symbol resolution

**Testing:**
- `tests/conftest.py` — shared fixtures used across all test files
- `tests/test_llms.py` — most comprehensive test file for the critical validation path

## Naming Conventions

**Files:**
- `snake_case.py` for all modules
- `test_<module_name>.py` for test files

**Directories:**
- `lowercase/` — all package subdirectories

## Where to Add New Code

**New vulnerability type:**
- Add enum value to `VulnType` in `vulnhuntr/core/models.py`
- Add prompt template to `vulnhuntr/prompts.py`
- Add to `vuln_specific_data` dict in `vulnhuntr/cli/runner.py`

**New output format:**
- Add reporter class in `vulnhuntr/reporters/<format>_reporter.py`
- Inherit from `BaseReporter` in `vulnhuntr/reporters/base.py`
- Re-export from `vulnhuntr/reporters/__init__.py`
- Register CLI flag in `vulnhuntr/cli/parser.py`

**New LLM provider:**
- Add class in `vulnhuntr/llms.py` inheriting from `LLM`
- Register in `initialize_llm()` in `vulnhuntr/cli/runner.py`

**New integration:**
- Add module in `vulnhuntr/integrations/<name>.py`
- Wire up CLI flag in `vulnhuntr/cli/parser.py` and `runner.py`

**Utilities / Cross-cutting:**
- Infrastructure helpers belong at `vulnhuntr/<name>.py` (e.g., `checkpoint.py`, `cost_tracker.py`)
- Do not put utility code inside `core/` or `cli/`

## Special Directories

**`tests/test_results/`:**
- Purpose: Stored test output artifacts (HTML reports, etc.)
- Generated: Yes (during test runs)
- Committed: Possibly — check `.gitignore`

**`vulnhuntr.egg-info/`:**
- Purpose: setuptools package metadata (auto-generated)
- Generated: Yes
- Committed: No (in `.gitignore`)

**`memory-bank/`:**
- Purpose: Agent/Copilot long-term memory files (project context, decisions, progress)
- Generated: By development workflow
- Committed: No (in `.gitignore`)

---

*Structure analysis: 2026-04-08*
