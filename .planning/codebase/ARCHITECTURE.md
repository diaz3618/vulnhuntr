# Architecture

**Analysis Date:** 2026-04-08

## Pattern Overview

**Overall:** Multi-layer pipeline with iterative LLM-based analysis

**Key Characteristics:**
- CLI entry point → Runner orchestrator → Core analysis engine → LLM provider
- Two-phase vulnerability analysis (initial broad scan → deep per-vuln-type dive)
- Iterative context expansion via Jedi symbol resolution between LLM calls
- All LLM responses validated with Pydantic before use
- Cost tracking and checkpoint/resume built into the execution flow

## Layers

**CLI Layer:**
- Purpose: Argument parsing, user I/O, orchestration of a full analysis run
- Location: `vulnhuntr/cli/`
- Contains: `parser.py` (argparse), `runner.py` (full run orchestration), `output.py` (Rich console output)
- Depends on: Core, LLMs, Reporters, Config, Checkpoint, CostTracker
- Used by: `__main__.py` entry point

**Core Layer:**
- Purpose: Vulnerability analysis logic, domain models, repository scanning
- Location: `vulnhuntr/core/`
- Contains: `analysis.py` (`VulnerabilityAnalyzer`), `models.py` (`VulnType`, `Response`, `ContextCode`, `LLMUsage`), `repo.py` (`RepoOps`), `xml_models.py` (Pydantic-XML prompt context)
- Depends on: LLMs (via TYPE_CHECKING only), SymbolFinder, Prompts
- Used by: CLI Runner

**LLM Layer:**
- Purpose: Provider-specific API clients with shared retry, validation, cost tracking
- Location: `vulnhuntr/llms.py`
- Contains: `LLM` (base), `Claude`, `ChatGPT`, `OpenRouter`, `Ollama` classes
- Key design: Shared `_validate_response()` applies multi-pass JSON repair before Pydantic validation; Claude uses prefill to reduce JSON wrapping issues
- Depends on: `anthropic`, `openai`, `requests`, `vulnhuntr.core.models`
- Used by: Core Analyzer (injected via constructor)

**Symbol Finder:**
- Purpose: Cross-file Python symbol resolution for context expansion
- Location: `vulnhuntr/symbol_finder.py` (`SymbolExtractor`)
- Contains: Three search strategies: `file_search` (Jedi Script.search), `project_search` (Jedi Project.search), `all_names_search` (fallback)
- Depends on: `jedi`, `parso`
- Used by: Core Analyzer (injected via constructor)

**Prompts Layer:**
- Purpose: Static prompt templates per vulnerability type
- Location: `vulnhuntr/prompts.py`
- Contains: `LFI_TEMPLATE`, `RCE_TEMPLATE`, `SSRF_TEMPLATE`, `AFO_TEMPLATE`, `SQLI_TEMPLATE`, `XSS_TEMPLATE`, `IDOR_TEMPLATE`, `README_SUMMARY_PROMPT_TEMPLATE`
- Depends on: Nothing
- Used by: Core Analyzer

**Reporters Layer:**
- Purpose: Convert findings to structured output formats
- Location: `vulnhuntr/reporters/`
- Contains: `base.py` (abstract `BaseReporter`, `Finding` dataclass, `FindingSeverity`), `html.py`, `sarif.py`, `json_reporter.py`, `csv_reporter.py`, `markdown_reporter.py`
- Depends on: Only stdlib + `vulnhuntr.reporters.base`
- Used by: CLI Runner

**Integrations Layer:**
- Purpose: Push findings to external systems (opt-in)
- Location: `vulnhuntr/integrations/`
- Contains: `github_issues.py` (`GitHubIssueCreator` via REST API), `webhook.py` (`WebhookNotifier` with HMAC signing)
- Depends on: `requests`, `vulnhuntr.reporters.base`
- Used by: CLI Runner (conditionally)

**Infrastructure:**
- `vulnhuntr/config.py` — load `.vulnhuntr.yaml` config; `VulnhuntrConfig` dataclass
- `vulnhuntr/checkpoint.py` — JSON-based save/resume for interrupted runs; `AnalysisCheckpoint`
- `vulnhuntr/cost_tracker.py` — per-call token counting and pricing; `CostTracker`, `BudgetEnforcer`
- `vulnhuntr/mcp/` — standalone MCP client (not in main pipeline); `MCPClientManager`, `MCPSettings`, `MCPServerConfig`

## Data Flow

**Normal Analysis Run:**

1. `__main__.py` loads `.env`, configures `structlog`, delegates to CLI
2. `cli/parser.py` parses args; `cli/runner.py` receives `Namespace`
3. Runner loads `.vulnhuntr.yaml` config, initializes `CostTracker` + `BudgetEnforcer`
4. Runner calls `RepoOps.get_network_related_files()` to discover files
5. Runner creates `SymbolExtractor` (Jedi project) + `VulnerabilityAnalyzer`
6. Per file: `VulnerabilityAnalyzer.analyze_file()` calls LLM for initial scan
7. For each vuln type with confidence ≥ threshold: iterative deep analysis (up to `max_iterations`)
8. Each iteration: LLM returns `Response` with `context_code`; extractor fetches symbol defs; loop repeats
9. `AnalysisResult` collected; reporters write output files
10. Optional: GitHub issues / webhook fired if configured

**Cost Guard:**

- `BudgetEnforcer` callback is checked before each LLM call; exceeding budget halts analysis
- `AnalysisCheckpoint` saves state every N files, enabling resume via `--resume`

## Key Abstractions

**`VulnType` (Enum):**
- Purpose: Typed set of supported vulnerability categories (LFI, RCE, SSRF, AFO, SQLI, XSS, IDOR)
- Examples: `vulnhuntr/core/models.py`
- Pattern: `str` enum — safe to serialize, appears in LLM responses and reports

**`Response` (Pydantic BaseModel):**
- Purpose: Canonical LLM output schema — every LLM call returns this
- Location: `vulnhuntr/core/models.py`
- Fields: `scratchpad`, `analysis`, `poc`, `confidence_score`, `vulnerability_types`, `context_code`, `mcp_tool_calls`
- Pattern: `_validate_response()` converts raw LLM text → validated `Response`

**`Finding` (dataclass):**
- Purpose: Reporter-facing normalized finding; decoupled from LLM layer
- Location: `vulnhuntr/reporters/base.py`
- Pattern: Created from `Response` via `response_to_finding()` factory function

**`BaseReporter` (ABC):**
- Purpose: Common interface for all output formats
- Location: `vulnhuntr/reporters/base.py`
- Pattern: `write(findings, output_path)` abstract method

## Entry Points

**CLI Entry:**
- Location: `vulnhuntr/__main__.py` → `vulnhuntr/cli/runner.py:run_analysis()`
- Triggers: `python -m vulnhuntr` or `vulnhuntr` script
- Responsibilities: env loading, logging setup, arg parsing, top-level error handling

**Library Entry:**
- Location: `vulnhuntr/__init__.py` — re-exports all public classes
- Public API: `VulnerabilityAnalyzer`, `Response`, `VulnType`, `RepoOps`, reporters, `run_analysis`

## Error Handling

**Strategy:** Typed exception hierarchy in LLM layer; domain errors propagate to CLI

**Patterns:**
- `LLMError` (base) → `RateLimitError`, `APIConnectionError`, `APIStatusError` in `vulnhuntr/llms.py`
- LLM clients retry on `RateLimitError`; other errors propagate
- `_validate_response()` raises `LLMError("Validation failed")` on JSON parse failure
- CLI runner wraps all exceptions with `except Exception as e` → logs via structlog → exit code 1

## Cross-Cutting Concerns

**Logging:** `structlog` with JSON renderer; all modules use `log = structlog.get_logger()`
**Validation:** All LLM output validated via Pydantic `model_validate_json()`
**Config:** YAML file + CLI args + env vars; merged priority is CLI > YAML > env default
**Cost guards:** Callback-based; injected into LLM at construction time

---

*Architecture analysis: 2026-04-08*
