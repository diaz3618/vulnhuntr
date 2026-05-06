# CHANGELOG

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.0] - 2026-05-06

### Removed

- **GitHub Issues integration**: `--create-issues` CLI flag, runner dispatch logic, and
  `vulnhuntr/integrations/github_issues.py` deleted. The scanner no longer creates GitHub
  issues for findings.
- **Webhook delivery integration**: `--webhook-url`, `--webhook-secret`, `--webhook-format`
  CLI flags, runner dispatch logic, and `vulnhuntr/integrations/webhook.py` deleted. Findings
  are no longer posted to external webhook endpoints.

### Changed

- All user-facing docs (README, QUICKSTART) updated to reflect the current feature set.
- Architecture docs and diagrams (`docs/architecture/`) updated to match the v1.0 codebase.
- Stale integration references removed from `docs/project/` files.

## [1.2.2] - 2026-05-05

### Added

- **CLI provider support** (`--llm claude-code`, `gemini-cli`, `codex`, `qwen-code`):
  delegates analysis to external AI binaries without requiring an API key.
- **Budget enforcement**: `--budget USD` stops analysis before the dollar limit is hit.
- **Native session continuation**: `ClaudeCodeLLM` and `QwenCodeLLM` use their provider's
  `--resume`/`--continue` flags to carry context across analysis passes.
- **MCP tool dispatch**: `VulnerabilityAnalyzer._secondary_analysis()` can inject MCP
  tool results into subsequent LLM passes when an `MCPAnalysisHelper` is active.
- **Execution tracing**: `ExecutionTracer` records probe, validation, session, fallback,
  and tool events for diagnostics and behavioral evaluation.
- **Cost classification**: `TokenUsage` distinguishes `api`, `provider_reported`, and
  `subscription` usage; `CostTracker.get_summary()` breaks costs down by type.
- **Provider fallback diagnostics**: verbose mode (`-v`) prints a fallback event log at
  the end of each run.
- **Analysis checkpoint** (`--resume`): `checkpoint.save_now()` persists progress after
  each file; `--no-checkpoint` disables this.
- **State-machine invariants**: `InvariantViolationError` guards known illegal state
  transitions in `FallbackLLM` and `ClaudeCodeLLM`.

### Fixed

- `checkpoint.save_now()` call (was incorrectly using `checkpoint.save()`).
- `GeminiCLILLM` and `CodexLLM` were not wired to accept a `tracer=` argument,
  meaning trace events were silently dropped for those providers.
- Gemini CLI models (e.g. `gemini-3.1-pro-preview`) now reported as zero-cost
  subscription usage rather than triggering an "Unknown model" warning.

### Changed

- `.env.example` model name updated from `claude-3-5-sonnet-latest` to
  `claude-sonnet-4-5` to match the current default used in production.
- `.env.example` now includes a CLI providers section documenting env-var auth for
  `codex` and `qwen-code`.

## [1.1.3] - 2026-02-11

### Fixed

- All Pyright/mypy type errors across 14 files
- Bandit B113: Added timeout to requests.post calls
- Security: Bumped actions/download-artifact to v4
- Security: Bumped minimum certifi to >=2024.7.4

### Added

- `to_xml_bytes()` helper for proper bytes typing from pydantic-xml
- `.venv-*/` pattern to gitignore

### Verified

- ruff: All checks passed (27 files)
- Pyright: 0 errors
- bandit: 0 Medium/High issues
- semgrep: 0 findings (843 rules)
- grype: All vulnerabilities fixed

## [1.1.2] - 2026-02-11

### Added

- Maintainer attribution in README with original Protect AI authors credited
- License section in README explaining AGPL-3.0 requirements

### Fixed

- Corrected license metadata from MIT to AGPL-3.0-or-later (matching LICENSE file)
- Removed deprecated license classifier per PEP 639
- Fixed package publishing configuration

## [1.1.1] - 2026-02-11

### Fixed

- License metadata corrections (superseded by 1.1.2)

## [1.1.0] - 2026-02-11

### Added

- Language support module structure (`vulnhuntr/language_support/`)
- MCP client integration (`vulnhuntr/mcp/`) with configurable MCP server support
- Cost tracking and budget management (`--budget`, `--dry-run` flags)
- Report generation: SARIF, HTML, JSON, CSV, Markdown formats
- Checkpoint/resume functionality (`--resume`, `--no-checkpoint`)

### Fixed

- Deprecated `datetime.utcnow()` usage

## [1.0.0] - 2025-10-01

### Added

- Initial release
- Claude, GPT-4, Ollama, OpenRouter support
- Iterative vulnerability analysis
- SARIF, HTML, JSON, CSV, Markdown report formats
- Checkpoint/resume functionality
