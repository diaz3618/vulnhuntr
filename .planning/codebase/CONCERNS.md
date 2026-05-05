# Codebase Concerns

**Analysis Date:** 2026-04-08

## Tech Debt

**Hardcoded pricing table in `cost_tracker.py`:**
- Issue: `PRICING_TABLE` in `vulnhuntr/cost_tracker.py` (lines ~17-50) is a hardcoded dict of model → price per 1K tokens. LLM providers update prices regularly.
- Files: `vulnhuntr/cost_tracker.py`
- Impact: Cost estimates become inaccurate as providers change pricing; unknown models fall back to `DEFAULT_PRICING = {"input": 0.01, "output": 0.03}` which may be wrong by orders of magnitude for new cheap models.
- Fix approach: Externalize pricing to `.vulnhuntr.yaml` config section or fetch from a provider-maintained registry on startup.

**Checkpoint version hardcoded to "0.1.0":**
- Issue: `CheckpointData.vulnhuntr_version` defaults to `"0.1.0"` in `vulnhuntr/checkpoint.py` while the package is `v1.2.1`.
- Files: `vulnhuntr/checkpoint.py` (`CheckpointData` dataclass, `vulnhuntr_version = "0.1.0"`)
- Impact: Resume compatibility checks based on version will report wrong version in checkpoint files.
- Fix approach: Replace literal with `from vulnhuntr import __version__` and use `field(default_factory=lambda: __version__)`.

**MCP client not integrated into the analysis pipeline:**
- Issue: `vulnhuntr/mcp/client.py` docstring explicitly states "This module is standalone and NOT integrated into Vulnhuntr's analysis pipeline." MCP analysis support (`vulnhuntr/mcp/analysis.py`) exists but the main runner does not invoke it.
- Files: `vulnhuntr/mcp/client.py`, `vulnhuntr/mcp/analysis.py`, `vulnhuntr/cli/runner.py`
- Impact: Users who configure MCP servers in `.vulnhuntr.yaml` may expect them to influence analysis; they currently do not.
- Fix approach: Wire `MCPClientManager` into `run_analysis()` in `vulnhuntr/cli/runner.py`; pass available tools to `VulnerabilityAnalyzer`.

**`runner.py` is too large (714 lines) — monolithic orchestration:**
- Issue: `vulnhuntr/cli/runner.py` handles LLM initialization, fallback logic, dry-run, checkpoint resume, file iteration, reporter setup, and integration dispatch — all in one file.
- Files: `vulnhuntr/cli/runner.py`
- Impact: Hard to test individual steps in isolation; high cognitive load for contributors.
- Fix approach: Extract `initialize_llm()`, `parse_fallback_spec()`, reporter dispatch, and integration dispatch into separate helpers or modules.

## Known Bugs

**`model_override` not applied to `OpenRouter` when env var is set:**
- Symptoms: If `OPENROUTER_MODEL` env var is set, `model_override` from `.vulnhuntr.yaml` `model:` field may be ignored depending on call order.
- Files: `vulnhuntr/cli/runner.py` (`initialize_llm()`)
- Trigger: Set both `OPENROUTER_MODEL` env var and `model:` in config file, use `--llm openrouter`
- Note: Likely affects all providers equally — env var is always read with `os.getenv(..., default)` so CLI model override takes precedence correctly if passed as `model_override`.

## Security Considerations

**Webhook URL and secret stored in config file:**
- Risk: `.vulnhuntr.yaml` could contain the webhook URL and HMAC secret. If committed to a repo, the secret leaks.
- Files: `vulnhuntr/integrations/webhook.py` (`WebhookConfig.secret`), `vulnhuntr/config.py`
- Current mitigation: Config file is user-managed; no enforcement that secrets are in env vars.
- Recommendations: Document that `webhook.secret` should reference an env var; add a validator warning if a literal secret value is detected in config.

**GitHub token passed as positional string in `GitHubConfig`:**
- Risk: `GitHubConfig(token=os.getenv("GITHUB_TOKEN"))` — if `GITHUB_TOKEN` is not set, `token` is `None` and the request is made without auth (no explicit guard).
- Files: `vulnhuntr/integrations/github_issues.py` (`GitHubConfig`, `GitHubIssueCreator.__init__`)
- Current mitigation: API calls will fail with HTTP 401; no credential exposure.
- Recommendations: Add a validation that `token` is non-empty at `GitHubConfig` construction time.

**Source code is sent to external LLM providers unredacted:**
- Risk: Analyzed repository source code (potentially containing secrets, PII) is sent verbatim to Anthropic/OpenAI/OpenRouter cloud APIs.
- Files: `vulnhuntr/core/analysis.py` (all `llm.chat()` calls)
- Current mitigation: Ollama and local models avoid this; README documents the external data flow.
- Recommendations: Add a user-facing warning before sending code externally; document in QUICKSTART.md.

## Performance Bottlenecks

**Jedi project-level search on large repos:**
- Problem: `SymbolExtractor.project_search()` calls `self.project.search(symbol_name)` which scans the entire Jedi project index.
- Files: `vulnhuntr/symbol_finder.py` (`project_search` method)
- Cause: Jedi's project search is not bounded by file count; large repos (thousands of files) can cause multi-second delays per context expansion iteration.
- Improvement path: Pre-filter candidate files using `RepoOps.get_relevant_py_files()` before calling `project_search`; cache repeated lookups within a single analysis run.

**Sequential file analysis (no parallelism):**
- Problem: Files are analyzed one at a time in `cli/runner.py`; each takes multiple LLM round-trips.
- Files: `vulnhuntr/cli/runner.py`
- Cause: Stateful LLM `history` list on each `LLM` instance; not thread-safe for sharing.
- Improvement path: Instantiate a separate `LLM` per file and run files in a thread pool with `concurrent.futures.ThreadPoolExecutor`; each provider SDK is GIL-safe for I/O-bound work.

## Fragile Areas

**`_validate_response()` JSON repair pipeline:**
- Files: `vulnhuntr/llms.py` (`LLM._validate_response`)
- Why fragile: Multi-pass repair (Python-literal substitution → escape stripping) modifies the JSON string in place. Regex `re.sub(r"\bNone\b", "null", ...)` can corrupt valid Python identifiers named `None` in code snippets within the JSON.
- Safe modification: Add unit tests for new edge cases before extending the repair logic; prefer `json.loads` error analysis over blind substitution.
- Test coverage: Well covered in `tests/test_llms.py`.

**`SymbolExtractor` edge case handling:**
- Files: `vulnhuntr/symbol_finder.py`
- Why fragile: The extractor documents five known edge cases inline; each code path handles one. Adding a new LLM-requested symbol type may silently return `None` (no match) rather than error, causing silent context-expansion failures.
- Safe modification: Add logging when all three search strategies fail; surface failure to the caller rather than returning `None`.

## Scaling Limits

**Token context window:**
- Current capacity: `max_tokens=8192` for output; input context is limited by provider (200K for Claude Sonnet)
- Limit: Very large files (>50K lines) passed as `file_code` may approach input limits
- Scaling path: Add file truncation or chunking logic in `VulnerabilityAnalyzer` before constructing the initial prompt.

**Single-process, single-provider architecture:**
- Current capacity: One LLM provider per run (with up to 2 fallbacks)
- Limit: Provider rate limits constrain throughput on large repos
- Scaling path: Multi-provider load balancing; async LLM calls using `asyncio` + provider async SDKs.

## Dependencies at Risk

**`jedi` / `parso` (Python version ceiling):**
- Risk: `jedi>=0.19.2` and `parso>=0.8.5` do not support Python 3.14+ as of this analysis. This is the sole reason for `requires-python = "<3.14"`.
- Impact: Vulnhuntr is blocked from Python 3.14 adoption until Jedi/Parso release compatible versions.
- Migration plan: Monitor [github.com/davidhalter/jedi](https://github.com/davidhalter/jedi) releases; test against Python 3.14 pre-releases periodically.

**`requests` library (soft dependency):**
- Risk: `requests` is listed as a core dependency (`pyproject.toml`) but is guarded with `try/except ImportError` in integration modules. This creates inconsistency — it is always installed but the guard implies it might not be.
- Files: `vulnhuntr/integrations/github_issues.py`, `vulnhuntr/integrations/webhook.py`
- Impact: Low; the guard is harmless but misleading.
- Fix approach: Remove the guard since `requests` is a required dep; or move it to an `[integrations]` optional extra.

## Missing Critical Features

**No coverage enforcement threshold:**
- Problem: `pyproject.toml` has no `--cov-fail-under` setting; coverage can drop to 0% without CI failure.
- Blocks: Confident refactoring; regression detection.

**No input sanitization for `analyze` path argument:**
- Problem: `args.analyze` (relative path within project) is passed to `RepoOps` without verifying it stays within `args.root` (path traversal risk for CLI misuse).
- Files: `vulnhuntr/cli/parser.py` (`validate_args`), `vulnhuntr/cli/runner.py`
- Risk: Low (local tool), but worth noting for packaging and downstream integrations.

## Test Coverage Gaps

**`vulnhuntr/cli/runner.py` (714 lines):**
- What's not tested: Full end-to-end `run_analysis()` call with mocked LLM; fallback LLM switching logic; budget exhaustion mid-run; checkpoint resume integration.
- Files: `tests/test_cli.py`
- Risk: Changes to orchestration logic may break silently.
- Priority: High

**`vulnhuntr/mcp/client.py` (521 lines):**
- What's not tested: Live MCP connection (gated behind `@pytest.mark.live`); error paths for failed stdio subprocess.
- Files: `tests/test_mcp_client.py`
- Risk: MCP connection failures may surface only in production.
- Priority: Medium

**`vulnhuntr/reporters/html.py` (630 lines):**
- What's not tested: HTML output correctness (no DOM assertion, only file-existence check likely).
- Files: `tests/test_reporters.py`
- Risk: HTML template regressions invisible to CI.
- Priority: Low

---

*Concerns audit: 2026-04-08*
