"""
CLI Runner
==========

Main execution orchestration for Vulnhuntr CLI.

This module ties together all components:
- Repository scanning
- LLM initialization
- Vulnerability analysis
- Report generation
- Cost tracking
"""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from vulnhuntr.checkpoint import AnalysisCheckpoint
from vulnhuntr.config import load_config, merge_config_with_args
from vulnhuntr.core.repo import RepoOps
from vulnhuntr.cost_tracker import (
    BudgetEnforcer,
    CostTracker,
    estimate_analysis_cost,
)
from vulnhuntr.reporters.base import Finding, response_to_finding
from vulnhuntr.symbol_finder import SymbolExtractor

from .output import (
    console,
    print_dry_run_report,
    print_findings_summary,
    print_readable,
    print_report_status,
    print_resume_info,
)

if TYPE_CHECKING:
    import argparse

log = structlog.get_logger()


def initialize_llm(
    llm_arg: str,
    system_prompt: str = "",
    cost_callback: Callable | None = None,
    model_override: str | None = None,
):
    """Initialize LLM client with optional cost tracking callback.

    Args:
        llm_arg: LLM provider ('claude', 'gpt', 'ollama', 'openrouter')
        system_prompt: System prompt to use
        cost_callback: Optional callback for cost tracking
        model_override: Model name from config (overrides env var default)

    Returns:
        Initialized LLM client

    Raises:
        ValueError: If invalid LLM argument provided
    """
    from vulnhuntr.llms import ChatGPT, Claude, Ollama, OpenRouter

    llm_arg = llm_arg.lower()

    if llm_arg == "claude":
        model = model_override or os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
        base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
        return Claude(model, base_url, system_prompt, cost_callback)

    elif llm_arg == "gpt":
        model = model_override or os.getenv("OPENAI_MODEL", "chatgpt-4o-latest")
        base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        return ChatGPT(model, base_url, system_prompt, cost_callback)

    elif llm_arg == "openrouter":
        model = model_override or os.getenv("OPENROUTER_MODEL", "qwen/qwen3-coder:free")
        base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
        return OpenRouter(model, base_url, system_prompt, cost_callback)

    elif llm_arg == "ollama":
        model = model_override or os.getenv("OLLAMA_MODEL", "llama3")
        base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434/api/generate")
        return Ollama(model, base_url, system_prompt, cost_callback)

    else:
        raise ValueError(f"Invalid LLM argument: {llm_arg}\nValid options are: claude, gpt, ollama, openrouter")


def parse_fallback_spec(
    spec: str,
    system_prompt: str = "",
    cost_callback: Callable | None = None,
    default_provider: str | None = None,
):
    """Parse a fallback spec like 'provider:model' and return an LLM instance.

    Supports two formats:
    - Explicit provider: 'provider:model' (e.g., 'openrouter:deepseek/deepseek-r1-0528:free')
    - Model-only: 'model' (e.g., 'qwen/qwen3-next-80b-a3b-instruct:free')
      When no valid provider prefix is found, uses default_provider or 'openrouter'
      if the model name contains '/' (typical of OpenRouter model identifiers).

    Args:
        spec: Fallback specification string
        system_prompt: System prompt to use
        cost_callback: Optional callback for cost tracking
        default_provider: Provider to use when spec has no explicit provider prefix

    Returns:
        Initialized LLM client

    Raises:
        ValueError: If spec format is invalid or provider unknown
    """
    from vulnhuntr.llms import ChatGPT, Claude, Ollama, OpenRouter

    providers: dict[str, type] = {
        "claude": Claude,
        "gpt": ChatGPT,
        "openrouter": OpenRouter,
        "ollama": Ollama,
    }

    parts = spec.split(":", 1)
    if len(parts) == 2 and parts[0].lower() in providers:  # noqa: PLR2004
        # Explicit provider prefix: 'openrouter:model-name:free'
        provider, model = parts[0].lower(), parts[1]
    else:
        # No valid provider prefix — treat entire spec as model name.
        # Infer provider: use default_provider, or 'openrouter' for slash-style names.
        model = spec
        if default_provider and default_provider.lower() in providers:
            provider = default_provider.lower()
        elif "/" in spec:
            provider = "openrouter"  # slash in name implies OpenRouter model ID
        else:
            raise ValueError(
                f"Cannot determine provider for fallback spec '{spec}'. "
                f"Use 'provider:model' format (e.g., 'openrouter:{spec}') "
                f"or set a primary provider in config. "
                f"Valid providers: {', '.join(providers)}"
            )
        log.info("Inferred provider for fallback spec", spec=spec, provider=provider)

    if provider not in providers:
        raise ValueError(f"Unknown provider '{provider}' in fallback spec. Valid providers: {', '.join(providers)}")

    # Determine base_url from environment
    base_urls = {
        "claude": os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com"),
        "gpt": os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        "openrouter": os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        "ollama": os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434/api/generate"),
    }

    cls = providers[provider]
    base_url = base_urls[provider]
    return cls(model, base_url, system_prompt, cost_callback)


def wrap_with_fallbacks(
    primary,
    args: argparse.Namespace,
    cost_callback: Callable | None = None,
    system_prompt: str = "",
    config: Any | None = None,
):
    """Wrap primary LLM with FallbackLLM if fallback args are specified.

    Fallback sources (in priority order):
    1. CLI arguments: --fallback1, --fallback2
    2. Config file: llm.fallback1, llm.fallback2

    Args:
        primary: Primary LLM instance
        args: Parsed CLI arguments (checks args.fallback1, args.fallback2)
        cost_callback: Cost tracking callback
        system_prompt: System prompt for fallback LLMs
        config: VulnhuntrConfig instance (for config-based fallbacks)

    Returns:
        FallbackLLM wrapper if fallbacks specified, otherwise primary unchanged
    """
    # Resolve fallback specs: CLI args take priority, then config
    fallback1 = getattr(args, "fallback1", None)
    fallback2 = getattr(args, "fallback2", None)
    if not fallback1 and config and getattr(config, "fallback1", None):
        fallback1 = config.fallback1
    if not fallback2 and config and getattr(config, "fallback2", None):
        fallback2 = config.fallback2

    if not fallback1 and not fallback2:
        return primary

    from vulnhuntr.llms import FallbackLLM

    # Resolve default_provider from config for specs without explicit provider
    default_provider = None
    if config and getattr(config, "provider", None):
        default_provider = config.provider

    fallbacks = []
    if fallback1:
        fb1 = parse_fallback_spec(fallback1, system_prompt, cost_callback, default_provider)
        fallbacks.append(fb1)
        log.info("Fallback 1 configured", spec=fallback1)
    if fallback2:
        fb2 = parse_fallback_spec(fallback2, system_prompt, cost_callback, default_provider)
        fallbacks.append(fb2)
        log.info("Fallback 2 configured", spec=fallback2)

    log.info("Wrapping LLM with fallback support", fallback_count=len(fallbacks))
    return FallbackLLM(primary, fallbacks)


def get_model_name(llm_arg: str) -> str:
    """Get the model name for the given LLM provider from environment.

    Args:
        llm_arg: LLM provider name

    Returns:
        Model name string
    """
    llm_arg = llm_arg.lower()
    if llm_arg == "claude":
        return os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
    elif llm_arg == "gpt":
        return os.getenv("OPENAI_MODEL", "chatgpt-4o-latest")
    elif llm_arg == "openrouter":
        return os.getenv("OPENROUTER_MODEL", "qwen/qwen3-coder:free")
    elif llm_arg == "ollama":
        return os.getenv("OLLAMA_MODEL", "llama3")
    return "unknown"


def run_analysis(args: argparse.Namespace) -> int:
    """Run the vulnerability analysis.

    Main entry point for CLI execution. Orchestrates:
    1. Configuration loading
    2. Repository scanning
    3. Cost estimation (if dry-run)
    4. Checkpoint management
    5. LLM analysis via VulnerabilityAnalyzer
    6. Report generation

    Args:
        args: Parsed CLI arguments

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    from vulnhuntr.core.analysis import AnalysisConfig, VulnerabilityAnalyzer
    from vulnhuntr.core.xml_models import (
        Instructions,
        ReadmeSummary,
        to_xml_bytes,
    )
    from vulnhuntr.prompts import (
        SYS_PROMPT_TEMPLATE,
    )

    # Load configuration from .vulnhuntr.yaml (if present)
    # Search from CWD first (where user launched vulnhuntr), then target repo
    config = load_config(start_dir=Path.cwd())
    if config.provider is None and config.budget is None:
        # CWD search found nothing useful, try target repo path
        config = load_config(start_dir=Path(args.root))
    config = merge_config_with_args(config, args)

    # Apply config to args where config provides defaults
    if config.budget and args.budget is None:
        args.budget = config.budget
    if config.provider and not args.llm:
        args.llm = config.provider
    if config.dry_run and not args.dry_run:
        args.dry_run = config.dry_run

    # Default provider to 'claude' if neither CLI nor config specified
    if not args.llm:
        args.llm = "claude"

    # ---- MCP initialisation (no-op when mode == "off") ----
    mcp_helper: _MCPAnalysisHelper | None = None
    try:
        from vulnhuntr.mcp import MCPAnalysisHelper as _MCPAnalysisHelper
        from vulnhuntr.mcp import load_mcp_config, run_async, should_use_mcp

        mcp_settings = load_mcp_config(start_dir=Path(args.root))
        if should_use_mcp(mcp_settings):
            mcp_helper = _MCPAnalysisHelper(mcp_settings)
            try:
                run_async(mcp_helper.initialize())
                if mcp_helper.is_active:
                    log.info(
                        "MCP analysis integration active",
                        mode=mcp_helper.mode,
                    )
                else:
                    log.warning("MCP initialised but no tools discovered, falling back")
                    mcp_helper = None
            except Exception as e:
                log.error("MCP initialisation failed, continuing without MCP", error=str(e))
                mcp_helper = None
    except ImportError:
        log.debug("MCP module not available (install with pip install vulnhuntr[mcp])")
        mcp_helper = None

    # Initialize repository operations
    repo = RepoOps(args.root)
    code_extractor = SymbolExtractor(args.root)

    # Get relevant files
    files = list(repo.get_relevant_py_files())

    # Determine files to analyze
    if args.analyze:
        analyze_path = Path(args.analyze)
        if analyze_path.is_absolute():
            files_to_analyze = list(repo.get_files_to_analyze(analyze_path))
        else:
            files_to_analyze = list(repo.get_files_to_analyze(Path(args.root) / analyze_path))
    else:
        files_to_analyze = list(repo.get_network_related_files(files))

    # Get model name for cost estimation
    model_name = get_model_name(args.llm)

    # Handle --dry-run: Estimate costs and exit
    if args.dry_run:
        console.print("\n[bold cyan]Running cost estimation (dry-run mode)...[/bold cyan]")
        estimate = estimate_analysis_cost(files_to_analyze, model_name)
        print_dry_run_report(estimate)
        return 0

    # Initialize cost tracker
    cost_tracker = CostTracker()

    # Initialize budget enforcer if budget specified
    budget_enforcer = (
        BudgetEnforcer(
            max_budget_usd=args.budget,
            warning_threshold=0.8,
        )
        if args.budget
        else None
    )

    # Create cost callback for LLM
    def cost_callback(
        input_tokens: int,
        output_tokens: int,
        model: str,
        file_path: str | None,
        call_type: str,
    ) -> None:
        cost_tracker.track_call(input_tokens, output_tokens, model, file_path, call_type)

    # Initialize checkpoint
    checkpoint = AnalysisCheckpoint(
        checkpoint_dir=Path(args.resume) if args.resume else Path(".vulnhuntr_checkpoint"),
        save_frequency=5,
        enabled=not args.no_checkpoint,
    )

    # Handle --resume: Check for existing checkpoint
    if args.resume:
        if checkpoint.can_resume():
            print_resume_info(checkpoint)
            console.print("\n[bold green]Resuming from checkpoint...[/bold green]\n")
            checkpoint_data = checkpoint.resume(cost_tracker)

            # Filter out already completed files
            completed_set = set(checkpoint_data.completed_files)
            files_to_analyze = [f for f in files_to_analyze if str(f) not in completed_set]

            console.print(f"[dim]Skipping {len(completed_set)} already completed files[/dim]")
            console.print(f"[dim]Remaining files to analyze: {len(files_to_analyze)}[/dim]\n")
        else:
            console.print("[yellow]No checkpoint found to resume. Starting fresh analysis.[/yellow]\n")

    # Start checkpoint tracking (if not resuming)
    if not args.resume or not checkpoint.can_resume():
        checkpoint.start(
            repo_path=Path(args.root),
            files_to_analyze=files_to_analyze,
            model=model_name,
            cost_tracker=cost_tracker,
        )

    # Initialize LLM (without system prompt initially, for README summarization)
    llm = initialize_llm(args.llm, cost_callback=cost_callback, model_override=config.model)
    llm = wrap_with_fallbacks(llm, args, cost_callback, config=config)

    # Create analyzer for README summarization
    analyzer = VulnerabilityAnalyzer(llm, code_extractor, AnalysisConfig(verbosity=getattr(args, "verbosity", 0)))

    # Get and summarize README
    readme_content = repo.get_readme_content()
    if readme_content:
        summary = analyzer.summarize_readme(readme_content)
    else:
        log.warning("No README summary found")
        summary = ""

    # Reinitialize LLM with system prompt
    system_prompt = (
        to_xml_bytes(Instructions(instructions=SYS_PROMPT_TEMPLATE))
        + b"\n"
        + to_xml_bytes(ReadmeSummary(readme_summary=summary))
    ).decode()

    # Inject MCP tool descriptions into system prompt when active
    if mcp_helper is not None and mcp_helper.is_active:
        mcp_tool_section = mcp_helper.get_tool_prompt_section()
        if mcp_tool_section:
            system_prompt += "\n" + mcp_tool_section

    llm = initialize_llm(args.llm, system_prompt, cost_callback, model_override=config.model)
    llm = wrap_with_fallbacks(llm, args, cost_callback, system_prompt, config=config)

    # Create analyzer with system-prompt-configured LLM
    analysis_config = AnalysisConfig(
        max_iterations=7,
        min_confidence_for_finding=5,
        verbosity=getattr(args, "verbosity", 0),
    )
    analyzer = VulnerabilityAnalyzer(llm, code_extractor, analysis_config)

    # Wire budget checking into analyzer callbacks
    if budget_enforcer:
        analyzer.set_continue_check(lambda: budget_enforcer.check(cost_tracker.total_cost))

    # Wire verbosity output into iteration callback
    if getattr(args, "verbosity", 0) > 0:
        analyzer.set_iteration_callback(lambda _iteration, report: print_readable(report))

    # Track analysis success for checkpoint finalization
    analysis_success = True

    # Collect findings for reporting
    all_findings: list[Finding] = []

    # Main analysis loop — delegates to VulnerabilityAnalyzer
    for py_f in files_to_analyze:
        # Check budget before starting file analysis
        if budget_enforcer and not budget_enforcer.check(cost_tracker.total_cost):
            console.print(f"\n[bold red]Budget limit reached (${args.budget:.2f}). Stopping analysis.[/bold red]")
            console.print("[dim]Progress saved to checkpoint. Use --resume to continue with higher budget.[/dim]")
            analysis_success = False
            break

        # Set checkpoint current file
        checkpoint.set_current_file(py_f)

        print(f"\nAnalyzing {py_f}")
        print("-" * 40 + "\n")

        try:
            result = analyzer.analyze_file(py_f, files)
        except (OSError, UnicodeDecodeError, ValueError) as e:
            log.error("Failed to analyze file", file=str(py_f), error=str(e))
            continue

        # Print initial analysis report
        print_readable(result.initial_report)

        # Execute MCP tool calls from initial analysis (if any)
        if mcp_helper is not None and mcp_helper.is_active and result.initial_report.mcp_tool_calls:
            try:
                mcp_results = run_async(mcp_helper.execute_tool_calls(result.initial_report.mcp_tool_calls))
                log.info("MCP tool calls executed (initial)", count=len(mcp_results))
            except Exception as e:
                log.error("MCP tool execution failed (initial)", error=str(e))

        # Collect findings from secondary analysis
        for vuln_type, report in result.findings.items():
            if getattr(args, "verbosity", 0) == 0:
                print_readable(report)

            # Execute MCP tool calls from final report (if any)
            if mcp_helper is not None and mcp_helper.is_active and report.mcp_tool_calls:
                try:
                    mcp_results = run_async(mcp_helper.execute_tool_calls(report.mcp_tool_calls))
                    log.info("MCP tool calls executed (secondary)", count=len(mcp_results))
                except Exception as e:
                    log.error("MCP tool execution failed (secondary)", error=str(e))

            finding = response_to_finding(
                response=report,
                file_path=str(py_f),
                vuln_type=vuln_type,
                context_code=result.context_code,
            )
            all_findings.append(finding)
            log.info(
                "Finding collected for reporting",
                vuln_type=vuln_type.value,
                file=str(py_f),
                confidence=report.confidence_score,
            )

        # Mark file as complete in checkpoint
        checkpoint.mark_file_complete(
            py_f,
            result.initial_report.model_dump(),
        )

    # Finalize checkpoint
    checkpoint.finalize(success=analysis_success and len(files_to_analyze) > 0)

    # Shutdown MCP connections
    if mcp_helper is not None:
        try:
            run_async(mcp_helper.shutdown())
            log.info("MCP connections closed")
        except Exception as e:
            log.warning("MCP shutdown error", error=str(e))

    # Print cost summary
    console.print(cost_tracker.get_detailed_report())
    log.info("Analysis complete", cost_summary=cost_tracker.get_summary())

    # Generate reports
    _generate_reports(args, all_findings, cost_tracker, files_to_analyze)

    return 0


def _generate_reports(
    args: argparse.Namespace,
    all_findings: list[Finding],
    cost_tracker: CostTracker,
    files_to_analyze: list[Path],
) -> None:
    """Generate all requested reports.

    Args:
        args: Parsed CLI arguments
        all_findings: List of findings to report
        cost_tracker: Cost tracker for summary
        files_to_analyze: List of files that were analyzed
    """
    from vulnhuntr.reporters import (
        CSVReporter,
        HTMLReporter,
        JSONReporter,
        MarkdownReporter,
        SARIFReporter,
    )

    if not all_findings:
        print_findings_summary(all_findings, len(files_to_analyze))
        return

    print_findings_summary(all_findings, len(files_to_analyze))

    # Build list of (format_name, arg_value, reporter_factory) for requested reports
    report_specs: list[tuple[str, str, Callable]] = []
    if args.sarif:
        report_specs.append(("SARIF", args.sarif, lambda p: SARIFReporter(output_path=p, repo_root=Path(args.root))))
    if args.html:
        report_specs.append(("HTML", args.html, lambda p: HTMLReporter(output_path=p)))
    if args.json:
        report_specs.append(("JSON", args.json, lambda p: JSONReporter(output_path=p)))
    if args.csv:
        report_specs.append(("CSV", args.csv, lambda p: CSVReporter(output_path=p)))
    if args.markdown:
        report_specs.append(
            (
                "Markdown",
                args.markdown,
                lambda p: MarkdownReporter(output_path=p, title=f"Vulnhuntr Security Report - {Path(args.root).name}"),
            )
        )

    for format_name, output_arg, factory in report_specs:
        try:
            output_path = Path(output_arg)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            reporter = factory(output_path)
            reporter.add_findings(all_findings)
            reporter.write()
            print_report_status(format_name, output_arg, True)
        except Exception as e:
            print_report_status(format_name, output_arg, False, str(e))
            log.error("Report generation failed", format=format_name, error=str(e))

    # Export all formats
    if hasattr(args, "export_all") and args.export_all:
        _export_all_reports(args, all_findings)

    # GitHub issues
    if args.create_issues:
        _create_github_issues(all_findings)

    # Webhook notification
    if args.webhook:
        _send_webhook(args, all_findings, cost_tracker, files_to_analyze)


def _export_all_reports(args: argparse.Namespace, findings: list[Finding]) -> None:
    """Export all report formats to a directory."""
    from vulnhuntr.reporters import (
        CSVReporter,
        HTMLReporter,
        JSONReporter,
        MarkdownReporter,
        SARIFReporter,
    )

    try:
        export_dir = Path(args.export_all)
        export_dir.mkdir(parents=True, exist_ok=True)

        repo_name = Path(args.root).name
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Export each format
        formats = [
            (SARIFReporter(repo_root=Path(args.root)), "sarif"),
            (HTMLReporter(), "html"),
            (JSONReporter(), "json"),
            (CSVReporter(), "csv"),
            (MarkdownReporter(), "md"),
        ]

        for reporter, ext in formats:
            path = export_dir / f"vulnhuntr_{repo_name}_{timestamp}.{ext}"
            reporter.output_path = path  # Set output path dynamically
            reporter.add_findings(findings)
            reporter.write()

        console.print(f"[green]✓ All reports exported to: {export_dir}[/green]")
    except Exception as e:
        console.print(f"[red]✗ Failed to export all reports: {e}[/red]")
        log.error("Export all failed", error=str(e))


def _create_github_issues(findings: list[Finding]) -> None:
    """Create GitHub issues for findings."""
    from vulnhuntr.integrations import GitHubConfig, GitHubIssueCreator

    github_token = os.getenv("GITHUB_TOKEN")
    github_owner = os.getenv("GITHUB_OWNER")
    github_repo = os.getenv("GITHUB_REPO")

    if not all([github_token, github_owner, github_repo]):
        console.print(
            "[red]✗ GitHub integration requires GITHUB_TOKEN, GITHUB_OWNER, and GITHUB_REPO environment variables[/red]"
        )
        return

    # Narrowed by the check above
    assert github_token is not None
    assert github_owner is not None
    assert github_repo is not None

    try:
        github_config = GitHubConfig(
            token=github_token,
            owner=github_owner,
            repo=github_repo,
            labels=["security", "vulnhuntr"],
        )
        issue_creator = GitHubIssueCreator(github_config)
        results = issue_creator.create_issues_for_findings(findings)

        created = sum(1 for r in results if r.success and r.error != "Issue already exists")
        skipped = sum(1 for r in results if r.success and r.error == "Issue already exists")
        failed = sum(1 for r in results if not r.success)

        console.print(
            f"[green]✓ GitHub issues: {created} created, {skipped} skipped (duplicates), {failed} failed[/green]"
        )
    except Exception as e:
        console.print(f"[red]✗ Failed to create GitHub issues: {e}[/red]")
        log.error("GitHub issue creation failed", error=str(e))


def _send_webhook(
    args: argparse.Namespace,
    findings: list[Finding],
    cost_tracker: CostTracker,
    files_to_analyze: list[Path],
) -> None:
    """Send findings to webhook."""
    from vulnhuntr.integrations import PayloadFormat, WebhookConfig, WebhookNotifier

    try:
        format_map = {
            "json": PayloadFormat.JSON,
            "slack": PayloadFormat.SLACK,
            "discord": PayloadFormat.DISCORD,
            "teams": PayloadFormat.TEAMS,
        }
        webhook_format = format_map.get(args.webhook_format, PayloadFormat.JSON)
        webhook_secret = args.webhook_secret or os.getenv("WEBHOOK_SECRET")

        config = WebhookConfig(
            url=args.webhook,
            format=webhook_format,
            secret=webhook_secret,
        )
        notifier = WebhookNotifier(config=config)
        result = notifier.send_batch(
            findings=findings,
        )
        if result.success:
            console.print(f"[green]✓ Findings sent to webhook: {args.webhook}[/green]")
        else:
            console.print("[red]✗ Failed to send findings to webhook[/red]")
    except Exception as e:
        console.print(f"[red]✗ Webhook notification failed: {e}[/red]")
        log.error("Webhook notification failed", error=str(e))
