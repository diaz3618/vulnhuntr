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
from typing import TYPE_CHECKING, cast

import structlog

from vulnhuntr.checkpoint import AnalysisCheckpoint
from vulnhuntr.config import load_config, merge_config_with_args
from vulnhuntr.core.models import Response
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
):
    """Initialize LLM client with optional cost tracking callback.

    Args:
        llm_arg: LLM provider ('claude', 'gpt', 'ollama')
        system_prompt: System prompt to use
        cost_callback: Optional callback for cost tracking

    Returns:
        Initialized LLM client

    Raises:
        ValueError: If invalid LLM argument provided
    """
    from vulnhuntr.llms import ChatGPT, Claude, Ollama, OpenRouter

    llm_arg = llm_arg.lower()

    if llm_arg == "claude":
        model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
        base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
        return Claude(model, base_url, system_prompt, cost_callback)

    elif llm_arg == "gpt":
        model = os.getenv("OPENAI_MODEL", "chatgpt-4o-latest")
        base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        return ChatGPT(model, base_url, system_prompt, cost_callback)

    elif llm_arg == "openrouter":
        model = os.getenv("OPENROUTER_MODEL", "qwen/qwen3-coder:free")
        base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
        return OpenRouter(model, base_url, system_prompt, cost_callback)

    elif llm_arg == "ollama":
        model = os.getenv("OLLAMA_MODEL", "llama3")
        base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434/api/generate")
        return Ollama(model, base_url, system_prompt, cost_callback)

    else:
        raise ValueError(f"Invalid LLM argument: {llm_arg}\nValid options are: claude, gpt, ollama, openrouter")


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
    5. LLM analysis
    6. Report generation

    Args:
        args: Parsed CLI arguments

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    import json
    import re

    from vulnhuntr.core.xml_models import (
        AnalysisApproach,
        CodeDefinitions,
        ExampleBypasses,
        FileCode,
        Guidelines,
        Instructions,
        PreviousAnalysis,
        ReadmeContent,
        ReadmeSummary,
        ResponseFormat,
        to_xml_bytes,
    )
    from vulnhuntr.prompts import (
        ANALYSIS_APPROACH_TEMPLATE,
        GUIDELINES_TEMPLATE,
        INITIAL_ANALYSIS_PROMPT_TEMPLATE,
        README_SUMMARY_PROMPT_TEMPLATE,
        SYS_PROMPT_TEMPLATE,
        VULN_SPECIFIC_BYPASSES_AND_PROMPTS,
    )

    # Load configuration from .vulnhuntr.yaml (if present)
    config = load_config(start_dir=Path(args.root))
    config = merge_config_with_args(config, args)

    # Apply config to args where config provides defaults
    if config.budget and args.budget is None:
        args.budget = config.budget
    if config.provider and not args.llm:
        args.llm = config.provider
    if config.dry_run and not args.dry_run:
        args.dry_run = config.dry_run

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
    llm = initialize_llm(args.llm, cost_callback=cost_callback)

    # Get and summarize README
    readme_content = repo.get_readme_content()
    if readme_content:
        log.info("Summarizing project README")
        llm.set_context(file_path=None, call_type="readme")
        summary_response = llm.chat(
            (
                to_xml_bytes(ReadmeContent(content=readme_content))
                + b"\n"
                + to_xml_bytes(Instructions(instructions=README_SUMMARY_PROMPT_TEMPLATE))
            ).decode()
        )
        summary_text = str(summary_response)
        summary_match = re.findall(r"<summary>(.+?)</summary>", summary_text, re.DOTALL)
        summary = summary_match[0] if summary_match else ""
        log.info("README summary complete", summary=summary)
    else:
        log.warning("No README summary found")
        summary = ""

    # Reinitialize LLM with system prompt
    system_prompt = (
        to_xml_bytes(Instructions(instructions=SYS_PROMPT_TEMPLATE))
        + b"\n"
        + to_xml_bytes(ReadmeSummary(readme_summary=summary))
    ).decode()

    llm = initialize_llm(args.llm, system_prompt, cost_callback)

    # Track analysis success for checkpoint finalization
    analysis_success = True

    # Collect findings for reporting
    all_findings: list[Finding] = []

    # Main analysis loop
    for py_f in files_to_analyze:
        # Check budget before starting file analysis
        if budget_enforcer and not budget_enforcer.check(cost_tracker.total_cost):
            console.print(f"\n[bold red]Budget limit reached (${args.budget:.2f}). Stopping analysis.[/bold red]")
            console.print("[dim]Progress saved to checkpoint. Use --resume to continue with higher budget.[/dim]")
            analysis_success = False
            break

        # Set checkpoint current file
        checkpoint.set_current_file(py_f)

        log.info("Performing initial analysis", file=str(py_f))
        llm.set_context(file_path=str(py_f), call_type="initial")

        # Read file content
        try:
            with py_f.open(encoding="utf-8") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError) as e:
            log.error("Failed to read file", file=str(py_f), error=str(e))
            continue

        if not content:
            continue

        print(f"\nAnalyzing {py_f}")
        print("-" * 40 + "\n")

        # Initial analysis
        user_prompt = (
            to_xml_bytes(FileCode(file_path=str(py_f), file_source=content))
            + b"\n"
            + to_xml_bytes(Instructions(instructions=INITIAL_ANALYSIS_PROMPT_TEMPLATE))
            + b"\n"
            + to_xml_bytes(AnalysisApproach(analysis_approach=ANALYSIS_APPROACH_TEMPLATE))
            + b"\n"
            + to_xml_bytes(PreviousAnalysis(previous_analysis=""))
            + b"\n"
            + to_xml_bytes(Guidelines(guidelines=GUIDELINES_TEMPLATE))
            + b"\n"
            + to_xml_bytes(ResponseFormat(response_format=json.dumps(Response.model_json_schema(), indent=4)))
        ).decode()

        initial_analysis_report = cast(Response, llm.chat(user_prompt, response_model=Response, max_tokens=8192))
        log.info("Initial analysis complete", report=initial_analysis_report.model_dump())

        print_readable(initial_analysis_report)

        # Secondary analysis for each vulnerability type
        if initial_analysis_report.confidence_score > 0 and initial_analysis_report.vulnerability_types:
            for vuln_type in initial_analysis_report.vulnerability_types:
                stored_code_definitions = {}
                definitions = CodeDefinitions(definitions=[])
                same_context = False
                previous_analysis = ""
                previous_context_amount = 0
                secondary_analysis_report: Response | None = None

                for i in range(7):
                    # Check budget during iterations
                    if budget_enforcer and not budget_enforcer.check(
                        cost_tracker.total_cost, cost_tracker.get_file_cost(str(py_f))
                    ):
                        console.print("\n[bold yellow]Budget limit reached during secondary analysis.[/bold yellow]")
                        break

                    cost_before_iteration = cost_tracker.total_cost

                    log.info(
                        "Performing vuln-specific analysis",
                        iteration=i,
                        vuln_type=vuln_type,
                        file=py_f,
                    )
                    llm.set_context(file_path=str(py_f), call_type="secondary")

                    # Expand context after first iteration
                    if i > 0 and secondary_analysis_report is not None:
                        previous_context_amount = len(stored_code_definitions)
                        previous_analysis = secondary_analysis_report.analysis

                        for context_item in secondary_analysis_report.context_code:
                            if context_item.name not in stored_code_definitions:
                                match = code_extractor.extract(context_item.name, context_item.code_line, files)
                                if match:
                                    stored_code_definitions[context_item.name] = match

                        # Pydantic-xml will convert dicts to CodeDefinition objects
                        code_definitions = list(stored_code_definitions.values())
                        definitions = CodeDefinitions(definitions=code_definitions)

                        if args.verbosity > 1:
                            for definition in definitions.definitions:
                                snippet = definition.source.split("\n")[:2]
                                snippet = "\n".join(snippet) if len(snippet) > 1 else definition.source[:75]
                                print(f"Name: {definition.name}")
                                print(f"Context search: {definition.context_name_requested}")
                                print(f"File Path: {definition.file_path}")
                                print(f"First two lines from source: {snippet}\n")

                    vuln_data = VULN_SPECIFIC_BYPASSES_AND_PROMPTS.get(vuln_type, {"bypasses": [], "prompt": ""})

                    vuln_specific_user_prompt = (
                        to_xml_bytes(FileCode(file_path=str(py_f), file_source=content))
                        + b"\n"
                        + to_xml_bytes(definitions)
                        + b"\n"
                        + to_xml_bytes(ExampleBypasses(example_bypasses="\n".join(vuln_data["bypasses"])))
                        + b"\n"
                        + to_xml_bytes(Instructions(instructions=vuln_data["prompt"]))
                        + b"\n"
                        + to_xml_bytes(AnalysisApproach(analysis_approach=ANALYSIS_APPROACH_TEMPLATE))
                        + b"\n"
                        + to_xml_bytes(PreviousAnalysis(previous_analysis=previous_analysis))
                        + b"\n"
                        + to_xml_bytes(Guidelines(guidelines=GUIDELINES_TEMPLATE))
                        + b"\n"
                        + to_xml_bytes(
                            ResponseFormat(response_format=json.dumps(Response.model_json_schema(), indent=4))
                        )
                    ).decode()

                    secondary_analysis_report = cast(
                        Response,
                        llm.chat(
                            vuln_specific_user_prompt,
                            response_model=Response,
                            max_tokens=8192,
                        ),
                    )
                    log.info(
                        "Secondary analysis complete",
                        secondary_analysis_report=secondary_analysis_report.model_dump(),
                    )

                    # Check iteration costs
                    if budget_enforcer:
                        iteration_cost = cost_tracker.total_cost - cost_before_iteration
                        if not budget_enforcer.should_continue_iteration(
                            file_path=str(py_f),
                            iteration=i,
                            iteration_cost=iteration_cost,
                            total_cost=cost_tracker.total_cost,
                        ):
                            if args.verbosity == 0:
                                print_readable(secondary_analysis_report)
                            console.print("\n[bold yellow]Stopping iterations - cost escalating.[/bold yellow]")
                            break

                    if args.verbosity > 0:
                        print_readable(secondary_analysis_report)

                    if not secondary_analysis_report.context_code:
                        log.debug("No new context functions or classes found")
                        if args.verbosity == 0:
                            print_readable(secondary_analysis_report)
                        break

                    if previous_context_amount >= len(stored_code_definitions) and i > 0:
                        if same_context:
                            log.debug("No new context functions or classes requested")
                            if args.verbosity == 0:
                                print_readable(secondary_analysis_report)
                            break
                        same_context = True
                        log.debug("No new context functions or classes requested")

                # Collect finding if vulnerability confirmed
                if "secondary_analysis_report" in dir() and secondary_analysis_report.confidence_score >= 5:
                    finding = response_to_finding(
                        response=secondary_analysis_report,
                        file_path=str(py_f),
                        vuln_type=vuln_type,
                        context_code=stored_code_definitions,
                    )
                    all_findings.append(finding)
                    log.info(
                        "Finding collected for reporting",
                        vuln_type=vuln_type.value,
                        file=str(py_f),
                        confidence=secondary_analysis_report.confidence_score,
                    )

        # Mark file as complete in checkpoint
        checkpoint.mark_file_complete(
            py_f,
            initial_analysis_report.model_dump() if initial_analysis_report else None,
        )

    # Finalize checkpoint
    checkpoint.finalize(success=analysis_success and len(files_to_analyze) > 0)

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

    # Ensure reports directory exists if any reports are being generated
    reports_dir = Path(args.reports_dir) if hasattr(args, "reports_dir") else None
    if reports_dir and (args.sarif or args.html or args.json or args.csv or args.markdown):
        reports_dir.mkdir(parents=True, exist_ok=True)

    # SARIF report
    if args.sarif:
        try:
            sarif_path = Path(args.sarif)
            sarif_path.parent.mkdir(parents=True, exist_ok=True)
            reporter = SARIFReporter(output_path=sarif_path)
            reporter.add_findings(all_findings)
            reporter.write()
            print_report_status("SARIF", args.sarif, True)
        except Exception as e:
            print_report_status("SARIF", args.sarif, False, str(e))
            log.error("SARIF report failed", error=str(e))

    # HTML report
    if args.html:
        try:
            html_path = Path(args.html)
            html_path.parent.mkdir(parents=True, exist_ok=True)
            reporter = HTMLReporter(output_path=html_path)
            reporter.add_findings(all_findings)
            reporter.write()
            print_report_status("HTML", args.html, True)
        except Exception as e:
            print_report_status("HTML", args.html, False, str(e))
            log.error("HTML report failed", error=str(e))

    # JSON report
    if args.json:
        try:
            json_path = Path(args.json)
            json_path.parent.mkdir(parents=True, exist_ok=True)
            reporter = JSONReporter(output_path=json_path)
            reporter.add_findings(all_findings)
            reporter.write()
            print_report_status("JSON", args.json, True)
        except Exception as e:
            print_report_status("JSON", args.json, False, str(e))
            log.error("JSON report failed", error=str(e))

    # CSV report
    if args.csv:
        try:
            csv_path = Path(args.csv)
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            reporter = CSVReporter(output_path=csv_path)
            reporter.add_findings(all_findings)
            reporter.write()
            print_report_status("CSV", args.csv, True)
        except Exception as e:
            print_report_status("CSV", args.csv, False, str(e))
            log.error("CSV report failed", error=str(e))

    # Markdown report
    if args.markdown:
        try:
            md_path = Path(args.markdown)
            md_path.parent.mkdir(parents=True, exist_ok=True)
            reporter = MarkdownReporter(
                output_path=md_path,
                title=f"Vulnhuntr Security Report - {Path(args.root).name}",
            )
            reporter.add_findings(all_findings)
            reporter.write()
            print_report_status("Markdown", args.markdown, True)
        except Exception as e:
            print_report_status("Markdown", args.markdown, False, str(e))
            log.error("Markdown report failed", error=str(e))

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
            (SARIFReporter(), "sarif"),
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
