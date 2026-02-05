"""
Command Line Interface Module
=============================

Provides CLI parsing, output formatting, and execution orchestration.

Submodules:
- parser: Argument parsing and validation
- output: Console output formatting and display
- runner: Main execution orchestration
"""

from vulnhuntr.cli.parser import create_argument_parser, validate_args, normalize_args
from vulnhuntr.cli.output import (
    print_readable,
    print_dry_run_report,
    print_resume_info,
    print_analysis_progress,
    print_cost_summary,
    print_findings_summary,
    print_report_status,
)
from vulnhuntr.cli.runner import run_analysis, initialize_llm, get_model_name

__all__ = [
    # Parser
    "create_argument_parser",
    "validate_args",
    "normalize_args",
    # Output
    "print_readable",
    "print_dry_run_report",
    "print_resume_info",
    "print_analysis_progress",
    "print_cost_summary",
    "print_findings_summary",
    "print_report_status",
    # Runner
    "run_analysis",
    "initialize_llm",
    "get_model_name",
]
