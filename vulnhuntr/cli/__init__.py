"""
Command Line Interface Module
=============================

Provides CLI parsing, output formatting, and execution orchestration.

Submodules:
- parser: Argument parsing and validation
- output: Console output formatting and display
- runner: Main execution orchestration
"""

from vulnhuntr.cli.output import (
    print_analysis_progress,
    print_cost_summary,
    print_dry_run_report,
    print_findings_summary,
    print_readable,
    print_report_status,
    print_resume_info,
)
from vulnhuntr.cli.parser import create_argument_parser, normalize_args, validate_args
from vulnhuntr.cli.runner import get_model_name, initialize_llm, run_analysis

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
