"""
CLI Argument Parser
===================

Handles command-line argument parsing and validation for Vulnhuntr.

This module provides:
- Argument parser creation with all supported options
- Argument validation and normalization
- Help text and usage documentation
"""

import argparse
from pathlib import Path
from typing import Optional


def create_argument_parser() -> argparse.ArgumentParser:
    """Create the argument parser with all CLI options.
    
    Returns:
        Configured ArgumentParser instance
        
    Example:
        >>> parser = create_argument_parser()
        >>> args = parser.parse_args(['--root', '/path/to/project'])
    """
    parser = argparse.ArgumentParser(
        prog='vulnhuntr',
        description='Analyze a GitHub project for vulnerabilities. '
                    'Export your ANTHROPIC_API_KEY/OPENAI_API_KEY before running.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vulnhuntr -r /path/to/project
  vulnhuntr -r /path/to/project -l gpt --budget 5.00
  vulnhuntr -r /path/to/project --sarif report.sarif --html report.html
  vulnhuntr -r /path/to/project --dry-run
        """
    )
    
    # Required arguments
    parser.add_argument(
        '-r', '--root',
        type=str,
        required=True,
        help='Path to the root directory of the project'
    )
    
    # Analysis options
    parser.add_argument(
        '-a', '--analyze',
        type=str,
        help='Specific path or file within the project to analyze'
    )
    
    parser.add_argument(
        '-l', '--llm',
        type=str,
        choices=['claude', 'gpt', 'ollama'],
        default='claude',
        help='LLM client to use (default: claude)'
    )
    
    parser.add_argument(
        '-v', '--verbosity',
        action='count',
        default=0,
        help='Increase output verbosity (-v for INFO, -vv for DEBUG)'
    )
    
    # Cost management arguments
    cost_group = parser.add_argument_group('Cost Management')
    
    cost_group.add_argument(
        '--dry-run',
        action='store_true',
        help='Estimate costs without running analysis'
    )
    
    cost_group.add_argument(
        '--budget',
        type=float,
        help='Maximum budget in USD (stops analysis when exceeded)'
    )
    
    cost_group.add_argument(
        '--resume',
        type=str,
        nargs='?',
        const='.vulnhuntr_checkpoint',
        help='Resume from checkpoint (default: .vulnhuntr_checkpoint)'
    )
    
    cost_group.add_argument(
        '--no-checkpoint',
        action='store_true',
        help='Disable checkpointing'
    )
    
    # Reporting arguments
    report_group = parser.add_argument_group('Report Generation')
    
    report_group.add_argument(
        '--sarif',
        type=str,
        metavar='PATH',
        help='Output SARIF 2.1.0 report to specified file'
    )
    
    report_group.add_argument(
        '--html',
        type=str,
        metavar='PATH',
        help='Output HTML report to specified file'
    )
    
    report_group.add_argument(
        '--json',
        type=str,
        metavar='PATH',
        help='Output JSON report to specified file'
    )
    
    report_group.add_argument(
        '--csv',
        type=str,
        metavar='PATH',
        help='Output CSV report to specified file'
    )
    
    report_group.add_argument(
        '--markdown',
        type=str,
        metavar='PATH',
        help='Output Markdown report to specified file'
    )
    
    report_group.add_argument(
        '--export-all',
        type=str,
        metavar='DIR',
        help='Export all report formats to specified directory'
    )
    
    # Integration arguments
    integration_group = parser.add_argument_group('Integrations')
    
    integration_group.add_argument(
        '--create-issues',
        action='store_true',
        help='Create GitHub issues for findings '
             '(requires GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO env vars)'
    )
    
    integration_group.add_argument(
        '--webhook',
        type=str,
        metavar='URL',
        help='Send findings to webhook URL'
    )
    
    integration_group.add_argument(
        '--webhook-format',
        type=str,
        choices=['json', 'slack', 'discord', 'teams'],
        default='json',
        help='Webhook payload format (default: json)'
    )
    
    integration_group.add_argument(
        '--webhook-secret',
        type=str,
        help='Secret for HMAC webhook signature (or set WEBHOOK_SECRET env var)'
    )
    
    return parser


def validate_args(args: argparse.Namespace) -> Optional[str]:
    """Validate parsed arguments.
    
    Args:
        args: Parsed argument namespace
        
    Returns:
        Error message if validation fails, None if valid
    """
    root_path = Path(args.root)
    
    # Validate root path exists
    if not root_path.exists():
        return f"Root path does not exist: {args.root}"
    
    if not root_path.is_dir():
        return f"Root path is not a directory: {args.root}"
    
    # Validate analyze path if specified
    if args.analyze:
        analyze_path = Path(args.analyze)
        if not analyze_path.is_absolute():
            analyze_path = root_path / analyze_path
        
        if not analyze_path.exists():
            return f"Analyze path does not exist: {args.analyze}"
    
    # Validate budget is positive
    if args.budget is not None and args.budget <= 0:
        return "Budget must be a positive number"
    
    # Validate report paths are writable
    for report_arg in ['sarif', 'html', 'json', 'csv', 'markdown']:
        report_path = getattr(args, report_arg, None)
        if report_path:
            report_file = Path(report_path)
            # Check parent directory exists or can be created
            if report_file.parent and not report_file.parent.exists():
                try:
                    report_file.parent.mkdir(parents=True, exist_ok=True)
                except OSError as e:
                    return f"Cannot create directory for {report_arg} report: {e}"
    
    # Validate export-all directory
    if hasattr(args, 'export_all') and args.export_all:
        export_dir = Path(args.export_all)
        if export_dir.exists() and not export_dir.is_dir():
            return f"Export path exists but is not a directory: {args.export_all}"
    
    return None


def normalize_args(args: argparse.Namespace) -> argparse.Namespace:
    """Normalize parsed arguments (convert paths to absolute, etc.).
    
    Args:
        args: Parsed argument namespace
        
    Returns:
        Normalized argument namespace
    """
    # Convert root to absolute path
    args.root = str(Path(args.root).resolve())
    
    # Convert analyze path to absolute if relative
    if args.analyze:
        analyze_path = Path(args.analyze)
        if not analyze_path.is_absolute():
            args.analyze = str((Path(args.root) / analyze_path).resolve())
        else:
            args.analyze = str(analyze_path.resolve())
    
    # Convert report paths to absolute
    for report_arg in ['sarif', 'html', 'json', 'csv', 'markdown']:
        report_path = getattr(args, report_arg, None)
        if report_path:
            setattr(args, report_arg, str(Path(report_path).resolve()))
    
    # Convert export-all to absolute
    if hasattr(args, 'export_all') and args.export_all:
        args.export_all = str(Path(args.export_all).resolve())
    
    # Convert resume path to absolute
    if args.resume:
        args.resume = str(Path(args.resume).resolve())
    
    return args
