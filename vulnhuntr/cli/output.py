"""
CLI Output Formatting
=====================

Handles console output, progress display, and formatted reporting.

Uses Rich library for styled console output.
"""

from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

if TYPE_CHECKING:
    from ..core.models import Response
    from ..checkpoint import AnalysisCheckpoint
    from ..cost_tracker import CostEstimate


# Module-level console instance
console = Console()


def print_readable(report: "Response") -> None:
    """Print a vulnerability report in a human-readable format.
    
    Args:
        report: Analysis response to print
        
    Example:
        >>> print_readable(analysis_report)
        scratchpad:
          Analyzing the file for potential vulnerabilities...
        ----------------------------------------
    """
    for attr, value in vars(report).items():
        print(f"{attr}:")
        if isinstance(value, str):
            # For multiline strings, add indentation
            lines = value.split('\n')
            for line in lines:
                print(f"  {line}")
        elif isinstance(value, list):
            # For lists, print each item on a new line
            for item in value:
                print(f"  - {item}")
        else:
            # For other types, just print the value
            print(f"  {value}")
        print('-' * 40)
        print()  # Add an empty line between attributes


def print_dry_run_report(estimate: "CostEstimate") -> None:
    """Print a formatted dry-run cost estimation report.
    
    Args:
        estimate: Cost estimation data
    """
    console.print("\n[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]              VULNHUNTR COST ESTIMATION (DRY RUN)               [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]\n")
    
    # File summary
    table = Table(title="Analysis Summary", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="dim")
    table.add_column("Value", justify="right")
    
    table.add_row("Total Files", str(estimate.total_files))
    table.add_row("Model", estimate.model)
    table.add_row("Est. Total Tokens", f"{estimate.estimated_total_tokens:,}")
    table.add_row("Est. Input Tokens", f"{estimate.estimated_input_tokens:,}")
    table.add_row("Est. Output Tokens", f"{estimate.estimated_output_tokens:,}")
    
    console.print(table)
    console.print()
    
    # Cost breakdown
    cost_table = Table(title="Cost Estimate", show_header=True, header_style="bold green")
    cost_table.add_column("Category", style="dim")
    cost_table.add_column("Amount", justify="right")
    
    cost_table.add_row("Input Cost", f"${estimate.estimated_input_cost:.4f}")
    cost_table.add_row("Output Cost", f"${estimate.estimated_output_cost:.4f}")
    cost_table.add_row("[bold]Total Estimated Cost[/bold]", f"[bold]${estimate.estimated_total_cost:.4f}[/bold]")
    
    console.print(cost_table)
    console.print()
    
    # Warnings
    if estimate.estimated_total_cost > 1.0:
        console.print("[yellow]⚠ Estimated cost exceeds $1.00. Consider using --budget flag.[/yellow]")
    
    console.print("\n[dim]Note: This is an estimate. Actual costs may vary based on LLM responses.[/dim]")
    console.print("[dim]Run without --dry-run to perform analysis.[/dim]\n")


def print_resume_info(checkpoint: "AnalysisCheckpoint") -> None:
    """Print information about a checkpoint being resumed.
    
    Args:
        checkpoint: Checkpoint to display info for
    """
    if not checkpoint.can_resume():
        return
    
    data = checkpoint.load()
    if not data:
        return
    
    console.print("\n[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]                  RESUMING FROM CHECKPOINT                     [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]\n")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Property", style="dim")
    table.add_column("Value")
    
    table.add_row("Repository", str(data.repo_path))
    table.add_row("Model", data.model)
    table.add_row("Files Completed", str(len(data.completed_files)))
    table.add_row("Files Remaining", str(data.total_files - len(data.completed_files)))
    table.add_row("Previous Cost", f"${data.total_cost:.4f}")
    table.add_row("Started At", data.started_at)
    
    console.print(table)
    console.print()


def print_analysis_progress(
    current_file: Path,
    file_index: int,
    total_files: int,
    current_cost: float,
    budget: Optional[float] = None,
) -> None:
    """Print progress information during analysis.
    
    Args:
        current_file: File currently being analyzed
        file_index: Current file index (1-based)
        total_files: Total number of files to analyze
        current_cost: Current accumulated cost
        budget: Optional budget limit
    """
    progress_pct = (file_index / total_files) * 100
    
    status = f"[{file_index}/{total_files}] ({progress_pct:.1f}%)"
    if budget:
        budget_pct = (current_cost / budget) * 100
        status += f" | Cost: ${current_cost:.4f}/${budget:.2f} ({budget_pct:.1f}%)"
    else:
        status += f" | Cost: ${current_cost:.4f}"
    
    console.print(f"\n[cyan]{status}[/cyan]")
    console.print(f"Analyzing: {current_file}")
    console.print('-' * 40)


def print_cost_summary(cost_summary: Dict[str, Any]) -> None:
    """Print a summary of analysis costs.
    
    Args:
        cost_summary: Cost summary dictionary from CostTracker
    """
    console.print("\n[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]                      COST SUMMARY                             [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]\n")
    
    table = Table(show_header=True, header_style="bold green")
    table.add_column("Metric", style="dim")
    table.add_column("Value", justify="right")
    
    table.add_row("Total Cost", f"${cost_summary.get('total_cost', 0):.4f}")
    table.add_row("Input Tokens", f"{cost_summary.get('total_input_tokens', 0):,}")
    table.add_row("Output Tokens", f"{cost_summary.get('total_output_tokens', 0):,}")
    table.add_row("Total Calls", str(cost_summary.get('total_calls', 0)))
    table.add_row("Files Analyzed", str(cost_summary.get('files_analyzed', 0)))
    
    console.print(table)
    console.print()


def print_findings_summary(findings: List[Any], total_files: int) -> None:
    """Print a summary of vulnerability findings.
    
    Args:
        findings: List of Finding objects
        total_files: Total files analyzed
    """
    if not findings:
        console.print("\n[dim]No vulnerabilities found with confidence >= 5[/dim]\n")
        return
    
    console.print(f"\n[bold green]Found {len(findings)} potential vulnerabilities[/bold green]\n")
    
    # Group by severity/type
    vuln_types: Dict[str, int] = {}
    for finding in findings:
        vuln_type = getattr(finding, 'vuln_type', 'Unknown')
        if hasattr(vuln_type, 'value'):
            vuln_type = vuln_type.value
        vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
    
    table = Table(title="Findings by Type", show_header=True, header_style="bold red")
    table.add_column("Vulnerability Type")
    table.add_column("Count", justify="right")
    
    for vtype, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
        table.add_row(vtype, str(count))
    
    console.print(table)
    console.print()


def print_report_status(
    report_type: str,
    path: str,
    success: bool,
    error: Optional[str] = None,
) -> None:
    """Print status of report generation.
    
    Args:
        report_type: Type of report (SARIF, HTML, etc.)
        path: Path where report was written
        success: Whether generation succeeded
        error: Error message if failed
    """
    if success:
        console.print(f"[green]✓ {report_type} report written to: {path}[/green]")
    else:
        console.print(f"[red]✗ Failed to write {report_type} report: {error}[/red]")


def create_progress_context():
    """Create a Rich progress context for long-running operations.
    
    Returns:
        Rich Progress context manager
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    )
