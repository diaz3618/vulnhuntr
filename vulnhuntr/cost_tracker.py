"""
Cost Tracker for Vulnhuntr
==========================

Token usage tracking, cost calculation, budget enforcement, and cost reporting
for LLM API calls.

This module provides:
- TokenUsage: Dataclass for individual API call metrics
- CostTracker: Tracks cumulative token usage and costs
- BudgetEnforcer: Enforces budget limits with warnings and hard stops
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import structlog

log = structlog.get_logger()


# =============================================================================
# Pricing Configuration
# =============================================================================

# Prices per 1,000 tokens (USD)
# Updated: 2024-12 - Check provider pricing pages for current rates
PRICING_TABLE: dict[str, dict[str, float]] = {
    # Claude models (Anthropic)
    "claude-3-5-sonnet-20241022": {"input": 0.003, "output": 0.015},
    "claude-3-5-sonnet-latest": {"input": 0.003, "output": 0.015},
    "claude-sonnet-4-5": {"input": 0.003, "output": 0.015},
    "claude-3-opus-20240229": {"input": 0.015, "output": 0.075},
    "claude-3-haiku-20240307": {"input": 0.00025, "output": 0.00125},
    # ChatGPT models (OpenAI)
    "gpt-4o": {"input": 0.005, "output": 0.015},
    "gpt-4o-2024-08-06": {"input": 0.005, "output": 0.015},
    "chatgpt-4o-latest": {"input": 0.005, "output": 0.015},
    "gpt-4-turbo": {"input": 0.01, "output": 0.03},
    "gpt-4-turbo-preview": {"input": 0.01, "output": 0.03},
    "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
    # Local models (free)
    "ollama": {"input": 0.0, "output": 0.0},
    "llama3": {"input": 0.0, "output": 0.0},
    "codellama": {"input": 0.0, "output": 0.0},
    "mistral": {"input": 0.0, "output": 0.0},
}

# Default pricing for unknown models (conservative estimate)
DEFAULT_PRICING: dict[str, float] = {"input": 0.01, "output": 0.03}


def get_model_pricing(model: str) -> dict[str, float]:
    """Get pricing for a model, with fallback to default pricing.
    
    Args:
        model: Model name/identifier
        
    Returns:
        Dict with 'input' and 'output' prices per 1K tokens
    """
    # Direct match
    if model in PRICING_TABLE:
        return PRICING_TABLE[model]
    
    # Partial match (e.g., "claude-3-5-sonnet" matches "claude-3-5-sonnet-20241022")
    model_lower = model.lower()
    for known_model, pricing in PRICING_TABLE.items():
        if known_model.lower() in model_lower or model_lower in known_model.lower():
            return pricing
    
    # Check for provider patterns
    if "claude" in model_lower:
        return PRICING_TABLE.get("claude-3-5-sonnet-20241022", DEFAULT_PRICING)
    if "gpt-4o" in model_lower:
        return PRICING_TABLE.get("gpt-4o", DEFAULT_PRICING)
    if "gpt-4" in model_lower:
        return PRICING_TABLE.get("gpt-4-turbo", DEFAULT_PRICING)
    if "gpt-3" in model_lower:
        return PRICING_TABLE.get("gpt-3.5-turbo", DEFAULT_PRICING)
    
    log.warning("Unknown model, using default pricing", model=model)
    return DEFAULT_PRICING


# =============================================================================
# Token Usage Dataclass
# =============================================================================

@dataclass
class TokenUsage:
    """Records token usage and cost for a single LLM API call."""
    
    input_tokens: int
    output_tokens: int
    model: str
    cost_usd: float
    timestamp: datetime = field(default_factory=datetime.now)
    file_path: Optional[str] = None
    call_type: str = "analysis"  # 'readme', 'initial', 'secondary'
    
    @property
    def total_tokens(self) -> int:
        """Total tokens for this call."""
        return self.input_tokens + self.output_tokens
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "model": self.model,
            "cost_usd": round(self.cost_usd, 6),
            "timestamp": self.timestamp.isoformat(),
            "file_path": self.file_path,
            "call_type": self.call_type,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> TokenUsage:
        """Create from dictionary (for checkpoint loading)."""
        return cls(
            input_tokens=data["input_tokens"],
            output_tokens=data["output_tokens"],
            model=data["model"],
            cost_usd=data["cost_usd"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            file_path=data.get("file_path"),
            call_type=data.get("call_type", "analysis"),
        )


# =============================================================================
# Cost Tracker
# =============================================================================

class CostTracker:
    """Tracks cumulative token usage and costs across all LLM calls.
    
    Usage:
        tracker = CostTracker()
        cost = tracker.track_call(1000, 500, "claude-3-5-sonnet-20241022", "file.py")
        summary = tracker.get_summary()
    """
    
    def __init__(self) -> None:
        """Initialize the cost tracker."""
        self._calls: list[TokenUsage] = []
        self._total_input_tokens: int = 0
        self._total_output_tokens: int = 0
        self._total_cost: float = 0.0
        self._costs_by_file: dict[str, float] = {}
        self._costs_by_model: dict[str, float] = {}
        self._start_time: datetime = datetime.now()
    
    def track_call(
        self,
        input_tokens: int,
        output_tokens: int,
        model: str,
        file_path: Optional[str] = None,
        call_type: str = "analysis",
    ) -> float:
        """Track a single LLM API call.
        
        Args:
            input_tokens: Number of input/prompt tokens
            output_tokens: Number of output/completion tokens
            model: Model name/identifier
            file_path: Path to file being analyzed (optional)
            call_type: Type of call ('readme', 'initial', 'secondary')
            
        Returns:
            Cost in USD for this call
        """
        pricing = get_model_pricing(model)
        cost = (input_tokens / 1000 * pricing["input"]) + \
               (output_tokens / 1000 * pricing["output"])
        
        usage = TokenUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=model,
            cost_usd=cost,
            file_path=file_path,
            call_type=call_type,
        )
        
        self._calls.append(usage)
        self._total_input_tokens += input_tokens
        self._total_output_tokens += output_tokens
        self._total_cost += cost
        
        # Track by file
        if file_path:
            self._costs_by_file[file_path] = \
                self._costs_by_file.get(file_path, 0.0) + cost
        
        # Track by model
        self._costs_by_model[model] = \
            self._costs_by_model.get(model, 0.0) + cost
        
        log.debug(
            "Tracked LLM call",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=model,
            cost_usd=round(cost, 4),
            total_cost_usd=round(self._total_cost, 4),
            file_path=file_path,
        )
        
        return cost
    
    @property
    def total_cost(self) -> float:
        """Total cost in USD."""
        return self._total_cost
    
    @property
    def total_input_tokens(self) -> int:
        """Total input tokens across all calls."""
        return self._total_input_tokens
    
    @property
    def total_output_tokens(self) -> int:
        """Total output tokens across all calls."""
        return self._total_output_tokens
    
    @property
    def total_tokens(self) -> int:
        """Total tokens (input + output) across all calls."""
        return self._total_input_tokens + self._total_output_tokens
    
    @property
    def call_count(self) -> int:
        """Number of API calls tracked."""
        return len(self._calls)
    
    def get_file_cost(self, file_path: str) -> float:
        """Get cost for a specific file."""
        return self._costs_by_file.get(file_path, 0.0)
    
    def get_summary(self) -> dict:
        """Get a summary of all costs.
        
        Returns:
            Dict with total costs, token counts, and breakdowns
        """
        elapsed = datetime.now() - self._start_time
        
        return {
            "total_cost_usd": round(self._total_cost, 4),
            "total_input_tokens": self._total_input_tokens,
            "total_output_tokens": self._total_output_tokens,
            "total_tokens": self.total_tokens,
            "api_calls": self.call_count,
            "costs_by_file": {k: round(v, 4) for k, v in self._costs_by_file.items()},
            "costs_by_model": {k: round(v, 4) for k, v in self._costs_by_model.items()},
            "elapsed_seconds": elapsed.total_seconds(),
            "start_time": self._start_time.isoformat(),
        }
    
    def get_detailed_report(self) -> str:
        """Get a human-readable cost report."""
        summary = self.get_summary()
        
        lines = [
            "",
            "=" * 60,
            "COST SUMMARY",
            "=" * 60,
            f"Total Cost: ${summary['total_cost_usd']:.4f} USD",
            f"Total Tokens: {summary['total_tokens']:,} "
            f"({summary['total_input_tokens']:,} in / "
            f"{summary['total_output_tokens']:,} out)",
            f"API Calls: {summary['api_calls']}",
            f"Elapsed Time: {summary['elapsed_seconds']:.1f} seconds",
            "",
        ]
        
        if summary['costs_by_model']:
            lines.append("Costs by Model:")
            for model, cost in sorted(
                summary['costs_by_model'].items(),
                key=lambda x: x[1],
                reverse=True
            ):
                lines.append(f"  {model}: ${cost:.4f}")
            lines.append("")
        
        if summary['costs_by_file']:
            lines.append("Top 10 Files by Cost:")
            sorted_files = sorted(
                summary['costs_by_file'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
            for file_path, cost in sorted_files:
                lines.append(f"  ${cost:.4f} - {file_path}")
            lines.append("")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    def to_dict(self) -> dict:
        """Serialize tracker state for checkpointing."""
        return {
            "calls": [c.to_dict() for c in self._calls],
            "total_input_tokens": self._total_input_tokens,
            "total_output_tokens": self._total_output_tokens,
            "total_cost": self._total_cost,
            "costs_by_file": self._costs_by_file,
            "costs_by_model": self._costs_by_model,
            "start_time": self._start_time.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> CostTracker:
        """Restore tracker from checkpoint data."""
        tracker = cls()
        tracker._calls = [TokenUsage.from_dict(c) for c in data.get("calls", [])]
        tracker._total_input_tokens = data.get("total_input_tokens", 0)
        tracker._total_output_tokens = data.get("total_output_tokens", 0)
        tracker._total_cost = data.get("total_cost", 0.0)
        tracker._costs_by_file = data.get("costs_by_file", {})
        tracker._costs_by_model = data.get("costs_by_model", {})
        if "start_time" in data:
            tracker._start_time = datetime.fromisoformat(data["start_time"])
        return tracker


# =============================================================================
# Budget Enforcer
# =============================================================================

class BudgetEnforcer:
    """Enforces budget limits with warnings and hard stops.
    
    Usage:
        enforcer = BudgetEnforcer(max_budget_usd=50.0, warning_threshold=0.8)
        
        # Returns True if can continue, False if budget exceeded
        if not enforcer.check(current_cost):
            print("Budget exceeded!")
            break
    """
    
    def __init__(
        self,
        max_budget_usd: Optional[float] = None,
        warning_threshold: float = 0.8,
        max_cost_per_file: Optional[float] = None,
        max_cost_per_iteration: Optional[float] = None,
    ) -> None:
        """Initialize budget enforcer.
        
        Args:
            max_budget_usd: Maximum budget in USD (None = no limit)
            warning_threshold: Warn when this fraction of budget is used (0.0-1.0)
            max_cost_per_file: Maximum cost per file in USD (None = no limit)
            max_cost_per_iteration: Maximum cost per iteration in USD (None = no limit)
        """
        self.max_budget_usd = max_budget_usd
        self.warning_threshold = warning_threshold
        self.max_cost_per_file = max_cost_per_file
        self.max_cost_per_iteration = max_cost_per_iteration
        self._warning_issued = False
        self._iteration_costs: dict[str, list[float]] = {}  # Track costs per file+iteration
    
    def check(
        self,
        current_cost: float,
        file_cost: Optional[float] = None,
    ) -> bool:
        """Check if analysis should continue based on budget.
        
        Args:
            current_cost: Total cost so far in USD
            file_cost: Cost for current file (optional, for per-file limit)
            
        Returns:
            True if analysis can continue, False if budget exceeded
        """
        # Check per-file limit
        if self.max_cost_per_file is not None and file_cost is not None:
            if file_cost >= self.max_cost_per_file:
                log.warning(
                    "Per-file cost limit reached",
                    file_cost_usd=round(file_cost, 4),
                    limit_usd=self.max_cost_per_file,
                )
                return False
        
        # No global budget limit
        if self.max_budget_usd is None:
            return True
        
        # Check warning threshold
        if not self._warning_issued and current_cost >= (self.max_budget_usd * self.warning_threshold):
            log.warning(
                "Budget warning threshold reached",
                current_cost_usd=round(current_cost, 4),
                budget_usd=self.max_budget_usd,
                percentage=round(current_cost / self.max_budget_usd * 100, 1),
            )
            self._warning_issued = True
        
        # Check hard limit
        if current_cost >= self.max_budget_usd:
            log.error(
                "Budget limit exceeded - stopping analysis",
                current_cost_usd=round(current_cost, 4),
                budget_usd=self.max_budget_usd,
            )
            return False
        
        return True
    
    def get_remaining_budget(self, current_cost: float) -> Optional[float]:
        """Get remaining budget in USD.
        
        Args:
            current_cost: Total cost so far
            
        Returns:
            Remaining budget in USD, or None if no limit
        """
        if self.max_budget_usd is None:
            return None
        return max(0.0, self.max_budget_usd - current_cost)
    
    def should_continue_iteration(
        self,
        file_path: str,
        iteration: int,
        iteration_cost: float,
        total_cost: float,
    ) -> bool:
        """Determine if analysis should continue with more iterations.
        
        This implements cost-aware context limiting by preventing expensive
        iteration loops that accumulate large context without improving results.
        
        Args:
            file_path: Path to file being analyzed
            iteration: Current iteration number (0-indexed)
            iteration_cost: Cost of the current iteration in USD
            total_cost: Total cost so far in USD
            
        Returns:
            True if should continue iterating, False if should stop
        """
        # Track iteration costs for this file
        file_key = file_path
        if file_key not in self._iteration_costs:
            self._iteration_costs[file_key] = []
        
        self._iteration_costs[file_key].append(iteration_cost)
        
        # Check per-iteration cost limit
        if self.max_cost_per_iteration is not None:
            if iteration_cost >= self.max_cost_per_iteration:
                log.warning(
                    "Per-iteration cost limit reached",
                    file=file_path,
                    iteration=iteration,
                    iteration_cost_usd=round(iteration_cost, 4),
                    limit_usd=self.max_cost_per_iteration,
                )
                return False
        
        # Check if costs are escalating (diminishing returns)
        # If iteration costs keep increasing without plateau, stop
        if len(self._iteration_costs[file_key]) >= 3:
            recent_costs = self._iteration_costs[file_key][-3:]
            # If each iteration is significantly more expensive than the last,
            # we're likely accumulating too much context
            if all(recent_costs[i] < recent_costs[i+1] * 0.8 for i in range(len(recent_costs)-1)):
                log.warning(
                    "Iteration costs escalating - stopping to prevent runaway context growth",
                    file=file_path,
                    recent_costs=[round(c, 4) for c in recent_costs],
                )
                return False
        
        # Check overall budget
        if not self.check(total_cost):
            return False
        
        return True


# =============================================================================
# Cost Estimation (for Dry Run)
# =============================================================================

def estimate_tokens(text: str) -> int:
    """Estimate token count for text.
    
    This is a rough estimate using character count heuristics.
    Actual token count varies by model and tokenizer.
    
    Args:
        text: Input text
        
    Returns:
        Estimated token count
    """
    # Rough heuristic: ~4 characters per token for English code
    # This is conservative (usually overestimates)
    return len(text) // 4


def estimate_file_cost(
    file_path: Path,
    model: str,
    max_iterations: int = 7,
    vuln_types_count: int = 7,  # Number of vulnerability types to check
) -> dict:
    """Estimate cost to analyze a single file.
    
    IMPORTANT: This is a conservative estimate. Actual costs depend on:
    - Number of vulnerability types found in initial analysis
    - How many iterations needed per vulnerability
    - Size of context code fetched during iterations
    
    Args:
        file_path: Path to Python file
        model: Model to use for analysis
        max_iterations: Maximum secondary analysis iterations per vuln type
        vuln_types_count: Number of vulnerability types that may be found
        
    Returns:
        Dict with estimated tokens and cost
    """
    try:
        content = file_path.read_text(encoding='utf-8')
    except (OSError, UnicodeDecodeError) as e:
        log.warning("Could not read file for estimation", file=str(file_path), error=str(e))
        return {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0, "error": str(e)}
    
    file_tokens = estimate_tokens(content)
    pricing = get_model_pricing(model)
    
    # Estimation based on ACTUAL vulnhuntr analysis pattern:
    # 
    # 1. Initial analysis: 1 call to scan for ALL vulnerability types
    # 2. Secondary analysis: For EACH vuln type found, up to max_iterations calls
    #    - Vulnhuntr checks: LFI, RCE, SSRF, AFO, SQLI, XSS, IDOR (7 types)
    #    - Average files trigger 2-3 vuln types for deeper analysis
    #    - Each secondary analysis can run up to 7 iterations
    #
    # Conservative estimate: assume 2-3 vuln types found, ~5 iterations each
    
    # Overhead for prompts, XML wrappers, instructions, examples
    prompt_overhead = 3000  # System prompt + vuln-specific prompts + examples
    
    # Context grows significantly with each iteration (fetched functions)
    # Each iteration typically adds 500-2000 tokens of context code
    avg_context_per_iteration = 1000
    
    # Initial analysis
    initial_input = file_tokens + prompt_overhead
    initial_output = 2000  # Full JSON response with scratchpad
    
    # Secondary analysis estimates
    # Assume average of 2.5 vuln types found, 5 iterations each
    avg_vuln_types_found = 2.5
    avg_iterations_per_vuln = 5  # Often hits max, but not always
    
    secondary_calls = avg_vuln_types_found * avg_iterations_per_vuln
    
    # Each secondary call includes file + accumulated context
    # Context grows: iteration 1 = 0, iteration 2 = 1000, ... iteration 5 = 4000
    avg_accumulated_context = avg_context_per_iteration * (avg_iterations_per_vuln / 2)
    secondary_input_per_call = file_tokens + prompt_overhead + avg_accumulated_context
    secondary_output_per_call = 2500  # Detailed analysis with POC
    
    total_input = int(initial_input + (secondary_input_per_call * secondary_calls))
    total_output = int(initial_output + (secondary_output_per_call * secondary_calls))
    
    cost = (total_input / 1000 * pricing["input"]) + \
           (total_output / 1000 * pricing["output"])
    
    return {
        "file_path": str(file_path),
        "file_tokens": file_tokens,
        "estimated_input_tokens": total_input,
        "estimated_output_tokens": total_output,
        "estimated_total_tokens": total_input + total_output,
        "estimated_calls": int(1 + secondary_calls),
        "estimated_cost_usd": round(cost, 4),
    }


def estimate_analysis_cost(
    files: list[Path],
    model: str,
    max_iterations: int = 7,
) -> dict:
    """Estimate total cost to analyze multiple files.
    
    Args:
        files: List of file paths to analyze
        model: Model to use
        max_iterations: Maximum secondary iterations per file
        
    Returns:
        Dict with total estimates and per-file breakdown
    """
    file_estimates = []
    total_input = 0
    total_output = 0
    total_cost = 0.0
    
    for file_path in files:
        estimate = estimate_file_cost(file_path, model, max_iterations)
        file_estimates.append(estimate)
        
        if "error" not in estimate:
            total_input += estimate["estimated_input_tokens"]
            total_output += estimate["estimated_output_tokens"]
            total_cost += estimate["estimated_cost_usd"]
    
    # Add README summarization overhead (if exists)
    readme_overhead_cost = 0.01  # Small overhead for README processing
    total_cost += readme_overhead_cost
    
    return {
        "model": model,
        "file_count": len(files),
        "estimated_input_tokens": total_input,
        "estimated_output_tokens": total_output,
        "estimated_total_tokens": total_input + total_output,
        "estimated_cost_usd": round(total_cost, 4),
        "estimated_cost_range": {
            "low": round(total_cost * 0.5, 4),  # Best case (few iterations)
            "high": round(total_cost * 1.5, 4),  # Worst case (max iterations)
        },
        "file_estimates": file_estimates,
    }


def print_dry_run_report(estimate: dict) -> None:
    """Print a formatted dry-run cost estimate report.
    
    Args:
        estimate: Result from estimate_analysis_cost()
    """
    from rich.console import Console
    from rich.table import Table
    
    console = Console()
    
    console.print("\n[bold cyan]" + "=" * 60 + "[/bold cyan]")
    console.print("[bold cyan]DRY RUN - COST ESTIMATE[/bold cyan]")
    console.print("[bold cyan]=" * 60)
    
    console.print(f"\n[bold]Model:[/bold] {estimate['model']}")
    console.print(f"[bold]Files to analyze:[/bold] {estimate['file_count']}")
    console.print(f"\n[bold]Estimated Tokens:[/bold]")
    console.print(f"  Input:  {estimate['estimated_input_tokens']:,}")
    console.print(f"  Output: {estimate['estimated_output_tokens']:,}")
    console.print(f"  Total:  {estimate['estimated_total_tokens']:,}")
    
    console.print(f"\n[bold yellow]Estimated Cost:[/bold yellow] ${estimate['estimated_cost_usd']:.4f} USD")
    console.print(f"  Range: ${estimate['estimated_cost_range']['low']:.4f} - "
                  f"${estimate['estimated_cost_range']['high']:.4f}")
    
    # Show top 10 most expensive files
    if estimate['file_estimates']:
        console.print("\n[bold]Top 10 Most Expensive Files:[/bold]")
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("File", style="cyan")
        table.add_column("Tokens", justify="right")
        table.add_column("Est. Cost", justify="right", style="yellow")
        
        sorted_files = sorted(
            [f for f in estimate['file_estimates'] if 'error' not in f],
            key=lambda x: x['estimated_cost_usd'],
            reverse=True
        )[:10]
        
        for f in sorted_files:
            table.add_row(
                Path(f['file_path']).name,
                f"{f['file_tokens']:,}",
                f"${f['estimated_cost_usd']:.4f}"
            )
        
        console.print(table)
    
    console.print("\n[dim]Actual costs might be different based on complexity.[/dim]")
    console.print("[dim]Use --budget to set a spending limit.[/dim]")
    console.print("\n[dim]Unless you feel like swiping your card a few times per scan, set a limit![/dim]")
    
