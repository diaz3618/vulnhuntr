"""
Checkpoint System for Vulnhuntr
===============================

Provides checkpointing and resume functionality for interrupted analyses.
Saves progress periodically and on errors/interrupts, allowing analysis
to resume from where it left off.

This module provides:
- AnalysisCheckpoint: Save/load/resume analysis state
- Signal handlers for graceful shutdown on Ctrl+C
"""
from __future__ import annotations

import json
import signal
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

import structlog

from vulnhuntr.cost_tracker import CostTracker

log = structlog.get_logger()


# =============================================================================
# Checkpoint Data Structures
# =============================================================================

@dataclass
class CheckpointData:
    """Data stored in a checkpoint file."""
    
    # Analysis progress
    completed_files: list[str] = field(default_factory=list)
    pending_files: list[str] = field(default_factory=list)
    current_file: Optional[str] = None
    
    # Results
    results: list[dict] = field(default_factory=list)
    
    # Cost tracking
    cost_tracker_data: Optional[dict] = None
    
    # Metadata
    repo_path: Optional[str] = None
    model: Optional[str] = None
    started_at: Optional[str] = None
    last_updated: Optional[str] = None
    vulnhuntr_version: str = "0.1.0"
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "completed_files": self.completed_files,
            "pending_files": self.pending_files,
            "current_file": self.current_file,
            "results": self.results,
            "cost_tracker_data": self.cost_tracker_data,
            "repo_path": self.repo_path,
            "model": self.model,
            "started_at": self.started_at,
            "last_updated": self.last_updated,
            "vulnhuntr_version": self.vulnhuntr_version,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> CheckpointData:
        """Create from dictionary (loaded from JSON)."""
        return cls(
            completed_files=data.get("completed_files", []),
            pending_files=data.get("pending_files", []),
            current_file=data.get("current_file"),
            results=data.get("results", []),
            cost_tracker_data=data.get("cost_tracker_data"),
            repo_path=data.get("repo_path"),
            model=data.get("model"),
            started_at=data.get("started_at"),
            last_updated=data.get("last_updated"),
            vulnhuntr_version=data.get("vulnhuntr_version", "0.1.0"),
        )


# =============================================================================
# Analysis Checkpoint
# =============================================================================

class AnalysisCheckpoint:
    """Manages checkpoint save/load/resume for vulnerability analysis.
    
    Usage:
        checkpoint = AnalysisCheckpoint(
            checkpoint_dir=Path(".vulnhuntr_checkpoint"),
            save_frequency=5
        )
        
        # Start new analysis
        checkpoint.start(repo_path, files_to_analyze, model)
        
        # During analysis
        for file in files:
            checkpoint.set_current_file(file)
            # ... analyze file ...
            checkpoint.mark_file_complete(file, result)
        
        # On completion or error
        checkpoint.finalize()
        
        # Resume interrupted analysis
        if checkpoint.can_resume():
            data = checkpoint.load()
            pending = data.pending_files
    """
    
    def __init__(
        self,
        checkpoint_dir: Path = Path(".vulnhuntr_checkpoint"),
        save_frequency: int = 5,
        enabled: bool = True,
    ) -> None:
        """Initialize checkpoint manager.
        
        Args:
            checkpoint_dir: Directory to store checkpoint files
            save_frequency: Save checkpoint every N completed files
            enabled: Whether checkpointing is enabled
        """
        self.checkpoint_dir = Path(checkpoint_dir)
        self.save_frequency = save_frequency
        self.enabled = enabled
        self._data: Optional[CheckpointData] = None
        self._files_since_save = 0
        self._cost_tracker: Optional[CostTracker] = None
        self._original_sigint_handler: Optional[Callable] = None
        
    @property
    def checkpoint_file(self) -> Path:
        """Path to the checkpoint file."""
        return self.checkpoint_dir / "checkpoint.json"
    
    def _ensure_directory(self) -> None:
        """Create checkpoint directory if it doesn't exist."""
        if self.enabled:
            self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
    
    def start(
        self,
        repo_path: Path,
        files_to_analyze: list[Path],
        model: str,
        cost_tracker: Optional[CostTracker] = None,
    ) -> None:
        """Start a new analysis session.
        
        Args:
            repo_path: Path to repository being analyzed
            files_to_analyze: List of files to analyze
            model: LLM model being used
            cost_tracker: Optional CostTracker instance to include in checkpoints
        """
        if not self.enabled:
            return
            
        self._ensure_directory()
        self._cost_tracker = cost_tracker
        
        self._data = CheckpointData(
            completed_files=[],
            pending_files=[str(f) for f in files_to_analyze],
            current_file=None,
            results=[],
            repo_path=str(repo_path),
            model=model,
            started_at=datetime.now().isoformat(),
            last_updated=datetime.now().isoformat(),
        )
        
        # Install signal handler for graceful shutdown
        self._install_signal_handler()
        
        self._save()
        log.info(
            "Checkpoint initialized",
            checkpoint_dir=str(self.checkpoint_dir),
            files_count=len(files_to_analyze),
        )
    
    def set_current_file(self, file_path: Path) -> None:
        """Set the currently processing file.
        
        Args:
            file_path: Path to file currently being analyzed
        """
        if not self.enabled or self._data is None:
            return
            
        self._data.current_file = str(file_path)
        self._data.last_updated = datetime.now().isoformat()
    
    def mark_file_complete(
        self,
        file_path: Path,
        result: Optional[dict] = None,
    ) -> None:
        """Mark a file as completed and optionally store its result.
        
        Args:
            file_path: Path to completed file
            result: Analysis result for this file (optional)
        """
        if not self.enabled or self._data is None:
            return
            
        file_str = str(file_path)
        
        # Move from pending to completed
        if file_str in self._data.pending_files:
            self._data.pending_files.remove(file_str)
        if file_str not in self._data.completed_files:
            self._data.completed_files.append(file_str)
        
        # Store result
        if result is not None:
            self._data.results.append({
                "file": file_str,
                "result": result,
                "timestamp": datetime.now().isoformat(),
            })
        
        self._data.current_file = None
        self._data.last_updated = datetime.now().isoformat()
        
        # Check if we should save
        self._files_since_save += 1
        if self._files_since_save >= self.save_frequency:
            self._save()
            self._files_since_save = 0
    
    def _save(self) -> None:
        """Save checkpoint to disk."""
        if not self.enabled or self._data is None:
            return
        
        # Include cost tracker data if available
        if self._cost_tracker is not None:
            self._data.cost_tracker_data = self._cost_tracker.to_dict()
        
        self._data.last_updated = datetime.now().isoformat()
        
        try:
            self._ensure_directory()
            
            # Write to temp file first, then rename (atomic operation)
            temp_file = self.checkpoint_file.with_suffix('.tmp')
            with temp_file.open('w', encoding='utf-8') as f:
                json.dump(self._data.to_dict(), f, indent=2)
            
            temp_file.replace(self.checkpoint_file)
            
            log.debug(
                "Checkpoint saved",
                completed=len(self._data.completed_files),
                pending=len(self._data.pending_files),
            )
        except OSError as e:
            log.error("Failed to save checkpoint", error=str(e))
    
    def save_now(self) -> None:
        """Force an immediate checkpoint save.
        
        Call this on errors or before potentially long operations.
        """
        self._save()
    
    def can_resume(self) -> bool:
        """Check if there's a checkpoint that can be resumed.
        
        Returns:
            True if a valid checkpoint exists with pending files
        """
        if not self.checkpoint_file.exists():
            return False
        
        try:
            data = self.load()
            return len(data.pending_files) > 0
        except (json.JSONDecodeError, KeyError, OSError) as e:
            log.warning("Invalid checkpoint file", error=str(e))
            return False
    
    def load(self) -> CheckpointData:
        """Load checkpoint from disk.
        
        Returns:
            CheckpointData with saved state
            
        Raises:
            FileNotFoundError: If checkpoint doesn't exist
            json.JSONDecodeError: If checkpoint is corrupted
        """
        if not self.checkpoint_file.exists():
            raise FileNotFoundError(f"No checkpoint found at {self.checkpoint_file}")
        
        with self.checkpoint_file.open('r', encoding='utf-8') as f:
            data = json.load(f)
        
        return CheckpointData.from_dict(data)
    
    def resume(self, cost_tracker: Optional[CostTracker] = None) -> CheckpointData:
        """Resume from a saved checkpoint.
        
        Args:
            cost_tracker: Optional CostTracker to populate from checkpoint
            
        Returns:
            CheckpointData with saved state
        """
        data = self.load()
        self._data = data
        self._cost_tracker = cost_tracker
        
        # Restore cost tracker state if available
        if cost_tracker is not None and data.cost_tracker_data is not None:
            restored_tracker = CostTracker.from_dict(data.cost_tracker_data)
            # Copy state to provided tracker
            cost_tracker._calls = restored_tracker._calls
            cost_tracker._total_input_tokens = restored_tracker._total_input_tokens
            cost_tracker._total_output_tokens = restored_tracker._total_output_tokens
            cost_tracker._total_cost = restored_tracker._total_cost
            cost_tracker._costs_by_file = restored_tracker._costs_by_file
            cost_tracker._costs_by_model = restored_tracker._costs_by_model
        
        # Install signal handler
        self._install_signal_handler()
        
        log.info(
            "Resumed from checkpoint",
            completed=len(data.completed_files),
            pending=len(data.pending_files),
        )
        
        return data
    
    def finalize(self, success: bool = True) -> None:
        """Finalize the checkpoint (analysis complete or error).
        
        Args:
            success: Whether analysis completed successfully
        """
        if not self.enabled:
            return
        
        # Save final state
        self._save()
        
        # Restore original signal handler
        self._restore_signal_handler()
        
        if success and self._data is not None and len(self._data.pending_files) == 0:
            # Analysis complete, remove checkpoint
            self._cleanup()
            log.info("Analysis complete, checkpoint removed")
        else:
            log.info(
                "Checkpoint saved for resume",
                checkpoint_file=str(self.checkpoint_file),
            )
    
    def _cleanup(self) -> None:
        """Remove checkpoint files."""
        try:
            if self.checkpoint_file.exists():
                self.checkpoint_file.unlink()
            # Remove directory if empty
            if self.checkpoint_dir.exists() and not any(self.checkpoint_dir.iterdir()):
                self.checkpoint_dir.rmdir()
        except OSError as e:
            log.warning("Failed to cleanup checkpoint", error=str(e))
    
    def _install_signal_handler(self) -> None:
        """Install signal handler for graceful shutdown on Ctrl+C."""
        self._original_sigint_handler = signal.getsignal(signal.SIGINT)
        
        def _handle_sigint(signum: int, frame: Any) -> None:
            log.warning("Interrupt received, saving checkpoint...")
            self._save()
            print("\n\nInterrupted! Progress saved to checkpoint.")
            print(f"Resume with: vulnhuntr --resume {self.checkpoint_dir}")
            
            # Restore original handler and re-raise
            if self._original_sigint_handler is not None:
                signal.signal(signal.SIGINT, self._original_sigint_handler)
            sys.exit(130)  # Standard exit code for Ctrl+C
        
        signal.signal(signal.SIGINT, _handle_sigint)
    
    def _restore_signal_handler(self) -> None:
        """Restore original signal handler."""
        if self._original_sigint_handler is not None:
            signal.signal(signal.SIGINT, self._original_sigint_handler)
            self._original_sigint_handler = None
    
    def get_progress_summary(self) -> dict:
        """Get a summary of analysis progress.
        
        Returns:
            Dict with progress statistics
        """
        if self._data is None:
            return {"status": "not_started"}
        
        total = len(self._data.completed_files) + len(self._data.pending_files)
        completed = len(self._data.completed_files)
        
        return {
            "status": "in_progress" if self._data.pending_files else "complete",
            "total_files": total,
            "completed_files": completed,
            "pending_files": len(self._data.pending_files),
            "progress_percent": round(completed / total * 100, 1) if total > 0 else 0,
            "current_file": self._data.current_file,
            "started_at": self._data.started_at,
            "last_updated": self._data.last_updated,
        }


def print_resume_info(checkpoint: AnalysisCheckpoint) -> None:
    """Print information about a checkpoint that can be resumed.
    
    Args:
        checkpoint: AnalysisCheckpoint instance
    """
    from rich.console import Console
    from rich.panel import Panel
    
    console = Console()
    
    if not checkpoint.can_resume():
        console.print("[yellow]No checkpoint found to resume.[/yellow]")
        return
    
    try:
        data = checkpoint.load()
    except (FileNotFoundError, json.JSONDecodeError) as e:
        console.print(f"[red]Error loading checkpoint: {e}[/red]")
        return
    
    total = len(data.completed_files) + len(data.pending_files)
    completed = len(data.completed_files)
    progress_pct = round(completed / total * 100, 1) if total > 0 else 0
    
    info_text = f"""
[bold]Repository:[/bold] {data.repo_path}
[bold]Model:[/bold] {data.model}
[bold]Progress:[/bold] {completed}/{total} files ({progress_pct}%)
[bold]Started:[/bold] {data.started_at}
[bold]Last Updated:[/bold] {data.last_updated}
"""
    
    # Cost info if available
    if data.cost_tracker_data:
        cost = data.cost_tracker_data.get('total_cost', 0)
        info_text += f"[bold]Cost so far:[/bold] ${cost:.4f} USD"
    
    console.print(Panel(
        info_text.strip(),
        title="[bold cyan]Checkpoint Found[/bold cyan]",
        border_style="cyan"
    ))
    
    console.print(f"\n[dim]Use --resume to continue this analysis.[/dim]")
