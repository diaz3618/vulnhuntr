"""
Vulnhuntr - AI-Powered Vulnerability Detection

Uses LLMs to identify security vulnerabilities in Python source code
repositories via iterative analysis with context expansion.

    python -m vulnhuntr -r /path/to/project
"""

from __future__ import annotations

__version__ = "1.3.1"
__author__ = "Protect AI"
__maintainer__ = "Daniel Diaz Santiago"

# Re-export key classes for convenience
from vulnhuntr.cli import get_model_name, initialize_llm, run_analysis
from vulnhuntr.core import (
    AnalysisConfig,
    AnalysisResult,
    ContextCode,
    RepoOps,
    Response,
    VulnerabilityAnalyzer,
    VulnType,
)
from vulnhuntr.reporters import (
    CSVReporter,
    Finding,
    FindingSeverity,
    HTMLReporter,
    JSONReporter,
    MarkdownReporter,
    SARIFReporter,
    response_to_finding,
)

__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__maintainer__",
    # Core
    "VulnType",
    "Response",
    "ContextCode",
    "RepoOps",
    "VulnerabilityAnalyzer",
    "AnalysisConfig",
    "AnalysisResult",
    # CLI
    "run_analysis",
    "initialize_llm",
    "get_model_name",
    # Reporters
    "Finding",
    "FindingSeverity",
    "SARIFReporter",
    "HTMLReporter",
    "JSONReporter",
    "CSVReporter",
    "MarkdownReporter",
    "response_to_finding",
]
