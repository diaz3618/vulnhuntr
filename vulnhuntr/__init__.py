"""
Vulnhuntr - AI-Powered Vulnerability Detection
==============================================

Vulnhuntr uses Large Language Models to identify potential security
vulnerabilities in Python source code repositories.

Key Features:
- Multi-LLM support (Claude, GPT-4, Ollama, OpenRouter)
- Iterative analysis with context expansion
- Support for common web frameworks
- Multiple output formats (SARIF, HTML, JSON, CSV, Markdown)
- Cost tracking and budget management
- Checkpoint/resume for long analyses

Modules:
- core: Core domain logic (models, analysis, repository scanning)
- cli: Command-line interface
- reporters: Report generation in various formats
- integrations: External service integrations (GitHub, webhooks)
- LLMs: LLM client implementations
- prompts: Prompt templates for vulnerability detection

Usage:
    # CLI
    python -m vulnhuntr -r /path/to/project

    # Programmatic
    from vulnhuntr.core import RepoOps, VulnerabilityAnalyzer
    from vulnhuntr.cli import initialize_llm
"""

__version__ = "1.1.3"
__author__ = "Protect AI"

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
