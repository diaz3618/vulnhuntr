"""Core domain logic for vulnerability analysis."""

from __future__ import annotations

from vulnhuntr.core.analysis import (
    AnalysisConfig,
    AnalysisResult,
    VulnerabilityAnalyzer,
)
from vulnhuntr.core.models import (
    ContextCode,
    Response,
    VulnType,
)
from vulnhuntr.core.repo import RepoOps
from vulnhuntr.core.trace import ExecutionTracer, InvariantViolationError
from vulnhuntr.core.xml_models import (
    AnalysisApproach,
    CodeDefinition,
    CodeDefinitions,
    ExampleBypasses,
    FileCode,
    Guidelines,
    Instructions,
    PreviousAnalysis,
    ReadmeContent,
    ReadmeSummary,
    ResponseFormat,
)

__all__ = [
    # Models
    "VulnType",
    "ContextCode",
    "Response",
    # XML Models
    "ReadmeContent",
    "ReadmeSummary",
    "Instructions",
    "ResponseFormat",
    "AnalysisApproach",
    "Guidelines",
    "FileCode",
    "PreviousAnalysis",
    "ExampleBypasses",
    "CodeDefinition",
    "CodeDefinitions",
    # Observability
    "ExecutionTracer",
    "InvariantViolationError",
    # Repo Operations
    "RepoOps",
    # Analysis
    "AnalysisConfig",
    "AnalysisResult",
    "VulnerabilityAnalyzer",
]
