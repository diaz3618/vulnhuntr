"""
Vulnhuntr Core Module
=====================

Core domain logic for vulnerability analysis.

Submodules:
- models: Data models (VulnType, Response, ContextCode)
- xml_models: XML/Pydantic models for LLM prompts
- repo: Repository operations (RepoOps)
- analysis: Vulnerability analysis orchestrator
"""

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
    # Repo Operations
    "RepoOps",
    # Analysis
    "AnalysisConfig",
    "AnalysisResult",
    "VulnerabilityAnalyzer",
]
