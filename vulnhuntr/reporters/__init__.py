"""
Vulnhuntr Reporters Package
===========================

This package provides report generation capabilities for vulnerability findings.

Supported formats:
- SARIF 2.1.0 (Static Analysis Results Interchange Format)
- HTML (Interactive reports with Jinja2 templates)
- JSON (Machine-readable format)
- CSV (Spreadsheet-compatible format)
- Markdown (Documentation-friendly format)
"""

from .base import (
    CWE_MAPPINGS,
    Finding,
    FindingSeverity,
    ReporterBase,
    response_to_finding,
)
from .csv_reporter import CSVReporter
from .html import HTMLReporter
from .json_reporter import JSONReporter
from .markdown_reporter import MarkdownReporter
from .sarif import SARIFReporter

__all__ = [
    "ReporterBase",
    "Finding",
    "FindingSeverity",
    "response_to_finding",
    "CWE_MAPPINGS",
    "SARIFReporter",
    "HTMLReporter",
    "JSONReporter",
    "CSVReporter",
    "MarkdownReporter",
]
