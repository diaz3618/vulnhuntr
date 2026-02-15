"""
JSON Reporter
=============

Generates machine-readable JSON reports for programmatic processing.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from .base import Finding, ReporterBase

log = structlog.get_logger("vulnhuntr.reporters.json")


class JSONReporter(ReporterBase):
    """Generate JSON format reports.

    Produces a structured JSON output that can be easily parsed
    by other tools, scripts, or APIs.

    Example:
        ```python
        reporter = JSONReporter(output_path=Path("report.json"))
        reporter.add_finding(finding)
        content = reporter.generate()
        ```
    """

    def __init__(
        self,
        output_path: Path | None = None,
        include_scratchpad: bool = False,
        include_context: bool = True,
        indent: int = 2,
        include_metadata: bool = True,
    ):
        """Initialize JSON reporter.

        Args:
            output_path: Path for the output JSON file
            include_scratchpad: Include LLM reasoning in reports
            include_context: Include code context snippets
            indent: JSON indentation level (None for compact)
            include_metadata: Include report metadata
        """
        super().__init__(output_path, include_scratchpad, include_context)
        self.indent = indent
        self.include_metadata = include_metadata

    def _finding_to_dict(self, finding: Finding) -> dict[str, Any]:
        """Convert a Finding to a dictionary."""
        result: dict[str, Any] = {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity.value,
            "confidence_score": finding.confidence_score,
            "file_path": finding.file_path,
            "description": finding.description,
            "analysis": finding.analysis,
            "poc": finding.poc if finding.poc else None,
            "cwe_id": finding.cwe_id,
            "cwe_name": finding.cwe_name,
            "discovered_at": finding.discovered_at.isoformat().replace("+00:00", "Z"),
        }

        # Add line information if available
        if finding.start_line is not None:
            result["location"] = {
                "start_line": finding.start_line,
                "end_line": finding.end_line,
                "start_column": finding.start_column,
                "end_column": finding.end_column,
            }

        if self.include_scratchpad and finding.scratchpad:
            result["scratchpad"] = finding.scratchpad

        if self.include_context and finding.context_code:
            result["context_code"] = finding.context_code

        return result

    def generate(self) -> str:
        """Generate JSON report.

        Returns:
            JSON string containing the report
        """
        summary = self.get_summary()

        report: dict[str, Any] = {
            "findings": [self._finding_to_dict(f) for f in self.findings],
            "summary": summary,
        }

        if self.include_metadata:
            report["metadata"] = {
                "tool": self.metadata.get("tool_name", "Vulnhuntr"),
                "version": self.metadata.get("tool_version", "1.0.0"),
                "generated_at": self.metadata.get(
                    "generated_at",
                    datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                ),
                "total_findings": len(self.findings),
            }

        log.info("JSON report generated", findings=len(self.findings))

        return json.dumps(report, indent=self.indent, ensure_ascii=False, default=str)
