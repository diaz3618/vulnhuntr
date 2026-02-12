"""
CSV Reporter
============

Generates CSV reports for spreadsheet applications.
"""

import csv
import io
from pathlib import Path
from typing import Any

import structlog

from .base import Finding, ReporterBase

log = structlog.get_logger("vulnhuntr.reporters.csv")


class CSVReporter(ReporterBase):
    """Generate CSV format reports.

    Produces comma-separated values output suitable for import
    into spreadsheet applications like Excel or Google Sheets.

    Note: Due to CSV's flat structure, some complex fields like
    context_code are serialized as JSON strings or omitted.

    Example:
        ```python
        reporter = CSVReporter(output_path=Path("report.csv"))
        reporter.add_finding(finding)
        reporter.write()
        ```
    """

    # Column definitions with headers
    COLUMNS = [
        ("rule_id", "Vulnerability Type"),
        ("title", "Title"),
        ("severity", "Severity"),
        ("confidence_score", "Confidence (0-10)"),
        ("file_path", "File Path"),
        ("start_line", "Start Line"),
        ("end_line", "End Line"),
        ("cwe_id", "CWE ID"),
        ("cwe_name", "CWE Name"),
        ("description", "Description"),
        ("analysis", "Analysis"),
        ("poc", "Proof of Concept"),
        ("discovered_at", "Discovered At"),
    ]

    def __init__(
        self,
        output_path: Path | None = None,
        include_scratchpad: bool = False,
        include_context: bool = True,
        delimiter: str = ",",
        include_header: bool = True,
    ):
        """Initialize CSV reporter.

        Args:
            output_path: Path for the output CSV file
            include_scratchpad: Include LLM reasoning in reports
            include_context: Include code context (as JSON string)
            delimiter: CSV delimiter character
            include_header: Include header row
        """
        super().__init__(output_path, include_scratchpad, include_context)
        self.delimiter = delimiter
        self.include_header = include_header

    def _get_columns(self) -> list[tuple]:
        """Get column definitions based on settings."""
        columns = list(self.COLUMNS)

        if self.include_scratchpad:
            columns.append(("scratchpad", "Analysis Details"))

        if self.include_context:
            columns.append(("context_code", "Context Code"))

        return columns

    def _finding_to_row(self, finding: Finding) -> dict[str, Any]:
        """Convert a Finding to a row dictionary."""
        row = {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity.value,
            "confidence_score": finding.confidence_score,
            "file_path": finding.file_path,
            "start_line": finding.start_line or "",
            "end_line": finding.end_line or "",
            "cwe_id": finding.cwe_id or "",
            "cwe_name": finding.cwe_name or "",
            "description": finding.description,
            "analysis": finding.analysis,
            "poc": finding.poc or "",
            "discovered_at": finding.discovered_at.isoformat(),
        }

        if self.include_scratchpad:
            row["scratchpad"] = finding.scratchpad or ""

        if self.include_context:
            # Serialize context as semicolon-separated names
            if finding.context_code:
                row["context_code"] = "; ".join(ctx.get("name", "") for ctx in finding.context_code)
            else:
                row["context_code"] = ""

        return row

    def generate(self) -> str:
        """Generate CSV report.

        Returns:
            CSV string containing the report
        """
        output = io.StringIO()
        columns = self._get_columns()
        field_names = [col[0] for col in columns]

        writer = csv.DictWriter(
            output,
            fieldnames=field_names,
            delimiter=self.delimiter,
            quoting=csv.QUOTE_ALL,
            extrasaction="ignore",
        )

        if self.include_header:
            # Write custom header with friendly names
            header_row = {col[0]: col[1] for col in columns}
            writer.writerow(header_row)

        for finding in self.findings:
            row = self._finding_to_row(finding)
            writer.writerow(row)

        log.info("CSV report generated", findings=len(self.findings))

        return output.getvalue()
