"""
Markdown Reporter
=================

Generates Markdown reports for documentation and README files.
"""

from datetime import datetime
from pathlib import Path
from typing import Optional
import structlog

from .base import ReporterBase, Finding, FindingSeverity

log = structlog.get_logger("vulnhuntr.reporters.markdown")

# Severity emoji mapping
SEVERITY_EMOJI = {
    FindingSeverity.CRITICAL: "🔴",
    FindingSeverity.HIGH: "🟠",
    FindingSeverity.MEDIUM: "🟡",
    FindingSeverity.LOW: "🟢",
    FindingSeverity.INFO: "🔵",
}


class MarkdownReporter(ReporterBase):
    """Generate Markdown format reports.

    Produces well-formatted Markdown output suitable for
    documentation, GitHub READMEs, or wiki pages.

    Example:
        ```python
        reporter = MarkdownReporter(output_path=Path("SECURITY_REPORT.md"))
        reporter.add_finding(finding)
        reporter.write()
        ```
    """

    def __init__(
        self,
        output_path: Optional[Path] = None,
        include_scratchpad: bool = False,
        include_context: bool = True,
        include_toc: bool = True,
        title: str = "Security Vulnerability Report",
    ):
        """Initialize Markdown reporter.

        Args:
            output_path: Path for the output Markdown file
            include_scratchpad: Include LLM reasoning in reports
            include_context: Include code context snippets
            include_toc: Include table of contents
            title: Report title
        """
        super().__init__(output_path, include_scratchpad, include_context)
        self.include_toc = include_toc
        self.title = title

    def _generate_summary_section(self) -> str:
        """Generate the summary section."""
        summary = self.get_summary()
        severity_counts = summary.get("by_severity", {})
        vuln_counts = summary.get("by_vulnerability_type", {})

        lines = [
            "## Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Findings | {summary.get('total_findings', 0)} |",
            f"| Files Affected | {summary.get('files_affected', 0)} |",
            f"| Vulnerability Types | {len(vuln_counts)} |",
            "",
        ]

        # Severity breakdown
        if severity_counts:
            lines.append("### Severity Breakdown")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for severity in ["critical", "high", "medium", "low", "info"]:
                if severity in severity_counts:
                    emoji = SEVERITY_EMOJI.get(FindingSeverity(severity), "")
                    lines.append(
                        f"| {emoji} {severity.title()} | {severity_counts[severity]} |"
                    )
            lines.append("")

        # Vulnerability type breakdown
        if vuln_counts:
            lines.append("### By Vulnerability Type")
            lines.append("")
            lines.append("| Type | Count |")
            lines.append("|------|-------|")
            for vuln_type, count in sorted(vuln_counts.items()):
                lines.append(f"| {vuln_type} | {count} |")
            lines.append("")

        return "\n".join(lines)

    def _generate_finding_section(self, finding: Finding, index: int) -> str:
        """Generate a section for a single finding."""
        emoji = SEVERITY_EMOJI.get(finding.severity, "")

        lines = [
            f"### {index}. {finding.title}",
            "",
            f"**Severity:** {emoji} {finding.severity.value.upper()} | "
            f"**Confidence:** {finding.confidence_score}/10",
            "",
            f"**File:** `{finding.file_path}`",
        ]

        if finding.start_line:
            line_info = f"Line {finding.start_line}"
            if finding.end_line and finding.end_line != finding.start_line:
                line_info += f"-{finding.end_line}"
            lines.append(f"**Location:** {line_info}")

        if finding.cwe_id:
            lines.append(
                f"**CWE:** [{finding.cwe_id}](https://cwe.mitre.org/data/definitions/{finding.cwe_id.replace('CWE-', '')}.html) - {finding.cwe_name}"
            )

        lines.append("")

        # Analysis
        lines.append("#### Analysis")
        lines.append("")
        lines.append(finding.analysis or finding.description)
        lines.append("")

        # Proof of Concept
        if finding.poc and finding.poc.strip():
            lines.append("#### Proof of Concept")
            lines.append("")
            lines.append("```")
            lines.append(finding.poc)
            lines.append("```")
            lines.append("")

        # Scratchpad (detailed reasoning)
        if self.include_scratchpad and finding.scratchpad:
            lines.append("<details>")
            lines.append("<summary>Analysis Details (LLM Reasoning)</summary>")
            lines.append("")
            lines.append(finding.scratchpad)
            lines.append("")
            lines.append("</details>")
            lines.append("")

        # Context code
        if self.include_context and finding.context_code:
            lines.append("<details>")
            lines.append(
                f"<summary>Analyzed Context ({len(finding.context_code)} items)</summary>"
            )
            lines.append("")
            for ctx in finding.context_code:
                name = ctx.get("name", "Unknown")
                reason = ctx.get("reason", "")
                lines.append(f"- **{name}**: {reason}")
            lines.append("")
            lines.append("</details>")
            lines.append("")

        lines.append("---")
        lines.append("")

        return "\n".join(lines)

    def _generate_toc(self) -> str:
        """Generate table of contents."""
        lines = [
            "## Table of Contents",
            "",
            "- [Summary](#summary)",
            "- [Findings](#findings)",
        ]

        for i, finding in enumerate(self.findings, 1):
            # Generate anchor from title
            anchor = finding.title.lower().replace(" ", "-").replace(".", "")
            lines.append(f"  - [{i}. {finding.title}](#{i}-{anchor})")

        lines.append("")
        return "\n".join(lines)

    def generate(self) -> str:
        """Generate Markdown report.

        Returns:
            Markdown string containing the report
        """
        lines = [
            f"# {self.title}",
            "",
            f"> Generated by **Vulnhuntr** v{self.metadata.get('tool_version', '1.0.0')} on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
        ]

        # Table of contents
        if self.include_toc and self.findings:
            lines.append(self._generate_toc())

        # Summary
        lines.append(self._generate_summary_section())

        # Findings
        lines.append("## Findings")
        lines.append("")

        if self.findings:
            for i, finding in enumerate(self.findings, 1):
                lines.append(self._generate_finding_section(finding, i))
        else:
            lines.append("No vulnerabilities found.")
            lines.append("")

        # Footer
        lines.extend(
            [
                "---",
                "",
                "*This report was automatically generated by [Vulnhuntr](https://github.com/protectai/vulnhuntr), an LLM-powered vulnerability scanner.*",
            ]
        )

        log.info("Markdown report generated", findings=len(self.findings))

        return "\n".join(lines)
