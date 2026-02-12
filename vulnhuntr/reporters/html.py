"""
HTML Reporter
=============

Generates interactive HTML reports with embedded styling.
Uses Jinja2 for template rendering with automatic HTML escaping.

Features:
- Responsive design with modern CSS
- Collapsible finding details
- Summary statistics and charts
- Syntax highlighting for code snippets
- Print-friendly formatting
- Dark mode support
"""

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

try:
    from jinja2 import BaseLoader, Environment, select_autoescape

    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

from .base import Finding, ReporterBase

log = structlog.get_logger("vulnhuntr.reporters.html")

# HTML Template with embedded CSS (no external dependencies)
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnhuntr Security Report</title>
    <style>
        :root {
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --bg-tertiary: #e9ecef;
            --text-primary: #212529;
            --text-secondary: #6c757d;
            --border-color: #dee2e6;
            --critical-color: #dc3545;
            --high-color: #fd7e14;
            --medium-color: #ffc107;
            --low-color: #28a745;
            --info-color: #17a2b8;
            --code-bg: #2d2d2d;
            --code-text: #f8f8f2;
        }

        @media (prefers-color-scheme: dark) {
            :root {
                --bg-primary: #1a1a2e;
                --bg-secondary: #16213e;
                --bg-tertiary: #0f3460;
                --text-primary: #eaeaea;
                --text-secondary: #a0a0a0;
                --border-color: #3a3a5e;
            }
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        header {
            text-align: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid var(--border-color);
        }

        header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }

        header .subtitle {
            color: var(--text-secondary);
            font-size: 1.1rem;
        }

        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .summary-card {
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid var(--border-color);
        }

        .summary-card .number {
            font-size: 2.5rem;
            font-weight: bold;
        }

        .summary-card .label {
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-breakdown {
            display: flex;
            gap: 0.5rem;
            justify-content: center;
            flex-wrap: wrap;
            margin-bottom: 2rem;
        }

        .severity-badge {
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.85rem;
        }

        .severity-critical { background: var(--critical-color); color: white; }
        .severity-high { background: var(--high-color); color: white; }
        .severity-medium { background: var(--medium-color); color: black; }
        .severity-low { background: var(--low-color); color: white; }
        .severity-info { background: var(--info-color); color: white; }

        .findings-section h2 {
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border-color);
        }

        .finding {
            background: var(--bg-secondary);
            border-radius: 8px;
            margin-bottom: 1rem;
            border: 1px solid var(--border-color);
            overflow: hidden;
        }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.5rem;
            cursor: pointer;
            background: var(--bg-tertiary);
            transition: background 0.2s;
        }

        .finding-header:hover {
            background: var(--border-color);
        }

        .finding-title {
            font-weight: 600;
            font-size: 1.1rem;
        }

        .finding-meta {
            display: flex;
            gap: 1rem;
            align-items: center;
        }

        .confidence-score {
            font-size: 0.85rem;
            padding: 0.25rem 0.75rem;
            background: var(--bg-primary);
            border-radius: 4px;
        }

        .finding-body {
            padding: 1.5rem;
            display: none;
        }

        .finding.expanded .finding-body {
            display: block;
        }

        .finding-row {
            margin-bottom: 1rem;
        }

        .finding-row:last-child {
            margin-bottom: 0;
        }

        .finding-label {
            font-weight: 600;
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 0.25rem;
        }

        .code-block {
            background: var(--code-bg);
            color: var(--code-text);
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.9rem;
            white-space: pre-wrap;
            word-wrap: break-word;
        }

        .cwe-tag {
            display: inline-block;
            background: var(--bg-tertiary);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.85rem;
            margin-right: 0.5rem;
        }

        .file-path {
            font-family: monospace;
            background: var(--bg-tertiary);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.9rem;
        }

        .context-item {
            background: var(--bg-tertiary);
            padding: 0.75rem;
            border-radius: 4px;
            margin-bottom: 0.5rem;
        }

        .context-name {
            font-weight: 600;
            font-family: monospace;
        }

        .context-reason {
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 0.25rem;
        }

        footer {
            text-align: center;
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border-color);
            color: var(--text-secondary);
            font-size: 0.85rem;
        }

        .expand-icon {
            transition: transform 0.2s;
        }

        .finding.expanded .expand-icon {
            transform: rotate(90deg);
        }

        @media print {
            body {
                padding: 0;
            }
            .finding-body {
                display: block !important;
            }
            .finding-header {
                cursor: default;
            }
            .expand-icon {
                display: none;
            }
        }

        @media (max-width: 768px) {
            body {
                padding: 1rem;
            }
            header h1 {
                font-size: 1.8rem;
            }
            .finding-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 0.5rem;
            }
            .finding-meta {
                width: 100%;
                justify-content: space-between;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Vulnhuntr Security Report</h1>
            <p class="subtitle">Generated on {{ generated_at }}</p>
        </header>

        <section class="summary">
            <div class="summary-card">
                <div class="number">{{ total_findings }}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="summary-card">
                <div class="number">{{ files_affected }}</div>
                <div class="label">Files Affected</div>
            </div>
            <div class="summary-card">
                <div class="number">{{ vuln_types|length }}</div>
                <div class="label">Vulnerability Types</div>
            </div>
        </section>

        <div class="severity-breakdown">
            {% if severity_counts.critical %}
            <span class="severity-badge severity-critical">{{ severity_counts.critical }} Critical</span>
            {% endif %}
            {% if severity_counts.high %}
            <span class="severity-badge severity-high">{{ severity_counts.high }} High</span>
            {% endif %}
            {% if severity_counts.medium %}
            <span class="severity-badge severity-medium">{{ severity_counts.medium }} Medium</span>
            {% endif %}
            {% if severity_counts.low %}
            <span class="severity-badge severity-low">{{ severity_counts.low }} Low</span>
            {% endif %}
            {% if severity_counts.info %}
            <span class="severity-badge severity-info">{{ severity_counts.info }} Info</span>
            {% endif %}
        </div>

        <section class="findings-section">
            <h2>Findings</h2>

            {% for finding in findings %}
            <div class="finding" id="finding-{{ loop.index }}">
                <div class="finding-header" onclick="toggleFinding({{ loop.index }})">
                    <span class="finding-title">
                        <span class="expand-icon">▶</span>
                        {{ finding.title }}
                    </span>
                    <div class="finding-meta">
                        <span class="severity-badge severity-{{ finding.severity }}">{{ finding.severity|upper }}</span>
                        <span class="confidence-score">Confidence: {{ finding.confidence_score }}/10</span>
                    </div>
                </div>
                <div class="finding-body">
                    <div class="finding-row">
                        <div class="finding-label">File</div>
                        <span class="file-path">{{ finding.file_path }}</span>
                        {% if finding.start_line %}
                        <span> (Line {{ finding.start_line }}{% if finding.end_line and finding.end_line != finding.start_line %}-{{ finding.end_line }}{% endif %})</span>
                        {% endif %}
                    </div>

                    {% if finding.cwe_id %}
                    <div class="finding-row">
                        <div class="finding-label">CWE Classification</div>
                        <span class="cwe-tag">{{ finding.cwe_id }}</span>
                        <span>{{ finding.cwe_name }}</span>
                    </div>
                    {% endif %}

                    <div class="finding-row">
                        <div class="finding-label">Analysis</div>
                        <p>{{ finding.analysis }}</p>
                    </div>

                    {% if finding.poc %}
                    <div class="finding-row">
                        <div class="finding-label">Proof of Concept</div>
                        <div class="code-block">{{ finding.poc }}</div>
                    </div>
                    {% endif %}

                    {% if include_scratchpad and finding.scratchpad %}
                    <div class="finding-row">
                        <div class="finding-label">Analysis Details</div>
                        <p>{{ finding.scratchpad }}</p>
                    </div>
                    {% endif %}

                    {% if include_context and finding.context_code %}
                    <div class="finding-row">
                        <div class="finding-label">Analyzed Context ({{ finding.context_code|length }} items)</div>
                        {% for ctx in finding.context_code %}
                        <div class="context-item">
                            <span class="context-name">{{ ctx.name }}</span>
                            {% if ctx.reason %}
                            <div class="context-reason">{{ ctx.reason }}</div>
                            {% endif %}
                        </div>
                        {% endfor %}
                    </div>
                    {% endif %}
                </div>
            </div>
            {% else %}
            <p>No vulnerabilities found.</p>
            {% endfor %}
        </section>

        <footer>
            <p>Report generated by <strong>Vulnhuntr</strong> v{{ tool_version }}</p>
            <p>LLM-Powered Vulnerability Scanner | <a href="https://github.com/protectai/vulnhuntr">GitHub</a></p>
        </footer>
    </div>

    <script>
        function toggleFinding(index) {
            const finding = document.getElementById('finding-' + index);
            finding.classList.toggle('expanded');
        }

        // Expand all findings on page load for accessibility
        document.addEventListener('DOMContentLoaded', function() {
            // Expand first finding by default
            const firstFinding = document.querySelector('.finding');
            if (firstFinding) {
                firstFinding.classList.add('expanded');
            }
        });
    </script>
</body>
</html>"""


class HTMLReporter(ReporterBase):
    """Generate interactive HTML reports.

    Creates self-contained HTML reports with embedded CSS and JavaScript.
    Features responsive design, dark mode support, and print-friendly
    formatting.

    Uses Jinja2 for template rendering with automatic HTML escaping
    to prevent XSS vulnerabilities in the report itself.

    Example:
        ```python
        reporter = HTMLReporter(output_path=Path("report.html"))
        reporter.add_finding(finding)
        reporter.write()
        ```
    """

    def __init__(
        self,
        output_path: Path | None = None,
        include_scratchpad: bool = False,
        include_context: bool = True,
        custom_template: str | None = None,
    ):
        """Initialize HTML reporter.

        Args:
            output_path: Path for the output HTML file
            include_scratchpad: Include LLM reasoning in reports
            include_context: Include code context snippets
            custom_template: Optional custom Jinja2 template string
        """
        super().__init__(output_path, include_scratchpad, include_context)
        self.custom_template = custom_template

        if not JINJA2_AVAILABLE:
            log.warning("Jinja2 not available, using basic HTML generation")

    def _escape(self, text: str) -> str:
        """HTML escape a string (fallback when Jinja2 not available)."""
        return html.escape(str(text)) if text else ""

    def _format_finding_for_template(self, finding: Finding) -> dict[str, Any]:
        """Format a finding for template rendering."""
        return {
            "title": finding.title,
            "rule_id": finding.rule_id,
            "severity": finding.severity.value,
            "confidence_score": finding.confidence_score,
            "file_path": finding.file_path,
            "start_line": finding.start_line,
            "end_line": finding.end_line,
            "cwe_id": finding.cwe_id,
            "cwe_name": finding.cwe_name,
            "description": finding.description,
            "analysis": finding.analysis,
            "scratchpad": finding.scratchpad,
            "poc": finding.poc,
            "context_code": finding.context_code,
        }

    def _generate_with_jinja2(self) -> str:
        """Generate HTML using Jinja2 templates."""
        env = Environment(
            loader=BaseLoader(),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

        template_source = self.custom_template or HTML_TEMPLATE
        template = env.from_string(template_source)

        # Prepare template context
        summary = self.get_summary()
        severity_counts = summary.get("by_severity", {})

        context = {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "tool_version": self.metadata.get("tool_version", "1.0.0"),
            "total_findings": len(self.findings),
            "files_affected": summary.get("files_affected", 0),
            "vuln_types": list(summary.get("by_vulnerability_type", {}).keys()),
            "severity_counts": severity_counts,
            "findings": [self._format_finding_for_template(f) for f in self.findings],
            "include_scratchpad": self.include_scratchpad,
            "include_context": self.include_context,
        }

        return template.render(**context)

    def _generate_basic_html(self) -> str:
        """Generate basic HTML without Jinja2 (fallback)."""
        summary = self.get_summary()

        findings_html = ""
        for i, finding in enumerate(self.findings, 1):
            poc_html = ""
            if finding.poc:
                poc_html = f"""
                <div class="finding-row">
                    <div class="finding-label">Proof of Concept</div>
                    <div class="code-block">{self._escape(finding.poc)}</div>
                </div>
                """

            findings_html += f"""
            <div class="finding expanded">
                <div class="finding-header">
                    <span class="finding-title">{self._escape(finding.title)}</span>
                    <div class="finding-meta">
                        <span class="severity-badge severity-{finding.severity.value}">{finding.severity.value.upper()}</span>
                        <span class="confidence-score">Confidence: {finding.confidence_score}/10</span>
                    </div>
                </div>
                <div class="finding-body" style="display:block;">
                    <div class="finding-row">
                        <div class="finding-label">File</div>
                        <span class="file-path">{self._escape(finding.file_path)}</span>
                    </div>
                    <div class="finding-row">
                        <div class="finding-label">Analysis</div>
                        <p>{self._escape(finding.analysis)}</p>
                    </div>
                    {poc_html}
                </div>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Vulnhuntr Security Report</title>
    <style>
        body {{ font-family: sans-serif; padding: 2rem; max-width: 1200px; margin: 0 auto; }}
        .finding {{ border: 1px solid #ddd; margin: 1rem 0; border-radius: 8px; }}
        .finding-header {{ background: #f5f5f5; padding: 1rem; display: flex; justify-content: space-between; }}
        .finding-body {{ padding: 1rem; }}
        .finding-label {{ font-weight: bold; color: #666; margin-bottom: 0.25rem; }}
        .finding-row {{ margin-bottom: 1rem; }}
        .code-block {{ background: #2d2d2d; color: #f8f8f2; padding: 1rem; border-radius: 4px; overflow-x: auto; }}
        .severity-badge {{ padding: 0.25rem 0.5rem; border-radius: 4px; color: white; font-weight: bold; }}
        .severity-critical {{ background: #dc3545; }}
        .severity-high {{ background: #fd7e14; }}
        .severity-medium {{ background: #ffc107; color: black; }}
        .severity-low {{ background: #28a745; }}
        .severity-info {{ background: #17a2b8; }}
        .file-path {{ font-family: monospace; background: #eee; padding: 0.25rem 0.5rem; border-radius: 4px; }}
    </style>
</head>
<body>
    <h1>🔍 Vulnhuntr Security Report</h1>
    <p>Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
    <p>Total Findings: {len(self.findings)} | Files Affected: {summary.get("files_affected", 0)}</p>
    <hr>
    {findings_html if findings_html else "<p>No vulnerabilities found.</p>"}
    <footer style="margin-top: 2rem; text-align: center; color: #666;">
        Generated by Vulnhuntr v{self.metadata.get("tool_version", "1.0.0")}
    </footer>
</body>
</html>"""

    def generate(self) -> str:
        """Generate HTML report.

        Returns:
            HTML string containing the full report
        """
        if JINJA2_AVAILABLE:
            content = self._generate_with_jinja2()
        else:
            content = self._generate_basic_html()

        log.info(
            "HTML report generated",
            findings=len(self.findings),
            jinja2=JINJA2_AVAILABLE,
        )

        return content
