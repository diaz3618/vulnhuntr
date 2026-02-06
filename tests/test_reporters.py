"""
Tests for vulnhuntr.reporters
==============================

Covers all reporter implementations: base classes, Finding dataclass,
SARIF, JSON, CSV, Markdown, and HTML reporters.
"""

import json
from datetime import datetime

from vulnhuntr.reporters.base import (
    Finding,
    FindingSeverity,
    CWE_MAPPINGS,
    response_to_finding,
)
from vulnhuntr.reporters.sarif import SARIFReporter
from vulnhuntr.reporters.json_reporter import JSONReporter
from vulnhuntr.reporters.csv_reporter import CSVReporter
from vulnhuntr.reporters.markdown_reporter import MarkdownReporter
from vulnhuntr.reporters.html import HTMLReporter


# ── FindingSeverity ────────────────────────────────────────────────────────


class TestFindingSeverity:
    def test_from_confidence_score_critical(self):
        assert FindingSeverity.from_confidence_score(9) == FindingSeverity.CRITICAL
        assert FindingSeverity.from_confidence_score(10) == FindingSeverity.CRITICAL

    def test_from_confidence_score_high(self):
        assert FindingSeverity.from_confidence_score(7) == FindingSeverity.HIGH
        assert FindingSeverity.from_confidence_score(8) == FindingSeverity.HIGH

    def test_from_confidence_score_medium(self):
        assert FindingSeverity.from_confidence_score(5) == FindingSeverity.MEDIUM
        assert FindingSeverity.from_confidence_score(6) == FindingSeverity.MEDIUM

    def test_from_confidence_score_low(self):
        assert FindingSeverity.from_confidence_score(3) == FindingSeverity.LOW
        assert FindingSeverity.from_confidence_score(4) == FindingSeverity.LOW

    def test_from_confidence_score_info(self):
        assert FindingSeverity.from_confidence_score(0) == FindingSeverity.INFO
        assert FindingSeverity.from_confidence_score(2) == FindingSeverity.INFO


# ── Finding dataclass ──────────────────────────────────────────────────────


class TestFinding:
    def test_creates_with_required_fields(self):
        f = Finding(rule_id="SQLI", title="SQL Injection", file_path="/app.py")
        assert f.rule_id == "SQLI"
        assert f.title == "SQL Injection"
        assert f.file_path == "/app.py"

    def test_severity_set_from_confidence(self):
        f = Finding(rule_id="RCE", title="RCE", file_path="/x.py", confidence_score=8)
        assert f.severity == FindingSeverity.HIGH

    def test_defaults(self):
        f = Finding(rule_id="XSS", title="XSS", file_path="/x.py")
        assert f.description == ""
        assert f.analysis == ""
        assert f.poc == ""
        assert f.context_code == []
        assert f.metadata == {}
        assert isinstance(f.discovered_at, datetime)

    def test_cwe_fields(self):
        f = Finding(
            rule_id="SQLI",
            title="Test",
            file_path="/x.py",
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
        )
        assert f.cwe_id == "CWE-89"
        assert f.cwe_name == "SQL Injection"


# ── CWE_MAPPINGS ───────────────────────────────────────────────────────────


class TestCWEMappings:
    def test_known_vuln_types(self):
        assert "LFI" in CWE_MAPPINGS
        assert "RCE" in CWE_MAPPINGS
        assert "SQLI" in CWE_MAPPINGS
        assert "XSS" in CWE_MAPPINGS
        assert "SSRF" in CWE_MAPPINGS
        assert "IDOR" in CWE_MAPPINGS
        assert "AFO" in CWE_MAPPINGS

    def test_mapping_structure(self):
        for vuln_type, cwe in CWE_MAPPINGS.items():
            assert "id" in cwe
            assert "name" in cwe
            assert cwe["id"].startswith("CWE-")


# ── response_to_finding ────────────────────────────────────────────────────


class TestResponseToFinding:
    def test_converts_basic_response(self, sample_response):
        finding = response_to_finding(sample_response, "/app.py", "SQLI")
        assert finding.rule_id == "SQLI"
        assert finding.file_path == "/app.py"
        assert finding.confidence_score == sample_response.confidence_score

    def test_extracts_analysis_fields(self, sample_response):
        finding = response_to_finding(sample_response, "/app.py", "SQLI")
        assert finding.analysis == sample_response.analysis
        assert finding.scratchpad == sample_response.scratchpad
        assert finding.poc == sample_response.poc


# ── JSONReporter ───────────────────────────────────────────────────────────


class TestJSONReporter:
    def test_empty_report(self):
        reporter = JSONReporter()
        output = reporter.generate()
        data = json.loads(output)
        assert data["findings"] == []

    def test_add_finding(self, sample_finding):
        reporter = JSONReporter()
        reporter.add_finding(sample_finding)
        output = reporter.generate()
        data = json.loads(output)
        assert len(data["findings"]) == 1
        assert data["findings"][0]["rule_id"] == sample_finding.rule_id

    def test_includes_metadata(self, sample_finding):
        reporter = JSONReporter(include_metadata=True)
        reporter.add_finding(sample_finding)
        output = reporter.generate()
        data = json.loads(output)
        assert "metadata" in data
        assert "tool" in data["metadata"]

    def test_excludes_metadata(self, sample_finding):
        reporter = JSONReporter(include_metadata=False)
        reporter.add_finding(sample_finding)
        output = reporter.generate()
        data = json.loads(output)
        assert "metadata" not in data

    def test_write_to_file(self, tmp_path, sample_finding):
        out = tmp_path / "report.json"
        reporter = JSONReporter(output_path=out)
        reporter.add_finding(sample_finding)
        reporter.write()
        assert out.exists()
        data = json.loads(out.read_text())
        assert len(data["findings"]) == 1


# ── CSVReporter ────────────────────────────────────────────────────────────


class TestCSVReporter:
    def test_empty_report_has_header(self):
        reporter = CSVReporter(include_header=True)
        output = reporter.generate()
        assert "Vulnerability Type" in output

    def test_add_finding(self, sample_finding):
        reporter = CSVReporter()
        reporter.add_finding(sample_finding)
        output = reporter.generate()
        assert sample_finding.rule_id in output
        assert sample_finding.file_path in output

    def test_custom_delimiter(self, sample_finding):
        reporter = CSVReporter(delimiter=";")
        reporter.add_finding(sample_finding)
        output = reporter.generate()
        assert ";" in output

    def test_write_to_file(self, tmp_path, sample_finding):
        out = tmp_path / "report.csv"
        reporter = CSVReporter(output_path=out)
        reporter.add_finding(sample_finding)
        reporter.write()
        assert out.exists()
        assert sample_finding.rule_id in out.read_text()


# ── MarkdownReporter ───────────────────────────────────────────────────────


class TestMarkdownReporter:
    def test_generates_markdown(self, sample_finding):
        reporter = MarkdownReporter()
        reporter.add_finding(sample_finding)
        output = reporter.generate()
        assert "## Summary" in output
        assert sample_finding.rule_id in output

    def test_includes_severity_emoji(self, sample_finding):
        reporter = MarkdownReporter()
        reporter.add_finding(sample_finding)
        output = reporter.generate()
        # HIGH severity should have orange emoji
        assert "🟠" in output or "🔴" in output or "🟡" in output

    def test_custom_title(self, sample_finding):
        reporter = MarkdownReporter(title="Custom Report Title")
        reporter.add_finding(sample_finding)
        output = reporter.generate()
        assert "Custom Report Title" in output

    def test_write_to_file(self, tmp_path, sample_finding):
        out = tmp_path / "SECURITY.md"
        reporter = MarkdownReporter(output_path=out)
        reporter.add_finding(sample_finding)
        reporter.write()
        assert out.exists()
        assert "## Summary" in out.read_text()


# ── SARIFReporter ──────────────────────────────────────────────────────────


class TestSARIFReporter:
    def test_valid_sarif_structure(self, sample_finding):
        reporter = SARIFReporter()
        reporter.add_finding(sample_finding)
        output = reporter.generate()
        data = json.loads(output)

        assert "$schema" in data
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) == 1

    def test_includes_rules(self, sample_finding):
        reporter = SARIFReporter()
        reporter.add_finding(sample_finding)
        output = reporter.generate()
        data = json.loads(output)

        run = data["runs"][0]
        assert "tool" in run
        assert "driver" in run["tool"]
        assert "rules" in run["tool"]["driver"]

    def test_includes_results(self, sample_finding):
        reporter = SARIFReporter()
        reporter.add_finding(sample_finding)
        output = reporter.generate()
        data = json.loads(output)

        run = data["runs"][0]
        assert "results" in run
        assert len(run["results"]) == 1

    def test_fingerprint_computed(self, sample_finding):
        reporter = SARIFReporter()
        fingerprint = reporter._compute_fingerprint(sample_finding)
        assert isinstance(fingerprint, str)
        assert len(fingerprint) == 64  # SHA-256 truncated

    def test_write_to_file(self, tmp_path, sample_finding):
        out = tmp_path / "results.sarif"
        reporter = SARIFReporter(output_path=out)
        reporter.add_finding(sample_finding)
        reporter.write()
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["version"] == "2.1.0"


# ── HTMLReporter ───────────────────────────────────────────────────────────


class TestHTMLReporter:
    def test_generates_html(self, sample_finding):
        reporter = HTMLReporter()
        reporter.add_finding(sample_finding)
        output = reporter.generate()
        assert "<!DOCTYPE html>" in output
        assert "<html" in output
        assert "</html>" in output

    def test_includes_finding_info(self, sample_finding):
        reporter = HTMLReporter()
        reporter.add_finding(sample_finding)
        output = reporter.generate()
        # HTML includes title, severity, and file info
        assert sample_finding.title in output
        assert sample_finding.file_path in output
        assert "HIGH" in output.upper()  # Severity

    def test_includes_poc(self, sample_finding):
        reporter = HTMLReporter()
        reporter.add_finding(sample_finding)
        output = reporter.generate()
        # POC may be HTML-escaped
        assert "curl" in output  # Part of POC

    def test_write_to_file(self, tmp_path, sample_finding):
        out = tmp_path / "report.html"
        reporter = HTMLReporter(output_path=out)
        reporter.add_finding(sample_finding)
        reporter.write()
        assert out.exists()
        assert "<!DOCTYPE html>" in out.read_text()


# ── Reporter summary ───────────────────────────────────────────────────────


class TestReporterSummary:
    def test_summary_counts(self, multiple_findings):
        reporter = JSONReporter()
        for f in multiple_findings:
            reporter.add_finding(f)
        summary = reporter.get_summary()
        assert summary["total_findings"] == 3

    def test_severity_breakdown(self, multiple_findings):
        reporter = JSONReporter()
        for f in multiple_findings:
            reporter.add_finding(f)
        summary = reporter.get_summary()
        assert "by_severity" in summary

    def test_vuln_type_breakdown(self, multiple_findings):
        reporter = JSONReporter()
        for f in multiple_findings:
            reporter.add_finding(f)
        summary = reporter.get_summary()
        assert "by_vulnerability_type" in summary
