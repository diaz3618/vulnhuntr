"""
Base Reporter Classes
=====================

Provides the base classes and data models for all reporter implementations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
import structlog

log = structlog.get_logger("vulnhuntr.reporters")


class FindingSeverity(str, Enum):
    """Severity levels for vulnerability findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_confidence_score(cls, score: int) -> "FindingSeverity":
        """Map confidence score (0-10) to severity level.

        Higher confidence means more certain the vulnerability exists,
        which typically correlates with higher severity.
        """
        if score >= 9:
            return cls.CRITICAL
        elif score >= 7:
            return cls.HIGH
        elif score >= 5:
            return cls.MEDIUM
        elif score >= 3:
            return cls.LOW
        else:
            return cls.INFO


@dataclass
class Finding:
    """Represents a single vulnerability finding.

    This is the canonical format used by all reporters. Data from
    Vulnhuntr's Response model should be converted to this format.
    """

    # Core identification
    rule_id: str  # Vulnerability type (LFI, RCE, etc.)
    title: str  # Human-readable title

    # Location information
    file_path: str
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    start_column: Optional[int] = None
    end_column: Optional[int] = None

    # Analysis details
    description: str = ""
    analysis: str = ""
    scratchpad: str = ""
    poc: str = ""

    # Severity and confidence
    confidence_score: int = 0
    severity: FindingSeverity = FindingSeverity.INFO

    # CWE mapping (Common Weakness Enumeration)
    cwe_id: Optional[str] = None
    cwe_name: Optional[str] = None

    # Context and metadata
    context_code: List[Dict[str, str]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Timestamps
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self):
        """Set severity from confidence score if not explicitly set."""
        if self.severity == FindingSeverity.INFO and self.confidence_score > 0:
            self.severity = FindingSeverity.from_confidence_score(self.confidence_score)


# CWE mappings for vulnerability types
# Based on MITRE CWE: https://cwe.mitre.org/
CWE_MAPPINGS = {
    "LFI": {"id": "CWE-22", "name": "Path Traversal"},
    "AFO": {"id": "CWE-73", "name": "External Control of File Name or Path"},
    "RCE": {"id": "CWE-78", "name": "OS Command Injection"},
    "SQLI": {"id": "CWE-89", "name": "SQL Injection"},
    "XSS": {"id": "CWE-79", "name": "Cross-site Scripting (XSS)"},
    "SSRF": {"id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)"},
    "IDOR": {
        "id": "CWE-639",
        "name": "Authorization Bypass Through User-Controlled Key",
    },
}

# Security severity scores (0-10 scale for SARIF)
# Based on CVSS-like scoring
SEVERITY_SCORES = {
    "LFI": 7.5,  # High - can read sensitive files
    "AFO": 8.0,  # High - can overwrite arbitrary files
    "RCE": 9.8,  # Critical - full system compromise
    "SQLI": 8.6,  # High - data breach, potential RCE
    "XSS": 6.1,  # Medium - client-side attack
    "SSRF": 7.5,  # High - internal network access
    "IDOR": 6.5,  # Medium - unauthorized data access
}


def response_to_finding(
    response: Any,
    file_path: str,
    vuln_type: Optional[str] = None,
    context_code: Optional[Dict[str, Any]] = None,
) -> Finding:
    """Convert a Vulnhuntr Response object to a Finding object.

    Args:
        response: Response model from Vulnhuntr analysis
        file_path: Path to the analyzed file
        vuln_type: Specific vulnerability type (from secondary analysis)
        context_code: Optional dictionary of fetched code definitions

    Returns:
        Finding object representing the vulnerability
    """
    # Convert vuln_type if it's an enum
    if vuln_type is not None:
        vt = str(vuln_type.value) if hasattr(vuln_type, "value") else str(vuln_type)
    elif hasattr(response, "vulnerability_types") and response.vulnerability_types:
        # Use first vulnerability type if not specified
        vt = (
            str(response.vulnerability_types[0].value)
            if hasattr(response.vulnerability_types[0], "value")
            else str(response.vulnerability_types[0])
        )
    else:
        vt = "UNKNOWN"

    cwe = CWE_MAPPINGS.get(vt, {})
    severity_score = SEVERITY_SCORES.get(vt, 5.0)

    # Map confidence score to severity
    confidence = getattr(response, "confidence_score", 0)
    severity = FindingSeverity.from_confidence_score(confidence)

    # Extract context code from response or from provided dict
    context_items = []
    if context_code:
        # Use the fetched code definitions
        for name, definition in context_code.items():
            context_items.append(
                {
                    "name": name,
                    "source": getattr(definition, "source", str(definition))[:500]
                    if definition
                    else "",
                    "file_path": getattr(definition, "file_path", ""),
                }
            )
    elif hasattr(response, "context_code") and response.context_code:
        for ctx in response.context_code:
            context_items.append(
                {
                    "name": getattr(ctx, "name", ""),
                    "reason": getattr(ctx, "reason", ""),
                    "code_line": getattr(ctx, "code_line", ""),
                }
            )

    finding = Finding(
        rule_id=vt,
        title=f"{vt} Vulnerability in {Path(file_path).name}",
        file_path=str(file_path),
        description=f"Potential {cwe.get('name', vt)} vulnerability detected",
        analysis=getattr(response, "analysis", ""),
        scratchpad=getattr(response, "scratchpad", ""),
        poc=getattr(response, "poc", ""),
        confidence_score=confidence,
        severity=severity,
        cwe_id=cwe.get("id"),
        cwe_name=cwe.get("name"),
        context_code=context_items,
        metadata={
            "security_severity": severity_score,
            "cwe": cwe,
        },
    )

    return finding


class ReporterBase(ABC):
    """Abstract base class for all report generators.

    Subclasses must implement the `generate` method to produce
    output in their specific format.
    """

    def __init__(
        self,
        output_path: Optional[Path] = None,
        include_scratchpad: bool = False,
        include_context: bool = True,
    ):
        """Initialize the reporter.

        Args:
            output_path: Path to write the report. If None, returns as string.
            include_scratchpad: Include LLM reasoning in reports
            include_context: Include context code snippets
        """
        self.output_path = Path(output_path) if output_path else None
        self.include_scratchpad = include_scratchpad
        self.include_context = include_context
        self.findings: List[Finding] = []
        self.metadata: Dict[str, Any] = {
            "tool_name": "Vulnhuntr",
            "tool_version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the report."""
        self.findings.append(finding)
        log.debug("Finding added", rule_id=finding.rule_id, file=finding.file_path)

    def add_findings(self, findings: List[Finding]) -> None:
        """Add multiple findings to the report."""
        for finding in findings:
            self.add_finding(finding)

    def set_metadata(self, key: str, value: Any) -> None:
        """Set a metadata field for the report."""
        self.metadata[key] = value

    @abstractmethod
    def generate(self) -> str:
        """Generate the report content.

        Returns:
            The report content as a string
        """
        pass

    def write(self) -> Optional[Path]:
        """Generate and write the report to file.

        Returns:
            Path to the written file, or None if no output_path configured
        """
        content = self.generate()

        if self.output_path:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            self.output_path.write_text(content, encoding="utf-8")
            log.info(
                "Report written",
                path=str(self.output_path),
                findings=len(self.findings),
            )
            return self.output_path

        return None

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the report contents."""
        severity_counts = {}
        vuln_type_counts = {}

        for finding in self.findings:
            # Count by severity
            sev = finding.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            # Count by vulnerability type
            vt = finding.rule_id
            vuln_type_counts[vt] = vuln_type_counts.get(vt, 0) + 1

        return {
            "total_findings": len(self.findings),
            "by_severity": severity_counts,
            "by_vulnerability_type": vuln_type_counts,
            "files_affected": len(set(f.file_path for f in self.findings)),
        }
