"""
SARIF 2.1.0 Reporter
====================

Generates Static Analysis Results Interchange Format (SARIF) reports
compliant with the SARIF 2.1.0 specification.

SARIF is the industry standard for static analysis tool output and is
supported by GitHub Code Scanning, Azure DevOps, and other platforms.

References:
- SARIF Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
- JSON Schema: https://json.schemastore.org/sarif-2.1.0.json
- GitHub SARIF Support: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import structlog

from .base import (
    ReporterBase,
    Finding,
    FindingSeverity,
    CWE_MAPPINGS,
    SEVERITY_SCORES,
)

log = structlog.get_logger("vulnhuntr.reporters.sarif")

# SARIF 2.1.0 constants
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# Map Vulnhuntr severity to SARIF level
SEVERITY_TO_SARIF_LEVEL = {
    FindingSeverity.CRITICAL: "error",
    FindingSeverity.HIGH: "error",
    FindingSeverity.MEDIUM: "warning",
    FindingSeverity.LOW: "note",
    FindingSeverity.INFO: "none",
}

# Map Vulnhuntr severity to SARIF kind
SEVERITY_TO_SARIF_KIND = {
    FindingSeverity.CRITICAL: "fail",
    FindingSeverity.HIGH: "fail",
    FindingSeverity.MEDIUM: "fail",
    FindingSeverity.LOW: "review",
    FindingSeverity.INFO: "informational",
}


class SARIFReporter(ReporterBase):
    """Generate SARIF 2.1.0 compliant reports.

    SARIF (Static Analysis Results Interchange Format) is the standard
    format for static analysis tools. This reporter generates output
    compatible with GitHub Code Scanning, Azure DevOps, and other
    SARIF-compatible platforms.

    Key SARIF features implemented:
    - Proper schema and version
    - Tool component with rules (reportingDescriptors)
    - Results with locations and messages
    - partialFingerprints for result deduplication
    - CWE tags for vulnerability classification
    - Security severity scores

    Example:
        ```python
        reporter = SARIFReporter(output_path=Path("results.sarif"))
        reporter.add_finding(finding)
        reporter.write()
        ```
    """

    def __init__(
        self,
        output_path: Optional[Path] = None,
        include_scratchpad: bool = False,
        include_context: bool = True,
        repository_uri: Optional[str] = None,
        repository_branch: Optional[str] = None,
    ):
        """Initialize SARIF reporter.

        Args:
            output_path: Path for the output .sarif file
            include_scratchpad: Include LLM reasoning in results
            include_context: Include code context in results
            repository_uri: URI of the scanned repository (for versionControlProvenance)
            repository_branch: Branch name (for versionControlProvenance)
        """
        super().__init__(output_path, include_scratchpad, include_context)
        self.repository_uri = repository_uri
        self.repository_branch = repository_branch

        # Track unique rules encountered
        self._rules: Dict[str, Dict[str, Any]] = {}

    def _compute_fingerprint(self, finding: Finding) -> str:
        """Compute a stable fingerprint for result deduplication.

        The fingerprint is used by platforms like GitHub to deduplicate
        results across multiple runs. It should be stable for the same
        vulnerability in the same location, even if line numbers change slightly.

        We use a hash of:
        - Rule ID (vulnerability type)
        - File path (relative)
        - First meaningful line of analysis (content-based)
        """
        # Normalize file path
        normalized_path = Path(finding.file_path).as_posix()

        # Take first 100 chars of analysis for content-based fingerprint
        analysis_snippet = (finding.analysis or finding.description)[:100]

        # Create composite key
        fingerprint_input = f"{finding.rule_id}:{normalized_path}:{analysis_snippet}"

        # SHA-256 hash, truncated to 64 chars as recommended
        hash_value = hashlib.sha256(fingerprint_input.encode("utf-8")).hexdigest()[:64]

        return hash_value

    def _get_rule(self, vuln_type: str) -> Dict[str, Any]:
        """Get or create a SARIF rule (reportingDescriptor) for a vulnerability type.

        Returns a rule definition suitable for the tool.driver.rules array.
        """
        if vuln_type in self._rules:
            return self._rules[vuln_type]

        cwe = CWE_MAPPINGS.get(vuln_type, {})
        severity_score = SEVERITY_SCORES.get(vuln_type, 5.0)

        # Build help text
        help_text = self._get_help_text(vuln_type, cwe)

        rule = {
            "id": f"vulnhuntr/{vuln_type.lower()}",
            "name": vuln_type,
            "shortDescription": {"text": f"{cwe.get('name', vuln_type)} Vulnerability"},
            "fullDescription": {"text": self._get_full_description(vuln_type, cwe)},
            "help": {"text": help_text, "markdown": help_text},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe.get('id', '').replace('CWE-', '')}.html"
            if cwe.get("id")
            else None,
            "properties": {
                "security-severity": str(severity_score),
                "precision": "medium",
                "problem.severity": "error" if severity_score >= 7.0 else "warning",
                "tags": self._get_rule_tags(vuln_type, cwe),
            },
        }

        # Remove None values
        rule = {k: v for k, v in rule.items() if v is not None}

        self._rules[vuln_type] = rule
        return rule

    def _get_full_description(self, vuln_type: str, cwe: Dict[str, str]) -> str:
        """Get full description for a vulnerability type."""
        descriptions = {
            "LFI": "Local File Inclusion allows attackers to read arbitrary files from the server filesystem, potentially exposing sensitive configuration files, credentials, or source code.",
            "AFO": "Arbitrary File Overwrite allows attackers to write or modify files on the server, which can lead to code execution, configuration tampering, or denial of service.",
            "RCE": "Remote Code Execution allows attackers to execute arbitrary code on the server, leading to complete system compromise.",
            "SQLI": "SQL Injection allows attackers to manipulate database queries, potentially leading to data breach, data modification, or in some cases remote code execution.",
            "XSS": "Cross-site Scripting allows attackers to inject malicious scripts into web pages viewed by other users, enabling session hijacking, credential theft, or malware distribution.",
            "SSRF": "Server-Side Request Forgery allows attackers to make the server send requests to internal services, potentially accessing sensitive internal resources or cloud metadata.",
            "IDOR": "Insecure Direct Object Reference allows attackers to access resources belonging to other users by manipulating identifiers, bypassing authorization controls.",
        }
        return descriptions.get(
            vuln_type, f"Potential {cwe.get('name', vuln_type)} vulnerability detected."
        )

    def _get_help_text(self, vuln_type: str, cwe: Dict[str, str]) -> str:
        """Get help/remediation text for a vulnerability type."""
        help_texts = {
            "LFI": "**Remediation**: Validate and sanitize all file path inputs. Use allowlists for permitted files. Avoid user-controlled file paths. Use chroot or containerization to limit filesystem access.",
            "AFO": "**Remediation**: Never use user input directly in file paths. Validate file extensions and paths against allowlists. Use secure temporary directories. Implement proper access controls.",
            "RCE": "**Remediation**: Avoid executing user input. Use parameterized commands with allowlisted arguments. Implement strict input validation. Use sandboxing or containerization.",
            "SQLI": "**Remediation**: Use parameterized queries or prepared statements. Never concatenate user input into SQL. Use ORM frameworks. Implement input validation and output encoding.",
            "XSS": "**Remediation**: Encode all user output based on context (HTML, JavaScript, URL, CSS). Use Content-Security-Policy headers. Implement input validation. Use modern frameworks with auto-escaping.",
            "SSRF": "**Remediation**: Validate and sanitize URLs. Use allowlists for permitted hosts. Block requests to internal networks and cloud metadata endpoints. Disable unnecessary URL schemes.",
            "IDOR": "**Remediation**: Implement proper authorization checks. Use indirect references. Validate user permissions for every resource access. Log and monitor access patterns.",
        }
        return help_texts.get(
            vuln_type,
            f"Review and remediate this {cwe.get('name', vuln_type)} vulnerability.",
        )

    def _get_rule_tags(self, vuln_type: str, cwe: Dict[str, str]) -> List[str]:
        """Get tags for a rule."""
        tags = ["security"]

        if cwe.get("id"):
            tags.append(f"external/cwe/{cwe['id'].lower()}")

        # Add category tags
        category_tags = {
            "LFI": ["file-access", "path-traversal"],
            "AFO": ["file-access", "file-write"],
            "RCE": ["command-injection", "code-execution"],
            "SQLI": ["injection", "database"],
            "XSS": ["injection", "web"],
            "SSRF": ["network", "server-side"],
            "IDOR": ["authorization", "access-control"],
        }
        tags.extend(category_tags.get(vuln_type, []))

        return tags

    def _finding_to_result(self, finding: Finding, index: int) -> Dict[str, Any]:
        """Convert a Finding to a SARIF result object."""
        # Ensure rule exists
        self._get_rule(finding.rule_id)

        # Build location
        physical_location: Dict[str, Any] = {
            "artifactLocation": {
                "uri": Path(finding.file_path).as_posix(),
                "uriBaseId": "%SRCROOT%",
            }
        }

        # Add region if line numbers available
        if finding.start_line is not None:
            region: Dict[str, Any] = {
                "startLine": finding.start_line,
            }
            if finding.end_line is not None:
                region["endLine"] = finding.end_line
            if finding.start_column is not None:
                region["startColumn"] = finding.start_column
            if finding.end_column is not None:
                region["endColumn"] = finding.end_column
            physical_location["region"] = region

        # Build message
        message_parts = [finding.analysis or finding.description]

        if finding.poc and finding.poc.strip():
            message_parts.append(f"\n\n**Proof of Concept:**\n```\n{finding.poc}\n```")

        if self.include_scratchpad and finding.scratchpad:
            message_parts.append(
                f"\n\n**Analysis Details:**\n{finding.scratchpad[:500]}"
            )

        message_text = "\n".join(message_parts)

        # Build result
        result: Dict[str, Any] = {
            "ruleId": f"vulnhuntr/{finding.rule_id.lower()}",
            "ruleIndex": list(self._rules.keys()).index(finding.rule_id),
            "level": SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning"),
            "kind": SEVERITY_TO_SARIF_KIND.get(finding.severity, "fail"),
            "message": {"text": message_text},
            "locations": [{"physicalLocation": physical_location}],
            # partialFingerprints required for GitHub deduplication
            "partialFingerprints": {
                "primaryLocationLineHash": self._compute_fingerprint(finding)
            },
            "properties": {
                "confidence": finding.confidence_score,
                "security-severity": finding.metadata.get("security_severity", 5.0),
            },
        }

        # Add CWE relationship if available
        if finding.cwe_id:
            result["taxa"] = [
                {
                    "toolComponent": {
                        "name": "CWE",
                        "guid": "A1B2C3D4-E5F6-7890-ABCD-EF1234567890",
                    },
                    "id": finding.cwe_id.replace("CWE-", ""),
                    "properties": {"name": finding.cwe_name},
                }
            ]

        # Add code flows if context available
        if self.include_context and finding.context_code:
            code_flows = []
            for ctx in finding.context_code:
                if ctx.get("name"):
                    code_flows.append(
                        {
                            "message": {
                                "text": f"Data flow through {ctx.get('name')}: {ctx.get('reason', '')}"
                            }
                        }
                    )
            if code_flows:
                result["codeFlows"] = [
                    {
                        "message": {"text": "Data flow analysis"},
                        "threadFlows": [
                            {
                                "locations": [
                                    {"location": {"message": cf["message"]}}
                                    for cf in code_flows
                                ]
                            }
                        ],
                    }
                ]

        return result

    def generate(self) -> str:
        """Generate SARIF 2.1.0 compliant JSON output.

        Returns:
            JSON string containing the SARIF report
        """
        # Build tool component
        tool = {
            "driver": {
                "name": "Vulnhuntr",
                "informationUri": "https://github.com/protectai/vulnhuntr",
                "version": self.metadata.get("tool_version", "1.0.0"),
                "semanticVersion": self.metadata.get("tool_version", "1.0.0"),
                "rules": [],
            }
        }

        # Build results and collect rules
        results = []
        for i, finding in enumerate(self.findings):
            results.append(self._finding_to_result(finding, i))

        # Add rules to tool
        tool["driver"]["rules"] = list(self._rules.values())

        # Add CWE taxonomy reference
        tool["driver"]["supportedTaxonomies"] = [
            {"name": "CWE", "index": 0, "guid": "A1B2C3D4-E5F6-7890-ABCD-EF1234567890"}
        ]

        # Build run
        run: Dict[str, Any] = {
            "tool": tool,
            "results": results,
            "taxonomies": [
                {
                    "name": "CWE",
                    "guid": "A1B2C3D4-E5F6-7890-ABCD-EF1234567890",
                    "informationUri": "https://cwe.mitre.org/",
                    "organization": "MITRE",
                    "shortDescription": {"text": "Common Weakness Enumeration"},
                    "isComprehensive": False,
                }
            ],
            "columnKind": "utf16CodeUnits",
        }

        # Add invocation info
        run["invocations"] = [
            {
                "executionSuccessful": True,
                "startTimeUtc": self.metadata.get(
                    "generated_at", datetime.utcnow().isoformat() + "Z"
                ),
            }
        ]

        # Add version control provenance if available
        if self.repository_uri:
            vcs = {"repositoryUri": self.repository_uri}
            if self.repository_branch:
                vcs["branch"] = self.repository_branch
            run["versionControlProvenance"] = [vcs]

        # Build SARIF log
        sarif_log = {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}

        log.info(
            "SARIF report generated",
            findings=len(self.findings),
            rules=len(self._rules),
        )

        return json.dumps(sarif_log, indent=2, ensure_ascii=False)
