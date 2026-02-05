"""
GitHub Issues Integration
=========================

Automatically create GitHub issues from vulnerability findings.

Uses the GitHub REST API to create issues with proper labels,
assignees, and formatted descriptions.

References:
- GitHub API: https://docs.github.com/en/rest/issues/issues
- Authentication: https://docs.github.com/en/authentication
"""

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import structlog

try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from ..reporters.base import Finding, FindingSeverity

log = structlog.get_logger("vulnhuntr.integrations.github")

# GitHub API constants
GITHUB_API_BASE = "https://api.github.com"

# Default labels for severity levels
DEFAULT_SEVERITY_LABELS = {
    FindingSeverity.CRITICAL: ["security", "critical", "priority-high"],
    FindingSeverity.HIGH: ["security", "high", "priority-high"],
    FindingSeverity.MEDIUM: ["security", "medium"],
    FindingSeverity.LOW: ["security", "low"],
    FindingSeverity.INFO: ["security", "info"],
}

# Severity emoji for issue titles
SEVERITY_EMOJI = {
    FindingSeverity.CRITICAL: "🔴",
    FindingSeverity.HIGH: "🟠",
    FindingSeverity.MEDIUM: "🟡",
    FindingSeverity.LOW: "🟢",
    FindingSeverity.INFO: "🔵",
}


@dataclass
class IssueResult:
    """Result of creating a GitHub issue."""

    success: bool
    issue_number: Optional[int] = None
    issue_url: Optional[str] = None
    error: Optional[str] = None


@dataclass
class GitHubConfig:
    """Configuration for GitHub API access."""

    token: str
    owner: str
    repo: str
    labels: List[str] = field(default_factory=lambda: ["security", "vulnhuntr"])
    assignees: List[str] = field(default_factory=list)
    milestone: Optional[int] = None
    dry_run: bool = False


class GitHubIssueCreator:
    """Create GitHub issues from vulnerability findings.

    Uses the GitHub REST API to create issues with appropriate
    labels, formatting, and optional assignees.

    Example:
        ```python
        config = GitHubConfig(
            token=os.getenv("GITHUB_TOKEN"),
            owner="myorg",
            repo="myrepo",
            labels=["security", "automated"]
        )
        creator = GitHubIssueCreator(config)

        for finding in findings:
            result = creator.create_issue(finding)
            if result.success:
                print(f"Created issue #{result.issue_number}")
        ```
    """

    def __init__(self, config: GitHubConfig):
        """Initialize GitHub issue creator.

        Args:
            config: GitHub API configuration
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library required for GitHub integration")

        self.config = config
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {config.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "Vulnhuntr/1.0.0",
            }
        )

        # Track created issues to avoid duplicates
        self._created_issues: Dict[str, int] = {}

    def _get_issue_fingerprint(self, finding: Finding) -> str:
        """Generate a unique fingerprint for deduplication."""
        return f"{finding.rule_id}:{finding.file_path}"

    def _format_issue_title(self, finding: Finding) -> str:
        """Format the issue title."""
        emoji = SEVERITY_EMOJI.get(finding.severity, "")
        return f"{emoji} [{finding.rule_id}] {finding.title}"

    def _format_issue_body(self, finding: Finding) -> str:
        """Format the issue body with Markdown."""
        lines = [
            f"## {finding.title}",
            "",
            f"**Severity:** {finding.severity.value.upper()}",
            f"**Confidence:** {finding.confidence_score}/10",
            f"**File:** `{finding.file_path}`",
        ]

        if finding.start_line:
            lines.append(f"**Line:** {finding.start_line}")

        if finding.cwe_id:
            cwe_num = finding.cwe_id.replace("CWE-", "")
            lines.append(
                f"**CWE:** [{finding.cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_num}.html) - {finding.cwe_name}"
            )

        lines.extend(
            [
                "",
                "### Description",
                "",
                finding.description or "Potential security vulnerability detected.",
                "",
                "### Analysis",
                "",
                finding.analysis or "See details below.",
                "",
            ]
        )

        if finding.poc and finding.poc.strip():
            lines.extend(
                [
                    "### Proof of Concept",
                    "",
                    "```",
                    finding.poc,
                    "```",
                    "",
                ]
            )

        lines.extend(
            [
                "---",
                "",
                "*This issue was automatically created by [Vulnhuntr](https://github.com/protectai/vulnhuntr), an LLM-powered vulnerability scanner.*",
            ]
        )

        return "\n".join(lines)

    def _get_labels_for_finding(self, finding: Finding) -> List[str]:
        """Get labels for a finding."""
        labels = list(self.config.labels)

        # Add severity labels
        severity_labels = DEFAULT_SEVERITY_LABELS.get(finding.severity, [])
        for label in severity_labels:
            if label not in labels:
                labels.append(label)

        # Add vulnerability type label
        vuln_label = f"vuln-{finding.rule_id.lower()}"
        if vuln_label not in labels:
            labels.append(vuln_label)

        return labels

    def check_duplicate(self, finding: Finding) -> Optional[int]:
        """Check if an issue already exists for this finding.

        Searches open issues with matching title pattern.

        Returns:
            Issue number if duplicate found, None otherwise
        """
        fingerprint = self._get_issue_fingerprint(finding)

        # Check local cache
        if fingerprint in self._created_issues:
            return self._created_issues[fingerprint]

        # Search GitHub for existing issues
        search_query = f'repo:{self.config.owner}/{self.config.repo} is:issue is:open "[{finding.rule_id}]" in:title "{finding.file_path}"'

        try:
            response = self.session.get(
                f"{GITHUB_API_BASE}/search/issues",
                params={"q": search_query, "per_page": 5},
            )
            response.raise_for_status()

            results = response.json()
            if results.get("total_count", 0) > 0:
                issue_number = results["items"][0]["number"]
                self._created_issues[fingerprint] = issue_number
                return issue_number

        except Exception as e:
            log.warning("Failed to check for duplicate issues", error=str(e))

        return None

    def create_issue(
        self,
        finding: Finding,
        skip_duplicates: bool = True,
    ) -> IssueResult:
        """Create a GitHub issue for a finding.

        Args:
            finding: The vulnerability finding
            skip_duplicates: Skip if similar issue exists

        Returns:
            IssueResult with success status and issue details
        """
        fingerprint = self._get_issue_fingerprint(finding)

        # Check for duplicates
        if skip_duplicates:
            existing = self.check_duplicate(finding)
            if existing:
                log.info(
                    "Skipping duplicate issue",
                    existing_issue=existing,
                    finding=finding.rule_id,
                    file=finding.file_path,
                )
                return IssueResult(
                    success=True,
                    issue_number=existing,
                    issue_url=f"https://github.com/{self.config.owner}/{self.config.repo}/issues/{existing}",
                    error="Issue already exists",
                )

        # Prepare issue data
        issue_data = {
            "title": self._format_issue_title(finding),
            "body": self._format_issue_body(finding),
            "labels": self._get_labels_for_finding(finding),
        }

        if self.config.assignees:
            issue_data["assignees"] = self.config.assignees

        if self.config.milestone:
            issue_data["milestone"] = self.config.milestone

        # Dry run mode
        if self.config.dry_run:
            log.info(
                "Dry run: would create issue",
                title=issue_data["title"],
                labels=issue_data["labels"],
            )
            return IssueResult(
                success=True,
                error="Dry run - issue not created",
            )

        # Create the issue
        try:
            response = self.session.post(
                f"{GITHUB_API_BASE}/repos/{self.config.owner}/{self.config.repo}/issues",
                json=issue_data,
            )
            response.raise_for_status()

            result = response.json()
            issue_number = result["number"]
            issue_url = result["html_url"]

            # Cache for deduplication
            self._created_issues[fingerprint] = issue_number

            log.info(
                "GitHub issue created",
                issue_number=issue_number,
                issue_url=issue_url,
                finding=finding.rule_id,
                file=finding.file_path,
            )

            return IssueResult(
                success=True,
                issue_number=issue_number,
                issue_url=issue_url,
            )

        except requests.exceptions.HTTPError as e:
            error_msg = str(e)
            if e.response is not None:
                try:
                    error_data = e.response.json()
                    error_msg = error_data.get("message", str(e))
                except Exception:
                    error_msg = e.response.text

            log.error(
                "Failed to create GitHub issue",
                error=error_msg,
                status_code=e.response.status_code if e.response else None,
                finding=finding.rule_id,
            )

            return IssueResult(
                success=False,
                error=f"HTTP {e.response.status_code if e.response else 'unknown'}: {error_msg}",
            )

        except Exception as e:
            log.error("Failed to create GitHub issue", error=str(e))
            return IssueResult(success=False, error=str(e))

    def create_issues_for_findings(
        self,
        findings: List[Finding],
        skip_duplicates: bool = True,
        max_issues: Optional[int] = None,
    ) -> List[IssueResult]:
        """Create issues for multiple findings.

        Args:
            findings: List of vulnerability findings
            skip_duplicates: Skip findings with existing issues
            max_issues: Maximum number of issues to create (None for unlimited)

        Returns:
            List of IssueResults
        """
        results = []
        created_count = 0

        for finding in findings:
            if max_issues and created_count >= max_issues:
                log.info("Reached maximum issue limit", max_issues=max_issues)
                break

            result = self.create_issue(finding, skip_duplicates)
            results.append(result)

            if result.success and result.error != "Issue already exists":
                created_count += 1

        log.info(
            "Batch issue creation complete",
            total_findings=len(findings),
            created=created_count,
            skipped=len(results) - created_count,
        )

        return results

    def verify_access(self) -> bool:
        """Verify API access to the repository.

        Returns:
            True if access is verified, False otherwise
        """
        try:
            response = self.session.get(
                f"{GITHUB_API_BASE}/repos/{self.config.owner}/{self.config.repo}"
            )
            response.raise_for_status()

            repo_data = response.json()
            log.info(
                "GitHub access verified",
                repo=repo_data.get("full_name"),
                permissions=repo_data.get("permissions", {}),
            )

            return True

        except Exception as e:
            log.error("GitHub access verification failed", error=str(e))
            return False


def create_github_config_from_env(
    owner: str,
    repo: str,
    labels: Optional[List[str]] = None,
    dry_run: bool = False,
) -> GitHubConfig:
    """Create GitHubConfig from environment variables.

    Reads GITHUB_TOKEN from environment.

    Args:
        owner: Repository owner
        repo: Repository name
        labels: Additional labels
        dry_run: Enable dry run mode

    Returns:
        GitHubConfig instance
    """
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise ValueError("GITHUB_TOKEN environment variable not set")

    return GitHubConfig(
        token=token,
        owner=owner,
        repo=repo,
        labels=labels or ["security", "vulnhuntr"],
        dry_run=dry_run,
    )
