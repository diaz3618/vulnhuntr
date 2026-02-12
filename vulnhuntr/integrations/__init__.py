"""
Vulnhuntr Integrations Package
==============================

This package provides integrations with external services for
reporting and notification of vulnerability findings.

Integrations:
- GitHub Issues: Automatically create issues from findings
- Webhooks: Send findings to custom endpoints
"""

from .github_issues import GitHubConfig, GitHubIssueCreator, IssueResult
from .webhook import PayloadFormat, WebhookConfig, WebhookNotifier

__all__ = [
    "GitHubIssueCreator",
    "GitHubConfig",
    "IssueResult",
    "WebhookConfig",
    "WebhookNotifier",
    "PayloadFormat",
]
