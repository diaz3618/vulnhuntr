"""External service integrations for findings (GitHub Issues, webhooks)."""

from __future__ import annotations

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
