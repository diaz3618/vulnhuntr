"""
Webhook Notifier
================

Send vulnerability findings to custom webhook endpoints.

Supports HMAC-SHA256 signatures for payload verification,
configurable retry logic, and multiple payload formats.

References:
- HMAC: https://docs.python.org/3/library/hmac.html
- Webhook Best Practices: https://docs.github.com/en/webhooks
"""

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import structlog

try:
    import requests  # type: ignore[import-untyped]

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from ..reporters.base import Finding, FindingSeverity

log = structlog.get_logger("vulnhuntr.integrations.webhook")


class PayloadFormat(str, Enum):
    """Supported webhook payload formats."""

    JSON = "json"
    SLACK = "slack"
    DISCORD = "discord"
    TEAMS = "teams"


@dataclass
class WebhookResult:
    """Result of sending a webhook."""

    success: bool
    status_code: int | None = None
    response_body: str | None = None
    error: str | None = None
    delivery_id: str | None = None
    attempts: int = 1


@dataclass
class WebhookConfig:
    """Configuration for webhook notifications."""

    url: str
    secret: str | None = None  # For HMAC signing
    format: PayloadFormat = PayloadFormat.JSON
    timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0  # Base delay, doubles each retry
    custom_headers: dict[str, str] = field(default_factory=dict)
    verify_ssl: bool = True


class WebhookNotifier:
    """Send vulnerability findings to webhook endpoints.

    Supports multiple payload formats and HMAC-SHA256 signatures
    for secure payload verification.

    Example:
        ```python
        config = WebhookConfig(
            url="https://example.com/webhook",
            secret="my-webhook-secret",
            format=PayloadFormat.SLACK,
        )
        notifier = WebhookNotifier(config)

        # Send single finding
        result = notifier.send_finding(finding)

        # Send batch notification
        result = notifier.send_batch(findings)
        ```
    """

    def __init__(self, config: WebhookConfig):
        """Initialize webhook notifier.

        Args:
            config: Webhook configuration
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library required for webhook integration")

        self.config = config
        self.session = requests.Session()

        # Set up default headers
        self.session.headers.update(
            {
                "User-Agent": "Vulnhuntr/1.0.0",
                "Content-Type": "application/json",
            }
        )
        self.session.headers.update(config.custom_headers)

    def _generate_signature(self, payload: bytes) -> str:
        """Generate HMAC-SHA256 signature for payload.

        Args:
            payload: The raw payload bytes

        Returns:
            Hex-encoded HMAC-SHA256 signature
        """
        if not self.config.secret:
            return ""

        signature = hmac.new(self.config.secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

        return f"sha256={signature}"

    def _finding_to_dict(self, finding: Finding) -> dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity.value,
            "confidence_score": finding.confidence_score,
            "file_path": finding.file_path,
            "start_line": finding.start_line,
            "end_line": finding.end_line,
            "cwe_id": finding.cwe_id,
            "cwe_name": finding.cwe_name,
            "description": finding.description,
            "analysis": finding.analysis,
            "poc": finding.poc,
            "discovered_at": finding.discovered_at.isoformat() + "Z",
        }

    def _format_json_payload(
        self,
        findings: list[Finding],
        event_type: str = "vulnerability_detected",
    ) -> dict[str, Any]:
        """Format payload as generic JSON."""
        return {
            "event": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "source": "vulnhuntr",
            "version": "1.0.0",
            "findings_count": len(findings),
            "findings": [self._finding_to_dict(f) for f in findings],
            "summary": {
                "total": len(findings),
                "by_severity": self._count_by_severity(findings),
                "by_type": self._count_by_type(findings),
            },
        }

    def _format_slack_payload(
        self,
        findings: list[Finding],
    ) -> dict[str, Any]:
        """Format payload for Slack webhooks."""
        severity_emoji = {
            FindingSeverity.CRITICAL: ":red_circle:",
            FindingSeverity.HIGH: ":large_orange_circle:",
            FindingSeverity.MEDIUM: ":large_yellow_circle:",
            FindingSeverity.LOW: ":large_green_circle:",
            FindingSeverity.INFO: ":large_blue_circle:",
        }

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🔍 Vulnhuntr: {len(findings)} Vulnerability(ies) Found",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Total Findings:* {len(findings)}",
                },
            },
            {"type": "divider"},
        ]

        # Add summary of findings (max 10 to avoid Slack limits)
        for finding in findings[:10]:
            emoji = severity_emoji.get(finding.severity, ":question:")
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"{emoji} *{finding.rule_id}* - {finding.severity.value.upper()}\n"
                            f"`{finding.file_path}`\n"
                            f"{finding.description[:200]}..."
                        ),
                    },
                }
            )

        if len(findings) > 10:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"_...and {len(findings) - 10} more findings_",
                    },
                }
            )

        return {"blocks": blocks}

    def _format_discord_payload(
        self,
        findings: list[Finding],
    ) -> dict[str, Any]:
        """Format payload for Discord webhooks."""
        color_map = {
            FindingSeverity.CRITICAL: 0xDC3545,  # Red
            FindingSeverity.HIGH: 0xFD7E14,  # Orange
            FindingSeverity.MEDIUM: 0xFFC107,  # Yellow
            FindingSeverity.LOW: 0x28A745,  # Green
            FindingSeverity.INFO: 0x17A2B8,  # Blue
        }

        embeds = []
        for finding in findings[:10]:  # Discord limit
            embeds.append(
                {
                    "title": f"{finding.rule_id}: {finding.title}",
                    "description": finding.description[:500],
                    "color": color_map.get(finding.severity, 0x6C757D),
                    "fields": [
                        {
                            "name": "Severity",
                            "value": finding.severity.value.upper(),
                            "inline": True,
                        },
                        {
                            "name": "Confidence",
                            "value": f"{finding.confidence_score}/10",
                            "inline": True,
                        },
                        {
                            "name": "File",
                            "value": f"`{finding.file_path}`",
                            "inline": False,
                        },
                    ],
                    "footer": {"text": "Vulnhuntr"},
                    "timestamp": finding.discovered_at.isoformat(),
                }
            )

        return {
            "content": f"🔍 **Vulnhuntr Security Scan**: {len(findings)} finding(s) detected",
            "embeds": embeds,
        }

    def _format_teams_payload(
        self,
        findings: list[Finding],
    ) -> dict[str, Any]:
        """Format payload for Microsoft Teams webhooks."""
        facts = []
        for finding in findings[:10]:
            facts.append(
                {
                    "title": f"{finding.rule_id} ({finding.severity.value.upper()})",
                    "value": f"{finding.file_path}: {finding.description[:100]}",
                }
            )

        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": f"Vulnhuntr: {len(findings)} vulnerabilities found",
            "themeColor": "DC3545" if any(f.severity == FindingSeverity.CRITICAL for f in findings) else "FFC107",
            "title": "🔍 Vulnhuntr Security Scan Results",
            "sections": [
                {
                    "activityTitle": f"Found {len(findings)} vulnerability(ies)",
                    "facts": facts,
                    "markdown": True,
                }
            ],
        }

    def _count_by_severity(self, findings: list[Finding]) -> dict[str, int]:
        """Count findings by severity."""
        counts: dict[str, int] = {}
        for finding in findings:
            sev = finding.severity.value
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _count_by_type(self, findings: list[Finding]) -> dict[str, int]:
        """Count findings by vulnerability type."""
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1
        return counts

    def _format_payload(
        self,
        findings: list[Finding],
        event_type: str = "vulnerability_detected",
    ) -> dict[str, Any]:
        """Format payload according to configured format."""
        if self.config.format == PayloadFormat.SLACK:
            return self._format_slack_payload(findings)
        elif self.config.format == PayloadFormat.DISCORD:
            return self._format_discord_payload(findings)
        elif self.config.format == PayloadFormat.TEAMS:
            return self._format_teams_payload(findings)
        else:
            return self._format_json_payload(findings, event_type)

    def _send_with_retry(
        self,
        payload: dict[str, Any],
        delivery_id: str,
    ) -> WebhookResult:
        """Send payload with retry logic."""
        payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        # Prepare headers
        headers = {
            "X-Vulnhuntr-Delivery": delivery_id,
            "X-Vulnhuntr-Event": "vulnerability_report",
        }

        # Add signature if secret configured
        if self.config.secret:
            headers["X-Vulnhuntr-Signature-256"] = self._generate_signature(payload_bytes)

        last_error = None
        for attempt in range(1, self.config.max_retries + 1):
            try:
                response = self.session.post(
                    self.config.url,
                    data=payload_bytes,
                    headers=headers,
                    timeout=self.config.timeout,
                    verify=self.config.verify_ssl,
                )

                # Success (2xx status codes)
                if 200 <= response.status_code < 300:
                    return WebhookResult(
                        success=True,
                        status_code=response.status_code,
                        response_body=response.text[:500] if response.text else None,
                        delivery_id=delivery_id,
                        attempts=attempt,
                    )

                # Client error (4xx) - don't retry
                if 400 <= response.status_code < 500:
                    return WebhookResult(
                        success=False,
                        status_code=response.status_code,
                        response_body=response.text[:500] if response.text else None,
                        error=f"Client error: {response.status_code}",
                        delivery_id=delivery_id,
                        attempts=attempt,
                    )

                # Server error (5xx) - retry
                last_error = f"Server error: {response.status_code}"

            except requests.exceptions.Timeout:
                last_error = "Request timed out"
            except requests.exceptions.ConnectionError as e:
                last_error = f"Connection error: {str(e)}"
            except Exception as e:
                last_error = f"Unexpected error: {str(e)}"

            # Wait before retry (exponential backoff)
            if attempt < self.config.max_retries:
                delay = self.config.retry_delay * (2 ** (attempt - 1))
                log.warning(
                    "Webhook delivery failed, retrying",
                    attempt=attempt,
                    max_retries=self.config.max_retries,
                    delay=delay,
                    error=last_error,
                )
                time.sleep(delay)

        return WebhookResult(
            success=False,
            error=last_error,
            delivery_id=delivery_id,
            attempts=self.config.max_retries,
        )

    def send_finding(self, finding: Finding) -> WebhookResult:
        """Send a single finding to the webhook.

        Args:
            finding: The vulnerability finding to send

        Returns:
            WebhookResult with delivery status
        """
        return self.send_batch([finding], event_type="vulnerability_detected")

    def send_batch(
        self,
        findings: list[Finding],
        event_type: str = "scan_complete",
    ) -> WebhookResult:
        """Send multiple findings in a single webhook call.

        Args:
            findings: List of vulnerability findings
            event_type: Event type for the payload

        Returns:
            WebhookResult with delivery status
        """
        if not findings:
            return WebhookResult(
                success=True,
                error="No findings to send",
            )

        delivery_id = str(uuid.uuid4())
        payload = self._format_payload(findings, event_type)

        log.info(
            "Sending webhook notification",
            delivery_id=delivery_id,
            findings_count=len(findings),
            format=self.config.format.value,
        )

        result = self._send_with_retry(payload, delivery_id)

        if result.success:
            log.info(
                "Webhook delivered successfully",
                delivery_id=delivery_id,
                status_code=result.status_code,
                attempts=result.attempts,
            )
        else:
            log.error(
                "Webhook delivery failed",
                delivery_id=delivery_id,
                error=result.error,
                attempts=result.attempts,
            )

        return result

    def test_connection(self) -> WebhookResult:
        """Send a test ping to verify webhook connectivity.

        Returns:
            WebhookResult with connection test status
        """
        delivery_id = str(uuid.uuid4())
        payload = {
            "event": "ping",
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "source": "vulnhuntr",
            "message": "Connection test from Vulnhuntr",
        }

        log.info("Testing webhook connection", url=self.config.url)

        return self._send_with_retry(payload, delivery_id)
