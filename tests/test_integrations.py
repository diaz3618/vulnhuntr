"""
Tests for vulnhuntr.integrations
================================

Tests for GitHub issues creation and webhook notifications.
"""

from unittest.mock import MagicMock, patch

import pytest

from vulnhuntr.reporters.base import Finding, FindingSeverity


# ── GitHub Issues ──────────────────────────────────────────────────────────


class TestGitHubConfig:
    def test_default_config(self):
        from vulnhuntr.integrations.github_issues import GitHubConfig

        config = GitHubConfig(
            token="test-token",
            owner="testorg",
            repo="testrepo",
        )
        assert config.token == "test-token"
        assert config.owner == "testorg"
        assert config.repo == "testrepo"
        assert config.labels == ["security", "vulnhuntr"]
        assert config.assignees == []
        assert config.milestone is None
        assert config.dry_run is False

    def test_custom_config(self):
        from vulnhuntr.integrations.github_issues import GitHubConfig

        config = GitHubConfig(
            token="token",
            owner="org",
            repo="repo",
            labels=["custom", "labels"],
            assignees=["user1", "user2"],
            milestone=5,
            dry_run=True,
        )
        assert config.labels == ["custom", "labels"]
        assert config.assignees == ["user1", "user2"]
        assert config.milestone == 5
        assert config.dry_run is True


class TestIssueResult:
    def test_success_result(self):
        from vulnhuntr.integrations.github_issues import IssueResult

        result = IssueResult(
            success=True,
            issue_number=42,
            issue_url="https://github.com/org/repo/issues/42",
        )
        assert result.success is True
        assert result.issue_number == 42
        assert result.error is None

    def test_failure_result(self):
        from vulnhuntr.integrations.github_issues import IssueResult

        result = IssueResult(
            success=False,
            error="Permission denied",
        )
        assert result.success is False
        assert result.issue_number is None
        assert result.error == "Permission denied"


class TestGitHubIssueCreator:
    @pytest.fixture
    def github_config(self):
        from vulnhuntr.integrations.github_issues import GitHubConfig

        return GitHubConfig(
            token="test-token",
            owner="testorg",
            repo="testrepo",
        )

    @pytest.fixture
    def sample_finding(self):
        return Finding(
            rule_id="SQLI",
            title="SQL Injection in user query",
            severity=FindingSeverity.HIGH,
            confidence_score=8,
            file_path="/app/db.py",
            start_line=42,
            description="User input passed directly to SQL query",
            analysis="Confirmed SQL injection vulnerability",
            poc="' OR 1=1 --",
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
        )

    @patch("vulnhuntr.integrations.github_issues.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.github_issues.requests")
    def test_init_creates_session(self, mock_requests, github_config):
        from vulnhuntr.integrations.github_issues import GitHubIssueCreator

        mock_session = MagicMock()
        mock_requests.Session.return_value = mock_session

        creator = GitHubIssueCreator(github_config)

        assert creator.config == github_config
        mock_session.headers.update.assert_called_once()

    @patch("vulnhuntr.integrations.github_issues.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.github_issues.requests")
    def test_format_issue_title(self, mock_requests, github_config, sample_finding):
        from vulnhuntr.integrations.github_issues import GitHubIssueCreator

        mock_requests.Session.return_value = MagicMock()
        creator = GitHubIssueCreator(github_config)

        title = creator._format_issue_title(sample_finding)

        assert "[SQLI]" in title
        assert "SQL Injection" in title
        # Should have severity emoji
        assert "🟠" in title  # High severity

    @patch("vulnhuntr.integrations.github_issues.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.github_issues.requests")
    def test_format_issue_body(self, mock_requests, github_config, sample_finding):
        from vulnhuntr.integrations.github_issues import GitHubIssueCreator

        mock_requests.Session.return_value = MagicMock()
        creator = GitHubIssueCreator(github_config)

        body = creator._format_issue_body(sample_finding)

        assert "SQL Injection" in body
        assert "HIGH" in body
        assert "8/10" in body
        assert "/app/db.py" in body
        assert "CWE-89" in body
        assert "OR 1=1" in body  # POC
        assert "Vulnhuntr" in body  # Footer

    @patch("vulnhuntr.integrations.github_issues.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.github_issues.requests")
    def test_get_labels_for_finding(self, mock_requests, github_config, sample_finding):
        from vulnhuntr.integrations.github_issues import GitHubIssueCreator

        mock_requests.Session.return_value = MagicMock()
        creator = GitHubIssueCreator(github_config)

        labels = creator._get_labels_for_finding(sample_finding)

        assert "security" in labels
        assert "vulnhuntr" in labels
        assert "high" in labels  # Severity label
        assert "vuln-sqli" in labels  # Type label

    @patch("vulnhuntr.integrations.github_issues.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.github_issues.requests")
    def test_create_issue_dry_run(self, mock_requests, sample_finding):
        from vulnhuntr.integrations.github_issues import GitHubConfig, GitHubIssueCreator

        config = GitHubConfig(
            token="token",
            owner="org",
            repo="repo",
            dry_run=True,
        )
        mock_requests.Session.return_value = MagicMock()
        creator = GitHubIssueCreator(config)

        result = creator.create_issue(sample_finding)

        assert result.success is True
        assert "Dry run" in result.error

    @patch("vulnhuntr.integrations.github_issues.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.github_issues.requests")
    def test_create_issue_success(self, mock_requests, github_config, sample_finding):
        from vulnhuntr.integrations.github_issues import GitHubIssueCreator

        mock_session = MagicMock()
        mock_requests.Session.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "number": 123,
            "html_url": "https://github.com/org/repo/issues/123",
        }
        mock_session.post.return_value = mock_response

        # Mock check_duplicate to return None
        creator = GitHubIssueCreator(github_config)
        creator.check_duplicate = MagicMock(return_value=None)

        result = creator.create_issue(sample_finding)

        assert result.success is True
        assert result.issue_number == 123
        assert "github.com" in result.issue_url

    @patch("vulnhuntr.integrations.github_issues.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.github_issues.requests")
    def test_create_issue_duplicate_skip(
        self, mock_requests, github_config, sample_finding
    ):
        from vulnhuntr.integrations.github_issues import GitHubIssueCreator

        mock_requests.Session.return_value = MagicMock()
        creator = GitHubIssueCreator(github_config)
        creator.check_duplicate = MagicMock(return_value=99)  # Existing issue

        result = creator.create_issue(sample_finding, skip_duplicates=True)

        assert result.success is True
        assert result.issue_number == 99
        assert "already exists" in result.error


class TestCreateGitHubConfigFromEnv:
    @patch.dict("os.environ", {"GITHUB_TOKEN": "env-token"})
    def test_creates_config_from_env(self):
        from vulnhuntr.integrations.github_issues import create_github_config_from_env

        config = create_github_config_from_env("owner", "repo")

        assert config.token == "env-token"
        assert config.owner == "owner"
        assert config.repo == "repo"

    @patch.dict("os.environ", {}, clear=True)
    def test_raises_without_token(self):
        from vulnhuntr.integrations.github_issues import create_github_config_from_env

        with pytest.raises(ValueError, match="GITHUB_TOKEN"):
            create_github_config_from_env("owner", "repo")


# ── Webhook Notifier ───────────────────────────────────────────────────────


class TestPayloadFormat:
    def test_enum_values(self):
        from vulnhuntr.integrations.webhook import PayloadFormat

        assert PayloadFormat.JSON.value == "json"
        assert PayloadFormat.SLACK.value == "slack"
        assert PayloadFormat.DISCORD.value == "discord"
        assert PayloadFormat.TEAMS.value == "teams"


class TestWebhookConfig:
    def test_default_config(self):
        from vulnhuntr.integrations.webhook import WebhookConfig

        config = WebhookConfig(url="https://webhook.example.com")

        assert config.url == "https://webhook.example.com"
        assert config.secret is None
        assert config.timeout == 30
        assert config.max_retries == 3
        assert config.verify_ssl is True

    def test_custom_config(self):
        from vulnhuntr.integrations.webhook import PayloadFormat, WebhookConfig

        config = WebhookConfig(
            url="https://hooks.slack.com/xxx",
            secret="my-secret",
            format=PayloadFormat.SLACK,
            timeout=60,
            max_retries=5,
        )
        assert config.secret == "my-secret"
        assert config.format == PayloadFormat.SLACK
        assert config.timeout == 60
        assert config.max_retries == 5


class TestWebhookResult:
    def test_success_result(self):
        from vulnhuntr.integrations.webhook import WebhookResult

        result = WebhookResult(
            success=True,
            status_code=200,
            delivery_id="abc-123",
            attempts=1,
        )
        assert result.success is True
        assert result.status_code == 200
        assert result.attempts == 1

    def test_failure_result(self):
        from vulnhuntr.integrations.webhook import WebhookResult

        result = WebhookResult(
            success=False,
            error="Connection timeout",
            attempts=3,
        )
        assert result.success is False
        assert result.error == "Connection timeout"
        assert result.attempts == 3


class TestWebhookNotifier:
    @pytest.fixture
    def webhook_config(self):
        from vulnhuntr.integrations.webhook import WebhookConfig

        return WebhookConfig(url="https://webhook.example.com")

    @pytest.fixture
    def sample_findings(self):
        return [
            Finding(
                rule_id="SQLI",
                title="SQL Injection",
                severity=FindingSeverity.HIGH,
                confidence_score=8,
                file_path="/app/db.py",
                description="SQL injection found",
            ),
            Finding(
                rule_id="XSS",
                title="Cross-Site Scripting",
                severity=FindingSeverity.MEDIUM,
                confidence_score=6,
                file_path="/app/views.py",
                description="XSS vulnerability",
            ),
        ]

    @patch("vulnhuntr.integrations.webhook.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.webhook.requests")
    def test_init_creates_session(self, mock_requests, webhook_config):
        from vulnhuntr.integrations.webhook import WebhookNotifier

        mock_session = MagicMock()
        mock_requests.Session.return_value = mock_session

        notifier = WebhookNotifier(webhook_config)

        assert notifier.config == webhook_config
        mock_session.headers.update.assert_called()

    @patch("vulnhuntr.integrations.webhook.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.webhook.requests")
    def test_generate_signature(self, mock_requests):
        from vulnhuntr.integrations.webhook import WebhookConfig, WebhookNotifier

        config = WebhookConfig(url="https://test.com", secret="test-secret")
        mock_requests.Session.return_value = MagicMock()

        notifier = WebhookNotifier(config)
        signature = notifier._generate_signature(b'{"test": "data"}')

        assert signature.startswith("sha256=")
        assert len(signature) > 10

    @patch("vulnhuntr.integrations.webhook.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.webhook.requests")
    def test_generate_signature_no_secret(self, mock_requests, webhook_config):
        from vulnhuntr.integrations.webhook import WebhookNotifier

        mock_requests.Session.return_value = MagicMock()

        notifier = WebhookNotifier(webhook_config)
        signature = notifier._generate_signature(b"data")

        assert signature == ""

    @patch("vulnhuntr.integrations.webhook.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.webhook.requests")
    def test_format_json_payload(
        self, mock_requests, webhook_config, sample_findings
    ):
        from vulnhuntr.integrations.webhook import WebhookNotifier

        mock_requests.Session.return_value = MagicMock()
        notifier = WebhookNotifier(webhook_config)

        payload = notifier._format_json_payload(sample_findings)

        assert payload["event"] == "vulnerability_detected"
        assert payload["source"] == "vulnhuntr"
        assert payload["findings_count"] == 2
        assert len(payload["findings"]) == 2
        assert "summary" in payload

    @patch("vulnhuntr.integrations.webhook.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.webhook.requests")
    def test_format_slack_payload(
        self, mock_requests, webhook_config, sample_findings
    ):
        from vulnhuntr.integrations.webhook import WebhookNotifier

        mock_requests.Session.return_value = MagicMock()
        notifier = WebhookNotifier(webhook_config)

        payload = notifier._format_slack_payload(sample_findings)

        assert "blocks" in payload
        assert len(payload["blocks"]) > 0

    @patch("vulnhuntr.integrations.webhook.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.webhook.requests")
    def test_format_discord_payload(
        self, mock_requests, webhook_config, sample_findings
    ):
        from vulnhuntr.integrations.webhook import WebhookNotifier

        mock_requests.Session.return_value = MagicMock()
        notifier = WebhookNotifier(webhook_config)

        payload = notifier._format_discord_payload(sample_findings)

        assert "content" in payload
        assert "embeds" in payload
        assert len(payload["embeds"]) == 2

    @patch("vulnhuntr.integrations.webhook.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.webhook.requests")
    def test_format_teams_payload(
        self, mock_requests, webhook_config, sample_findings
    ):
        from vulnhuntr.integrations.webhook import WebhookNotifier

        mock_requests.Session.return_value = MagicMock()
        notifier = WebhookNotifier(webhook_config)

        payload = notifier._format_teams_payload(sample_findings)

        assert payload["@type"] == "MessageCard"
        assert "sections" in payload

    @patch("vulnhuntr.integrations.webhook.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.webhook.requests")
    def test_send_batch_success(
        self, mock_requests, webhook_config, sample_findings
    ):
        from vulnhuntr.integrations.webhook import WebhookNotifier

        mock_session = MagicMock()
        mock_requests.Session.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "OK"
        mock_session.post.return_value = mock_response

        notifier = WebhookNotifier(webhook_config)
        result = notifier.send_batch(sample_findings)

        assert result.success is True
        assert result.status_code == 200
        mock_session.post.assert_called_once()

    @patch("vulnhuntr.integrations.webhook.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.webhook.requests")
    def test_send_batch_empty(self, mock_requests, webhook_config):
        from vulnhuntr.integrations.webhook import WebhookNotifier

        mock_requests.Session.return_value = MagicMock()
        notifier = WebhookNotifier(webhook_config)

        result = notifier.send_batch([])

        assert result.success is True
        assert "No findings" in result.error

    @patch("vulnhuntr.integrations.webhook.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.webhook.requests")
    def test_send_finding(self, mock_requests, webhook_config, sample_findings):
        from vulnhuntr.integrations.webhook import WebhookNotifier

        mock_session = MagicMock()
        mock_requests.Session.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        notifier = WebhookNotifier(webhook_config)
        result = notifier.send_finding(sample_findings[0])

        assert result.success is True

    @patch("vulnhuntr.integrations.webhook.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.webhook.requests")
    @patch("vulnhuntr.integrations.webhook.time.sleep")
    def test_retry_on_server_error(
        self, mock_sleep, mock_requests, webhook_config, sample_findings
    ):
        from vulnhuntr.integrations.webhook import WebhookNotifier

        mock_session = MagicMock()
        mock_requests.Session.return_value = mock_session

        # First 2 calls fail with 500, third succeeds
        mock_response_500 = MagicMock()
        mock_response_500.status_code = 500
        mock_response_500.text = "Server Error"

        mock_response_200 = MagicMock()
        mock_response_200.status_code = 200
        mock_response_200.text = "OK"

        mock_session.post.side_effect = [
            mock_response_500,
            mock_response_500,
            mock_response_200,
        ]

        notifier = WebhookNotifier(webhook_config)
        result = notifier.send_batch(sample_findings)

        assert result.success is True
        assert result.attempts == 3

    @patch("vulnhuntr.integrations.webhook.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.webhook.requests")
    def test_no_retry_on_client_error(
        self, mock_requests, webhook_config, sample_findings
    ):
        from vulnhuntr.integrations.webhook import WebhookNotifier

        mock_session = MagicMock()
        mock_requests.Session.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Bad Request"
        mock_session.post.return_value = mock_response

        notifier = WebhookNotifier(webhook_config)
        result = notifier.send_batch(sample_findings)

        assert result.success is False
        assert result.attempts == 1  # No retry
        assert "Client error" in result.error

    @patch("vulnhuntr.integrations.webhook.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.webhook.requests")
    def test_test_connection(self, mock_requests, webhook_config):
        from vulnhuntr.integrations.webhook import WebhookNotifier

        mock_session = MagicMock()
        mock_requests.Session.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        notifier = WebhookNotifier(webhook_config)
        result = notifier.test_connection()

        assert result.success is True


class TestCountHelpers:
    @pytest.fixture
    def findings_for_counting(self):
        return [
            Finding(
                rule_id="SQLI",
                title="SQLi 1",
                severity=FindingSeverity.HIGH,
                confidence_score=8,
                file_path="a.py",
            ),
            Finding(
                rule_id="SQLI",
                title="SQLi 2",
                severity=FindingSeverity.HIGH,
                confidence_score=7,
                file_path="b.py",
            ),
            Finding(
                rule_id="XSS",
                title="XSS",
                severity=FindingSeverity.MEDIUM,
                confidence_score=6,
                file_path="c.py",
            ),
        ]

    @patch("vulnhuntr.integrations.webhook.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.webhook.requests")
    def test_count_by_severity(self, mock_requests, findings_for_counting):
        from vulnhuntr.integrations.webhook import WebhookConfig, WebhookNotifier

        config = WebhookConfig(url="https://test.com")
        mock_requests.Session.return_value = MagicMock()
        notifier = WebhookNotifier(config)

        counts = notifier._count_by_severity(findings_for_counting)

        assert counts["high"] == 2
        assert counts["medium"] == 1

    @patch("vulnhuntr.integrations.webhook.REQUESTS_AVAILABLE", True)
    @patch("vulnhuntr.integrations.webhook.requests")
    def test_count_by_type(self, mock_requests, findings_for_counting):
        from vulnhuntr.integrations.webhook import WebhookConfig, WebhookNotifier

        config = WebhookConfig(url="https://test.com")
        mock_requests.Session.return_value = MagicMock()
        notifier = WebhookNotifier(config)

        counts = notifier._count_by_type(findings_for_counting)

        assert counts["SQLI"] == 2
        assert counts["XSS"] == 1
