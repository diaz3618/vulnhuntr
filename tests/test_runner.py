"""Tests for vulnhuntr.cli.runner — initialize_llm() CLI provider wiring.

Covers Task 1 of Plan 04-03:
- initialize_llm("claude-code", config=...) returns ClaudeCodeLLM
- initialize_llm("gemini-cli", config=...) returns GeminiCLILLM
- initialize_llm("codex", ...) raises NotImplementedError with "Phase 5"
- initialize_llm("qwen-code", ...) raises NotImplementedError with "Phase 5"
- initialize_llm("claude-code", config=None) works — uses CLIPolicy() defaults
- Timeout override from policy.overrides["claude-code"]["timeout"] is passed
"""

from __future__ import annotations

from unittest.mock import MagicMock


def _make_config(
    timeout: int = 300,
    workdir: str | None = None,
    overrides: dict | None = None,
    tool_mode: str = "none",
    strip_env_vars: list | None = None,
) -> MagicMock:
    """Build a minimal VulnhuntrConfig mock that satisfies CLIPolicy lookups."""
    cfg = MagicMock()
    cfg.cli.timeout = timeout
    cfg.cli.workdir = workdir
    cfg.cli.overrides = overrides or {}
    cfg.cli.tool_mode = tool_mode
    cfg.cli.strip_env_vars = strip_env_vars or []
    return cfg


class TestInitializeLlmCliProviders:
    """initialize_llm() CLI provider wiring tests (Plan 04-03 Task 1)."""

    def test_claude_code_returns_claude_code_llm(self):
        """initialize_llm('claude-code', config=cfg) returns ClaudeCodeLLM instance."""
        from vulnhuntr.cli.runner import initialize_llm
        from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM

        cfg = _make_config()
        result = initialize_llm("claude-code", config=cfg)
        assert isinstance(result, ClaudeCodeLLM)

    def test_gemini_cli_returns_gemini_cli_llm(self):
        """initialize_llm('gemini-cli', config=cfg) returns GeminiCLILLM instance."""
        from vulnhuntr.cli.runner import initialize_llm
        from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM

        cfg = _make_config()
        result = initialize_llm("gemini-cli", config=cfg)
        assert isinstance(result, GeminiCLILLM)

    def test_codex_returns_codex_llm(self):
        """initialize_llm('codex', ...) returns CodexLLM instance (Phase 5 wired)."""
        from vulnhuntr.cli.runner import initialize_llm
        from vulnhuntr.cli_providers import CodexLLM

        cfg = _make_config()
        result = initialize_llm("codex", config=cfg)
        assert isinstance(result, CodexLLM)

    def test_qwen_code_returns_qwen_code_llm(self):
        """initialize_llm('qwen-code', ...) returns QwenCodeLLM instance (Phase 5 wired)."""
        from vulnhuntr.cli.runner import initialize_llm
        from vulnhuntr.cli_providers import QwenCodeLLM

        cfg = _make_config()
        result = initialize_llm("qwen-code", config=cfg)
        assert isinstance(result, QwenCodeLLM)

    def test_claude_code_with_config_none_uses_defaults(self):
        """initialize_llm('claude-code', config=None) uses CLIPolicy() defaults — no error."""
        from vulnhuntr.cli.runner import initialize_llm
        from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM

        result = initialize_llm("claude-code", config=None)
        assert isinstance(result, ClaudeCodeLLM)

    def test_timeout_override_from_policy_overrides(self):
        """Timeout override from policy.overrides['claude-code']['timeout'] is applied."""
        from vulnhuntr.cli.runner import initialize_llm
        from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM
        from vulnhuntr.config import CLIPolicy

        # Use a real CLIPolicy so overrides.get() works correctly
        policy = CLIPolicy()
        policy.overrides = {"claude-code": {"timeout": 600}}

        cfg = MagicMock()
        cfg.cli = policy

        result = initialize_llm("claude-code", config=cfg)
        assert isinstance(result, ClaudeCodeLLM)
        assert result.timeout == 600

    def test_config_parameter_accepted_by_signature(self):
        """initialize_llm signature must include config keyword argument."""
        import inspect

        from vulnhuntr.cli.runner import initialize_llm

        sig = inspect.signature(initialize_llm)
        assert "config" in sig.parameters, "config parameter missing from initialize_llm signature"

    def test_old_not_implemented_message_gone(self):
        """'not yet implemented' message must not appear for claude-code or gemini-cli."""
        from vulnhuntr.cli.runner import initialize_llm

        cfg = _make_config()
        # These must not raise NotImplementedError at all
        r1 = initialize_llm("claude-code", config=cfg)
        r2 = initialize_llm("gemini-cli", config=cfg)
        assert r1 is not None
        assert r2 is not None
