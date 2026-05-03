"""Tests for vulnhuntr.cli_providers (AICLI-01..04, GEMINI-CLI-01).

Covers:
- AICLI-01: CLIProviderLLM inherits from LLM; CapabilityResult dataclass shape
- AICLI-02: probe() abstract; CapabilityResult fields; diagnostic_message present
- AICLI-03: _run_subprocess uses list-form, shell=False, stdin=DEVNULL; error taxonomy
- AICLI-04: chat() calls _log_response() for cost tracking; response normalization
- GEMINI-CLI-01: GeminiCLILLM adapter — probe, send_message, get_response, _extract_usage
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import fields
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from vulnhuntr.cli_providers import (
    CLIAuthError,
    CLIBinaryNotFoundError,
    CLIParseError,
    CLIProviderLLM,
    CLIRuntimeError,
    CLISandboxError,
    CLITimeoutError,
    CapabilityResult,
)
from vulnhuntr.llms import LLM, LLMError


# ---------------------------------------------------------------------------
# Minimal concrete subclass for testing the abstract base
# ---------------------------------------------------------------------------


class _FakeCLIProvider(CLIProviderLLM):
    """Minimal concrete provider used only in tests."""

    def probe(self) -> CapabilityResult:
        return CapabilityResult(
            ok=True,
            binary_found=True,
            version="1.0.0",
            auth_valid=True,
            diagnostic_message="",
        )

    def get_response(self, response: Any) -> str:
        return response.stdout

    def _extract_usage(self, response: Any) -> Any:
        from vulnhuntr.core.models import LLMUsage

        return LLMUsage(input_tokens=0, output_tokens=0, model=self.model)

    def send_message(self, user_prompt: str, max_tokens: int, response_model: Any) -> Any:
        return self._run_subprocess(["echo", user_prompt])


# ---------------------------------------------------------------------------
# AICLI-01: Inheritance and package exports
# ---------------------------------------------------------------------------


class TestInheritance:
    def test_cli_provider_llm_is_subclass_of_llm(self):
        assert issubclass(CLIProviderLLM, LLM)

    def test_concrete_provider_is_subclass_of_llm(self):
        assert issubclass(_FakeCLIProvider, LLM)

    def test_concrete_provider_is_subclass_of_cli_provider_llm(self):
        assert issubclass(_FakeCLIProvider, CLIProviderLLM)

    def test_instantiation(self):
        provider = _FakeCLIProvider()
        assert isinstance(provider, LLM)
        assert isinstance(provider, CLIProviderLLM)


class TestErrorTaxonomy:
    """All CLI*Error classes must be subclasses of LLMError."""

    @pytest.mark.parametrize(
        "error_cls",
        [
            CLIBinaryNotFoundError,
            CLIAuthError,
            CLITimeoutError,
            CLIParseError,
            CLISandboxError,
            CLIRuntimeError,
        ],
    )
    def test_error_is_subclass_of_llm_error(self, error_cls):
        assert issubclass(error_cls, LLMError)

    def test_six_error_classes_exported(self):
        from vulnhuntr import cli_providers

        error_names = [
            "CLIBinaryNotFoundError",
            "CLIAuthError",
            "CLITimeoutError",
            "CLIParseError",
            "CLISandboxError",
            "CLIRuntimeError",
        ]
        for name in error_names:
            assert hasattr(cli_providers, name), f"{name} not exported from cli_providers"


class TestPackageExports:
    def test_cli_provider_llm_importable(self):
        from vulnhuntr.cli_providers import CLIProviderLLM as C

        assert C is CLIProviderLLM

    def test_capability_result_importable(self):
        from vulnhuntr.cli_providers import CapabilityResult as CR

        assert CR is CapabilityResult

    def test_all_defined(self):
        from vulnhuntr import cli_providers

        assert hasattr(cli_providers, "__all__")
        assert "CLIProviderLLM" in cli_providers.__all__
        assert "CapabilityResult" in cli_providers.__all__


# ---------------------------------------------------------------------------
# AICLI-02: CapabilityResult shape and probe() contract
# ---------------------------------------------------------------------------


class TestCapabilityResult:
    def test_has_exactly_five_fields(self):
        field_names = {f.name for f in fields(CapabilityResult)}
        assert field_names == {"ok", "binary_found", "version", "auth_valid", "diagnostic_message"}

    def test_ok_field(self):
        cr = CapabilityResult(ok=True, binary_found=True, version=None, auth_valid=None, diagnostic_message="")
        assert cr.ok is True

    def test_binary_found_field(self):
        cr = CapabilityResult(ok=False, binary_found=False, version=None, auth_valid=None, diagnostic_message="not found")
        assert cr.binary_found is False

    def test_version_can_be_none(self):
        cr = CapabilityResult(ok=True, binary_found=True, version=None, auth_valid=None, diagnostic_message="")
        assert cr.version is None

    def test_auth_valid_can_be_none(self):
        cr = CapabilityResult(ok=True, binary_found=True, version="1.0", auth_valid=None, diagnostic_message="")
        assert cr.auth_valid is None

    def test_diagnostic_message_present(self):
        cr = CapabilityResult(ok=False, binary_found=True, version=None, auth_valid=False, diagnostic_message="auth failed")
        assert cr.diagnostic_message == "auth failed"

    def test_probe_returns_capability_result(self):
        provider = _FakeCLIProvider()
        result = provider.probe()
        assert isinstance(result, CapabilityResult)


class TestProbeAbstract:
    def test_cannot_instantiate_without_probe(self):
        """CLIProviderLLM is abstract — instantiation without probe() must fail."""

        class _Incomplete(CLIProviderLLM):
            def get_response(self, response: Any) -> str:
                return ""

            def _extract_usage(self, response: Any) -> Any:
                from vulnhuntr.core.models import LLMUsage

                return LLMUsage(0, 0, "")

            def send_message(self, *args: Any, **kwargs: Any) -> Any:
                return None

        with pytest.raises(TypeError):
            _Incomplete()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# AICLI-03: Subprocess dispatch — list-form, shell=False, stdin=DEVNULL
# ---------------------------------------------------------------------------


class TestSubprocessDispatch:
    def test_run_subprocess_uses_list_form(self):
        """_run_subprocess must never use shell=True."""
        provider = _FakeCLIProvider()
        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "hello"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            provider._run_subprocess(["echo", "hello"])

            call_kwargs = mock_run.call_args
            # First positional arg must be a list, not a string
            cmd_arg = call_kwargs[0][0]
            assert isinstance(cmd_arg, list), "cmd must be a list, not a shell string"
            assert call_kwargs[1].get("shell") is not True, "shell=True must never be used"

    def test_run_subprocess_stdin_devnull_by_default(self):
        provider = _FakeCLIProvider()
        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            provider._run_subprocess(["echo"])

            call_kwargs = mock_run.call_args[1]
            assert call_kwargs["stdin"] == subprocess.DEVNULL

    def test_run_subprocess_stdin_pipe_when_input_given(self):
        provider = _FakeCLIProvider()
        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            provider._run_subprocess(["cat"], input_text="hello")

            call_kwargs = mock_run.call_args[1]
            assert call_kwargs["stdin"] == subprocess.PIPE

    def test_binary_not_found_raises_cli_binary_not_found_error(self):
        provider = _FakeCLIProvider()
        with patch("subprocess.run", side_effect=FileNotFoundError("no such file")):
            with pytest.raises(CLIBinaryNotFoundError):
                provider._run_subprocess(["nonexistent-binary"])

    def test_timeout_raises_cli_timeout_error(self):
        provider = _FakeCLIProvider()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="x", timeout=1)):
            with pytest.raises(CLITimeoutError):
                provider._run_subprocess(["sleep", "999"])

    def test_nonzero_exit_raises_cli_runtime_error(self):
        provider = _FakeCLIProvider()
        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 1
            mock_result.stderr = "something went wrong"
            mock_run.return_value = mock_result

            with pytest.raises(CLIRuntimeError):
                provider._run_subprocess(["false"])

    def test_env_stripping(self):
        """Vars listed in _STRIP_ENV_VARS must not appear in subprocess env."""

        class _StripProvider(_FakeCLIProvider):
            _STRIP_ENV_VARS = ("SECRET_KEY",)

        import os

        os.environ["SECRET_KEY"] = "should-be-stripped"
        provider = _StripProvider()
        env = provider._build_env()
        assert "SECRET_KEY" not in env
        del os.environ["SECRET_KEY"]


# ---------------------------------------------------------------------------
# AICLI-04: chat() calls _log_response() for cost tracking
# ---------------------------------------------------------------------------


class TestChatCostTracking:
    def test_chat_calls_log_response(self):
        """chat() must call _log_response() so cost tracking fires."""
        provider = _FakeCLIProvider()
        provider._log_response = MagicMock()

        with patch.object(provider, "send_message") as mock_send:
            mock_result = MagicMock()
            mock_result.stdout = "response text"
            mock_result.returncode = 0
            mock_send.return_value = mock_result

            provider.chat("hello")

        provider._log_response.assert_called_once_with(mock_result)

    def test_chat_adds_to_history(self):
        provider = _FakeCLIProvider()

        with patch.object(provider, "send_message") as mock_send:
            mock_result = MagicMock()
            mock_result.stdout = "world"
            mock_result.returncode = 0
            mock_send.return_value = mock_result

            provider.chat("hello")

        assert len(provider.history) == 2
        assert provider.history[0] == {"role": "user", "content": "hello"}
        assert provider.history[1]["role"] == "assistant"

    def test_chat_with_cost_callback(self):
        """Cost callback must be invoked when chat() completes."""
        callback = MagicMock()
        provider = _FakeCLIProvider(cost_callback=callback)

        with patch.object(provider, "send_message") as mock_send:
            mock_result = MagicMock()
            mock_result.stdout = "result"
            mock_result.returncode = 0
            mock_send.return_value = mock_result

            provider.chat("test prompt")

        callback.assert_called_once()

    def test_create_messages_raises_not_implemented(self):
        """CLI providers don't use create_messages() — it must raise."""
        provider = _FakeCLIProvider()
        with pytest.raises(NotImplementedError):
            provider.create_messages("anything")


# ---------------------------------------------------------------------------
# ClaudeCodeLLM tests (CLAUDECLI-01)
# ---------------------------------------------------------------------------


class TestClaudeCodeLLMImport:
    def test_importable_from_cli_providers(self):
        from vulnhuntr.cli_providers import ClaudeCodeLLM  # noqa: F401

    def test_in_all(self):
        from vulnhuntr import cli_providers
        assert "ClaudeCodeLLM" in cli_providers.__all__

    def test_subclass_of_cli_provider_llm(self):
        from vulnhuntr.cli_providers import ClaudeCodeLLM
        assert issubclass(ClaudeCodeLLM, CLIProviderLLM)

    def test_strip_env_vars_contains_anthropic_api_key(self):
        from vulnhuntr.cli_providers import ClaudeCodeLLM
        assert "ANTHROPIC_API_KEY" in ClaudeCodeLLM._STRIP_ENV_VARS

    def test_no_chat_override(self):
        from vulnhuntr.cli_providers import ClaudeCodeLLM
        from vulnhuntr.cli_providers.base import CLIProviderLLM as Base
        assert ClaudeCodeLLM.chat is Base.chat


class TestClaudeCodeLLMProbe:
    def test_probe_missing_binary(self):
        from vulnhuntr.cli_providers import ClaudeCodeLLM
        with patch("shutil.which", return_value=None):
            provider = ClaudeCodeLLM()
            result = provider.probe()
        assert result.ok is False
        assert result.binary_found is False
        assert result.auth_valid is None
        assert "npm i -g @anthropic-ai/claude-code" in result.diagnostic_message

    def test_probe_ok(self):
        from vulnhuntr.cli_providers import ClaudeCodeLLM
        mock_result = MagicMock()
        mock_result.stdout = "2.1.126 (Claude Code)"
        mock_result.returncode = 0
        mock_result.stderr = ""
        with patch("shutil.which", return_value="/usr/bin/claude"):
            with patch("subprocess.run", return_value=mock_result):
                provider = ClaudeCodeLLM()
                result = provider.probe()
        assert result.ok is True
        assert result.binary_found is True
        assert result.version == "2.1.126"
        assert result.auth_valid is None


class TestClaudeCodeLLMSendMessage:
    def test_send_message_success(self):
        from vulnhuntr.cli_providers import ClaudeCodeLLM
        payload_json = '{"result":"hello","usage":{"input_tokens":10,"output_tokens":5},"modelUsage":{"claude-sonnet-4-6":{}}}'
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = payload_json
        mock_result.stderr = ""
        with patch("subprocess.run", return_value=mock_result):
            provider = ClaudeCodeLLM()
            response = provider.send_message("test prompt", 8192)
        assert "result" in response
        assert "usage" in response
        assert provider.model == "claude-sonnet-4-6"

    def test_send_message_empty_stdout_raises_cli_parse_error(self):
        from vulnhuntr.cli_providers import ClaudeCodeLLM
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        with patch("subprocess.run", return_value=mock_result):
            provider = ClaudeCodeLLM()
            with pytest.raises(CLIParseError):
                provider.send_message("test", 8192)

    def test_send_message_bad_json_raises_cli_parse_error(self):
        from vulnhuntr.cli_providers import ClaudeCodeLLM
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "not json"
        mock_result.stderr = ""
        with patch("subprocess.run", return_value=mock_result):
            provider = ClaudeCodeLLM()
            with pytest.raises(CLIParseError):
                provider.send_message("test", 8192)


class TestClaudeCodeLLMGetResponse:
    def test_get_response_ok(self):
        from vulnhuntr.cli_providers import ClaudeCodeLLM
        provider = ClaudeCodeLLM()
        result = provider.get_response({"result": "text"})
        assert result == "text"

    def test_get_response_missing_raises_cli_parse_error(self):
        from vulnhuntr.cli_providers import ClaudeCodeLLM
        provider = ClaudeCodeLLM()
        with pytest.raises(CLIParseError):
            provider.get_response({"other": "x"})


class TestClaudeCodeLLMExtractUsage:
    def test_extract_usage_sums_cache_tokens(self):
        from vulnhuntr.cli_providers import ClaudeCodeLLM
        from vulnhuntr.core.models import LLMUsage
        provider = ClaudeCodeLLM()
        payload = {
            "usage": {
                "input_tokens": 10,
                "cache_creation_input_tokens": 5,
                "cache_read_input_tokens": 3,
                "output_tokens": 7,
            },
            "modelUsage": {"m": {}},
        }
        usage = provider._extract_usage(payload)
        assert isinstance(usage, LLMUsage)
        assert usage.input_tokens == 18
        assert usage.output_tokens == 7
        assert usage.model == "m"


class TestClaudeCodeLLMBuildEnv:
    def test_build_env_strips_anthropic_api_key(self):
        import os
        from vulnhuntr.cli_providers import ClaudeCodeLLM
        os.environ["ANTHROPIC_API_KEY"] = "test-key-should-be-stripped"
        try:
            provider = ClaudeCodeLLM()
            env = provider._build_env()
            assert "ANTHROPIC_API_KEY" not in env
        finally:
            del os.environ["ANTHROPIC_API_KEY"]

    def test_build_env_strips_policy_vars(self):
        import os
        from vulnhuntr.cli_providers import ClaudeCodeLLM
        from vulnhuntr.config import CLIPolicy
        os.environ["CUSTOM_SECRET"] = "should-also-be-stripped"
        try:
            policy = CLIPolicy()
            policy.strip_env_vars = ["CUSTOM_SECRET"]
            provider = ClaudeCodeLLM(policy=policy)
            env = provider._build_env()
            assert "CUSTOM_SECRET" not in env
        finally:
            del os.environ["CUSTOM_SECRET"]


# ---------------------------------------------------------------------------
# GeminiCLILLM tests (GEMINI-CLI-01)
# ---------------------------------------------------------------------------


class TestGeminiCLILLM:
    """Tests for GeminiCLILLM (GEMINI-CLI-01).

    All subprocess calls are mocked — no live binary required.
    Live tests are marked @pytest.mark.live and excluded from CI.
    """

    @pytest.fixture
    def gemini(self):
        """Return a GeminiCLILLM instance with default policy."""
        from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM

        return GeminiCLILLM()

    # Test 1: probe — binary missing
    def test_probe_missing_binary(self):
        """probe() returns ok=False, binary_found=False when gemini not on PATH."""
        from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM

        provider = GeminiCLILLM()
        with patch("shutil.which", return_value=None):
            result = provider.probe()
        assert result.ok is False
        assert result.binary_found is False
        assert "npm i -g @google/gemini-cli" in result.diagnostic_message

    # Test 2: probe — version too old
    def test_probe_version_too_old(self):
        """probe() rejects version < 0.6.0 with exact diagnostic message."""
        from unittest.mock import MagicMock

        from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM

        provider = GeminiCLILLM()
        mock_result = MagicMock()
        mock_result.stdout = "0.5.9"
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("shutil.which", return_value="/usr/bin/gemini"), patch(
            "subprocess.run", return_value=mock_result
        ):
            result = provider.probe()

        assert result.ok is False
        assert result.binary_found is True
        assert result.version == "0.5.9"
        assert result.diagnostic_message == (
            "Gemini CLI 0.5.9 too old; --output-format json requires >= 0.6.0. "
            "Run: npm i -g @google/gemini-cli"
        )

    # Test 3: probe — version 0.40.1 passes gate (0.40.1 >= 0.6.0 as tuples)
    def test_probe_ok_version_0_40_1(self):
        """probe() returns ok=True for gemini 0.40.1 (tuple comparison, not string)."""
        from unittest.mock import MagicMock

        from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM

        provider = GeminiCLILLM()
        mock_result = MagicMock()
        mock_result.stdout = "0.40.1"
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("shutil.which", return_value="/usr/bin/gemini"), patch(
            "subprocess.run", return_value=mock_result
        ):
            result = provider.probe()

        assert result.ok is True
        assert result.binary_found is True
        assert result.version == "0.40.1"
        assert result.auth_valid is None

    # Test 4: semver tuple gate correctness
    @pytest.mark.parametrize(
        "version_str,expected_ok",
        [
            ("0.40.1", True),   # (0,40,1) >= (0,6,0) — string compare would fail
            ("0.9.0", True),    # (0,9,0) >= (0,6,0)
            ("0.5.9", False),   # (0,5,9) < (0,6,0)
            ("0.6.0", True),    # exactly at minimum
            ("1.0.0", True),    # major version bump
        ],
    )
    def test_probe_semver_tuple_comparison(self, version_str, expected_ok):
        """Semver gate must use tuple integers, not string comparison."""
        from unittest.mock import MagicMock

        from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM

        provider = GeminiCLILLM()
        mock_result = MagicMock()
        mock_result.stdout = version_str
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("shutil.which", return_value="/usr/bin/gemini"), patch(
            "subprocess.run", return_value=mock_result
        ):
            result = provider.probe()

        assert result.ok is expected_ok

    # Test 5: send_message success
    def test_send_message_success(self):
        """send_message() returns parsed JSON dict and sets self.model."""
        from unittest.mock import MagicMock

        from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM

        provider = GeminiCLILLM()
        stdout_payload = (
            '{"response":"hello",'
            '"stats":{"models":{"gemini-2.5-flash":{"tokens":{"input":100,"candidates":20}}}}}'
        )
        mock_result = MagicMock()
        mock_result.stdout = stdout_payload
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            payload = provider.send_message("test prompt", 8192, None)

        assert isinstance(payload, dict)
        assert payload["response"] == "hello"

    # Test 6: send_message — empty stdout raises CLIParseError
    def test_send_message_empty_stdout_raises(self):
        """send_message() raises CLIParseError when subprocess returns empty stdout."""
        from unittest.mock import MagicMock

        from vulnhuntr.cli_providers.base import CLIParseError
        from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM

        provider = GeminiCLILLM()
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(CLIParseError):
                provider.send_message("test", 8192, None)

    # Test 7: send_message — invalid JSON raises CLIParseError
    def test_send_message_invalid_json_raises(self):
        """send_message() raises CLIParseError when stdout is not valid JSON."""
        from unittest.mock import MagicMock

        from vulnhuntr.cli_providers.base import CLIParseError
        from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM

        provider = GeminiCLILLM()
        mock_result = MagicMock()
        mock_result.stdout = "not json"
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(CLIParseError):
                provider.send_message("test", 8192, None)

    # Test 8: get_response — ok path
    def test_get_response_ok(self, gemini):
        """get_response() returns value of 'response' key."""
        result = gemini.get_response({"response": "text"})
        assert result == "text"

    # Test 9: get_response — missing 'response' field raises CLIParseError
    def test_get_response_missing_field_raises(self, gemini):
        """get_response() raises CLIParseError when 'response' key absent (NOT 'result')."""
        from vulnhuntr.cli_providers.base import CLIParseError

        with pytest.raises(CLIParseError):
            gemini.get_response({"result": "wrong-field"})

    # Test 10: _extract_usage — single model
    def test_extract_usage_single_model(self, gemini):
        """_extract_usage() returns correct token counts for single model."""
        from vulnhuntr.core.models import LLMUsage

        payload = {
            "stats": {
                "models": {
                    "gemini-2.5-flash": {
                        "tokens": {"input": 100, "candidates": 20}
                    }
                }
            }
        }
        usage = gemini._extract_usage(payload)
        assert isinstance(usage, LLMUsage)
        assert usage.input_tokens == 100
        assert usage.output_tokens == 20

    # Test 11: _extract_usage — multi-model summing
    def test_extract_usage_multi_model_sums(self, gemini):
        """_extract_usage() sums tokens across ALL model entries."""
        from vulnhuntr.core.models import LLMUsage

        payload = {
            "stats": {
                "models": {
                    "gemini-2.5-flash-lite": {
                        "tokens": {"input": 100, "candidates": 20}
                    },
                    "gemini-2.5-flash": {
                        "tokens": {"input": 50, "candidates": 10}
                    },
                }
            }
        }
        usage = gemini._extract_usage(payload)
        assert usage.input_tokens == 150
        assert usage.output_tokens == 30

    # Test 12: _extract_usage — missing stats
    def test_extract_usage_missing_stats(self, gemini):
        """_extract_usage() returns zero tokens when stats absent."""
        from vulnhuntr.core.models import LLMUsage

        usage = gemini._extract_usage({})
        assert isinstance(usage, LLMUsage)
        assert usage.input_tokens == 0
        assert usage.output_tokens == 0

    # Test 13: _build_env strips all three Gemini-specific env vars
    def test_build_env_strips_gemini_vars(self, gemini):
        """_build_env() removes GEMINI_API_KEY, GOOGLE_API_KEY, GOOGLE_GENAI_USE_VERTEXAI."""
        with patch.dict(
            os.environ,
            {
                "GEMINI_API_KEY": "key1",
                "GOOGLE_API_KEY": "key2",
                "GOOGLE_GENAI_USE_VERTEXAI": "true",
            },
        ):
            env = gemini._build_env()

        assert "GEMINI_API_KEY" not in env
        assert "GOOGLE_API_KEY" not in env
        assert "GOOGLE_GENAI_USE_VERTEXAI" not in env

    # Test 14: approval-mode plan for tool_mode none
    def test_send_message_approval_mode_plan_for_none(self):
        """send_message() uses --approval-mode plan when tool_mode is 'none'."""
        from unittest.mock import MagicMock, call

        from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM

        provider = GeminiCLILLM()
        mock_result = MagicMock()
        mock_result.stdout = '{"response":"ok","stats":{"models":{}}}'
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            provider.send_message("hello", 8192, None)

        cmd = mock_run.call_args[0][0]
        assert "--approval-mode" in cmd
        idx = cmd.index("--approval-mode")
        assert cmd[idx + 1] == "plan"

    # Test 15: approval-mode yolo for tool_mode full
    def test_send_message_approval_mode_yolo_for_full(self):
        """send_message() uses --approval-mode yolo when tool_mode is 'full'."""
        from unittest.mock import MagicMock

        from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM
        from vulnhuntr.config import CLIPolicy

        policy = CLIPolicy()
        policy.tool_mode = "full"
        provider = GeminiCLILLM(policy=policy)
        mock_result = MagicMock()
        mock_result.stdout = '{"response":"ok","stats":{"models":{}}}'
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            provider.send_message("hello", 8192, None)

        cmd = mock_run.call_args[0][0]
        assert "--approval-mode" in cmd
        idx = cmd.index("--approval-mode")
        assert cmd[idx + 1] == "yolo"

    # Test: approval-mode plan for tool_mode read-only
    def test_send_message_approval_mode_plan_for_readonly(self):
        """send_message() uses --approval-mode plan when tool_mode is 'read-only'."""
        from unittest.mock import MagicMock

        from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM
        from vulnhuntr.config import CLIPolicy

        policy = CLIPolicy()
        policy.tool_mode = "read-only"
        provider = GeminiCLILLM(policy=policy)
        mock_result = MagicMock()
        mock_result.stdout = '{"response":"ok","stats":{"models":{}}}'
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            provider.send_message("hello", 8192, None)

        cmd = mock_run.call_args[0][0]
        assert "--approval-mode" in cmd
        idx = cmd.index("--approval-mode")
        assert cmd[idx + 1] == "plan"

    # Test: chat is NOT overridden (uses CLIProviderLLM.chat)
    def test_chat_not_overridden(self):
        """GeminiCLILLM must not override chat() — base class handles pipeline."""
        from vulnhuntr.cli_providers.base import CLIProviderLLM
        from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM

        assert GeminiCLILLM.chat is CLIProviderLLM.chat

    # Test: _STRIP_ENV_VARS contains all three required vars
    def test_strip_env_vars_class_attribute(self):
        """GeminiCLILLM._STRIP_ENV_VARS must include all three auth-forcing vars."""
        from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM

        strip = GeminiCLILLM._STRIP_ENV_VARS
        assert "GEMINI_API_KEY" in strip
        assert "GOOGLE_API_KEY" in strip
        assert "GOOGLE_GENAI_USE_VERTEXAI" in strip

    # Test: --allowed-tools is never used
    def test_no_allowed_tools_flag(self):
        """send_message() must never use deprecated --allowed-tools flag."""
        from unittest.mock import MagicMock

        from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM

        provider = GeminiCLILLM()
        mock_result = MagicMock()
        mock_result.stdout = '{"response":"ok","stats":{"models":{}}}'
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            provider.send_message("hello", 8192, None)

        cmd = mock_run.call_args[0][0]
        assert "--allowed-tools" not in cmd

    @pytest.mark.live
    def test_live_probe(self):
        """Live: probe() returns ok=True on an installed and authenticated gemini binary."""
        from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM

        provider = GeminiCLILLM()
        result = provider.probe()
        assert result.ok is True
        assert result.binary_found is True
        assert result.version is not None

    @pytest.mark.live
    def test_live_send_message(self):
        """Live: gemini -p '...' --output-format json returns a valid response."""
        from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM

        provider = GeminiCLILLM()
        payload = provider.send_message("Say hello in one word.", 256, None)
        assert isinstance(payload, dict)
        assert "response" in payload

    def test_send_message_binary_not_found(self):
        """send_message() raises CLIBinaryNotFoundError when gemini binary absent."""
        from pydantic import BaseModel

        from vulnhuntr.cli_providers import CLIBinaryNotFoundError
        from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM

        class _Dummy(BaseModel):
            pass

        provider = GeminiCLILLM()
        with patch("subprocess.run", side_effect=FileNotFoundError("no such file")):
            with pytest.raises(CLIBinaryNotFoundError):
                provider.send_message(user_prompt="test", max_tokens=100, response_model=_Dummy)


# ---------------------------------------------------------------------------
# TestClaudeCodeLLM — consolidated class (CLAUDECLI-01, Plan 04-03)
#
# This class consolidates all ClaudeCodeLLM behaviors into a single class,
# adding test_send_message_binary_not_found and test_env_stripping variants
# that were not covered by the split classes above.
# ---------------------------------------------------------------------------

_CLAUDE_SUCCESS_JSON = (
    '{"result": "vuln found", '
    '"usage": {"input_tokens": 10, "cache_creation_input_tokens": 3, '
    '"cache_read_input_tokens": 2, "output_tokens": 5}, '
    '"modelUsage": {"claude-sonnet-4-6": {}}, "total_cost_usd": 0.001}'
)

_GEMINI_SUCCESS_JSON = (
    '{"response": "no vulns", '
    '"stats": {"models": {'
    '"gemini-2.5-flash": {"tokens": {"input": 100, "candidates": 20}}, '
    '"gemini-2.5-flash-lite": {"tokens": {"input": 50, "candidates": 10}}'
    '}}}'
)


class TestClaudeCodeLLM:
    """Consolidated TestClaudeCodeLLM class (Plan 04-03 Task 2, CLAUDECLI-01).

    Covers probe, send_message, get_response, _extract_usage, _build_env,
    and CLIBinaryNotFoundError path with response_model kwarg.
    All subprocess calls are mocked — no live binary required.
    """

    def test_probe_ok(self):
        from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM

        provider = ClaudeCodeLLM()
        with patch("shutil.which", return_value="/usr/bin/claude"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0, stdout="2.1.126 (Claude Code)", stderr=""
                )
                result = provider.probe()
        assert result.ok is True
        assert result.binary_found is True
        assert result.version == "2.1.126"
        assert result.auth_valid is None

    def test_probe_missing_binary(self):
        from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM

        provider = ClaudeCodeLLM()
        with patch("shutil.which", return_value=None):
            result = provider.probe()
        assert result.ok is False
        assert result.binary_found is False
        assert "npm i -g @anthropic-ai/claude-code" in result.diagnostic_message

    def test_send_message_success(self):
        from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM

        provider = ClaudeCodeLLM()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=_CLAUDE_SUCCESS_JSON, stderr=""
            )
            payload = provider.send_message("test prompt", 256, None)
        assert "result" in payload
        assert provider.model == "claude-sonnet-4-6"

    def test_send_message_timeout(self):
        from vulnhuntr.cli_providers import CLITimeoutError
        from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM

        provider = ClaudeCodeLLM()
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="claude", timeout=300),
        ):
            with pytest.raises(CLITimeoutError):
                provider.send_message("test", 256, None)

    def test_send_message_parse_error_bad_json(self):
        from vulnhuntr.cli_providers import CLIParseError
        from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM

        provider = ClaudeCodeLLM()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="not json at all", stderr="")
            with pytest.raises(CLIParseError):
                provider.send_message("test", 256, None)

    def test_send_message_parse_error_empty_stdout(self):
        from vulnhuntr.cli_providers import CLIParseError
        from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM

        provider = ClaudeCodeLLM()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            with pytest.raises(CLIParseError):
                provider.send_message("test", 256, None)

    def test_get_response_extracts_result_field(self):
        from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM

        provider = ClaudeCodeLLM()
        assert provider.get_response({"result": "vuln found"}) == "vuln found"

    def test_get_response_raises_on_missing_field(self):
        from vulnhuntr.cli_providers import CLIParseError
        from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM

        provider = ClaudeCodeLLM()
        with pytest.raises(CLIParseError):
            provider.get_response({"response": "wrong key"})

    def test_extract_usage_sums_cache_tokens(self):
        from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM

        provider = ClaudeCodeLLM()
        payload = {
            "usage": {
                "input_tokens": 10,
                "cache_creation_input_tokens": 3,
                "cache_read_input_tokens": 2,
                "output_tokens": 5,
            },
            "modelUsage": {"claude-sonnet-4-6": {}},
        }
        usage = provider._extract_usage(payload)
        assert usage.input_tokens == 15  # 10 + 3 + 2
        assert usage.output_tokens == 5
        assert usage.model == "claude-sonnet-4-6"

    def test_env_stripping_removes_anthropic_api_key(self):
        from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM

        provider = ClaudeCodeLLM()
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test123"}):
            env = provider._build_env()
        assert "ANTHROPIC_API_KEY" not in env

    def test_send_message_binary_not_found(self):
        """send_message() raises CLIBinaryNotFoundError when claude binary absent."""
        from pydantic import BaseModel

        from vulnhuntr.cli_providers import CLIBinaryNotFoundError
        from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM

        class _Dummy(BaseModel):
            pass

        provider = ClaudeCodeLLM()
        with patch("subprocess.run", side_effect=FileNotFoundError("no such file")):
            with pytest.raises(CLIBinaryNotFoundError):
                provider.send_message(user_prompt="test", max_tokens=100, response_model=_Dummy)


# ---------------------------------------------------------------------------
# Live round-trip tests (excluded from CI via pyproject.toml addopts)
# Run: pytest tests/test_cli_providers.py -m live -k "claude or gemini"
# ---------------------------------------------------------------------------


@pytest.mark.live
def test_claude_code_live_round_trip():
    """Requires 'claude' binary installed and authenticated.

    Run locally: pytest tests/test_cli_providers.py -m live -k claude
    Excluded from CI via pyproject.toml addopts = '-m "not live"'
    """
    from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM

    provider = ClaudeCodeLLM()
    probe_result = provider.probe()
    assert probe_result.ok, f"probe failed: {probe_result.diagnostic_message}"
    payload = provider.send_message("Say 'hello' in exactly one word.", 256, None)
    assert "result" in payload
    text = provider.get_response(payload)
    assert isinstance(text, str) and len(text) > 0


@pytest.mark.live
def test_gemini_cli_live_round_trip():
    """Requires 'gemini' binary installed and authenticated (>= 0.6.0).

    Run locally: pytest tests/test_cli_providers.py -m live -k gemini
    Excluded from CI via pyproject.toml addopts = '-m "not live"'
    """
    from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM

    provider = GeminiCLILLM()
    probe_result = provider.probe()
    assert probe_result.ok, f"probe failed: {probe_result.diagnostic_message}"
    payload = provider.send_message("Say 'hello' in exactly one word.", 256, None)
    assert "response" in payload
    text = provider.get_response(payload)
    assert isinstance(text, str) and len(text) > 0
