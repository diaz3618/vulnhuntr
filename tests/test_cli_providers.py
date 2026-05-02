"""Tests for vulnhuntr.cli_providers (AICLI-01..04).

Covers:
- AICLI-01: CLIProviderLLM inherits from LLM; CapabilityResult dataclass shape
- AICLI-02: probe() abstract; CapabilityResult fields; diagnostic_message present
- AICLI-03: _run_subprocess uses list-form, shell=False, stdin=DEVNULL; error taxonomy
- AICLI-04: chat() calls _log_response() for cost tracking; response normalization
"""

from __future__ import annotations

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
