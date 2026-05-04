"""Behavioral trace tests for Vulnhuntr providers — EVAL-02 / EVAL-03.

Tests verify that provider actions emit the correct trace events with the
expected fields, using injected ExecutionTracer instances.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from vulnhuntr.cli_providers.base import (
    CapabilityResult,
    CLIBinaryNotFoundError,
    CLIParseError,
)
from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM
from vulnhuntr.config import CLIPolicy
from vulnhuntr.core.trace import ExecutionTracer
from vulnhuntr.llms import LLMError

# ---------------------------------------------------------------------------
# TestProbeToSendTrace — EVAL-02 (probe_result trace event)
# ---------------------------------------------------------------------------


class TestProbeToSendTrace:
    """Inject a tracer into a CLI provider; probe() must emit probe_result."""

    def _make_llm(self, tracer: ExecutionTracer) -> ClaudeCodeLLM:
        policy = CLIPolicy()
        return ClaudeCodeLLM(policy=policy, tracer=tracer)

    def test_probe_emits_probe_result_event(self):
        tracer = ExecutionTracer()
        llm = self._make_llm(tracer)
        ok_result = CapabilityResult(
            ok=True,
            binary_found=True,
            version="2.1.126",
            auth_valid=True,
            diagnostic_message="",
        )
        with patch.object(llm, "_do_probe", return_value=ok_result):
            llm.probe()
        events = tracer.filter("probe_result")
        assert len(events) == 1

    def test_probe_result_event_ok_field(self):
        tracer = ExecutionTracer()
        llm = self._make_llm(tracer)
        ok_result = CapabilityResult(ok=True, binary_found=True, version="1.0", auth_valid=True, diagnostic_message="")
        with patch.object(llm, "_do_probe", return_value=ok_result):
            llm.probe()
        assert tracer.filter("probe_result")[0].data["ok"] is True

    def test_probe_result_event_binary_found(self):
        tracer = ExecutionTracer()
        llm = self._make_llm(tracer)
        ok_result = CapabilityResult(ok=True, binary_found=True, version="1.0", auth_valid=True, diagnostic_message="")
        with patch.object(llm, "_do_probe", return_value=ok_result):
            llm.probe()
        assert tracer.filter("probe_result")[0].data["binary_found"] is True

    def test_probe_result_event_version(self):
        tracer = ExecutionTracer()
        llm = self._make_llm(tracer)
        ok_result = CapabilityResult(
            ok=True, binary_found=True, version="2.1.126", auth_valid=True, diagnostic_message=""
        )
        with patch.object(llm, "_do_probe", return_value=ok_result):
            llm.probe()
        assert tracer.filter("probe_result")[0].data["version"] == "2.1.126"

    def test_probe_result_event_provider_is_class_name(self):
        tracer = ExecutionTracer()
        llm = self._make_llm(tracer)
        ok_result = CapabilityResult(ok=True, binary_found=True, version="1.0", auth_valid=True, diagnostic_message="")
        with patch.object(llm, "_do_probe", return_value=ok_result):
            llm.probe()
        assert tracer.filter("probe_result")[0].provider == "ClaudeCodeLLM"

    def test_probe_emits_event_before_raising_on_missing_binary(self):
        """Trace event is emitted even when probe() subsequently raises."""
        tracer = ExecutionTracer()
        llm = self._make_llm(tracer)
        missing = CapabilityResult(
            ok=False, binary_found=False, version=None, auth_valid=None, diagnostic_message="not on PATH"
        )
        with patch.object(llm, "_do_probe", return_value=missing):
            with pytest.raises(CLIBinaryNotFoundError):
                llm.probe()
        assert len(tracer.filter("probe_result")) == 1
        assert tracer.filter("probe_result")[0].data["binary_found"] is False

    def test_probe_no_tracer_does_not_raise(self):
        """probe() with tracer=None must not raise an AttributeError."""
        llm = ClaudeCodeLLM(policy=CLIPolicy())
        ok_result = CapabilityResult(ok=True, binary_found=True, version="1.0", auth_valid=True, diagnostic_message="")
        with patch.object(llm, "_do_probe", return_value=ok_result):
            result = llm.probe()
        assert result.ok is True


# ---------------------------------------------------------------------------
# TestFallbackChainTrace — EVAL-02 (fallback_triggered trace event)
# ---------------------------------------------------------------------------


class TestFallbackChainTrace:
    """FallbackLLM.chat() must emit fallback_triggered when primary fails."""

    def _make_primary(self, error: Exception) -> MagicMock:
        m = MagicMock()
        m.chat.side_effect = error
        return m

    def _make_fallback(self, response: str = "ok") -> MagicMock:
        m = MagicMock()
        m.chat.return_value = response
        # set_context / _add_to_history need to be callable
        m.set_context = MagicMock()
        m._history = []
        return m

    def test_fallback_triggered_event_emitted(self):
        from vulnhuntr.llms import FallbackLLM

        tracer = ExecutionTracer()
        primary = self._make_primary(LLMError("api down"))
        fallback = self._make_fallback()
        llm = FallbackLLM(primary=primary, fallbacks=[fallback], tracer=tracer)
        llm.chat("hello")
        events = tracer.filter("fallback_triggered")
        assert len(events) == 1

    def test_fallback_triggered_error_class(self):
        from vulnhuntr.llms import FallbackLLM

        tracer = ExecutionTracer()
        primary = self._make_primary(LLMError("api down"))
        fallback = self._make_fallback()
        llm = FallbackLLM(primary=primary, fallbacks=[fallback], tracer=tracer)
        llm.chat("hello")
        event = tracer.filter("fallback_triggered")[0]
        assert event.data["error_class"] == "LLMError"

    def test_fallback_triggered_failed_provider(self):
        from vulnhuntr.llms import FallbackLLM

        tracer = ExecutionTracer()
        primary = self._make_primary(LLMError("fail"))
        primary.__class__ = type("PrimaryLLM", (), {})  # custom class name
        fallback = self._make_fallback()
        llm = FallbackLLM(primary=primary, fallbacks=[fallback], tracer=tracer)
        llm.chat("hello")
        event = tracer.filter("fallback_triggered")[0]
        # failed_provider is the class name of the LLM that raised
        assert "failed_provider" in event.data

    def test_fallback_triggered_fallback_index_zero(self):
        from vulnhuntr.llms import FallbackLLM

        tracer = ExecutionTracer()
        primary = self._make_primary(LLMError("fail"))
        fallback = self._make_fallback()
        llm = FallbackLLM(primary=primary, fallbacks=[fallback], tracer=tracer)
        llm.chat("hello")
        event = tracer.filter("fallback_triggered")[0]
        assert event.data["fallback_index"] == 0

    def test_no_tracer_no_crash(self):
        from vulnhuntr.llms import FallbackLLM

        primary = self._make_primary(LLMError("fail"))
        fallback = self._make_fallback()
        llm = FallbackLLM(primary=primary, fallbacks=[fallback])
        result = llm.chat("hello")
        assert result == "ok"


# ---------------------------------------------------------------------------
# TestSessionDecisionTrace — EVAL-02 (session_decision trace event)
# ---------------------------------------------------------------------------


class TestSessionDecisionTrace:
    """ClaudeCodeLLM.send_message() must emit session_decision with mode and flags."""

    def _make_payload(self) -> str:
        return json.dumps({"result": "done", "usage": {}, "modelUsage": {}})

    def _make_llm(self, session_mode: str, tracer: ExecutionTracer) -> ClaudeCodeLLM:
        policy = CLIPolicy(session_mode=session_mode)
        return ClaudeCodeLLM(policy=policy, tracer=tracer)

    def test_stateless_emits_session_decision(self):
        tracer = ExecutionTracer()
        llm = self._make_llm("stateless", tracer)
        fake = MagicMock(stdout=self._make_payload(), returncode=0)
        with patch.object(llm, "_run_subprocess", return_value=fake):
            llm.send_message("hello", max_tokens=256)
        events = tracer.filter("session_decision")
        assert len(events) == 1

    def test_stateless_flags_contains_no_session_persistence(self):
        tracer = ExecutionTracer()
        llm = self._make_llm("stateless", tracer)
        fake = MagicMock(stdout=self._make_payload(), returncode=0)
        with patch.object(llm, "_run_subprocess", return_value=fake):
            llm.send_message("hello", max_tokens=256)
        event = tracer.filter("session_decision")[0]
        assert "--no-session-persistence" in event.data["flags_added"]

    def test_stateless_session_mode_in_event(self):
        tracer = ExecutionTracer()
        llm = self._make_llm("stateless", tracer)
        fake = MagicMock(stdout=self._make_payload(), returncode=0)
        with patch.object(llm, "_run_subprocess", return_value=fake):
            llm.send_message("hello", max_tokens=256)
        event = tracer.filter("session_decision")[0]
        assert event.data["session_mode"] == "stateless"

    def test_continue_flags_contains_continue(self):
        tracer = ExecutionTracer()
        llm = self._make_llm("continue", tracer)
        fake = MagicMock(stdout=self._make_payload(), returncode=0)
        with patch.object(llm, "_run_subprocess", return_value=fake):
            llm.send_message("hello", max_tokens=256)
        event = tracer.filter("session_decision")[0]
        assert "--continue" in event.data["flags_added"]

    def test_provider_is_class_name(self):
        tracer = ExecutionTracer()
        llm = self._make_llm("stateless", tracer)
        fake = MagicMock(stdout=self._make_payload(), returncode=0)
        with patch.object(llm, "_run_subprocess", return_value=fake):
            llm.send_message("hello", max_tokens=256)
        event = tracer.filter("session_decision")[0]
        assert event.provider == "ClaudeCodeLLM"


# ---------------------------------------------------------------------------
# TestValidationFailureTrace — EVAL-02 (response_validated with valid=False)
# ---------------------------------------------------------------------------


class TestValidationFailureTrace:
    """chat() must emit response_validated with valid=False on CLIParseError."""

    def _make_llm(self, tracer: ExecutionTracer) -> ClaudeCodeLLM:
        return ClaudeCodeLLM(policy=CLIPolicy(), tracer=tracer)

    def test_parse_error_emits_response_validated(self):
        tracer = ExecutionTracer()
        llm = self._make_llm(tracer)
        with patch.object(llm, "send_message", side_effect=CLIParseError("bad JSON")):
            with pytest.raises(CLIParseError):
                llm.chat("hello")
        events = tracer.filter("response_validated")
        assert len(events) == 1

    def test_parse_error_event_valid_is_false(self):
        tracer = ExecutionTracer()
        llm = self._make_llm(tracer)
        with patch.object(llm, "send_message", side_effect=CLIParseError("bad JSON")):
            with pytest.raises(CLIParseError):
                llm.chat("hello")
        event = tracer.filter("response_validated")[0]
        assert event.data["valid"] is False

    def test_parse_error_event_has_error_field(self):
        tracer = ExecutionTracer()
        llm = self._make_llm(tracer)
        with patch.object(llm, "send_message", side_effect=CLIParseError("bad JSON")):
            with pytest.raises(CLIParseError):
                llm.chat("hello")
        event = tracer.filter("response_validated")[0]
        assert "bad JSON" in event.data["error"]

    def test_no_tracer_does_not_suppress_exception(self):
        llm = ClaudeCodeLLM(policy=CLIPolicy())
        with patch.object(llm, "send_message", side_effect=CLIParseError("err")):
            with pytest.raises(CLIParseError):
                llm.chat("hello")
