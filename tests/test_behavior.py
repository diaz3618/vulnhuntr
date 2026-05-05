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


# ---------------------------------------------------------------------------
# TestDataFlowParsing — EVAL-05 (_validate_response() def-use coverage)
# ---------------------------------------------------------------------------


class TestDataFlowParsing:
    """Partitions tested:
      happy_path: valid JSON input → model_validate_json succeeds on first try
      python_literal_repair: JSON with None/True/False literals → repaired before second try
      escape_char_repair: JSON with invalid \\escape sequence → stripped before final try
      all_fail_path: JSON that cannot be repaired → LLMError raised

    Def-use pairs covered:
      DEF: response_text (raw LLM string) → USE: model_validate_json (final validated model)
      DEF: repaired_text (after Python-literal sub) → USE: model_validate_json (second attempt)
      DEF: repaired_text (after escape strip) → USE: model_validate_json (third attempt)
    """

    from pydantic import BaseModel as _BaseModel

    class _SimpleModel(_BaseModel):
        value: str | None = None
        flag: bool = False

    def _make_llm(self) -> ClaudeCodeLLM:
        return ClaudeCodeLLM(policy=CLIPolicy())

    def test_happy_path_valid_json_returns_model(self):
        """DEF: valid JSON string → USE: model_validate_json → returns _SimpleModel instance."""
        llm = self._make_llm()
        raw = '{"value": "hello", "flag": true}'
        result = llm._validate_response(raw, self._SimpleModel)
        assert isinstance(result, self._SimpleModel)
        assert result.value == "hello"
        assert result.flag is True

    def test_python_literal_none_repaired_to_null(self):
        """DEF: JSON with None literal → USE: Python-literal repair → repaired text parsed."""
        llm = self._make_llm()
        raw = '{"value": None, "flag": false}'
        result = llm._validate_response(raw, self._SimpleModel)
        assert isinstance(result, self._SimpleModel)
        assert result.value is None

    def test_python_literal_true_false_repaired(self):
        """DEF: JSON with True/False literals → USE: Python-literal repair → repaired text parsed."""
        llm = self._make_llm()
        raw = '{"value": "x", "flag": True}'
        result = llm._validate_response(raw, self._SimpleModel)
        assert isinstance(result, self._SimpleModel)
        assert result.flag is True

    def test_escape_char_repair_strips_invalid_escape(self):
        """DEF: JSON with invalid \\j escape → USE: escape-char strip → valid JSON parsed."""
        llm = self._make_llm()
        # \j is invalid in JSON; json.JSONDecodeError message mentions "escape"
        # After stripping the bad backslash: {"value": "testjvalue", "flag": false}
        raw = '{"value": "test\\jvalue", "flag": false}'
        result = llm._validate_response(raw, self._SimpleModel)
        assert isinstance(result, self._SimpleModel)
        assert result.value is not None
        assert "test" in result.value

    def test_all_fail_raises_llm_error(self):
        """DEF: completely broken JSON → USE: all repair paths fail → LLMError raised."""
        llm = self._make_llm()
        raw = '{"value": "unclosed'
        with pytest.raises(LLMError):
            llm._validate_response(raw, self._SimpleModel)

    def test_empty_response_raises_llm_error(self):
        """DEF: empty string → USE: early guard → LLMError raised before repair attempts."""
        llm = self._make_llm()
        with pytest.raises(LLMError):
            llm._validate_response("", self._SimpleModel)

    def test_whitespace_only_response_raises_llm_error(self):
        """DEF: whitespace-only string → USE: early guard → LLMError raised."""
        llm = self._make_llm()
        with pytest.raises(LLMError):
            llm._validate_response("   \n  ", self._SimpleModel)


# ---------------------------------------------------------------------------
# TestMCPToolResultPropagation — EVAL-05 (MCP result def-use coverage)
# ---------------------------------------------------------------------------


class TestMCPToolResultPropagation:
    """Partitions tested:
      success_result → XML with status="success", tool output in body
      error_result → XML with status="error", ERROR: prefix in body
      empty_list → empty string returned (no XML wrapper)
      multiple_results → all results included in single XML block

    Def-use pairs covered:
      DEF: MCPToolCallResult (produced by MCP executor) →
      USE: format_results_for_prompt() (formats for LLM context) →
      OBSERVABLE: XML string injected as mcp_pending_block into next iteration's prompt
    """

    def _make_helper(self):
        from vulnhuntr.mcp.analysis import MCPAnalysisHelper
        from vulnhuntr.mcp.config import MCPSettings

        settings = MCPSettings(enabled=False, servers={})
        return MCPAnalysisHelper(settings=settings)

    def test_success_result_xml_contains_mcp_tool_results_tag(self):
        """DEF: success MCPToolCallResult → USE: format_results_for_prompt → OBSERVABLE: outer XML tag."""
        from vulnhuntr.core.models import MCPToolCallResult

        helper = self._make_helper()
        result = MCPToolCallResult(server="srv", tool="scan", success=True, output="vuln found")
        xml = helper.format_results_for_prompt([result])
        assert xml.startswith("<mcp_tool_results>")
        assert xml.strip().endswith("</mcp_tool_results>")

    def test_success_result_xml_contains_tool_name(self):
        """DEF: MCPToolCallResult.tool → OBSERVABLE: tool attribute in XML."""
        from vulnhuntr.core.models import MCPToolCallResult

        helper = self._make_helper()
        result = MCPToolCallResult(server="srv", tool="my_tool", success=True, output="data")
        xml = helper.format_results_for_prompt([result])
        assert 'tool="my_tool"' in xml

    def test_success_result_xml_contains_server_name(self):
        """DEF: MCPToolCallResult.server → OBSERVABLE: server attribute in XML."""
        from vulnhuntr.core.models import MCPToolCallResult

        helper = self._make_helper()
        result = MCPToolCallResult(server="my_server", tool="t", success=True, output="data")
        xml = helper.format_results_for_prompt([result])
        assert 'server="my_server"' in xml

    def test_success_result_xml_status_is_success(self):
        """DEF: MCPToolCallResult(success=True) → OBSERVABLE: status="success" in XML."""
        from vulnhuntr.core.models import MCPToolCallResult

        helper = self._make_helper()
        result = MCPToolCallResult(server="s", tool="t", success=True, output="out")
        xml = helper.format_results_for_prompt([result])
        assert 'status="success"' in xml

    def test_success_result_output_appears_in_xml_body(self):
        """DEF: MCPToolCallResult.output → OBSERVABLE: text appears inside tool_result tag."""
        from vulnhuntr.core.models import MCPToolCallResult

        helper = self._make_helper()
        result = MCPToolCallResult(server="s", tool="t", success=True, output="unique_output_string_42")
        xml = helper.format_results_for_prompt([result])
        assert "unique_output_string_42" in xml

    def test_error_result_xml_status_is_error(self):
        """DEF: MCPToolCallResult(success=False) → OBSERVABLE: status="error" in XML."""
        from vulnhuntr.core.models import MCPToolCallResult

        helper = self._make_helper()
        result = MCPToolCallResult(server="s", tool="t", success=False, error="connection refused")
        xml = helper.format_results_for_prompt([result])
        assert 'status="error"' in xml

    def test_error_result_error_text_prefixed(self):
        """DEF: MCPToolCallResult.error → OBSERVABLE: 'ERROR: <text>' in XML body."""
        from vulnhuntr.core.models import MCPToolCallResult

        helper = self._make_helper()
        result = MCPToolCallResult(server="s", tool="t", success=False, error="connection refused")
        xml = helper.format_results_for_prompt([result])
        assert "ERROR: connection refused" in xml

    def test_empty_results_returns_empty_string(self):
        """DEF: empty list → OBSERVABLE: empty string (no XML wrapper emitted)."""
        helper = self._make_helper()
        xml = helper.format_results_for_prompt([])
        assert xml == ""

    def test_multiple_results_all_included(self):
        """DEF: list of two MCPToolCallResult → OBSERVABLE: both tool names in XML."""
        from vulnhuntr.core.models import MCPToolCallResult

        helper = self._make_helper()
        r1 = MCPToolCallResult(server="s1", tool="tool_alpha", success=True, output="a")
        r2 = MCPToolCallResult(server="s2", tool="tool_beta", success=True, output="b")
        xml = helper.format_results_for_prompt([r1, r2])
        assert 'tool="tool_alpha"' in xml
        assert 'tool="tool_beta"' in xml
