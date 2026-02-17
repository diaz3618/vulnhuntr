"""
Tests for vulnhuntr.mcp.analysis — MCP analysis integration module.

Tests cover:
- ToolDescriptor rendering
- MCPAnalysisHelper prompt generation, tool execution, and lifecycle
- MCPToolCallRequest / MCPToolCallResult models
- should_use_mcp / run_async helpers
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vulnhuntr.core.models import (
    MAX_TOOL_RESULT_CHARS,
    MCPToolCallRequest,
    MCPToolCallResult,
    Response,
)
from vulnhuntr.mcp.analysis import (
    MCPAnalysisHelper,
    ToolDescriptor,
    _extract_text,
    run_async,
    should_use_mcp,
)
from vulnhuntr.mcp.config import (
    MCPAnalysisPolicy,
    MCPServerConfig,
    MCPSettings,
    TransportType,
)

# ---------------------------------------------------------------------------
# MCPToolCallRequest model
# ---------------------------------------------------------------------------


class TestMCPToolCallRequest:
    def test_basic_creation(self):
        req = MCPToolCallRequest(server="scanner", tool="check_vuln", arguments={"path": "/app"})
        assert req.server == "scanner"
        assert req.tool == "check_vuln"
        assert req.arguments == {"path": "/app"}
        assert req.reason == ""

    def test_with_reason(self):
        req = MCPToolCallRequest(
            server="cve-db",
            tool="lookup_cve",
            arguments={"cve_id": "CVE-2024-1234"},
            reason="Need to verify vulnerability details",
        )
        assert req.reason == "Need to verify vulnerability details"

    def test_empty_arguments(self):
        req = MCPToolCallRequest(server="s", tool="t")
        assert req.arguments == {}


# ---------------------------------------------------------------------------
# MCPToolCallResult model
# ---------------------------------------------------------------------------


class TestMCPToolCallResult:
    def test_success_result(self):
        r = MCPToolCallResult(server="s", tool="t", success=True, output="found 3 vulns")
        assert r.success is True
        assert r.output == "found 3 vulns"
        assert r.error is None

    def test_error_result(self):
        r = MCPToolCallResult(server="s", tool="t", success=False, error="connection refused")
        assert r.success is False
        assert r.error == "connection refused"

    def test_truncated_output_short(self):
        r = MCPToolCallResult(server="s", tool="t", success=True, output="short")
        assert r.truncated_output() == "short"

    def test_truncated_output_long(self):
        long_output = "x" * (MAX_TOOL_RESULT_CHARS + 1000)
        r = MCPToolCallResult(server="s", tool="t", success=True, output=long_output)
        truncated = r.truncated_output()
        assert len(truncated) < len(long_output)
        assert truncated.endswith("... [truncated]")

    def test_truncated_output_custom_max(self):
        r = MCPToolCallResult(server="s", tool="t", success=True, output="a" * 100)
        truncated = r.truncated_output(max_chars=50)
        assert len(truncated) == 50 + len("\n... [truncated]")


# ---------------------------------------------------------------------------
# Response model with mcp_tool_calls
# ---------------------------------------------------------------------------


class TestResponseMCPToolCalls:
    def test_default_empty_tool_calls(self):
        resp = Response()
        assert resp.mcp_tool_calls == []

    def test_with_tool_calls(self):
        resp = Response(
            scratchpad="test",
            analysis="test analysis",
            confidence_score=5,
            mcp_tool_calls=[
                MCPToolCallRequest(server="scanner", tool="scan", arguments={"target": "app.py"}),
            ],
        )
        assert len(resp.mcp_tool_calls) == 1
        assert resp.mcp_tool_calls[0].server == "scanner"

    def test_serialization_round_trip(self):
        req = MCPToolCallRequest(server="s", tool="t", arguments={"k": "v"}, reason="r")
        resp = Response(mcp_tool_calls=[req])
        data = resp.model_dump()
        resp2 = Response(**data)
        assert len(resp2.mcp_tool_calls) == 1
        assert resp2.mcp_tool_calls[0].server == "s"

    def test_json_schema_includes_mcp_tool_calls(self):
        schema = Response.model_json_schema()
        props = schema.get("properties", {})
        assert "mcp_tool_calls" in props


# ---------------------------------------------------------------------------
# ToolDescriptor
# ---------------------------------------------------------------------------


class TestToolDescriptor:
    def test_basic_rendering(self):
        td = ToolDescriptor(server="analyzer", name="scan_code", description="Scan source code for issues")
        text = td.to_prompt_text()
        assert "[analyzer]" in text
        assert "scan_code" in text
        assert "Scan source code" in text

    def test_rendering_with_schema(self):
        td = ToolDescriptor(
            server="cve-db",
            name="lookup",
            description="Look up a CVE",
            input_schema={
                "properties": {
                    "cve_id": {"type": "string", "description": "The CVE ID"},
                    "year": {"type": "integer", "description": "Filter year"},
                },
                "required": ["cve_id"],
            },
        )
        text = td.to_prompt_text()
        assert "cve_id" in text
        assert "(required)" in text
        assert "year" in text

    def test_rendering_empty_schema(self):
        td = ToolDescriptor(server="s", name="t", description="d", input_schema={})
        text = td.to_prompt_text()
        assert "[s] t: d" in text

    def test_slots_defined(self):
        td = ToolDescriptor(server="s", name="t", description="d")
        assert hasattr(td, "__slots__")


# ---------------------------------------------------------------------------
# _extract_text helper
# ---------------------------------------------------------------------------


class TestExtractText:
    def test_none(self):
        assert _extract_text(None) == ""

    def test_string(self):
        assert _extract_text("hello") == "hello"

    def test_dict(self):
        result = _extract_text({"key": "value"})
        assert "key" in result
        assert "value" in result

    def test_object_with_content_text(self):
        item = MagicMock()
        item.text = "extracted text"
        container = MagicMock()
        container.content = [item]
        assert _extract_text(container) == "extracted text"

    def test_object_with_content_dict(self):
        container = MagicMock()
        container.content = [{"text": "from dict"}]
        assert _extract_text(container) == "from dict"

    def test_object_with_content_fallback(self):
        container = MagicMock()
        container.content = [42]
        assert _extract_text(container) == "42"


# ---------------------------------------------------------------------------
# should_use_mcp
# ---------------------------------------------------------------------------


class TestShouldUseMCP:
    def test_none_settings(self):
        assert should_use_mcp(None) is False

    def test_disabled_settings(self):
        settings = MCPSettings(enabled=False)
        assert should_use_mcp(settings) is False

    def test_off_mode(self):
        settings = MCPSettings(analysis=MCPAnalysisPolicy(mode="off"))
        assert should_use_mcp(settings) is False

    def test_auto_mode(self):
        settings = MCPSettings(analysis=MCPAnalysisPolicy(mode="auto"))
        assert should_use_mcp(settings) is True

    def test_force_mode(self):
        settings = MCPSettings(analysis=MCPAnalysisPolicy(mode="force", force_servers=["x"]))
        assert should_use_mcp(settings) is True

    def test_enabled_but_off(self):
        settings = MCPSettings(enabled=True, analysis=MCPAnalysisPolicy(mode="off"))
        assert should_use_mcp(settings) is False


# ---------------------------------------------------------------------------
# run_async
# ---------------------------------------------------------------------------


class TestRunAsync:
    def test_runs_coroutine(self):
        async def simple():
            return 42

        assert run_async(simple()) == 42

    def test_runs_async_with_await(self):
        async def delayed():
            await asyncio.sleep(0.01)
            return "done"

        assert run_async(delayed()) == "done"


# ---------------------------------------------------------------------------
# MCPAnalysisHelper — prompt generation
# ---------------------------------------------------------------------------


def _make_settings(mode: str = "auto", **kwargs) -> MCPSettings:
    """Create an MCPSettings with a single stdio server and given analysis mode."""
    analysis_kwargs = {"mode": mode}
    if mode == "force":
        analysis_kwargs["force_servers"] = kwargs.pop("force_servers", ["test-server"])
    analysis_kwargs.update(kwargs)
    return MCPSettings(
        servers={
            "test-server": MCPServerConfig(
                name="test-server",
                transport=TransportType.STDIO,
                command="echo",
                args=["hello"],
            ),
        },
        analysis=MCPAnalysisPolicy(**analysis_kwargs),
    )


class TestMCPAnalysisHelperPrompt:
    """Test get_tool_prompt_section without actual server connections."""

    def test_no_tools_returns_empty(self):
        helper = MCPAnalysisHelper(_make_settings())
        # Not initialized, no tools
        assert helper.get_tool_prompt_section() == ""

    def test_auto_mode_prompt(self):
        helper = MCPAnalysisHelper(_make_settings("auto"))
        # Manually inject tools to avoid needing real servers
        helper._tools = [
            ToolDescriptor("test-server", "scan", "Scan code for vulnerabilities"),
        ]
        helper._initialized = True

        prompt = helper.get_tool_prompt_section()
        assert "<mcp_tools>" in prompt
        assert "</mcp_tools>" in prompt
        assert "AUTO" in prompt
        assert "scan" in prompt
        assert "UNTRUSTED" in prompt
        assert "mcp_tool_calls" in prompt

    def test_force_mode_prompt(self):
        helper = MCPAnalysisHelper(_make_settings("force"))
        helper._tools = [
            ToolDescriptor("test-server", "scan", "Scan code"),
        ]
        helper._initialized = True

        prompt = helper.get_tool_prompt_section()
        assert "FORCE" in prompt
        assert "MUST request" in prompt

    def test_multiple_tools_listed(self):
        helper = MCPAnalysisHelper(_make_settings("auto"))
        helper._tools = [
            ToolDescriptor("server-a", "tool1", "Description 1"),
            ToolDescriptor("server-b", "tool2", "Description 2"),
        ]
        helper._initialized = True

        prompt = helper.get_tool_prompt_section()
        assert "[server-a] tool1" in prompt
        assert "[server-b] tool2" in prompt


# ---------------------------------------------------------------------------
# MCPAnalysisHelper — is_active property
# ---------------------------------------------------------------------------


class TestMCPAnalysisHelperIsActive:
    def test_not_initialized(self):
        helper = MCPAnalysisHelper(_make_settings())
        assert helper.is_active is False

    def test_initialized_no_tools(self):
        helper = MCPAnalysisHelper(_make_settings())
        helper._initialized = True
        helper._tools = []
        assert helper.is_active is False

    def test_initialized_with_tools(self):
        helper = MCPAnalysisHelper(_make_settings())
        helper._initialized = True
        helper._tools = [ToolDescriptor("s", "t", "d")]
        assert helper.is_active is True


# ---------------------------------------------------------------------------
# MCPAnalysisHelper — mode property
# ---------------------------------------------------------------------------


class TestMCPAnalysisHelperMode:
    def test_auto_mode(self):
        helper = MCPAnalysisHelper(_make_settings("auto"))
        assert helper.mode == "auto"

    def test_force_mode(self):
        helper = MCPAnalysisHelper(_make_settings("force"))
        assert helper.mode == "force"


# ---------------------------------------------------------------------------
# MCPAnalysisHelper — execute_tool_calls
# ---------------------------------------------------------------------------


class TestMCPAnalysisHelperExecuteToolCalls:
    @pytest.fixture()
    def helper_with_mock_client(self):
        """Create a helper with mocked MCPClientManager."""
        settings = _make_settings("auto")
        helper = MCPAnalysisHelper(settings)
        helper._initialized = True
        helper._tools = [
            ToolDescriptor("test-server", "scan", "Scan code"),
            ToolDescriptor("test-server", "get_info", "Get info"),
        ]

        # Mock client
        mock_client = AsyncMock()
        helper._client = mock_client
        return helper, mock_client

    def test_successful_call(self, helper_with_mock_client):
        helper, mock_client = helper_with_mock_client

        # Mock return value with .content attribute
        mock_result = MagicMock()
        mock_item = MagicMock()
        mock_item.text = "Found 2 vulnerabilities"
        mock_result.content = [mock_item]
        mock_client.call_tool = AsyncMock(return_value=mock_result)

        req = MCPToolCallRequest(server="test-server", tool="scan", arguments={"path": "/app"})
        results = run_async(helper.execute_tool_calls([req]))

        assert len(results) == 1
        assert results[0].success is True
        assert "Found 2 vulnerabilities" in results[0].output

    def test_blocked_destructive_tool(self, helper_with_mock_client):
        helper, mock_client = helper_with_mock_client

        req = MCPToolCallRequest(server="test-server", tool="delete_file", arguments={"path": "/etc"})
        results = run_async(helper.execute_tool_calls([req]))

        assert len(results) == 1
        assert results[0].success is False
        assert "blocked" in results[0].error.lower()
        mock_client.call_tool.assert_not_called()

    def test_timeout(self, helper_with_mock_client):
        helper, mock_client = helper_with_mock_client
        helper._policy = MCPAnalysisPolicy(mode="auto", tool_timeout_seconds=1)

        async def slow_call(*args, **kwargs):
            await asyncio.sleep(10)

        mock_client.call_tool = slow_call

        req = MCPToolCallRequest(server="test-server", tool="scan", arguments={})
        results = run_async(helper.execute_tool_calls([req]))

        assert len(results) == 1
        assert results[0].success is False
        assert "Timeout" in results[0].error

    def test_cap_enforced(self, helper_with_mock_client):
        helper, mock_client = helper_with_mock_client
        helper._policy = MCPAnalysisPolicy(mode="auto", max_tool_calls_per_iteration=1)

        mock_result = MagicMock()
        mock_result.content = [MagicMock(text="ok")]
        mock_client.call_tool = AsyncMock(return_value=mock_result)

        requests = [
            MCPToolCallRequest(server="test-server", tool="scan", arguments={}),
            MCPToolCallRequest(server="test-server", tool="get_info", arguments={}),
        ]
        results = run_async(helper.execute_tool_calls(requests))

        # Only 1 call should execute due to cap
        assert len(results) == 1

    def test_empty_requests(self, helper_with_mock_client):
        helper, mock_client = helper_with_mock_client
        results = run_async(helper.execute_tool_calls([]))
        assert results == []

    def test_not_initialized_returns_empty(self):
        helper = MCPAnalysisHelper(_make_settings())
        helper._initialized = False
        req = MCPToolCallRequest(server="s", tool="t", arguments={})
        results = run_async(helper.execute_tool_calls([req]))
        assert results == []

    def test_call_error_captured(self, helper_with_mock_client):
        helper, mock_client = helper_with_mock_client
        mock_client.call_tool = AsyncMock(side_effect=RuntimeError("connection lost"))

        req = MCPToolCallRequest(server="test-server", tool="scan", arguments={})
        results = run_async(helper.execute_tool_calls([req]))

        assert len(results) == 1
        assert results[0].success is False
        assert "connection lost" in results[0].error

    def test_output_truncation(self, helper_with_mock_client):
        helper, mock_client = helper_with_mock_client

        long_text = "x" * (MAX_TOOL_RESULT_CHARS + 5000)
        mock_result = MagicMock()
        mock_result.content = [MagicMock(text=long_text)]
        mock_client.call_tool = AsyncMock(return_value=mock_result)

        req = MCPToolCallRequest(server="test-server", tool="scan", arguments={})
        results = run_async(helper.execute_tool_calls([req]))

        assert len(results[0].output) <= MAX_TOOL_RESULT_CHARS


# ---------------------------------------------------------------------------
# MCPAnalysisHelper — format_results_for_prompt
# ---------------------------------------------------------------------------


class TestFormatResultsForPrompt:
    def test_empty_results(self):
        helper = MCPAnalysisHelper(_make_settings())
        assert helper.format_results_for_prompt([]) == ""

    def test_success_result_formatting(self):
        helper = MCPAnalysisHelper(_make_settings())
        results = [
            MCPToolCallResult(server="scanner", tool="scan", success=True, output="No issues found"),
        ]
        text = helper.format_results_for_prompt(results)
        assert "<mcp_tool_results>" in text
        assert "</mcp_tool_results>" in text
        assert 'status="success"' in text
        assert "No issues found" in text

    def test_error_result_formatting(self):
        helper = MCPAnalysisHelper(_make_settings())
        results = [
            MCPToolCallResult(server="s", tool="t", success=False, error="timed out"),
        ]
        text = helper.format_results_for_prompt(results)
        assert 'status="error"' in text
        assert "timed out" in text

    def test_mixed_results(self):
        helper = MCPAnalysisHelper(_make_settings())
        results = [
            MCPToolCallResult(server="a", tool="t1", success=True, output="ok"),
            MCPToolCallResult(server="b", tool="t2", success=False, error="fail"),
        ]
        text = helper.format_results_for_prompt(results)
        assert text.count("<tool_result") == 2


# ---------------------------------------------------------------------------
# MCPAnalysisHelper — initialize with mocked client
# ---------------------------------------------------------------------------


class TestMCPAnalysisHelperInitialize:
    def test_initialize_discovers_tools(self):
        settings = _make_settings("auto")
        helper = MCPAnalysisHelper(settings)

        # Mock MCPClientManager
        mock_tool = MagicMock()
        mock_tool.name = "scan_code"
        mock_tool.description = "Scan source code"
        mock_tool.inputSchema = {"properties": {"path": {"type": "string"}}}

        mock_client = AsyncMock()
        mock_client.connect_all = AsyncMock()
        mock_client.list_all_tools = AsyncMock(return_value={"test-server": [mock_tool]})

        with patch("vulnhuntr.mcp.client.MCPClientManager", return_value=mock_client):
            run_async(helper.initialize())

        assert helper.is_active is True
        assert len(helper._tools) == 1
        assert helper._tools[0].name == "scan_code"

    def test_initialize_filters_destructive_tools(self):
        settings = _make_settings("auto")
        helper = MCPAnalysisHelper(settings)

        safe_tool = MagicMock()
        safe_tool.name = "scan_code"
        safe_tool.description = "Scan"
        safe_tool.inputSchema = {}

        destructive_tool = MagicMock()
        destructive_tool.name = "delete_file"
        destructive_tool.description = "Delete a file"
        destructive_tool.inputSchema = {}

        mock_client = AsyncMock()
        mock_client.connect_all = AsyncMock()
        mock_client.list_all_tools = AsyncMock(return_value={"test-server": [safe_tool, destructive_tool]})

        with patch("vulnhuntr.mcp.client.MCPClientManager", return_value=mock_client):
            run_async(helper.initialize())

        assert len(helper._tools) == 1
        assert helper._tools[0].name == "scan_code"

    def test_initialize_connection_failure(self):
        settings = _make_settings("auto")
        helper = MCPAnalysisHelper(settings)

        mock_client = AsyncMock()
        mock_client.connect_all = AsyncMock(side_effect=ConnectionError("refused"))

        with patch("vulnhuntr.mcp.client.MCPClientManager", return_value=mock_client):
            run_async(helper.initialize())

        assert helper.is_active is False

    def test_double_initialize_is_noop(self):
        settings = _make_settings("auto")
        helper = MCPAnalysisHelper(settings)
        helper._initialized = True  # Pre-mark

        # Should return immediately without touching client
        run_async(helper.initialize())
        assert helper._client is None  # Never created


# ---------------------------------------------------------------------------
# MCPAnalysisHelper — shutdown
# ---------------------------------------------------------------------------


class TestMCPAnalysisHelperShutdown:
    def test_shutdown_cleans_up(self):
        helper = MCPAnalysisHelper(_make_settings())
        helper._initialized = True
        helper._tools = [ToolDescriptor("s", "t", "d")]
        mock_client = AsyncMock()
        helper._client = mock_client

        run_async(helper.shutdown())

        mock_client.disconnect_all.assert_called_once()
        assert helper._client is None
        assert helper._initialized is False
        assert helper._tools == []

    def test_shutdown_no_client(self):
        helper = MCPAnalysisHelper(_make_settings())
        # Should not raise
        run_async(helper.shutdown())

    def test_shutdown_handles_disconnect_error(self):
        helper = MCPAnalysisHelper(_make_settings())
        helper._initialized = True
        mock_client = AsyncMock()
        mock_client.disconnect_all = AsyncMock(side_effect=RuntimeError("boom"))
        helper._client = mock_client

        # Should not raise
        run_async(helper.shutdown())
        assert helper._client is None
        assert helper._initialized is False
