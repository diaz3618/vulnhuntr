"""
Tests for vulnhuntr.mcp.client — MCPClientManager unit tests.

These tests mock the MCP SDK to test connection management, tool discovery,
and tool invocation without requiring actual MCP servers.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vulnhuntr.mcp.client import MCPClientManager, ServerConnection
from vulnhuntr.mcp.config import MCPServerConfig, MCPSettings, TransportType


# Helpers
def _make_settings(**servers: MCPServerConfig) -> MCPSettings:
    """Create MCPSettings with the given servers."""
    return MCPSettings(servers=servers)


def _make_stdio_server(name: str, enabled: bool = True) -> MCPServerConfig:
    """Create a stdio server config for testing."""
    return MCPServerConfig(
        name=name,
        transport=TransportType.STDIO,
        command="echo",
        args=["test"],
        enabled=enabled,
    )


def _make_http_server(name: str, url: str = "http://localhost:8000/mcp") -> MCPServerConfig:
    """Create an HTTP server config for testing."""
    return MCPServerConfig(
        name=name,
        transport=TransportType.STREAMABLE_HTTP,
        url=url,
    )


_SENTINEL = object()


def _inject_connection(
    manager: MCPClientManager,
    name: str,
    config: MCPServerConfig,
    *,
    tools: list[dict] | None = None,
    session: object = _SENTINEL,
    connected: bool = True,
    error: str | None = None,
) -> ServerConnection:
    """Inject a fake ServerConnection into the manager for testing.

    Pass ``session=None`` explicitly to simulate a connection with no active
    session.  If *session* is not specified, a new ``MagicMock()`` is used.
    """
    if session is _SENTINEL:
        session = MagicMock()
    conn = ServerConnection(
        config=config,
        session=session,
        tools=tools or [],
        connected=connected,
        error=error,
    )
    manager._connections[name] = conn
    return conn


# ServerConnection dataclass
class TestServerConnection:
    def test_default_values(self):
        cfg = _make_stdio_server("test")
        conn = ServerConnection(config=cfg)
        assert conn.connected is False
        assert conn.session is None
        assert conn.tools == []
        assert conn.error is None

    def test_with_values(self):
        cfg = _make_stdio_server("test")
        conn = ServerConnection(
            config=cfg,
            session="mock_session",
            tools=[{"name": "tool1"}],
            connected=True,
        )
        assert conn.connected is True
        assert len(conn.tools) == 1

    def test_with_error(self):
        cfg = _make_stdio_server("test")
        conn = ServerConnection(config=cfg, error="Connection refused")
        assert conn.connected is False
        assert conn.error == "Connection refused"


# MCPClientManager — initialization and status
class TestMCPClientManagerInit:
    def test_init_empty_settings(self):
        settings = MCPSettings()
        manager = MCPClientManager(settings)
        assert manager.connected_servers == []
        assert manager.has_connections is False

    def test_init_with_servers_not_connected_yet(self):
        settings = _make_settings(
            server1=_make_stdio_server("server1"),
            server2=_make_stdio_server("server2"),
        )
        manager = MCPClientManager(settings)
        assert manager.connected_servers == []

    def test_get_status_not_connected(self):
        settings = _make_settings(
            server1=_make_stdio_server("server1"),
            server2=_make_stdio_server("server2", enabled=False),
        )
        manager = MCPClientManager(settings)
        status = manager.get_status()
        assert len(status) == 2
        assert status["server1"]["enabled"] is True
        assert status["server1"]["connected"] is False
        assert status["server2"]["enabled"] is False

    def test_get_status_with_connection(self):
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)
        _inject_connection(
            manager,
            "s1",
            settings.servers["s1"],
            tools=[{"name": "t1"}],
        )
        status = manager.get_status()
        assert status["s1"]["connected"] is True
        assert status["s1"]["tools"] == 1

    def test_get_status_with_error(self):
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)
        _inject_connection(
            manager,
            "s1",
            settings.servers["s1"],
            connected=False,
            error="timeout",
        )
        status = manager.get_status()
        assert status["s1"]["error"] == "timeout"

    def test_print_status_connected(self):
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)
        _inject_connection(
            manager,
            "s1",
            settings.servers["s1"],
            tools=[{"name": "t1"}, {"name": "t2"}],
        )
        output = manager.print_status()
        assert "[+]" in output
        assert "2 tools" in output

    def test_print_status_disabled(self):
        settings = _make_settings(
            disabled=_make_stdio_server("disabled", enabled=False),
        )
        manager = MCPClientManager(settings)
        output = manager.print_status()
        assert "[-]" in output
        assert "Disabled" in output

    def test_print_status_error(self):
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)
        _inject_connection(
            manager,
            "s1",
            settings.servers["s1"],
            connected=False,
            error="Connection refused",
        )
        output = manager.print_status()
        assert "[x]" in output

    def test_connected_servers_property(self):
        settings = _make_settings(
            s1=_make_stdio_server("s1"),
            s2=_make_stdio_server("s2"),
        )
        manager = MCPClientManager(settings)
        _inject_connection(manager, "s1", settings.servers["s1"], connected=True)
        _inject_connection(manager, "s2", settings.servers["s2"], connected=False)
        assert manager.connected_servers == ["s1"]

    def test_has_connections_true(self):
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)
        _inject_connection(manager, "s1", settings.servers["s1"])
        assert manager.has_connections is True

    def test_has_connections_false(self):
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)
        _inject_connection(manager, "s1", settings.servers["s1"], connected=False)
        assert manager.has_connections is False


# MCPClientManager — tool discovery (mocked connections)
class TestToolDiscovery:
    @pytest.mark.asyncio
    async def test_list_all_tools_empty(self):
        manager = MCPClientManager(MCPSettings())
        result = await manager.list_all_tools()
        assert result == {}

    @pytest.mark.asyncio
    async def test_list_all_tools_with_connections(self):
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)
        _inject_connection(
            manager,
            "s1",
            settings.servers["s1"],
            tools=[
                {"name": "tool-a", "description": "Tool A", "input_schema": {}},
                {"name": "tool-b", "description": "Tool B", "input_schema": {}},
            ],
        )
        result = await manager.list_all_tools()
        assert "s1" in result
        assert len(result["s1"]) == 2

    @pytest.mark.asyncio
    async def test_list_all_tools_skips_disconnected(self):
        settings = _make_settings(
            s1=_make_stdio_server("s1"),
            s2=_make_stdio_server("s2"),
        )
        manager = MCPClientManager(settings)
        _inject_connection(
            manager,
            "s1",
            settings.servers["s1"],
            tools=[{"name": "t1"}],
        )
        _inject_connection(
            manager,
            "s2",
            settings.servers["s2"],
            tools=[{"name": "t2"}],
            connected=False,
        )
        result = await manager.list_all_tools()
        assert "s1" in result
        assert "s2" not in result

    @pytest.mark.asyncio
    async def test_list_server_tools(self):
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)
        _inject_connection(
            manager,
            "s1",
            settings.servers["s1"],
            tools=[{"name": "tool-x", "description": "X"}],
        )
        tools = await manager.list_server_tools("s1")
        assert len(tools) == 1
        assert tools[0]["name"] == "tool-x"

    @pytest.mark.asyncio
    async def test_list_server_tools_not_connected(self):
        manager = MCPClientManager(MCPSettings())
        with pytest.raises(KeyError, match="not connected"):
            await manager.list_server_tools("unknown")

    def test_find_tool_found(self):
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)
        _inject_connection(
            manager,
            "s1",
            settings.servers["s1"],
            tools=[{"name": "my-tool", "description": "Desc", "input_schema": {}}],
        )
        result = manager.find_tool("my-tool")
        assert result is not None
        server_name, tool_info = result
        assert server_name == "s1"
        assert tool_info["name"] == "my-tool"

    def test_find_tool_searches_multiple_servers(self):
        settings = _make_settings(
            s1=_make_stdio_server("s1"),
            s2=_make_stdio_server("s2"),
        )
        manager = MCPClientManager(settings)
        _inject_connection(
            manager,
            "s1",
            settings.servers["s1"],
            tools=[{"name": "tool-a"}],
        )
        _inject_connection(
            manager,
            "s2",
            settings.servers["s2"],
            tools=[{"name": "tool-b"}],
        )
        result = manager.find_tool("tool-b")
        assert result is not None
        assert result[0] == "s2"

    def test_find_tool_not_found(self):
        manager = MCPClientManager(MCPSettings())
        assert manager.find_tool("nonexistent") is None

    def test_find_tool_skips_disconnected(self):
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)
        _inject_connection(
            manager,
            "s1",
            settings.servers["s1"],
            tools=[{"name": "hidden"}],
            connected=False,
        )
        assert manager.find_tool("hidden") is None


# MCPClientManager — tool invocation (mocked)
class TestToolInvocation:
    @pytest.mark.asyncio
    async def test_call_tool_success(self):
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.content = [MagicMock(text="result text")]
        mock_session.call_tool.return_value = mock_result

        _inject_connection(
            manager,
            "s1",
            settings.servers["s1"],
            session=mock_session,
            tools=[{"name": "test-tool", "description": "", "input_schema": {}}],
        )

        result = await manager.call_tool("s1", "test-tool", {"arg": "value"})
        mock_session.call_tool.assert_called_once_with("test-tool", {"arg": "value"})
        assert result is mock_result

    @pytest.mark.asyncio
    async def test_call_tool_default_args(self):
        """call_tool with arguments=None should pass empty dict."""
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)

        mock_session = AsyncMock()
        mock_session.call_tool.return_value = MagicMock()

        _inject_connection(
            manager,
            "s1",
            settings.servers["s1"],
            session=mock_session,
            tools=[{"name": "t"}],
        )

        await manager.call_tool("s1", "t")
        mock_session.call_tool.assert_called_once_with("t", {})

    @pytest.mark.asyncio
    async def test_call_tool_server_not_connected(self):
        manager = MCPClientManager(MCPSettings())
        with pytest.raises(KeyError, match="not connected"):
            await manager.call_tool("unknown", "tool", {})

    @pytest.mark.asyncio
    async def test_call_tool_no_session(self):
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)
        _inject_connection(
            manager,
            "s1",
            settings.servers["s1"],
            session=None,
            connected=True,
        )
        with pytest.raises(RuntimeError, match="no active session"):
            await manager.call_tool("s1", "tool", {})

    @pytest.mark.asyncio
    async def test_call_tool_auto_found(self):
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_session.call_tool.return_value = mock_result

        _inject_connection(
            manager,
            "s1",
            settings.servers["s1"],
            session=mock_session,
            tools=[{"name": "auto-tool", "description": "", "input_schema": {}}],
        )

        result = await manager.call_tool_auto("auto-tool", {"key": "val"})
        assert result is mock_result

    @pytest.mark.asyncio
    async def test_call_tool_auto_not_found(self):
        manager = MCPClientManager(MCPSettings())
        with pytest.raises(KeyError, match="No connected server"):
            await manager.call_tool_auto("missing-tool")

    @pytest.mark.asyncio
    async def test_call_tool_exception_wrapped(self):
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)

        mock_session = AsyncMock()
        mock_session.call_tool.side_effect = RuntimeError("Server error")

        _inject_connection(
            manager,
            "s1",
            settings.servers["s1"],
            session=mock_session,
            tools=[{"name": "fail-tool", "description": "", "input_schema": {}}],
        )

        with pytest.raises(RuntimeError, match="failed"):
            await manager.call_tool("s1", "fail-tool", {})


# MCPClientManager — resource access (mocked)
class TestResourceAccess:
    @pytest.mark.asyncio
    async def test_list_resources_success(self):
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)

        mock_resource = MagicMock()
        mock_resource.uri = "file:///test.py"
        mock_resource.name = "test.py"
        mock_resource.description = "A test file"
        mock_resource.mimeType = "text/plain"

        mock_session = AsyncMock()
        mock_list_result = MagicMock()
        mock_list_result.resources = [mock_resource]
        mock_session.list_resources.return_value = mock_list_result

        _inject_connection(
            manager,
            "s1",
            settings.servers["s1"],
            session=mock_session,
        )

        resources = await manager.list_resources("s1")
        assert len(resources) == 1
        assert resources[0]["uri"] == "file:///test.py"
        assert resources[0]["name"] == "test.py"

    @pytest.mark.asyncio
    async def test_list_resources_server_not_connected(self):
        manager = MCPClientManager(MCPSettings())
        with pytest.raises(KeyError, match="not connected"):
            await manager.list_resources("unknown")

    @pytest.mark.asyncio
    async def test_list_resources_no_session(self):
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)
        _inject_connection(
            manager,
            "s1",
            settings.servers["s1"],
            session=None,
        )
        with pytest.raises(RuntimeError, match="no active session"):
            await manager.list_resources("s1")

    @pytest.mark.asyncio
    async def test_list_resources_exception_returns_empty(self):
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)

        mock_session = AsyncMock()
        mock_session.list_resources.side_effect = RuntimeError("not supported")

        _inject_connection(
            manager,
            "s1",
            settings.servers["s1"],
            session=mock_session,
        )

        resources = await manager.list_resources("s1")
        assert resources == []

    @pytest.mark.asyncio
    async def test_read_resource_server_not_connected(self):
        manager = MCPClientManager(MCPSettings())
        with pytest.raises(KeyError, match="not connected"):
            await manager.read_resource("unknown", "file:///test.py")

    @pytest.mark.asyncio
    async def test_read_resource_no_session(self):
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)
        _inject_connection(
            manager,
            "s1",
            settings.servers["s1"],
            session=None,
        )
        with pytest.raises(RuntimeError, match="no active session"):
            await manager.read_resource("s1", "file:///test.py")


# MCPClientManager — connect_all with mocked MCP SDK
class TestConnectAll:
    @pytest.mark.asyncio
    async def test_connect_all_no_servers(self):
        settings = MCPSettings()
        manager = MCPClientManager(settings)
        results = await manager.connect_all()
        assert results == {}

    @pytest.mark.asyncio
    async def test_connect_all_disabled_servers_skipped(self):
        settings = _make_settings(
            s1=_make_stdio_server("s1", enabled=False),
        )
        manager = MCPClientManager(settings)
        results = await manager.connect_all()
        assert results == {}

    @pytest.mark.asyncio
    async def test_connect_all_globally_disabled(self):
        settings = MCPSettings(
            servers={"s1": _make_stdio_server("s1")},
            enabled=False,
        )
        manager = MCPClientManager(settings)
        results = await manager.connect_all()
        assert results == {}

    @pytest.mark.asyncio
    async def test_connect_all_mcp_not_installed(self):
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)

        with patch("vulnhuntr.mcp.client._check_mcp_available", return_value=False):
            results = await manager.connect_all()
            assert results["s1"] is False


# MCPClientManager — disconnect
class TestDisconnect:
    @pytest.mark.asyncio
    async def test_disconnect_all_clears_state(self):
        settings = _make_settings(s1=_make_stdio_server("s1"))
        manager = MCPClientManager(settings)
        _inject_connection(manager, "s1", settings.servers["s1"])
        assert manager.has_connections is True

        await manager.disconnect_all()
        assert manager.has_connections is False
        assert manager.connected_servers == []

    @pytest.mark.asyncio
    async def test_disconnect_all_with_multiple_servers(self):
        settings = _make_settings(
            s1=_make_stdio_server("s1"),
            s2=_make_stdio_server("s2"),
        )
        manager = MCPClientManager(settings)
        _inject_connection(manager, "s1", settings.servers["s1"])
        _inject_connection(manager, "s2", settings.servers["s2"])
        assert len(manager.connected_servers) == 2

        await manager.disconnect_all()
        assert len(manager.connected_servers) == 0
        assert manager._connections == {}
