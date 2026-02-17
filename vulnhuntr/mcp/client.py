"""
MCP Client Manager — manages connections to configured MCP servers.

This module is standalone and NOT integrated into Vulnhuntr's analysis
pipeline. It provides a generic interface for connecting to any MCP server,
discovering tools, and invoking them.
"""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

import structlog

from vulnhuntr.mcp.config import MCPServerConfig, MCPSettings, TransportType

log = structlog.get_logger(__name__)

# Lazy imports for the mcp package — only imported when actually needed
# so that the module doesn't fail if `mcp` is not installed.
_MCP_AVAILABLE: bool | None = None


def _check_mcp_available() -> bool:
    """Check if the MCP Python SDK is installed."""
    global _MCP_AVAILABLE
    if _MCP_AVAILABLE is None:
        try:
            import mcp  # noqa: F401

            _MCP_AVAILABLE = True
        except ImportError:
            _MCP_AVAILABLE = False
            log.warning("MCP Python SDK not installed. Install with: pip install 'mcp[cli]'")
    return _MCP_AVAILABLE


@dataclass
class ServerConnection:
    """Tracks a live connection to an MCP server.

    Attributes:
        config: The server configuration.
        session: The active MCP ClientSession.
        tools: Cached list of available tools (populated after connect).
        connected: Whether the server is currently connected.
        error: Last error message if connection failed.
    """

    config: MCPServerConfig
    session: Any = None  # mcp.ClientSession — typed as Any to avoid import issues
    tools: list[dict[str, Any]] = field(default_factory=list)
    connected: bool = False
    error: str | None = None


class MCPClientManager:
    """Manages connections to multiple MCP servers.

    This class handles the full lifecycle of MCP server connections:
    - Reading server configs from MCPSettings
    - Establishing connections via the appropriate transport
    - Discovering tools from each server
    - Routing tool calls to the correct server
    - Graceful shutdown of all connections

    Designed to be used as an async context manager::

        async with MCPClientManager(settings) as manager:
            tools = await manager.list_all_tools()
    """

    def __init__(self, settings: MCPSettings) -> None:
        self._settings = settings
        self._connections: dict[str, ServerConnection] = {}
        self._exit_stack: AsyncExitStack | None = None

    async def __aenter__(self) -> MCPClientManager:
        """Connect to all enabled servers."""
        self._exit_stack = AsyncExitStack()
        await self._exit_stack.__aenter__()
        await self.connect_all()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Disconnect from all servers."""
        await self.disconnect_all()
        if self._exit_stack:
            await self._exit_stack.__aexit__(exc_type, exc_val, exc_tb)

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    async def connect_all(self) -> dict[str, bool]:
        """Connect to all enabled servers concurrently.

        Returns:
            Dict mapping server name -> success boolean.
        """
        enabled = self._settings.get_enabled_servers()
        if not enabled:
            log.info("No MCP servers enabled")
            return {}

        if not _check_mcp_available():
            log.error("Cannot connect to MCP servers: mcp package not installed")
            return {name: False for name in enabled}

        results: dict[str, bool] = {}
        tasks = [self._connect_server(name, cfg) for name, cfg in enabled.items()]
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)

        for (name, _), outcome in zip(enabled.items(), outcomes):
            if isinstance(outcome, Exception):
                log.error("Failed to connect MCP server", server=name, error=str(outcome))
                self._connections[name] = ServerConnection(config=enabled[name], error=str(outcome))
                results[name] = False
            elif isinstance(outcome, bool):
                results[name] = outcome
            else:
                results[name] = False

        connected = sum(1 for v in results.values() if v)
        log.info(
            "MCP servers connected",
            connected=connected,
            total=len(enabled),
        )
        return results

    async def _connect_server(self, name: str, config: MCPServerConfig) -> bool:
        """Connect to a single MCP server.

        Args:
            name: Server identifier.
            config: Server configuration.

        Returns:
            True if connection succeeded.
        """
        transport = config.transport
        if isinstance(transport, str):
            transport = TransportType(transport)

        log.debug("Connecting to MCP server", server=name, transport=transport)

        try:
            if transport == TransportType.STDIO:
                return await self._connect_stdio(name, config)
            elif transport == TransportType.STREAMABLE_HTTP:
                return await self._connect_streamable_http(name, config)
            elif transport == TransportType.SSE:
                return await self._connect_sse(name, config)
            else:
                log.error("Unknown transport type", server=name, transport=transport)
                return False
        except Exception as e:
            log.error("Connection failed", server=name, error=str(e))
            self._connections[name] = ServerConnection(config=config, error=str(e))
            return False

    async def _connect_stdio(self, name: str, config: MCPServerConfig) -> bool:
        """Connect via stdio transport (subprocess)."""
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        assert config.command is not None, f"stdio server '{name}' has no command"
        assert self._exit_stack is not None

        env = config.env if config.env else None
        server_params = StdioServerParameters(
            command=config.command,
            args=config.args,
            env=env,
        )

        # Enter the stdio_client context via our exit stack so it stays alive
        transport = await self._exit_stack.enter_async_context(stdio_client(server_params))
        read_stream, write_stream = transport

        session = await self._exit_stack.enter_async_context(ClientSession(read_stream, write_stream))
        await session.initialize()

        # Discover tools
        tools_response = await session.list_tools()
        tools = [
            {
                "name": t.name,
                "description": getattr(t, "description", ""),
                "input_schema": getattr(t, "inputSchema", {}),
            }
            for t in tools_response.tools
        ]

        self._connections[name] = ServerConnection(config=config, session=session, tools=tools, connected=True)
        log.info("Connected to MCP server", server=name, tools=len(tools), transport="stdio")
        return True

    async def _connect_streamable_http(self, name: str, config: MCPServerConfig) -> bool:
        """Connect via Streamable HTTP transport."""
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        assert config.url is not None, f"streamable-http server '{name}' has no url"
        assert self._exit_stack is not None

        transport = await self._exit_stack.enter_async_context(streamable_http_client(config.url))
        read_stream, write_stream, _ = transport

        session = await self._exit_stack.enter_async_context(ClientSession(read_stream, write_stream))
        await session.initialize()

        # Discover tools
        tools_response = await session.list_tools()
        tools = [
            {
                "name": t.name,
                "description": getattr(t, "description", ""),
                "input_schema": getattr(t, "inputSchema", {}),
            }
            for t in tools_response.tools
        ]

        self._connections[name] = ServerConnection(config=config, session=session, tools=tools, connected=True)
        log.info(
            "Connected to MCP server",
            server=name,
            tools=len(tools),
            transport="streamable-http",
        )
        return True

    async def _connect_sse(self, name: str, config: MCPServerConfig) -> bool:
        """Connect via SSE transport (legacy).

        Note: SSE is being superseded by Streamable HTTP in the MCP spec.
        """
        from mcp import ClientSession
        from mcp.client.sse import sse_client

        assert config.url is not None, f"sse server '{name}' has no url"
        assert self._exit_stack is not None

        transport = await self._exit_stack.enter_async_context(sse_client(config.url))
        read_stream, write_stream = transport

        session = await self._exit_stack.enter_async_context(ClientSession(read_stream, write_stream))
        await session.initialize()

        # Discover tools
        tools_response = await session.list_tools()
        tools = [
            {
                "name": t.name,
                "description": getattr(t, "description", ""),
                "input_schema": getattr(t, "inputSchema", {}),
            }
            for t in tools_response.tools
        ]

        self._connections[name] = ServerConnection(config=config, session=session, tools=tools, connected=True)
        log.info("Connected to MCP server", server=name, tools=len(tools), transport="sse")
        return True

    async def disconnect_all(self) -> None:
        """Disconnect from all servers.

        Note: Actual cleanup happens via the AsyncExitStack in __aexit__.
        This method just resets internal state.
        """
        for name, conn in self._connections.items():
            if conn.connected:
                log.debug("Disconnecting MCP server", server=name)
                conn.connected = False
                conn.session = None
        self._connections.clear()

    # ------------------------------------------------------------------
    # Tool discovery
    # ------------------------------------------------------------------

    async def list_all_tools(self) -> dict[str, list[dict[str, Any]]]:
        """List all tools from all connected servers.

        Returns:
            Dict mapping server name -> list of tool info dicts.
            Each tool dict has: name, description, input_schema.
        """
        result: dict[str, list[dict[str, Any]]] = {}
        for name, conn in self._connections.items():
            if conn.connected:
                result[name] = conn.tools
        return result

    async def list_server_tools(self, server_name: str) -> list[dict[str, Any]]:
        """List tools from a specific server.

        Args:
            server_name: Name of the server.

        Returns:
            List of tool info dicts.

        Raises:
            KeyError: If server is not connected.
        """
        conn = self._connections.get(server_name)
        if not conn or not conn.connected:
            raise KeyError(f"Server '{server_name}' is not connected")
        return conn.tools

    def find_tool(self, tool_name: str) -> tuple[str, dict[str, Any]] | None:
        """Find which server provides a specific tool.

        Args:
            tool_name: Name of the tool to find.

        Returns:
            Tuple of (server_name, tool_info) or None if not found.
        """
        for server_name, conn in self._connections.items():
            if conn.connected:
                for tool in conn.tools:
                    if tool["name"] == tool_name:
                        return server_name, tool
        return None

    # ------------------------------------------------------------------
    # Tool invocation
    # ------------------------------------------------------------------

    async def call_tool(
        self,
        server_name: str,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> Any:
        """Call a tool on a specific server.

        Args:
            server_name: Name of the server hosting the tool.
            tool_name: Name of the tool to call.
            arguments: Tool arguments as a dictionary.

        Returns:
            The tool's response (CallToolResult).

        Raises:
            KeyError: If server is not connected.
            RuntimeError: If tool call fails.
        """
        conn = self._connections.get(server_name)
        if not conn or not conn.connected:
            raise KeyError(f"Server '{server_name}' is not connected")

        if conn.session is None:
            raise RuntimeError(f"Server '{server_name}' has no active session")

        log.debug("Calling MCP tool", server=server_name, tool=tool_name)

        try:
            result = await conn.session.call_tool(tool_name, arguments or {})
            return result
        except Exception as e:
            log.error(
                "MCP tool call failed",
                server=server_name,
                tool=tool_name,
                error=str(e),
            )
            raise RuntimeError(f"Tool call '{tool_name}' on '{server_name}' failed: {e}") from e

    async def call_tool_auto(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> Any:
        """Call a tool, automatically finding which server provides it.

        Args:
            tool_name: Name of the tool to call.
            arguments: Tool arguments as a dictionary.

        Returns:
            The tool's response (CallToolResult).

        Raises:
            KeyError: If no server provides this tool.
            RuntimeError: If tool call fails.
        """
        found = self.find_tool(tool_name)
        if not found:
            raise KeyError(f"No connected server provides tool '{tool_name}'")

        server_name, _ = found
        return await self.call_tool(server_name, tool_name, arguments)

    # ------------------------------------------------------------------
    # Resource access
    # ------------------------------------------------------------------

    async def list_resources(self, server_name: str) -> list[dict[str, Any]]:
        """List resources from a specific server.

        Args:
            server_name: Name of the server.

        Returns:
            List of resource info dicts.

        Raises:
            KeyError: If server is not connected.
        """
        conn = self._connections.get(server_name)
        if not conn or not conn.connected:
            raise KeyError(f"Server '{server_name}' is not connected")

        if conn.session is None:
            raise RuntimeError(f"Server '{server_name}' has no active session")

        try:
            result = await conn.session.list_resources()
            return [
                {
                    "uri": str(r.uri),
                    "name": getattr(r, "name", ""),
                    "description": getattr(r, "description", ""),
                    "mime_type": getattr(r, "mimeType", ""),
                }
                for r in result.resources
            ]
        except Exception as e:
            log.error("Failed to list resources", server=server_name, error=str(e))
            return []

    async def read_resource(self, server_name: str, uri: str) -> Any:
        """Read a resource from a specific server.

        Args:
            server_name: Name of the server.
            uri: Resource URI.

        Returns:
            Resource contents.

        Raises:
            KeyError: If server is not connected.
        """
        conn = self._connections.get(server_name)
        if not conn or not conn.connected:
            raise KeyError(f"Server '{server_name}' is not connected")

        if conn.session is None:
            raise RuntimeError(f"Server '{server_name}' has no active session")

        from pydantic import AnyUrl

        return await conn.session.read_resource(AnyUrl(uri))

    # ------------------------------------------------------------------
    # Status & diagnostics
    # ------------------------------------------------------------------

    def get_status(self) -> dict[str, dict[str, Any]]:
        """Get status of all configured servers.

        Returns:
            Dict mapping server name -> status info dict.
        """
        all_servers = self._settings.servers
        status: dict[str, dict[str, Any]] = {}

        for name, cfg in all_servers.items():
            conn = self._connections.get(name)
            if conn:
                status[name] = {
                    "enabled": cfg.enabled,
                    "transport": cfg.transport,
                    "connected": conn.connected,
                    "tools": len(conn.tools),
                    "error": conn.error,
                }
            else:
                status[name] = {
                    "enabled": cfg.enabled,
                    "transport": cfg.transport,
                    "connected": False,
                    "tools": 0,
                    "error": "Not attempted" if cfg.enabled else "Disabled",
                }

        return status

    def print_status(self) -> str:
        """Get a human-readable status report.

        Returns:
            Formatted status string.
        """
        status = self.get_status()
        lines = ["MCP Server Status:"]

        for name, info in status.items():
            if info["connected"]:
                icon = "+"
                detail = f"{info['tools']} tools"
            elif info["enabled"]:
                icon = "x"
                detail = info.get("error", "Not connected")
            else:
                icon = "-"
                detail = "Disabled"

            transport = info.get("transport", "unknown")
            lines.append(f"  [{icon}] {name} ({transport}): {detail}")

        return "\n".join(lines)

    @property
    def connected_servers(self) -> list[str]:
        """List names of currently connected servers."""
        return [name for name, conn in self._connections.items() if conn.connected]

    @property
    def has_connections(self) -> bool:
        """Whether any servers are currently connected."""
        return any(conn.connected for conn in self._connections.values())
