"""
MCP (Model Context Protocol) integration for Vulnhuntr.

Users configure MCP servers in .vulnhuntr.yaml and the client manager handles
connection lifecycle, tool discovery, and tool invocation.

Supported transports:
- stdio: Subprocess-based (npx, uvx, python, any local binary)
- streamable-http: HTTP endpoint (recommended for production)
- sse: Server-Sent Events endpoint (legacy)
"""

from vulnhuntr.mcp.analysis import (
    MCPAnalysisHelper,
    run_async,
    should_use_mcp,
)
from vulnhuntr.mcp.client import MCPClientManager
from vulnhuntr.mcp.config import (
    MCPAnalysisMode,
    MCPAnalysisPolicy,
    MCPServerConfig,
    MCPSettings,
    TransportType,
    load_mcp_config,
)

__all__ = [
    "MCPAnalysisHelper",
    "MCPAnalysisMode",
    "MCPAnalysisPolicy",
    "MCPClientManager",
    "MCPServerConfig",
    "MCPSettings",
    "TransportType",
    "load_mcp_config",
    "run_async",
    "should_use_mcp",
]
