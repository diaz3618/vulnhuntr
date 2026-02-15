"""
Pydantic configuration models for MCP server definitions.

Parses the "mcp:" section of .vulnhuntr.yaml and validates server configurations
including transport type, command/URL, environment variables, and timeouts.
"""

from __future__ import annotations

import enum
from pathlib import Path
from typing import Any

import structlog
from pydantic import BaseModel, Field, model_validator

log = structlog.get_logger(__name__)

# Try to import yaml, provide fallback if not available
try:
    import yaml  # type: ignore[import-untyped]

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class TransportType(str, enum.Enum):
    """Supported MCP transport types.

    - stdio: Launch server as subprocess, communicate via stdin/stdout.
             Covers npx, uvx, python, any local binary.
    - streamable_http: Connect to an HTTP endpoint (recommended for production).
    - sse: Connect to a Server-Sent Events endpoint (legacy).
    """

    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable-http"
    SSE = "sse"


class MCPServerConfig(BaseModel):
    """Configuration for a single MCP server.

    Attributes:
        name: Unique server identifier (set from YAML key, not user-specified).
        transport: Transport type (stdio, streamable-http, sse).
        enabled: Whether this server is active.
        command: Executable command for stdio transport (e.g., "npx", "uvx", "python").
        args: Arguments for the command (e.g., ["-y", "mcp-server-analyzer"]).
        url: Endpoint URL for streamable-http or sse transports.
        headers: HTTP headers for streamable-http/sse transports.
        env: Environment variables to pass to stdio subprocess.
        timeout: Connection timeout in seconds (0 = no timeout).
        description: Human-readable description of what this server provides.
    """

    name: str = Field(default="", description="Server identifier (populated from YAML key)")
    transport: TransportType = Field(default=TransportType.STDIO, description="Transport type")
    enabled: bool = Field(default=True, description="Whether this server is active")

    # stdio transport fields
    command: str | None = Field(default=None, description="Executable command for stdio transport")
    args: list[str] = Field(default_factory=list, description="Arguments for the command")

    # HTTP/SSE transport fields
    url: str | None = Field(default=None, description="Endpoint URL for HTTP/SSE transports")
    headers: dict[str, str] = Field(default_factory=dict, description="HTTP headers")

    # Common fields
    env: dict[str, str] = Field(default_factory=dict, description="Environment variables for subprocess")
    timeout: int = Field(default=30, description="Connection timeout in seconds (0 = no timeout)")
    description: str = Field(default="", description="Human-readable description")

    model_config = {"use_enum_values": True}

    @model_validator(mode="after")
    def validate_transport_fields(self) -> MCPServerConfig:
        """Validate that required fields are present for the chosen transport."""
        transport = self.transport
        if isinstance(transport, str):
            transport = TransportType(transport)

        if transport == TransportType.STDIO:
            if not self.command:
                raise ValueError(f"Server '{self.name}': stdio transport requires 'command' field")
        elif transport in (TransportType.STREAMABLE_HTTP, TransportType.SSE):
            if not self.url:
                raise ValueError(f"Server '{self.name}': {transport} transport requires 'url' field")
        return self


class MCPSettings(BaseModel):
    """Top-level MCP configuration from .vulnhuntr.yaml.

    Attributes:
        servers: Dictionary of server name -> server configuration.
        enabled: Global toggle to enable/disable all MCP servers.
        log_level: Logging level for MCP operations.
    """

    servers: dict[str, MCPServerConfig] = Field(default_factory=dict, description="Named MCP server configurations")
    enabled: bool = Field(default=True, description="Global MCP toggle")
    log_level: str = Field(default="info", description="MCP logging level")

    @model_validator(mode="after")
    def populate_server_names(self) -> MCPSettings:
        """Set server name from dictionary key if not already set."""
        for key, server in self.servers.items():
            if not server.name:
                server.name = key
        return self

    def get_enabled_servers(self) -> dict[str, MCPServerConfig]:
        """Return only servers that are enabled (respecting global toggle)."""
        if not self.enabled:
            return {}
        return {name: cfg for name, cfg in self.servers.items() if cfg.enabled}

    def get_server(self, name: str) -> MCPServerConfig | None:
        """Get a specific server config by name."""
        return self.servers.get(name)


def parse_mcp_section(data: dict[str, Any]) -> MCPSettings:
    """Parse the `mcp:` section from a YAML config dictionary.

    Args:
        data: The raw dictionary from YAML parsing (top-level or mcp section).

    Returns:
        Validated MCPSettings instance.
    """
    # Extract the mcp section if passed the full config
    mcp_data = data.get("mcp", data)

    # Parse servers from the raw dict
    raw_servers = mcp_data.get("servers", {})
    servers: dict[str, MCPServerConfig] = {}

    for name, server_data in raw_servers.items():
        if not isinstance(server_data, dict):
            log.warning("Skipping invalid server config", server=name, data=server_data)
            continue
        try:
            server_data["name"] = name
            servers[name] = MCPServerConfig(**server_data)
        except Exception as e:
            log.error("Failed to parse MCP server config", server=name, error=str(e))
            continue

    return MCPSettings(
        servers=servers,
        enabled=mcp_data.get("enabled", True),
        log_level=mcp_data.get("log_level", "info"),
    )


def load_mcp_config(
    config_path: Path | None = None,
    start_dir: Path | None = None,
) -> MCPSettings:
    """Load MCP configuration from .vulnhuntr.yaml.

    Searches for the config file in the standard locations (project root,
    parent dirs, home directory) and parses the `mcp:` section.

    Args:
        config_path: Explicit path to config file (optional).
        start_dir: Directory to start searching from (optional).

    Returns:
        MCPSettings instance (empty if no config found).
    """
    if not YAML_AVAILABLE:
        log.debug("YAML not available, returning empty MCP config")
        return MCPSettings()

    # Use the existing find_config_file from vulnhuntr.config
    from vulnhuntr.config import find_config_file

    path = config_path or find_config_file(start_dir)

    if not path or not path.exists():
        log.debug("No config file found, returning empty MCP config")
        return MCPSettings()

    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if data is None or "mcp" not in data:
            log.debug("No MCP section in config file", path=str(path))
            return MCPSettings()

        settings = parse_mcp_section(data)
        enabled_count = len(settings.get_enabled_servers())
        log.info(
            "MCP config loaded",
            path=str(path),
            total_servers=len(settings.servers),
            enabled_servers=enabled_count,
        )
        return settings

    except yaml.YAMLError as e:
        log.error("Failed to parse MCP config", path=str(path), error=str(e))
        return MCPSettings()
    except Exception as e:
        log.error("Failed to load MCP config", path=str(path), error=str(e))
        return MCPSettings()
