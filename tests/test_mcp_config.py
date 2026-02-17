"""
Tests for vulnhuntr.mcp.config — Pydantic config models and YAML parsing.
"""

import textwrap
from pathlib import Path

import pytest

from vulnhuntr.mcp.config import (
    MCPAnalysisMode,
    MCPAnalysisPolicy,
    MCPServerConfig,
    MCPSettings,
    TransportType,
    _parse_analysis_policy,
    load_mcp_config,
    parse_mcp_section,
)

# ---------------------------------------------------------------------------
# TransportType enum
# ---------------------------------------------------------------------------


class TestTransportType:
    def test_stdio_value(self):
        assert TransportType.STDIO.value == "stdio"

    def test_streamable_http_value(self):
        assert TransportType.STREAMABLE_HTTP.value == "streamable-http"

    def test_sse_value(self):
        assert TransportType.SSE.value == "sse"

    def test_from_string(self):
        assert TransportType("stdio") == TransportType.STDIO
        assert TransportType("streamable-http") == TransportType.STREAMABLE_HTTP
        assert TransportType("sse") == TransportType.SSE

    def test_invalid_transport(self):
        with pytest.raises(ValueError):
            TransportType("invalid-transport")


# ---------------------------------------------------------------------------
# MCPServerConfig
# ---------------------------------------------------------------------------


class TestMCPServerConfig:
    """Test individual server configuration models."""

    def test_stdio_server_valid(self):
        cfg = MCPServerConfig(
            name="test-stdio",
            transport=TransportType.STDIO,
            command="npx",
            args=["-y", "some-package"],
        )
        assert cfg.name == "test-stdio"
        assert cfg.transport == "stdio"
        assert cfg.command == "npx"
        assert cfg.args == ["-y", "some-package"]
        assert cfg.enabled is True
        assert cfg.timeout == 30

    def test_stdio_server_no_command_raises(self):
        with pytest.raises(ValueError, match="requires 'command'"):
            MCPServerConfig(
                name="bad-stdio",
                transport=TransportType.STDIO,
                command=None,
            )

    def test_streamable_http_valid(self):
        cfg = MCPServerConfig(
            name="test-http",
            transport=TransportType.STREAMABLE_HTTP,
            url="http://localhost:8000/mcp",
        )
        assert cfg.url == "http://localhost:8000/mcp"

    def test_streamable_http_no_url_raises(self):
        with pytest.raises(ValueError, match="requires 'url'"):
            MCPServerConfig(
                name="bad-http",
                transport=TransportType.STREAMABLE_HTTP,
                url=None,
            )

    def test_sse_valid(self):
        cfg = MCPServerConfig(
            name="test-sse",
            transport=TransportType.SSE,
            url="http://localhost:9000/sse",
        )
        assert cfg.url == "http://localhost:9000/sse"

    def test_sse_no_url_raises(self):
        with pytest.raises(ValueError, match="requires 'url'"):
            MCPServerConfig(
                name="bad-sse",
                transport=TransportType.SSE,
                url=None,
            )

    def test_env_variables(self):
        cfg = MCPServerConfig(
            name="env-test",
            transport=TransportType.STDIO,
            command="python",
            args=["server.py"],
            env={"API_KEY": "secret", "DB_URL": "postgres://..."},
        )
        assert cfg.env["API_KEY"] == "secret"
        assert cfg.env["DB_URL"] == "postgres://..."

    def test_http_headers(self):
        cfg = MCPServerConfig(
            name="headers-test",
            transport=TransportType.STREAMABLE_HTTP,
            url="https://example.com/mcp",
            headers={"Authorization": "Bearer token123"},
        )
        assert cfg.headers["Authorization"] == "Bearer token123"

    def test_disabled_server(self):
        cfg = MCPServerConfig(
            name="disabled",
            transport=TransportType.STDIO,
            command="npx",
            enabled=False,
        )
        assert cfg.enabled is False

    def test_description(self):
        cfg = MCPServerConfig(
            name="desc-test",
            transport=TransportType.STDIO,
            command="npx",
            description="A test server",
        )
        assert cfg.description == "A test server"

    def test_custom_timeout(self):
        cfg = MCPServerConfig(
            name="timeout-test",
            transport=TransportType.STDIO,
            command="python",
            timeout=120,
        )
        assert cfg.timeout == 120


# ---------------------------------------------------------------------------
# MCPSettings
# ---------------------------------------------------------------------------


class TestMCPSettings:
    """Test top-level MCP configuration."""

    def test_empty_settings(self):
        settings = MCPSettings()
        assert settings.enabled is True
        assert settings.servers == {}
        assert settings.get_enabled_servers() == {}

    def test_global_toggle(self):
        settings = MCPSettings(
            enabled=False,
            servers={"test": MCPServerConfig(name="test", transport=TransportType.STDIO, command="npx")},
        )
        assert settings.get_enabled_servers() == {}

    def test_get_enabled_servers(self):
        settings = MCPSettings(
            servers={
                "enabled1": MCPServerConfig(
                    name="enabled1",
                    transport=TransportType.STDIO,
                    command="npx",
                    enabled=True,
                ),
                "disabled1": MCPServerConfig(
                    name="disabled1",
                    transport=TransportType.STDIO,
                    command="npx",
                    enabled=False,
                ),
                "enabled2": MCPServerConfig(
                    name="enabled2",
                    transport=TransportType.STREAMABLE_HTTP,
                    url="http://localhost:8000/mcp",
                    enabled=True,
                ),
            },
        )
        enabled = settings.get_enabled_servers()
        assert len(enabled) == 2
        assert "enabled1" in enabled
        assert "enabled2" in enabled
        assert "disabled1" not in enabled

    def test_get_server(self):
        cfg = MCPServerConfig(name="my-server", transport=TransportType.STDIO, command="npx")
        settings = MCPSettings(servers={"my-server": cfg})
        assert settings.get_server("my-server") is cfg
        assert settings.get_server("nonexistent") is None

    def test_populate_server_names(self):
        settings = MCPSettings(servers={"auto-named": MCPServerConfig(transport=TransportType.STDIO, command="npx")})
        assert settings.servers["auto-named"].name == "auto-named"


# ---------------------------------------------------------------------------
# parse_mcp_section
# ---------------------------------------------------------------------------


class TestParseMCPSection:
    """Test parsing YAML dictionary into MCPSettings."""

    def test_parse_stdio_server(self):
        data = {
            "mcp": {
                "enabled": True,
                "servers": {
                    "analyzer": {
                        "transport": "stdio",
                        "command": "uvx",
                        "args": ["mcp-server-analyzer"],
                        "enabled": True,
                    }
                },
            }
        }
        settings = parse_mcp_section(data)
        assert len(settings.servers) == 1
        assert "analyzer" in settings.servers
        cfg = settings.servers["analyzer"]
        assert cfg.command == "uvx"
        assert cfg.args == ["mcp-server-analyzer"]
        assert cfg.transport == "stdio"

    def test_parse_http_server(self):
        data = {
            "mcp": {
                "servers": {
                    "remote": {
                        "transport": "streamable-http",
                        "url": "http://localhost:8000/mcp",
                        "headers": {"Authorization": "Bearer test"},
                    }
                }
            }
        }
        settings = parse_mcp_section(data)
        cfg = settings.servers["remote"]
        assert cfg.transport == "streamable-http"
        assert cfg.url == "http://localhost:8000/mcp"
        assert cfg.headers["Authorization"] == "Bearer test"

    def test_parse_multiple_servers(self):
        data = {
            "mcp": {
                "servers": {
                    "server1": {
                        "transport": "stdio",
                        "command": "npx",
                        "args": ["-y", "pkg1"],
                    },
                    "server2": {
                        "transport": "stdio",
                        "command": "uvx",
                        "args": ["pkg2"],
                        "enabled": False,
                    },
                    "server3": {
                        "transport": "streamable-http",
                        "url": "http://example.com/mcp",
                    },
                }
            }
        }
        settings = parse_mcp_section(data)
        assert len(settings.servers) == 3
        enabled = settings.get_enabled_servers()
        assert len(enabled) == 2  # server2 is disabled

    def test_parse_invalid_server_skipped(self):
        data = {
            "mcp": {
                "servers": {
                    "valid": {
                        "transport": "stdio",
                        "command": "npx",
                    },
                    "invalid": "not-a-dict",
                }
            }
        }
        settings = parse_mcp_section(data)
        assert len(settings.servers) == 1
        assert "valid" in settings.servers

    def test_parse_global_disabled(self):
        data = {
            "mcp": {
                "enabled": False,
                "servers": {
                    "test": {
                        "transport": "stdio",
                        "command": "npx",
                    }
                },
            }
        }
        settings = parse_mcp_section(data)
        assert settings.enabled is False
        assert settings.get_enabled_servers() == {}

    def test_parse_empty_servers(self):
        data = {"mcp": {"servers": {}}}
        settings = parse_mcp_section(data)
        assert len(settings.servers) == 0

    def test_parse_no_mcp_section(self):
        data = {"other": "stuff"}
        settings = parse_mcp_section(data)
        assert len(settings.servers) == 0


# ---------------------------------------------------------------------------
# load_mcp_config (file-based)
# ---------------------------------------------------------------------------


class TestLoadMCPConfig:
    """Test loading MCP config from YAML files."""

    def test_load_from_file(self, tmp_path: Path):
        config_content = textwrap.dedent("""\
            mcp:
              enabled: true
              servers:
                test-server:
                  transport: stdio
                  command: echo
                  args: ["hello"]
                  enabled: true
        """)
        config_file = tmp_path / ".vulnhuntr.yaml"
        config_file.write_text(config_content, encoding="utf-8")

        settings = load_mcp_config(config_path=config_file)
        assert len(settings.servers) == 1
        assert "test-server" in settings.servers
        assert settings.servers["test-server"].command == "echo"

    def test_load_no_mcp_section(self, tmp_path: Path):
        config_content = textwrap.dedent("""\
            cost:
              budget: 10.0
        """)
        config_file = tmp_path / ".vulnhuntr.yaml"
        config_file.write_text(config_content, encoding="utf-8")

        settings = load_mcp_config(config_path=config_file)
        assert len(settings.servers) == 0

    def test_load_nonexistent_file(self, tmp_path: Path):
        settings = load_mcp_config(config_path=tmp_path / "nonexistent.yaml")
        assert len(settings.servers) == 0

    def test_load_empty_file(self, tmp_path: Path):
        config_file = tmp_path / ".vulnhuntr.yaml"
        config_file.write_text("", encoding="utf-8")

        settings = load_mcp_config(config_path=config_file)
        assert len(settings.servers) == 0

    def test_load_invalid_yaml(self, tmp_path: Path):
        config_file = tmp_path / ".vulnhuntr.yaml"
        config_file.write_text("{{{{invalid yaml", encoding="utf-8")

        settings = load_mcp_config(config_path=config_file)
        assert len(settings.servers) == 0

    def test_load_multiple_transports(self, tmp_path: Path):
        config_content = textwrap.dedent("""\
            mcp:
              servers:
                stdio-server:
                  transport: stdio
                  command: npx
                  args: ["-y", "test-pkg"]
                http-server:
                  transport: streamable-http
                  url: http://localhost:8000/mcp
                sse-server:
                  transport: sse
                  url: http://localhost:9000/sse
        """)
        config_file = tmp_path / ".vulnhuntr.yaml"
        config_file.write_text(config_content, encoding="utf-8")

        settings = load_mcp_config(config_path=config_file)
        assert len(settings.servers) == 3

        stdio = settings.servers["stdio-server"]
        assert stdio.transport == "stdio"
        assert stdio.command == "npx"

        http = settings.servers["http-server"]
        assert http.transport == "streamable-http"
        assert http.url == "http://localhost:8000/mcp"

        sse = settings.servers["sse-server"]
        assert sse.transport == "sse"
        assert sse.url == "http://localhost:9000/sse"

    def test_load_with_env_and_headers(self, tmp_path: Path):
        config_content = textwrap.dedent("""\
            mcp:
              servers:
                custom:
                  transport: stdio
                  command: python
                  args: [server.py]
                  env:
                    API_KEY: secret123
                    DB_URL: postgres://localhost/db
                auth-http:
                  transport: streamable-http
                  url: https://example.com/mcp
                  headers:
                    Authorization: Bearer token456
                    X-Custom: value
        """)
        config_file = tmp_path / ".vulnhuntr.yaml"
        config_file.write_text(config_content, encoding="utf-8")

        settings = load_mcp_config(config_path=config_file)
        custom = settings.servers["custom"]
        assert custom.env["API_KEY"] == "secret123"

        auth = settings.servers["auth-http"]
        assert auth.headers["Authorization"] == "Bearer token456"


# ---------------------------------------------------------------------------
# MCPAnalysisMode enum
# ---------------------------------------------------------------------------


class TestMCPAnalysisMode:
    def test_off_value(self):
        assert MCPAnalysisMode.OFF.value == "off"

    def test_auto_value(self):
        assert MCPAnalysisMode.AUTO.value == "auto"

    def test_force_value(self):
        assert MCPAnalysisMode.FORCE.value == "force"

    def test_from_string(self):
        assert MCPAnalysisMode("off") == MCPAnalysisMode.OFF
        assert MCPAnalysisMode("auto") == MCPAnalysisMode.AUTO
        assert MCPAnalysisMode("force") == MCPAnalysisMode.FORCE

    def test_invalid_mode(self):
        with pytest.raises(ValueError):
            MCPAnalysisMode("invalid")


# ---------------------------------------------------------------------------
# MCPAnalysisPolicy
# ---------------------------------------------------------------------------


class TestMCPAnalysisPolicy:
    def test_defaults(self):
        policy = MCPAnalysisPolicy()
        assert policy.mode == "off"
        assert policy.force_servers == []
        assert policy.max_tool_calls_per_iteration == 3
        assert policy.allow_destructive_tools is False
        assert policy.tool_timeout_seconds == 30

    def test_auto_mode(self):
        policy = MCPAnalysisPolicy(mode="auto")
        assert policy.mode == "auto"

    def test_force_mode_valid(self):
        policy = MCPAnalysisPolicy(mode="force", force_servers=["snyk", "semgrep"])
        assert policy.mode == "force"
        assert policy.force_servers == ["snyk", "semgrep"]

    def test_force_mode_no_servers_raises(self):
        with pytest.raises(ValueError, match="force_servers must list at least one"):
            MCPAnalysisPolicy(mode="force", force_servers=[])

    def test_max_tool_calls_zero(self):
        policy = MCPAnalysisPolicy(max_tool_calls_per_iteration=0)
        assert policy.max_tool_calls_per_iteration == 0

    def test_max_tool_calls_negative_raises(self):
        with pytest.raises(ValueError):
            MCPAnalysisPolicy(max_tool_calls_per_iteration=-1)

    def test_tool_timeout_zero(self):
        policy = MCPAnalysisPolicy(tool_timeout_seconds=0)
        assert policy.tool_timeout_seconds == 0

    # -- is_tool_allowed ---------------------------------------------------

    def test_read_only_tool_allowed(self):
        policy = MCPAnalysisPolicy()
        assert policy.is_tool_allowed("search_vulnerabilities") is True
        assert policy.is_tool_allowed("get_cve_info") is True
        assert policy.is_tool_allowed("list_packages") is True
        assert policy.is_tool_allowed("analyze_code") is True

    def test_destructive_tool_blocked(self):
        policy = MCPAnalysisPolicy()
        assert policy.is_tool_allowed("write_file") is False
        assert policy.is_tool_allowed("delete_resource") is False
        assert policy.is_tool_allowed("create_issue") is False
        assert policy.is_tool_allowed("modify_config") is False
        assert policy.is_tool_allowed("update_record") is False
        assert policy.is_tool_allowed("execute_command") is False
        assert policy.is_tool_allowed("run_script") is False
        assert policy.is_tool_allowed("remove_entry") is False
        assert policy.is_tool_allowed("drop_table") is False
        assert policy.is_tool_allowed("put_object") is False
        assert policy.is_tool_allowed("post_data") is False
        assert policy.is_tool_allowed("patch_resource") is False
        assert policy.is_tool_allowed("send_notification") is False

    def test_destructive_tool_allowed_when_enabled(self):
        policy = MCPAnalysisPolicy(allow_destructive_tools=True)
        assert policy.is_tool_allowed("write_file") is True
        assert policy.is_tool_allowed("delete_resource") is True
        assert policy.is_tool_allowed("execute_command") is True

    def test_case_insensitive_blocking(self):
        policy = MCPAnalysisPolicy()
        assert policy.is_tool_allowed("WriteFile") is False
        assert policy.is_tool_allowed("DELETE_ALL") is False
        assert policy.is_tool_allowed("RunAnalysis") is False


# ---------------------------------------------------------------------------
# _parse_analysis_policy
# ---------------------------------------------------------------------------


class TestParseAnalysisPolicy:
    def test_parse_none(self):
        policy = _parse_analysis_policy(None)
        assert policy.mode == "off"

    def test_parse_empty(self):
        policy = _parse_analysis_policy({})
        assert policy.mode == "off"

    def test_parse_auto(self):
        policy = _parse_analysis_policy({"mode": "auto"})
        assert policy.mode == "auto"

    def test_parse_force(self):
        policy = _parse_analysis_policy({"mode": "force", "force_servers": ["scanner"]})
        assert policy.mode == "force"
        assert policy.force_servers == ["scanner"]

    def test_parse_with_all_fields(self):
        policy = _parse_analysis_policy(
            {
                "mode": "auto",
                "max_tool_calls_per_iteration": 5,
                "allow_destructive_tools": True,
                "tool_timeout_seconds": 60,
            }
        )
        assert policy.max_tool_calls_per_iteration == 5
        assert policy.allow_destructive_tools is True
        assert policy.tool_timeout_seconds == 60

    def test_parse_invalid_falls_back_to_defaults(self):
        # Invalid mode should fall back
        policy = _parse_analysis_policy({"mode": "invalid-mode"})
        assert policy.mode == "off"

    def test_parse_non_dict(self):
        policy = _parse_analysis_policy("not-a-dict")  # type: ignore[arg-type]
        assert policy.mode == "off"


# ---------------------------------------------------------------------------
# MCPSettings with analysis field
# ---------------------------------------------------------------------------


class TestMCPSettingsAnalysis:
    def test_default_analysis_policy(self):
        settings = MCPSettings()
        assert settings.analysis.mode == "off"

    def test_analysis_in_parse_mcp_section(self):
        data = {
            "mcp": {
                "servers": {
                    "test": {"transport": "stdio", "command": "npx"},
                },
                "analysis": {"mode": "auto", "max_tool_calls_per_iteration": 5},
            }
        }
        settings = parse_mcp_section(data)
        assert settings.analysis.mode == "auto"
        assert settings.analysis.max_tool_calls_per_iteration == 5

    def test_analysis_force_in_yaml(self, tmp_path: Path):
        config_content = textwrap.dedent("""\
            mcp:
              servers:
                scanner:
                  transport: stdio
                  command: npx
                  args: ["-y", "scanner-pkg"]
              analysis:
                mode: force
                force_servers: [scanner]
                max_tool_calls_per_iteration: 2
                tool_timeout_seconds: 15
        """)
        config_file = tmp_path / ".vulnhuntr.yaml"
        config_file.write_text(config_content, encoding="utf-8")

        settings = load_mcp_config(config_path=config_file)
        assert settings.analysis.mode == "force"
        assert settings.analysis.force_servers == ["scanner"]
        assert settings.analysis.max_tool_calls_per_iteration == 2
        assert settings.analysis.tool_timeout_seconds == 15

    def test_no_analysis_section_defaults_to_off(self, tmp_path: Path):
        config_content = textwrap.dedent("""\
            mcp:
              servers:
                test:
                  transport: stdio
                  command: echo
        """)
        config_file = tmp_path / ".vulnhuntr.yaml"
        config_file.write_text(config_content, encoding="utf-8")

        settings = load_mcp_config(config_path=config_file)
        assert settings.analysis.mode == "off"
