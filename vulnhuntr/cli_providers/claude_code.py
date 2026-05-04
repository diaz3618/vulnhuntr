"""Claude Code headless adapter for Vulnhuntr.

Verified against claude 2.1.126. Key flags:
  -p <prompt>  --output-format json  --permission-mode bypassPermissions
  --no-session-persistence
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
from typing import Any, ClassVar

import structlog

from vulnhuntr.cli_providers.base import (
    CapabilityResult,
    CLIParseError,
    CLIProviderLLM,
    CLIRuntimeError,
)
from vulnhuntr.config import CLIPolicy
from vulnhuntr.core.models import LLMUsage

log = structlog.get_logger(__name__)


class ClaudeCodeLLM(CLIProviderLLM):
    """Claude Code headless adapter.

    ANTHROPIC_API_KEY is stripped before subprocess spawn so the binary uses
    its own OAuth auth rather than falling back to API key mode.
    """

    _STRIP_ENV_VARS: ClassVar[tuple[str, ...]] = ("ANTHROPIC_API_KEY",)

    def __init__(
        self,
        system_prompt: str = "",
        cost_callback: Any | None = None,
        timeout: int = 300,
        workdir: str | None = None,
        policy: CLIPolicy | None = None,
    ) -> None:
        super().__init__(system_prompt, cost_callback, timeout, workdir)
        self._policy = policy

    def _build_env(self) -> dict[str, str]:
        """Strip class-level vars plus any operator-supplied vars from CLIPolicy."""
        env = super()._build_env()
        for var in self._policy.strip_env_vars if self._policy else []:
            env.pop(var, None)
        return env

    def _build_mcp_config_args(self) -> list[str]:
        """Write MCP server config and return --mcp-config args when mcp_mode requires it.

        Lazy-loads MCPSettings from the current working directory so the method
        never hard-fails when MCP is not configured.

        mcp_mode='none' or mcp_mode='provider' → return []
        mcp_mode='vulnhuntr' or mcp_mode='both' → write real server config, return args
        """
        policy = self._policy
        if not policy:
            return []
        if policy.mcp_mode not in ("vulnhuntr", "both"):
            return []

        # Lazy-load MCPSettings — optional dependency; gracefully return [] on failure
        try:
            from vulnhuntr.mcp import load_mcp_config
            from vulnhuntr.mcp.config import TransportType

            mcp_settings = load_mcp_config()
        except Exception:
            return []

        # Build {"mcpServers": {...}} JSON from enabled servers
        mcp_servers: dict[str, dict] = {}
        for server_name, server_cfg in (mcp_settings.servers or {}).items():
            if not server_cfg.enabled:
                continue
            transport = server_cfg.transport
            if isinstance(transport, str):
                transport = TransportType(transport)

            if transport == TransportType.STDIO:
                entry: dict = {"command": server_cfg.command or "", "args": server_cfg.args}
                if server_cfg.env:
                    entry["env"] = server_cfg.env
            else:
                # streamable-http or sse
                entry = {"url": server_cfg.url or ""}
                if server_cfg.headers:
                    entry["headers"] = server_cfg.headers

            mcp_servers[server_name] = entry

        if not mcp_servers:
            return []

        workdir = self.workdir or "/tmp/vulnhuntr"
        config_path = pathlib.Path(workdir) / "mcp_config.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps({"mcpServers": mcp_servers}), encoding="utf-8")
        return ["--mcp-config", str(config_path)]

    def probe(self) -> CapabilityResult:
        """Check binary availability and capture version string.

        auth_valid is always None — OAuth state can only be confirmed on the
        first real call, not by running --version.
        """
        binary = shutil.which("claude")
        if not binary:
            return CapabilityResult(
                ok=False,
                binary_found=False,
                version=None,
                auth_valid=None,
                diagnostic_message=("Claude Code binary not found. Install with: npm i -g @anthropic-ai/claude-code"),
            )
        try:
            result = self._run_subprocess(["claude", "--version"])
        except Exception as exc:
            return CapabilityResult(
                ok=False,
                binary_found=True,
                version=None,
                auth_valid=None,
                diagnostic_message=f"Failed to run claude --version: {exc}",
            )
        match = re.search(r"(\d+\.\d+\.\d+)", result.stdout)
        version = match.group(1) if match else result.stdout.strip()
        self._last_probe_version = version
        return CapabilityResult(
            ok=True,
            binary_found=True,
            version=version,
            auth_valid=None,
            diagnostic_message="",
        )

    def send_message(
        self,
        user_prompt: str,
        max_tokens: int,
        response_model: Any = None,
    ) -> dict[str, Any]:
        """Build the claude CLI command and return the parsed JSON payload.

        tool_mode controls which tools Claude Code can use:
          "none"      → --tools ""               (disable everything)
          "read-only" → --permission-mode plan   (file reads only)
          "full"      → default tool set
        """
        del max_tokens, response_model

        # Prepend stored system prompt when set so vulnerability-analysis
        # context (instructions + README summary) reaches the model.
        # Claude Code CLI supports --system-prompt in recent versions but
        # prompt-prepending works across all versions without flag detection.
        full_prompt = user_prompt
        if self.system_prompt:
            full_prompt = f"{self.system_prompt}\n\n{user_prompt}"

        tool_mode = self._policy.tool_mode if self._policy else "none"
        session_mode = self._policy.session_mode if self._policy else "stateless"

        if tool_mode == "read-only":
            permission_mode = "plan"
        else:
            permission_mode = "bypassPermissions"

        cmd: list[str] = [
            "claude",
            "-p",
            full_prompt,
            "--output-format",
            "json",
            "--permission-mode",
            permission_mode,
        ]

        if session_mode == "stateless":
            cmd.append("--no-session-persistence")
        elif session_mode == "continue":
            cmd.append("--continue")
        elif session_mode == "resume":
            if not self.session_id:
                raise CLIRuntimeError(
                    "session_mode='resume' requires a stored session_id; "
                    "run with session_mode='stateless' or 'continue' first to create one."
                )
            cmd.extend(["--resume", self.session_id])

        if tool_mode == "none":
            cmd.extend(["--tools", ""])

        cmd.extend(self._build_mcp_config_args())

        result = self._run_subprocess(cmd)
        stdout = result.stdout.strip()
        if not stdout:
            raise CLIParseError("Claude Code returned empty stdout")
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise CLIParseError(f"Claude Code returned invalid JSON: {stdout[:500]}") from exc
        model_usage = payload.get("modelUsage") or {}
        self.model = next(iter(model_usage.keys()), "claude-code")
        self.session_id = payload.get("session_id")
        return payload

    def get_response(self, response: Any) -> str:
        """Pull the text response out of the Claude Code JSON envelope ('result' key)."""
        result = response.get("result")
        if result is None:
            raise CLIParseError("Claude Code response did not contain a 'result' field")
        return str(result)

    def _extract_usage(self, response: Any) -> LLMUsage:
        """Sum token counts from the Claude Code JSON envelope.

        input_tokens includes cache_creation and cache_read buckets.
        """
        usage = response.get("usage") or {}
        model_usage = response.get("modelUsage") or {}
        model_name = next(iter(model_usage.keys()), self.model or "claude-code")
        input_tokens = (
            int(usage.get("input_tokens", 0))
            + int(usage.get("cache_creation_input_tokens", 0))
            + int(usage.get("cache_read_input_tokens", 0))
        )
        output_tokens = int(usage.get("output_tokens", 0))
        return LLMUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=model_name,
        )
