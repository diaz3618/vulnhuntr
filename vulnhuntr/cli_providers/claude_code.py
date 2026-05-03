"""Claude Code headless adapter for Vulnhuntr.

Implements the four abstract methods of CLIProviderLLM using Claude Code CLI
flags verified against claude 2.1.126:
  -p <prompt>  --output-format json  --permission-mode bypassPermissions
  --no-session-persistence
"""

from __future__ import annotations

import json
import re
import shutil
from typing import Any, ClassVar

import structlog

from vulnhuntr.cli_providers.base import (
    CLIBinaryNotFoundError,
    CLIParseError,
    CLIProviderLLM,
    CapabilityResult,
)
from vulnhuntr.config import CLIPolicy
from vulnhuntr.core.models import LLMUsage

log = structlog.get_logger(__name__)


class ClaudeCodeLLM(CLIProviderLLM):
    """Claude Code headless adapter (CLIProviderLLM subclass).

    Promotes the transport-swap approach from internal/experiments/vulnhuntr_claude_code.
    The base class CLIProviderLLM.chat() owns the full subprocess + validation pipeline.
    This class implements only the four provider-specific methods.

    Env stripping: ANTHROPIC_API_KEY is removed before subprocess spawn to force
    CLI-native OAuth auth instead of API key auth (D-05).
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
        for var in (self._policy.strip_env_vars if self._policy else []):
            env.pop(var, None)
        return env

    def probe(self) -> CapabilityResult:
        """Check binary availability and capture version.

        auth_valid is always None — Claude Code OAuth auth can only be
        verified at the first real call, not statically (D-04).
        """
        binary = shutil.which("claude")
        if not binary:
            return CapabilityResult(
                ok=False,
                binary_found=False,
                version=None,
                auth_valid=None,
                diagnostic_message=(
                    "Claude Code binary not found. "
                    "Install with: npm i -g @anthropic-ai/claude-code"
                ),
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

        Flags (D-02, D-03):
          -p <prompt>            — prompt via positional flag, list-form (no shell injection)
          --output-format json   — structured JSON envelope
          --permission-mode bypassPermissions — required for headless operation
          --no-session-persistence           — stateless; no cross-call session reuse

        tool_mode mapping (D-12; RESEARCH.md Tool Mode Flag Mappings):
          "none"      -> --tools ""         (disable all built-in tools)
          "read-only" -> --permission-mode plan (overrides bypassPermissions)
          "full"      -> omit --tools flag  (default built-in tool set)
        """
        del max_tokens, response_model

        tool_mode = self._policy.tool_mode if self._policy else "none"

        if tool_mode == "read-only":
            permission_mode = "plan"
        else:
            permission_mode = "bypassPermissions"

        cmd: list[str] = [
            "claude",
            "-p",
            user_prompt,
            "--output-format",
            "json",
            "--permission-mode",
            permission_mode,
            "--no-session-persistence",
        ]

        if tool_mode == "none":
            cmd.extend(["--tools", ""])

        result = self._run_subprocess(cmd)
        stdout = result.stdout.strip()
        if not stdout:
            raise CLIParseError("Claude Code returned empty stdout")
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise CLIParseError(
                f"Claude Code returned invalid JSON: {stdout[:500]}"
            ) from exc
        model_usage = payload.get("modelUsage") or {}
        self.model = next(iter(model_usage.keys()), "claude-code")
        return payload

    def get_response(self, response: Any) -> str:
        """Extract the text response from the Claude Code JSON envelope.

        Claude Code uses the 'result' key (verified via live run — D-02).
        """
        result = response.get("result")
        if result is None:
            raise CLIParseError(
                "Claude Code response did not contain a 'result' field"
            )
        return str(result)

    def _extract_usage(self, response: Any) -> LLMUsage:
        """Extract token usage from the Claude Code JSON envelope.

        input_tokens includes cache_creation_input_tokens and
        cache_read_input_tokens (verified schema from live run).
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
