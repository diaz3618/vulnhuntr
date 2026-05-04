"""Gemini CLI headless adapter for Vulnhuntr.

Verified against gemini 0.40.1. Key flags:
  -p <prompt>  --output-format json  --approval-mode plan|yolo

JSON envelope:
  {"response": "...", "stats": {"models": {"<name>": {"tokens": {"input": N, "candidates": N}}}}}

--allowed-tools was deprecated in 0.40.1; use --approval-mode instead.
"""

from __future__ import annotations

import json
import re
import shutil
from typing import Any, ClassVar

import structlog

from vulnhuntr.cli_providers.base import (
    CapabilityResult,
    CLIParseError,
    CLIProviderLLM,
)
from vulnhuntr.config import CLIPolicy
from vulnhuntr.core.models import LLMUsage

log = structlog.get_logger(__name__)


class GeminiCLILLM(CLIProviderLLM):
    """Gemini CLI headless adapter.

    Three env vars (GEMINI_API_KEY, GOOGLE_API_KEY, GOOGLE_GENAI_USE_VERTEXAI)
    are stripped before subprocess spawn to prevent API key auth or Vertex AI
    routing — the binary should use its own OAuth flow.

    probe() rejects versions before 0.6.0 because --output-format json was
    added in that release.
    """

    _STRIP_ENV_VARS: ClassVar[tuple[str, ...]] = (
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_GENAI_USE_VERTEXAI",
    )
    _MIN_VERSION: ClassVar[tuple[int, ...]] = (0, 6, 0)

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

    def _do_probe(self) -> CapabilityResult:
        """Check binary and reject versions older than 0.6.0.

        Uses tuple comparison, not string comparison — "0.40.1" > "0.9.0"
        is False as strings but correct as (0,40,1) > (0,9,0).
        auth_valid stays None; OAuth can only be confirmed on the first real call.
        """
        binary = shutil.which("gemini")
        if not binary:
            return CapabilityResult(
                ok=False,
                binary_found=False,
                version=None,
                auth_valid=None,
                diagnostic_message=("Gemini CLI binary not found. Install with: npm i -g @google/gemini-cli"),
            )
        try:
            result = self._run_subprocess(["gemini", "--version"])
        except Exception as exc:
            return CapabilityResult(
                ok=False,
                binary_found=True,
                version=None,
                auth_valid=None,
                diagnostic_message=f"Failed to run gemini --version: {exc}",
            )
        # Accept both 3-part (0.40.1) and 2-part (0.6) version strings.
        match = re.search(r"(\d+\.\d+(?:\.\d+)?)", result.stdout)
        version_str = match.group(1) if match else result.stdout.strip()
        # MUST use tuple comparison — string comparison breaks for "0.40.1" vs "0.9.0".
        # Pad to 3 elements so (0, 6) == (0, 6, 0) instead of being incorrectly
        # treated as less-than (0, 6, 0) by Python's length-aware tuple ordering.
        try:
            parts = [int(x) for x in version_str.split(".", 2)]
            while len(parts) < 3:
                parts.append(0)
            parsed = tuple(parts)
        except ValueError:
            parsed = (0, 0, 0)
        if parsed < self._MIN_VERSION:
            min_s = ".".join(str(x) for x in self._MIN_VERSION)
            return CapabilityResult(
                ok=False,
                binary_found=True,
                version=version_str,
                auth_valid=None,
                diagnostic_message=(
                    f"Gemini CLI {version_str} too old; "
                    f"--output-format json requires >= {min_s}. "
                    "Run: npm i -g @google/gemini-cli"
                ),
            )
        self._last_probe_version = version_str
        return CapabilityResult(
            ok=True,
            binary_found=True,
            version=version_str,
            auth_valid=None,
            diagnostic_message="",
        )

    def send_message(
        self,
        user_prompt: str,
        max_tokens: int,
        response_model: Any = None,
    ) -> dict[str, Any]:
        """Build the gemini CLI command and return the parsed JSON payload.

        tool_mode maps to --approval-mode (--allowed-tools is deprecated):
          "none" / "read-only" → plan   (read-only, safe for scanning)
          "full"               → yolo   (auto-approves all tools)
        """
        del max_tokens, response_model

        # Prepend stored system prompt when set so vulnerability-analysis
        # context (instructions + README summary) reaches the model.
        # Gemini CLI does not expose a dedicated --system-prompt flag so
        # prompt-prepending is the only portable approach.
        full_prompt = user_prompt
        if self.system_prompt:
            full_prompt = f"{self.system_prompt}\n\n{user_prompt}"

        tool_mode = self._policy.tool_mode if self._policy else "none"
        approval_mode = "yolo" if tool_mode == "full" else "plan"

        session_mode = self._policy.session_mode if self._policy else "stateless"
        if session_mode != "stateless":
            log.warning(
                "session_mode not supported by Gemini CLI; falling back to stateless",
                requested_session_mode=session_mode,
            )

        cmd: list[str] = [
            "gemini",
            "-p",
            full_prompt,
            "--output-format",
            "json",
            "--approval-mode",
            approval_mode,
        ]

        # Model override from per-provider policy overrides
        if self._policy:
            gemini_overrides = self._policy.overrides.get("gemini-cli", {})
            model_override = gemini_overrides.get("model")
            if model_override:
                cmd.extend(["--model", str(model_override)])

        cmd.extend(self._build_mcp_config_args())

        result = self._run_subprocess(cmd)
        stdout = result.stdout.strip()
        if not stdout:
            raise CLIParseError("Gemini CLI returned empty stdout")
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise CLIParseError(f"Gemini CLI returned invalid JSON: {stdout[:500]}") from exc
        return payload

    def get_response(self, response: Any) -> str:
        """Pull the text response out of the Gemini CLI JSON envelope ('response' key).

        Not 'result' — that's Claude Code's field name.
        """
        result = response.get("response")
        if result is None:
            raise CLIParseError("Gemini CLI response did not contain a 'response' field")
        return str(result)

    def _extract_usage(self, response: Any) -> LLMUsage:
        """Sum token counts across all entries in stats.models.

        stats.inputTokenCount does not exist in gemini 0.40.1 output — the
        correct path is stats.models.<name>.tokens.input and .candidates.
        Multiple model entries are possible when Gemini uses a routing model.
        """
        stats = response.get("stats") or {}
        models = stats.get("models") or {}
        input_tokens = 0
        output_tokens = 0
        model_name = self.model or "gemini"
        for name, mdata in models.items():
            tokens = (mdata or {}).get("tokens") or {}
            input_tokens += int(tokens.get("input", 0))
            output_tokens += int(tokens.get("candidates", 0))
            model_name = name  # last model name wins; acceptable for usage reporting
        self.model = model_name
        return LLMUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=model_name,
        )
