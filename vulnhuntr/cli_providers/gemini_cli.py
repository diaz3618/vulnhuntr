"""Gemini CLI headless adapter for Vulnhuntr.

Implements the four abstract methods of CLIProviderLLM using Gemini CLI flags
verified against gemini 0.40.1:
  -p <prompt>  --output-format json  --approval-mode plan|yolo

JSON envelope (verified live run):
  {"response": "...", "stats": {"models": {"<name>": {"tokens": {"input": N, "candidates": N}}}}}

Tool control: use --approval-mode plan (read-only) or yolo (full).
The --approval-mode flag replaces the old tool policy flags deprecated in 0.40.1.
"""

from __future__ import annotations

import json
import re
import shutil
from typing import Any, ClassVar

import structlog

from vulnhuntr.cli_providers.base import (
    CLIParseError,
    CLIProviderLLM,
    CapabilityResult,
)
from vulnhuntr.config import CLIPolicy
from vulnhuntr.core.models import LLMUsage

log = structlog.get_logger(__name__)


class GeminiCLILLM(CLIProviderLLM):
    """Gemini CLI headless adapter (CLIProviderLLM subclass).

    Env stripping: GEMINI_API_KEY, GOOGLE_API_KEY, and GOOGLE_GENAI_USE_VERTEXAI
    are removed before subprocess spawn to force CLI-native OAuth instead of API
    key auth or Vertex AI routing (D-09, RESEARCH.md env-var analysis).

    Version gate: probe() rejects gemini < 0.6.0 because --output-format json
    was added in that release (D-08).
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
        for var in (self._policy.strip_env_vars if self._policy else []):
            env.pop(var, None)
        return env

    def probe(self) -> CapabilityResult:
        """Check binary availability and gate on version >= 0.6.0.

        Semver comparison uses tuple integers — NOT string comparison.
        "0.40.1" > "0.6.0" lexicographically is False; as tuples (0,40,1) > (0,6,0) is True.

        auth_valid is always None — Gemini CLI OAuth can only be verified at the
        first real call (D-08).
        """
        binary = shutil.which("gemini")
        if not binary:
            return CapabilityResult(
                ok=False,
                binary_found=False,
                version=None,
                auth_valid=None,
                diagnostic_message=(
                    "Gemini CLI binary not found. "
                    "Install with: npm i -g @google/gemini-cli"
                ),
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
        match = re.search(r"(\d+\.\d+\.\d+)", result.stdout)
        version_str = match.group(1) if match else result.stdout.strip()
        # MUST use tuple comparison — string comparison breaks for "0.40.1" vs "0.9.0"
        try:
            parsed = tuple(int(x) for x in version_str.split(".", 2))
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

        Flags (D-10):
          -p <prompt>          — prompt flag, list-form (no shell injection)
          --output-format json — structured JSON envelope

        tool_mode mapping (D-12; use --approval-mode, not deprecated tool flags):
          "none"      → --approval-mode plan  (read-only safe headless default)
          "read-only" → --approval-mode plan  (same as none — plan mode is read-only)
          "full"      → --approval-mode yolo  (auto-approves all tools)

        Model override: --model <model> when CLIPolicy.overrides["gemini-cli"]["model"] set (D-10).
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

        result = self._run_subprocess(cmd)
        stdout = result.stdout.strip()
        if not stdout:
            raise CLIParseError("Gemini CLI returned empty stdout")
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise CLIParseError(
                f"Gemini CLI returned invalid JSON: {stdout[:500]}"
            ) from exc
        return payload

    def get_response(self, response: Any) -> str:
        """Extract the text response from the Gemini CLI JSON envelope.

        Gemini CLI uses 'response' key (D-06, verified via live run).
        NOT 'result' — that is Claude Code's field name.
        """
        result = response.get("response")
        if result is None:
            raise CLIParseError(
                "Gemini CLI response did not contain a 'response' field"
            )
        return str(result)

    def _extract_usage(self, response: Any) -> LLMUsage:
        """Extract token usage from the Gemini CLI JSON envelope.

        Gemini CLI uses stats.models.<model-name>.tokens.input and .candidates.
        Multiple model entries are possible (e.g., routing model + main model).
        Sum across ALL models — do not use only the first entry.

        IMPORTANT: stats.inputTokenCount does NOT exist in gemini 0.40.1 output.
        The correct path is stats.models.<name>.tokens.input (D-07 CORRECTED).
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
