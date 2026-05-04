"""Base class and error taxonomy for CLI-backed LLM providers.

Claude Code, Gemini CLI, Codex, Qwen Code all subclass CLIProviderLLM and
implement probe(), get_response(), and _extract_usage(). Subprocess transport,
timeout, env-stripping, and cost tracking live here.
"""

from __future__ import annotations

import os
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import structlog

from vulnhuntr.core.models import LLMUsage
from vulnhuntr.llms import LLM, LLMError

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class CLIBinaryNotFoundError(LLMError):
    """Required CLI binary is not installed or not on PATH."""


class CLIAuthError(LLMError):
    """CLI provider authentication failed or credentials are missing."""


class CLITimeoutError(LLMError):
    """CLI provider subprocess exceeded the configured timeout."""


class CLIParseError(LLMError):
    """CLI provider returned output that could not be parsed."""


class CLISandboxError(LLMError):
    """CLI provider rejected the request due to sandbox policy."""


class CLIRuntimeError(LLMError):
    """CLI provider subprocess exited with a non-zero status for an unclassified reason."""


# ---------------------------------------------------------------------------
# Capability probe result
# ---------------------------------------------------------------------------


@dataclass
class CapabilityResult:
    """Result of a pre-scan capability probe.

    Attributes:
        ok: True when the provider is ready to accept requests.
        binary_found: True when the required binary exists on PATH.
        version: Version string reported by the binary, or None if unavailable.
        auth_valid: True/False when auth can be checked statically; None otherwise.
        diagnostic_message: Human-readable explanation for operators when ok is False.
    """

    ok: bool
    binary_found: bool
    version: str | None
    auth_valid: bool | None
    diagnostic_message: str


# ---------------------------------------------------------------------------
# Shared CLI provider base class
# ---------------------------------------------------------------------------


class CLIProviderLLM(LLM, ABC):
    """Base class for CLI-backed LLM providers.

    Subclasses implement probe(), get_response(), send_message(), and
    _extract_usage(). The chat() method here handles subprocess dispatch,
    timeout, env-stripping, and cost tracking.
    """

    # Provider-specific keys to strip before spawning the subprocess.
    _STRIP_ENV_VARS: tuple[str, ...] = ()

    def __init__(
        self,
        system_prompt: str = "",
        cost_callback: Any | None = None,
        timeout: int = 300,
        workdir: str | None = None,
    ) -> None:
        super().__init__(system_prompt, cost_callback)
        self.timeout = timeout
        self.workdir = workdir
        self.session_id: str | None = None
        self._last_probe_version: str | None = None

    @abstractmethod
    def probe(self) -> CapabilityResult:
        """Check binary availability and auth before the scan starts."""

    @abstractmethod
    def get_response(self, response: Any) -> str:
        """Extract plain text from the provider's response envelope."""

    @abstractmethod
    def send_message(
        self,
        user_prompt: str,
        max_tokens: int,
        response_model: Any = None,
    ) -> dict[str, Any]:
        """Build and execute the provider subprocess command."""

    @abstractmethod
    def _extract_usage(self, response: Any) -> LLMUsage:
        """Extract token usage from the provider response envelope."""

    def _build_env(self) -> dict[str, str]:
        """Return os.environ copy with _STRIP_ENV_VARS removed."""
        env = os.environ.copy()
        for var in self._STRIP_ENV_VARS:
            env.pop(var, None)
        return env

    def _run_subprocess(
        self,
        cmd: list[str],
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run cmd with shell=False, capturing stdout/stderr.

        Raises CLIBinaryNotFoundError, CLITimeoutError, or CLIRuntimeError.
        """
        stdin_mode = subprocess.PIPE if input_text is not None else subprocess.DEVNULL
        env = self._build_env()

        log.debug("Spawning CLI provider subprocess", cmd=cmd[0], args=cmd[1:])

        try:
            result = subprocess.run(
                cmd,
                input=input_text,
                stdin=stdin_mode,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env,
                shell=False,
                cwd=self.workdir if self.workdir else None,
            )
        except FileNotFoundError as exc:
            raise CLIBinaryNotFoundError(
                f"CLI binary not found: {cmd[0]!r}. Ensure it is installed and available on PATH."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise CLITimeoutError(f"CLI provider subprocess timed out after {self.timeout}s: {cmd[0]!r}") from exc

        if result.returncode != 0:
            log.warning(
                "CLI provider subprocess exited with non-zero status",
                cmd=cmd[0],
                returncode=result.returncode,
                stderr=result.stderr[:500],
            )
            raise CLIRuntimeError(
                f"CLI provider {cmd[0]!r} exited with status {result.returncode}. stderr: {result.stderr[:200]}"
            )

        return result

    def get_session_metadata(self) -> dict[str, Any] | None:
        """Return session metadata after a send_message() call, or None if no session."""
        if not self.session_id:
            return None
        return {
            "provider": self.__class__.__name__,
            "session_id": self.session_id,
            "started_at": datetime.utcnow().isoformat(),
            "workdir": self.workdir,
            "binary_version": self._last_probe_version,
        }

    def _build_mcp_config_args(self) -> list[str]:
        """Return extra CLI args for MCP config injection, or [] if not applicable.

        Subclasses with --mcp-config support override this. The default logs a
        warning when mcp_mode is non-none and returns [] so scans continue safely.
        """
        policy = getattr(self, "_policy", None)
        if not policy:
            return []
        mcp_mode = getattr(policy, "mcp_mode", "none")
        if mcp_mode != "none":
            log.warning(
                "mcp_mode requested but provider does not implement MCP config injection; "
                "continuing with mcp_mode='none' behavior",
                provider=self.__class__.__name__,
                mcp_mode=mcp_mode,
            )
        return []

    def chat(
        self,
        user_prompt: str,
        response_model: Any | None = None,
        max_tokens: int = 8192,
    ) -> Any:
        """Send a prompt and return a validated response.

        Wires send_message() → _log_response() → get_response() →
        _validate_response(). Do not override in subclasses.
        """
        self._add_to_history("user", user_prompt)

        response = self.send_message(user_prompt, max_tokens, response_model)
        self._log_response(response)

        response_text = self.get_response(response)
        if response_model:
            response_text = self._validate_response(response_text, response_model)

        self._add_to_history("assistant", str(response_text))
        return response_text

    def create_messages(self, user_prompt: str) -> Any:
        raise NotImplementedError("CLI providers use send_message(), not create_messages()")
