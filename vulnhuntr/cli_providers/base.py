"""Shared base class and error taxonomy for CLI-backed LLM providers.

All CLI providers (Claude Code, Gemini CLI, Codex, Qwen Code) subclass
``CLIProviderLLM`` and implement the three abstract methods:
- ``probe()`` — check binary availability and auth before the scan starts
- ``get_response()`` — extract plain text from the provider's JSON envelope
- ``_extract_usage()`` — pull token counts from the provider's response object

The subprocess transport, timeout enforcement, env-stripping, and cost
tracking wiring live here so individual providers stay thin.
"""

from __future__ import annotations

import os
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
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
    """Intermediate base class for CLI-backed LLM providers.

    Subclasses must implement:
    - ``probe()`` — return a ``CapabilityResult`` before the scan starts
    - ``get_response(response)`` — extract plain text from the provider envelope
    - ``_extract_usage(response)`` — return an ``LLMUsage`` with token counts

    The ``chat()`` override here handles subprocess dispatch, timeout, env
    stripping, and cost tracking so individual providers only need to deal
    with their own JSON envelope format.
    """

    #: Environment variables stripped before spawning the subprocess.
    #: Subclasses may extend this list to strip provider-specific keys.
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

    # ------------------------------------------------------------------
    # Abstract interface — implemented per provider in Phases 4/5
    # ------------------------------------------------------------------

    @abstractmethod
    def probe(self) -> CapabilityResult:
        """Check binary availability and auth before the scan starts.

        Returns:
            CapabilityResult with ok=True when the provider is ready.
        """

    @abstractmethod
    def get_response(self, response: Any) -> str:
        """Extract plain text from the provider's response envelope.

        Args:
            response: Raw object returned by ``_run_subprocess``.

        Returns:
            Plain text content of the provider's reply.
        """

    @abstractmethod
    def send_message(
        self,
        user_prompt: str,
        max_tokens: int,
        response_model: Any = None,
    ) -> dict[str, Any]:
        """Build and execute the provider subprocess command.

        Args:
            user_prompt: The user message to send.
            max_tokens: Token budget hint for the provider.
            response_model: Optional Pydantic model hint (may be unused).

        Returns:
            Raw provider response dict for downstream parsing.
        """

    @abstractmethod
    def _extract_usage(self, response: Any) -> LLMUsage:
        """Extract token usage from the provider response envelope.

        Args:
            response: Raw provider response dict.

        Returns:
            LLMUsage with input_tokens, output_tokens, and model name.
        """

    # ------------------------------------------------------------------
    # Subprocess transport
    # ------------------------------------------------------------------

    def _build_env(self) -> dict[str, str]:
        """Build the subprocess environment with sensitive vars stripped."""
        env = os.environ.copy()
        for var in self._STRIP_ENV_VARS:
            env.pop(var, None)
        return env

    def _run_subprocess(
        self,
        cmd: list[str],
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run a CLI command and return the completed process.

        Always uses list-form ``subprocess.run()`` with ``shell=False`` and
        ``stdin=subprocess.DEVNULL`` (or a pipe when ``input_text`` is given)
        to prevent shell injection.

        Args:
            cmd: Command and arguments as a list — never a shell string.
            input_text: Optional text to pipe to the process stdin.

        Returns:
            ``subprocess.CompletedProcess`` with stdout/stderr captured.

        Raises:
            CLIBinaryNotFoundError: When the binary is not found.
            CLITimeoutError: When the process exceeds ``self.timeout``.
            CLIRuntimeError: When the process exits with a non-zero status.
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

    # ------------------------------------------------------------------
    # chat() override — wires subprocess + cost tracking
    # ------------------------------------------------------------------

    def chat(
        self,
        user_prompt: str,
        response_model: Any | None = None,
        max_tokens: int = 8192,
    ) -> Any:
        """Send a prompt to the CLI provider and return a validated response.

        Calls ``get_response()`` to extract text from the provider envelope,
        then feeds it into the inherited ``_validate_response()`` path for
        Pydantic validation. Calls ``_log_response()`` for cost tracking.

        Args:
            user_prompt: The user message to send.
            response_model: Optional Pydantic model to validate the response.
            max_tokens: Hint passed to the provider (interpretation varies).

        Returns:
            Validated Pydantic model instance, or raw string when no model given.
        """
        self._add_to_history("user", user_prompt)

        # Subclasses implement the actual subprocess call via send_message
        response = self.send_message(user_prompt, max_tokens, response_model)
        self._log_response(response)

        response_text = self.get_response(response)
        if response_model:
            response_text = self._validate_response(response_text, response_model)

        self._add_to_history("assistant", str(response_text))
        return response_text

    def create_messages(self, user_prompt: str) -> Any:
        """Not used by CLI providers — subprocess handles message formatting."""
        raise NotImplementedError(
            "CLIProviderLLM does not use create_messages(). "
            "Override send_message() to build the subprocess command instead."
        )
