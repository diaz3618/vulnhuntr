"""OpenAI Codex CLI headless adapter for Vulnhuntr.

Verified against codex 0.128.0. Key flags:
  codex exec --json --sandbox <mode> --ask-for-approval never "<prompt>"

JSONL output events:
  {"type":"thread.started","thread_id":"..."}
  {"type":"item.completed","item":{"type":"agent_message","text":"<response>"}}
  {"type":"turn.completed","usage":{"input_tokens":N,"cached_input_tokens":N,"output_tokens":N,"reasoning_output_tokens":N}}

IMPORTANT: Codex CLI does NOT support -p. The prompt is a positional argument
to 'codex exec'. The --json flag produces JSONL (one JSON object per line),
not a single JSON object like Gemini CLI.

D-02 (CONTEXT.md) referenced --approval-mode suggest/auto-edit/full-auto from
the legacy TypeScript CLI. The current Rust CLI (0.95+) uses:
  --sandbox read-only|workspace-write  +  --ask-for-approval never
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


class CodexLLM(CLIProviderLLM):
    """OpenAI Codex CLI headless adapter.

    OPENAI_API_KEY is stripped before subprocess spawn so the binary uses
    its own OAuth auth rather than falling back to API key mode.

    probe() rejects versions before 0.95.0 because the current Rust CLI
    with --sandbox / --ask-for-approval flags requires that minimum version.
    """

    _STRIP_ENV_VARS: ClassVar[tuple[str, ...]] = ("OPENAI_API_KEY",)
    _MIN_VERSION: ClassVar[tuple[int, ...]] = (0, 95, 0)

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
        """Check binary and reject versions older than 0.95.0.

        Uses tuple comparison, not string comparison — "0.128.0" > "0.95.0"
        is False as strings but correct as (0,128,0) > (0,95,0).
        auth_valid stays None; OAuth can only be confirmed on the first real call.
        """
        binary = shutil.which("codex")
        if not binary:
            return CapabilityResult(
                ok=False,
                binary_found=False,
                version=None,
                auth_valid=None,
                diagnostic_message=("Codex CLI binary not found. Install with: npm i -g @openai/codex"),
            )
        try:
            result = self._run_subprocess(["codex", "--version"])
        except Exception as exc:
            return CapabilityResult(
                ok=False,
                binary_found=True,
                version=None,
                auth_valid=None,
                diagnostic_message=f"Failed to run codex --version: {exc}",
            )
        # Accept both 3-part (0.128.0) and 2-part (0.95) version strings.
        match = re.search(r"(\d+\.\d+(?:\.\d+)?)", result.stdout)
        version_str = match.group(1) if match else result.stdout.strip()
        # MUST use tuple comparison — string comparison breaks for "0.128.0" vs "0.95.0".
        # Pad to 3 elements so (0, 95) == (0, 95, 0) instead of being incorrectly
        # treated as less-than (0, 95, 0) by Python's length-aware tuple ordering.
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
                    f"Codex CLI {version_str} too old; "
                    f"--sandbox / --ask-for-approval flags require >= {min_s}. "
                    "Run: npm i -g @openai/codex"
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
        """Build the codex CLI command and return the parsed JSONL event list.

        tool_mode maps to --sandbox flag (current Rust CLI 0.95+):
          "none" / "read-only" → read-only       (safe for scanning)
          "full"               → workspace-write  (auto-approves all tools)

        The prompt is a positional argument — Codex CLI has no -p flag.
        Output is JSONL (newline-delimited JSON), not a single JSON object.
        """
        del max_tokens, response_model

        # Prepend stored system prompt when set so vulnerability-analysis
        # context (instructions + README summary) reaches the model.
        full_prompt = user_prompt
        if self.system_prompt:
            full_prompt = f"{self.system_prompt}\n\n{user_prompt}"

        tool_mode = self._policy.tool_mode if self._policy else "none"
        sandbox_mode = self._policy.sandbox_mode if self._policy else "none"
        if sandbox_mode == "workspace-write":
            sandbox = "workspace-write"
        else:
            # tool_mode="full" also enables workspace-write for backward compatibility
            sandbox = "workspace-write" if tool_mode == "full" else "read-only"

        session_mode = self._policy.session_mode if self._policy else "stateless"
        if session_mode != "stateless":
            log.warning(
                "session_mode not supported by Codex CLI; falling back to stateless",
                requested_session_mode=session_mode,
            )

        # NOTE: full_prompt is the LAST element (positional arg), NOT after -p
        cmd: list[str] = [
            "codex",
            "exec",
            "--json",
            "--sandbox",
            sandbox,
            "--ask-for-approval",
            "never",
            full_prompt,
        ]

        cmd.extend(self._build_mcp_config_args())

        result = self._run_subprocess(cmd)
        stdout = result.stdout.strip()
        if not stdout:
            raise CLIParseError("Codex returned empty stdout")

        # Parse JSONL — one JSON object per line
        events: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                log.debug("codex: skipping non-JSON line", line=line[:200])

        if not events:
            raise CLIParseError(f"Codex returned JSONL with no parseable lines: {stdout[:500]}")

        # Resolve model name from policy overrides
        if self._policy:
            self.model = self._policy.overrides.get("codex", {}).get("model", "codex")
        else:
            self.model = "codex"

        return {"events": events}

    def get_response(self, response: Any) -> str:
        """Extract text from the last item.completed agent_message event."""
        events = response.get("events") or []
        text = None
        for event in events:
            if event.get("type") == "item.completed":
                item = event.get("item") or {}
                if item.get("type") == "agent_message":
                    text = item.get("text")
        if text is None:
            raise CLIParseError("Codex response contained no item.completed/agent_message event")
        return str(text)

    def _extract_usage(self, response: Any) -> LLMUsage:
        """Extract token counts from the turn.completed event."""
        events = response.get("events") or []
        usage: dict[str, Any] = {}
        for event in events:
            if event.get("type") == "turn.completed":
                usage = event.get("usage") or {}
                break
        input_tokens = int(usage.get("input_tokens", 0)) + int(usage.get("cached_input_tokens", 0))
        output_tokens = int(usage.get("output_tokens", 0))
        return LLMUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=self.model or "codex",
        )
