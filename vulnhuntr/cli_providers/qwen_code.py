"""Qwen Code CLI headless adapter for Vulnhuntr.

Verified against qwen 0.15.6. Key flags:
  qwen -p <prompt> --output-format json [--approval-mode plan | --yolo]

JSON array output (buffered at end, NOT streaming):
  [
    {"type":"system","subtype":"session_start","model":"qwen3-coder-plus",...},
    {"type":"assistant","message":{"content":[{"type":"text","text":"..."}],"usage":{...}},...},
    {"type":"result","subtype":"success","result":"<resp>","usage":{...},...}
  ]

Bridge mode: set CLIPolicy.overrides["qwen-code"]["base_url"] to inject
OPENAI_BASE_URL in the subprocess env (for OpenRouter, Ollama, Azure, etc.).
In bridge mode, OPENAI_API_KEY must NOT be stripped.

Qwen OAuth was discontinued April 15, 2026. Auth is now via DASHSCOPE_API_KEY
or BAILIAN_CODING_PLAN_API_KEY (direct Qwen) or OPENAI_API_KEY (bridge mode).
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


class QwenCodeLLM(CLIProviderLLM):
    """Qwen Code CLI headless adapter.

    DASHSCOPE_API_KEY and BAILIAN_CODING_PLAN_API_KEY are stripped before
    subprocess spawn to prevent direct-Qwen API key auth from leaking into
    the CLI subprocess. OPENAI_API_KEY is intentionally NOT stripped — it is
    required for bridge mode (OpenRouter, Ollama, Azure, etc.).

    probe() accepts any version >= 0.1.0 (JSON output available from v0.1).
    """

    # NOTE: OPENAI_API_KEY is intentionally absent — needed for bridge mode (D-09)
    _STRIP_ENV_VARS: ClassVar[tuple[str, ...]] = (
        "DASHSCOPE_API_KEY",
        "BAILIAN_CODING_PLAN_API_KEY",
    )
    _MIN_VERSION: ClassVar[tuple[int, ...]] = (0, 1, 0)

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
        """Strip class-level vars, operator-supplied vars, then inject bridge URL."""
        env = super()._build_env()
        for var in self._policy.strip_env_vars if self._policy else []:
            env.pop(var, None)
        # Bridge mode: inject OPENAI_BASE_URL when operator has configured a base_url
        if self._policy:
            qwen_overrides = self._policy.overrides.get("qwen-code", {})
            base_url = qwen_overrides.get("base_url")
            if base_url:
                env["OPENAI_BASE_URL"] = str(base_url)
        return env

    def _do_probe(self) -> CapabilityResult:
        """Check binary availability and reject versions older than 0.1.0.

        Uses tuple comparison, not string comparison.
        auth_valid stays None; auth can only be confirmed on the first real call.
        """
        binary = shutil.which("qwen")
        if not binary:
            return CapabilityResult(
                ok=False,
                binary_found=False,
                version=None,
                auth_valid=None,
                diagnostic_message=("Qwen Code binary not found. Install with: npm i -g @qwen-code/qwen-code"),
            )
        try:
            result = self._run_subprocess(["qwen", "--version"])
        except Exception as exc:
            return CapabilityResult(
                ok=False,
                binary_found=True,
                version=None,
                auth_valid=None,
                diagnostic_message=f"Failed to run qwen --version: {exc}",
            )
        # Accept both 3-part (0.15.6) and 2-part (0.1) version strings.
        match = re.search(r"(\d+\.\d+(?:\.\d+)?)", result.stdout)
        version_str = match.group(1) if match else result.stdout.strip()
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
                    f"Qwen Code {version_str} too old; "
                    f"--output-format json requires >= {min_s}. "
                    "Run: npm i -g @qwen-code/qwen-code"
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
        """Build the qwen CLI command and return the parsed JSON array payload.

        tool_mode maps to approval mode:
          "none" / "read-only" → --approval-mode plan  (read-only, analysis only)
          "full"               → --yolo                 (auto-approve all tools)
        """
        del max_tokens, response_model

        # Prepend stored system prompt when set so vulnerability-analysis
        # context (instructions + README summary) reaches the model.
        full_prompt = user_prompt
        if self.system_prompt:
            full_prompt = f"{self.system_prompt}\n\n{user_prompt}"

        tool_mode = self._policy.tool_mode if self._policy else "none"

        session_mode = self._policy.session_mode if self._policy else "stateless"
        if session_mode != "stateless":
            log.warning(
                "session_mode not supported by Qwen Code; falling back to stateless",
                requested_session_mode=session_mode,
            )

        cmd: list[str] = [
            "qwen",
            "-p",
            full_prompt,
            "--output-format",
            "json",
        ]
        if tool_mode == "full":
            cmd.append("--yolo")
        else:
            cmd.extend(["--approval-mode", "plan"])

        cmd.extend(self._build_mcp_config_args())

        result = self._run_subprocess(cmd)
        stdout = result.stdout.strip()
        if not stdout:
            raise CLIParseError("Qwen Code returned empty stdout")

        try:
            messages = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise CLIParseError(f"Qwen Code returned invalid JSON: {stdout[:500]}") from exc

        if not isinstance(messages, list):
            raise CLIParseError(f"Qwen Code JSON output was not an array: {type(messages)}")

        # Extract model name from the system entry
        system_entry = next((m for m in messages if m.get("type") == "system"), {})
        self.model = system_entry.get("model", "qwen-code")

        return {"messages": messages}

    def get_response(self, response: Any) -> str:
        """Extract text from the result entry (type=='result', subtype=='success')."""
        messages = response.get("messages") or []
        result_entry = next((m for m in messages if m.get("type") == "result"), None)
        if result_entry is None:
            raise CLIParseError("Qwen Code JSON array contained no 'result' entry")
        if result_entry.get("is_error"):
            raise CLIParseError(f"Qwen Code returned an error result: {result_entry.get('result', '')[:200]}")
        text = result_entry.get("result")
        if text is None:
            raise CLIParseError("Qwen Code 'result' entry missing 'result' field")
        return str(text)

    def _extract_usage(self, response: Any) -> LLMUsage:
        """Extract token counts from the result entry's usage dict.

        Falls back to the assistant entry's usage if result entry has no tokens.
        """
        messages = response.get("messages") or []
        result_entry = next((m for m in messages if m.get("type") == "result"), None)
        usage: dict[str, Any] = {}
        if result_entry:
            usage = result_entry.get("usage") or {}
        input_tokens = int(usage.get("input_tokens", 0))
        output_tokens = int(usage.get("output_tokens", 0))

        # Fallback: check assistant entry if result entry had no token data
        if input_tokens == 0 and output_tokens == 0:
            assistant_entry = next((m for m in messages if m.get("type") == "assistant"), None)
            if assistant_entry:
                asst_usage = (assistant_entry.get("message") or {}).get("usage") or {}
                input_tokens = int(asst_usage.get("input_tokens", 0))
                output_tokens = int(asst_usage.get("output_tokens", 0))

        return LLMUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=self.model or "qwen-code",
        )
