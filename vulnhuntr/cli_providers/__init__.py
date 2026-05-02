"""CLI provider package for Vulnhuntr.

Exports the shared base class, capability probe result, and error taxonomy
used by all CLI-backed LLM providers (Claude Code, Gemini CLI, Codex, Qwen Code).
Individual provider implementations land in Phases 4 and 5.
"""

from vulnhuntr.cli_providers.base import (
    CLIAuthError,
    CLIBinaryNotFoundError,
    CLIParseError,
    CLIProviderLLM,
    CLIRuntimeError,
    CLISandboxError,
    CLITimeoutError,
    CapabilityResult,
)

__all__ = [
    "CLIProviderLLM",
    "CapabilityResult",
    "CLIBinaryNotFoundError",
    "CLIAuthError",
    "CLITimeoutError",
    "CLIParseError",
    "CLISandboxError",
    "CLIRuntimeError",
]
