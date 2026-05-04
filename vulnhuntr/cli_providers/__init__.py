"""CLI provider package for Vulnhuntr.

Exports the shared base class, capability probe result, error taxonomy,
and concrete provider implementations for all CLI-backed LLM providers.
"""

from vulnhuntr.cli_providers.base import (
    CapabilityResult,
    CLIAuthError,
    CLIBinaryNotFoundError,
    CLIParseError,
    CLIProviderLLM,
    CLIRuntimeError,
    CLISandboxError,
    CLITimeoutError,
)
from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM
from vulnhuntr.cli_providers.codex import CodexLLM
from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM
from vulnhuntr.cli_providers.qwen_code import QwenCodeLLM

__all__ = [
    "CLIProviderLLM",
    "CapabilityResult",
    "CLIBinaryNotFoundError",
    "CLIAuthError",
    "CLITimeoutError",
    "CLIParseError",
    "CLISandboxError",
    "CLIRuntimeError",
    "ClaudeCodeLLM",
    "GeminiCLILLM",
    "CodexLLM",
    "QwenCodeLLM",
]
