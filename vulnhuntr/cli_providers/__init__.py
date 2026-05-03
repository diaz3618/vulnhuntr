"""CLI provider package for Vulnhuntr.

Exports the shared base class, capability probe result, error taxonomy,
and concrete provider implementations for all CLI-backed LLM providers.
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
from vulnhuntr.cli_providers.gemini_cli import GeminiCLILLM

__all__ = [
    "CLIProviderLLM",
    "CapabilityResult",
    "CLIBinaryNotFoundError",
    "CLIAuthError",
    "CLITimeoutError",
    "CLIParseError",
    "CLISandboxError",
    "CLIRuntimeError",
    "GeminiCLILLM",
]
