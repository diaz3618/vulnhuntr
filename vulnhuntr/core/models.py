"""
Core Data Models
================

Domain models for vulnerability analysis.

These models represent the core data structures used throughout
the application for representing vulnerabilities, analysis results,
and context information.
"""

from __future__ import annotations

import logging
from enum import Enum

from pydantic import BaseModel, Field, field_validator

log = logging.getLogger(__name__)


class VulnType(str, Enum):
    """Vulnerability types that Vulnhuntr can detect.

    Each type maps to a CWE (Common Weakness Enumeration) category.
    """

    LFI = "LFI"  # Local File Inclusion (CWE-22)
    RCE = "RCE"  # Remote Code Execution (CWE-78)
    SSRF = "SSRF"  # Server-Side Request Forgery (CWE-918)
    AFO = "AFO"  # Arbitrary File Overwrite (CWE-73)
    SQLI = "SQLI"  # SQL Injection (CWE-89)
    XSS = "XSS"  # Cross-Site Scripting (CWE-79)
    IDOR = "IDOR"  # Insecure Direct Object Reference (CWE-639)


# ---------------------------------------------------------------------------
# MCP tool-call models (used when analysis.mode != "off")
# ---------------------------------------------------------------------------

MAX_TOOL_RESULT_CHARS = 4096  # Truncation limit for tool output fed back to LLM


class MCPToolCallRequest(BaseModel):
    """A single tool call the LLM wants to make via MCP.

    The LLM populates these inside its structured response so the runner can
    execute them on behalf of the analysis agent.
    """

    server: str = Field(description="Name of the MCP server that exposes the tool")
    tool: str = Field(description="Exact tool name to invoke")
    arguments: dict[str, object] = Field(
        default_factory=dict,
        description="Tool arguments as a JSON-serialisable dictionary",
    )
    reason: str = Field(
        default="",
        description="Brief justification for why this tool call aids the analysis",
    )


class MCPToolCallResult(BaseModel):
    """Result of executing a single MCP tool call (populated by the runner)."""

    server: str = Field(description="Server that handled the call")
    tool: str = Field(description="Tool name that was invoked")
    success: bool = Field(description="Whether the call succeeded")
    output: str = Field(default="", description="Truncated tool output (max 4 KiB)")
    error: str | None = Field(default=None, description="Error message, if any")

    def truncated_output(self, max_chars: int = MAX_TOOL_RESULT_CHARS) -> str:
        """Return output truncated to *max_chars* with an ellipsis marker."""
        if len(self.output) <= max_chars:
            return self.output
        return self.output[:max_chars] + "\n... [truncated]"


class ContextCode(BaseModel):
    """Represents a request for additional code context.

    During iterative analysis, the LLM may request more context
    about specific functions or classes to better understand
    the code flow and potential vulnerabilities.
    """

    name: str = Field(description="Function or Class name")
    reason: str = Field(description="Brief reason why this function's code is needed for analysis")
    code_line: str = Field(description="The single line of code where this context object is referenced.")


class Response(BaseModel):
    """LLM analysis response model.

    Represents the structured output from the LLM's vulnerability analysis.
    This model ensures consistent parsing of LLM responses.
    """

    scratchpad: str = Field(
        default="",
        description="Your step-by-step analysis process. Output in plaintext with no line breaks.",
    )
    analysis: str = Field(
        default="",
        description="Your final analysis. Output in plaintext with no line breaks.",
    )
    poc: str | None = Field(
        default=None,
        description="Proof-of-concept exploit, if applicable.",
    )
    confidence_score: int = Field(
        default=0,
        description="0-10, where 0 is no confidence and 10 is absolute certainty "
        "because you have the entire user input to server output code path.",
    )
    vulnerability_types: list[VulnType] = Field(
        default_factory=list,
        description="The types of identified vulnerabilities",
    )

    @field_validator("vulnerability_types", mode="before")
    @classmethod
    def _filter_unknown_vuln_types(cls, v: list[object]) -> list[str]:
        """Filter out unknown vulnerability types instead of failing validation.

        LLMs sometimes return valid-but-unsupported types (e.g., INFO_DISCLOSURE,
        AUTH_BYPASS). Instead of rejecting the entire response, keep only the
        types we support and log a warning for the rest.
        """
        if not isinstance(v, list):
            return v  # let Pydantic handle non-list input
        valid_values = {member.value for member in VulnType}
        kept: list[str] = []
        for item in v:
            raw = str(item).replace("VulnType.", "") if isinstance(item, str) else str(item)
            if raw in valid_values:
                kept.append(raw)
            else:
                log.warning("Ignoring unsupported vulnerability type from LLM: %s", raw)
        return kept

    context_code: list[ContextCode] = Field(
        default_factory=list,
        description="List of context code items requested for analysis, "
        "one function or class name per item. "
        "No standard library or third-party package code.",
    )
    mcp_tool_calls: list[MCPToolCallRequest] = Field(
        default_factory=list,
        description="Optional MCP tool calls the analysis agent wants to make. "
        "Only populated when MCP integration is enabled.",
    )
