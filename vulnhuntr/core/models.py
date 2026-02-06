"""
Core Data Models
================

Domain models for vulnerability analysis.

These models represent the core data structures used throughout
the application for representing vulnerabilities, analysis results,
and context information.
"""

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


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


class ContextCode(BaseModel):
    """Represents a request for additional code context.

    During iterative analysis, the LLM may request more context
    about specific functions or classes to better understand
    the code flow and potential vulnerabilities.
    """

    name: str = Field(description="Function or Class name")
    reason: str = Field(
        description="Brief reason why this function's code is needed for analysis"
    )
    code_line: str = Field(
        description="The single line of code where this context object is referenced."
    )


class Response(BaseModel):
    """LLM analysis response model.

    Represents the structured output from the LLM's vulnerability analysis.
    This model ensures consistent parsing of LLM responses.
    """

    scratchpad: str = Field(
        description="Your step-by-step analysis process. Output in plaintext with no line breaks."
    )
    analysis: str = Field(
        description="Your final analysis. Output in plaintext with no line breaks."
    )
    poc: Optional[str] = Field(
        default=None,
        description="Proof-of-concept exploit, if applicable.",
    )
    confidence_score: int = Field(
        description="0-10, where 0 is no confidence and 10 is absolute certainty "
        "because you have the entire user input to server output code path."
    )
    vulnerability_types: List[VulnType] = Field(
        description="The types of identified vulnerabilities"
    )
    context_code: List[ContextCode] = Field(
        description="List of context code items requested for analysis, "
        "one function or class name per item. "
        "No standard library or third-party package code."
    )
