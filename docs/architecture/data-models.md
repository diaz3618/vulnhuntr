# Data Models

Pydantic models used for LLM response validation and prompt construction.

## Response

```python
class Response(BaseModel):
    scratchpad: str
    # Step-by-step reasoning, plaintext, no line breaks

    analysis: str
    # Final analysis summary, plaintext, no line breaks

    poc: str
    # Proof-of-concept exploit code

    confidence_score: int
    # 0-10 scale:
    # 0-6: Low confidence, unlikely vulnerability
    # 7: Should be investigated
    # 8-10: High confidence, likely valid vulnerability

    vulnerability_types: List[VulnType]
    # One or more of: LFI, RCE, SSRF, AFO, SQLI, XSS, IDOR

    context_code: List[ContextCode]
    # Additional code the LLM needs to complete analysis
```

## ContextCode

```python
class ContextCode(BaseModel):
    name: str
    # Function or class name to fetch
    # Examples: "validate_input", "AuthHandler", "db.execute"

    reason: str
    # Why this code is needed
    # Example: "Need to verify input sanitization logic"

    code_line: str
    # The line where this symbol is referenced
    # Used by Jedi to locate the exact definition
    # Example: "result = validate_input(user_data)"
```

## CodeDefinition (XML)

```python
class CodeDefinition(BaseXmlModel, tag="code"):
    name: str
    # Actual symbol name found

    context_name_requested: str
    # Original request from LLM (may differ due to resolution)

    file_path: str
    # Absolute path to file containing definition

    source: str
    # Full source code of the function/class
    # Or placeholder text for third-party libraries
```

## VulnType

```python
class VulnType(str, Enum):
    LFI = "LFI"      # Local File Inclusion
    RCE = "RCE"      # Remote Code Execution
    SSRF = "SSRF"    # Server-Side Request Forgery
    AFO = "AFO"      # Arbitrary File Overwrite
    SQLI = "SQLI"    # SQL Injection
    XSS = "XSS"      # Cross-Site Scripting
    IDOR = "IDOR"    # Insecure Direct Object Reference
```
