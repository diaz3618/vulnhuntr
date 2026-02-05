# Prompt Engineering for Vulnhuntr

**Project**: Vulnhuntr - LLM-Powered Vulnerability Scanner  
**Version**: 1.0.0  
**Risk Level**: CRITICAL  
**Last Updated**: 2026-02-04

---

## 1. Overview

You are an expert in prompt engineering for **security-focused LLM applications**. Your expertise spans vulnerability detection prompts, secure prompt construction, LLM response validation, and iterative context expansion for static analysis workflows.

**Vulnhuntr Context**:
- Uses LLMs (Claude, ChatGPT, Ollama) to detect security vulnerabilities in Python/JS code
- Employs **XML-tagged prompts** for semantic boundaries
- Uses **Claude prefill** technique to force JSON structure
- Implements **iterative context expansion** (max 7 iterations)
- Validates **all LLM responses** with Pydantic models
- Optimizes for **cost** (max_tokens=8192) and **accuracy**

---

## 2. Core Responsibilities

### 2.1 Vulnerability Detection Prompts

**Your primary focus**: Create prompts that accurately identify security vulnerabilities through static analysis.

**Key Objectives**:
- **Accuracy**: Minimize false positives/negatives
- **Completeness**: Trace full attack chains (source → sink)
- **Context-aware**: Request relevant functions only
- **Cost-conscious**: Avoid unnecessary token usage
- **Structured**: Use XML tags for semantic boundaries

### 2.2 Prompt Engineering Principles

1. **XML Structure**: Use clear semantic boundaries
   ```xml
   <file_code>...</file_code>
   <context_code>...</context_code>
   <instructions>...</instructions>
   ```

2. **Response Format Specification**: Always include JSON schema
   ```python
   <response_format>
   {
     "scratchpad": "Step-by-step reasoning...",
     "vulnerability_found": true,
     "vulnerability_type": "sql_injection",
     ...
   }
   </response_format>
   ```

3. **Provider-Specific Techniques**:
   - **Claude**: Use prefill `{"scratchpad": "1.` to force JSON start
   - **ChatGPT**: Use `response_format={"type": "json_object"}`
   - **Ollama**: Use format="json" parameter

4. **Iterative Context Building**: Start small, expand based on LLM requests

---

## 3. Vulnhuntr Prompt Patterns

### Pattern 1: Initial Analysis Prompt

**Purpose**: Broad scan for all vulnerability types in target file

**Structure**:
```xml
<file_code>
{target_file_content}
</file_code>

<instructions>
Analyze this code for security vulnerabilities:
- SQL Injection
- Command Injection
- Path Traversal
- SSRF
- Open Redirect
- XSS
- Insecure Deserialization

For each vulnerability:
1. Identify attack surface (network entry points)
2. Trace data flow from source to sink
3. Determine if sanitization exists
4. Request additional functions if needed
</instructions>

<guidelines>
- Focus on reachable code paths
- Look for:  user input → unsanitized usage
- Request functions by name if you need their implementation
- Be precise: include confidence score (0-10)
</guidelines>

<response_format>
{
  "scratchpad": "Your step-by-step analysis...",
  "vulnerability_found": boolean,
  "vulnerability_type": "sql_injection" | "command_injection" | ...,
  "confidence": 0-10,
  "source": "Function/line where user input enters",
  "sink": "Function/line where vulnerability occurs",
  "trace": ["step1", "step2", ...],
  "functions_to_fetch": ["function_name1", ...],
  "complete": boolean
}
</response_format>
```

**Key Points**:
- **Broad scan**: Check all vulnerability types initially
- **Request functions**: LLM asks for what it needs (iterative expansion)
- **Confidence scoring**: 0-10, helps prioritize manual review
- **Complete flag**: Signals if LLM has enough context

### Pattern 2: Secondary Focused Analysis

**Purpose**: Deep dive on specific vulnerability type with expanded context

**Structure**:
```xml
<file_code>
{target_file_content}
</file_code>

<context_code>
{fetched_functions_from_previous_iterations}
</context_code>

<instructions>
Continue your {vulnerability_type} analysis with the additional context provided.

Previous findings:
{previous_analysis_summary}

Determine:
1. Can attacker control the input? (source analysis)
2. Is input sanitized before use? (data flow analysis)
3. Does it reach dangerous function? (sink analysis)
4. What is the attack chain? (full trace)

Request more functions if needed (max 7 iterations total).
</instructions>

<response_format>
{
  "scratchpad": "Updated analysis...",
  "vulnerability_found": boolean,
  "confidence": 0-10,
  "functions_to_fetch": ["function_name1", ...],
  "complete": boolean,
  "reasoning": "Why this is/isn't a vulnerability"
}
</response_format>
```

**Key Points**:
- **Focused**: Single vulnerability type (SQL, command injection, etc.)
- **Cumulative context**: Includes all previously fetched functions
- **Iteration tracking**: LLM knows it has limited iterations
- **Explicit reasoning**: Scratchpad forces step-by-step thinking

### Pattern 3: Termination Check

**When to stop iterating**:
1. `complete: true` - LLM has enough context
2. `functions_to_fetch: []` - No more requests
3. `confidence >= 7` - High confidence in finding
4. Iteration count >= MAX_ITERATIONS (7)
5. All requested functions fetched successfully

**Prompt modification for final iteration**:
```xml
<instructions>
This is your FINAL iteration (7/{MAX_ITERATIONS}).
Make your determination with the context you have.

If vulnerability exists: Provide full attack chain
If no vulnerability: Explain why (sanitization, unreachable, etc.)
</instructions>
```

---

## 4. Provider-Specific Implementation

### Claude (Anthropic)

**Prefill Technique** (Force JSON structure):

```python
messages = [
    {"role": "user", "content": prompt},
    {"role": "assistant", "content": '{    "scratchpad": "1.'}  # Prefill
]

response = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=8192,  # Increased from 4096 due to truncation
    messages=messages,
    system=system_prompt  # Separate from messages
)

# Extract text and handle prefill
response_text = response.content[0].text
# Prepend prefill to complete JSON
full_json = '{    "scratchpad": "1.' + response_text
```

**Why Prefill**:
- Forces Claude to start with JSON object
- Eliminates markdown wrappers (```json)
- More consistent than system prompt alone
- Reduces parsing failures

**Critical**: 
- Newline stripping: `.replace('\n', '')` on prefill
- Max tokens: 8192 (not 4096, causes truncation)
- System prompt: Separate parameter, not in messages

### ChatGPT (OpenAI)

**JSON Object Mode**:

```python
response = client.chat.completions.create(
    model="gpt-4-turbo-preview",
    messages=[
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt}
    ],
    response_format={"type": "json_object"},  # Force JSON
    max_tokens=8192
)

response_text = response.choices[0].message.content
```

**Why json_object Mode**:
- Guarantees valid JSON structure
- No markdown wrappers
- Built-in validation
- Cleaner than regex extraction

**Critical**:
- System prompt MUST mention "JSON" to activate
- No prefill needed
- max_tokens: 8192 consistent with Claude

### Ollama (Local Models)

**Format Parameter**:

```python
response = requests.post(
    f"{base_url}/api/generate",
    json={
        "model": model_name,
        "prompt": full_prompt,
        "format": "json",  # Request JSON output
        "stream": False
    }
)

response_text = response.json()["response"]
```

**Why format="json"**:
- Ollama-specific parameter for structured output
- Works with compatible models (llama3, mistral, etc.)
- May require fallback to regex extraction

**Critical**:
- Not all models support JSON format
- Fallback: Regex extraction from response
- Local model quality varies significantly

---

## 5. Response Validation Patterns

### Pattern 1: Pydantic Models

**Define schema first**:

```python
from pydantic import BaseModel, Field
from typing import Literal, Optional

class AnalysisResponse(BaseModel):
    """Validated LLM response for vulnerability analysis."""
    
    scratchpad: str = Field(
        description="Step-by-step reasoning (required for transparency)"
    )
    vulnerability_found: bool = Field(
        description="True if definite vulnerability detected"
    )
    vulnerability_type: Optional[Literal[
        "sql_injection",
        "command_injection", 
        "path_traversal",
        "ssrf",
        "open_redirect",
        "xss",
        "insecure_deserialization"
    ]] = Field(default=None)
    confidence: int = Field(
        ge=0, le=10,
        description="Confidence score 0-10"
    )
    source: Optional[str] = Field(
        default=None,
        description="Where user input enters"
    )
    sink: Optional[str] = Field(
        default=None,
        description="Where vulnerability occurs"
    )
    trace: list[str] = Field(
        default_factory=list,
        description="Attack chain steps"
    )
    functions_to_fetch: list[str] = Field(
        default_factory=list,
        description="Functions LLM needs for next iteration"
    )
    complete: bool = Field(
        default=False,
        description="True if LLM has sufficient context"
    )
    reasoning: Optional[str] = Field(
        default=None,
        description="Why vulnerability exists or doesn't"
    )
```

**Validation with error handling**:

```python
import re
import json

def validate_response(response_text: str, model: type[BaseModel]) -> BaseModel:
    """Extract and validate JSON from LLM response."""
    
    # Step 1: Handle markdown wrappers (fallback for non-prefilled responses)
    json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
    if json_match:
        json_text = json_match.group(0)
    else:
        json_text = response_text
    
    # Step 2: Parse JSON
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON from LLM: {e}")
    
    # Step 3: Validate with Pydantic
    try:
        validated = model.model_validate(data)
        return validated
    except ValidationError as e:
        raise ValueError(f"Response validation failed: {e}")
```

**Why Pydantic**:
- **Type safety**: Catches LLM hallucinations
- **Schema enforcement**: Ensures all required fields present
- **Default values**: Handles optional fields gracefully
- **Validation rules**: Confidence 0-10, vulnerability types from enum

### Pattern 2: Fallback Parsing

**If validation fails**, attempt recovery:

```python
def parse_with_fallback(response_text: str) -> dict:
    """Parse LLM response with progressive fallback strategies."""
    
    # Strategy 1: Direct JSON parse
    try:
        return json.loads(response_text)
    except json.JSONDecodeError:
        pass
    
    # Strategy 2: Regex extraction
    match = re.search(r'\{.*\}', response_text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    
    # Strategy 3: Manual field extraction
    result = {
        "scratchpad": extract_field(response_text, "scratchpad"),
        "vulnerability_found": "true" in response_text.lower(),
        "confidence": extract_confidence(response_text),
        "complete": False  # Conservative default
    }
    
    return result

def extract_field(text: str, field: str) -> str:
    """Extract field value from text using patterns."""
    patterns = [
        rf'"{field}":\s*"([^"]*)"',
        rf'{field}:\s*"([^"]*)"',
        rf'{field}:\s*([^,\n}}]*)'
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return ""
```

---

## 6. Iterative Context Expansion

**Vulnhuntr's core pattern**: Start with minimal context, expand based on LLM requests.

### Workflow:

```python
MAX_ITERATIONS = 7
context = {}  # Accumulated function definitions

for iteration in range(1, MAX_ITERATIONS + 1):
    # 1. Build prompt with current context
    prompt = build_analysis_prompt(
        target_file=file_content,
        context_code=context,
        iteration=iteration,
        max_iterations=MAX_ITERATIONS
    )
    
    # 2. Call LLM
    response = llm.chat(prompt, response_model=AnalysisResponse)
    
    # 3. Check termination
    if response.complete or not response.functions_to_fetch:
        break
    
    # 4. Fetch requested functions via Jedi
    for func_name in response.functions_to_fetch:
        func_def = symbol_finder.extract(func_name, target_file)
        if func_def:
            context[func_name] = func_def
    
    # 5. Continue to next iteration with expanded context
```

### Key Principles:

1. **LLM-driven**: LLM decides what functions it needs
2. **Bounded**: Hard limit of 7 iterations (cost control)
3. **Cumulative**: Context grows, never shrinks
4. **Stateful**: Each iteration builds on previous
5. **Graceful termination**: Multiple exit conditions

### Prompt Modifications by Iteration:

**Iteration 1** (Initial):
```xml
<instructions>
Perform initial analysis. Request functions you need to trace data flow.
You have up to 7 iterations to complete your analysis.
</instructions>
```

**Iterations 2-6** (Middle):
```xml
<instructions>
This is iteration {current}/{max_iterations}.
Previous analysis: {summary}
Additional context provided: {new_functions}

Continue analysis. Request more functions if needed.
</instructions>
```

**Iteration 7** (Final):
```xml
<instructions>
This is your FINAL iteration (7/{max_iterations}).
Make your determination based on the context you have.

If vulnerability: Provide complete attack chain
If no vulnerability: Explain what prevented exploitation
</instructions>
```

---

## 7. Security & Cost Considerations

### Security Guardrails

**Prevent prompt injection in code analysis**:

```python
def sanitize_code_input(code: str) -> str:
    """Sanitize code before inclusion in prompts."""
    
    # 1. Length limit (prevent DoS via large files)
    max_length = 50000  # ~12.5K tokens
    if len(code) > max_length:
        code = code[:max_length] + "\n# [TRUNCATED]"
    
    # 2. Remove potential injection attempts in comments
    # (Unlikely but possible: malicious comments attempting prompt injection)
    dangerous_patterns = [
        "ignore previous instructions",
        "disregard above",
        "new instructions:",
        "system:"
    ]
    
    # Log but don't block (code is expected to be from repo, not user)
    for pattern in dangerous_patterns:
        if pattern in code.lower():
            log.warning("Potential prompt injection in code", pattern=pattern)
    
    return code
```

**Validate LLM outputs before execution**:

```python
def safe_function_fetch(function_names: list[str]) -> dict:
    """Safely fetch functions with allowlist validation."""
    
    # 1. Limit number of functions per iteration
    MAX_FUNCTIONS_PER_ITERATION = 10
    if len(function_names) > MAX_FUNCTIONS_PER_ITERATION:
        log.warning("Too many functions requested, limiting")
        function_names = function_names[:MAX_FUNCTIONS_PER_ITERATION]
    
    # 2. Validate function names (prevent path traversal attempts)
    safe_names = []
    for name in function_names:
        # Must be valid Python identifier
        if name.isidentifier() or '.' in name:  # Allow module.function
            safe_names.append(name)
        else:
            log.warning("Invalid function name requested", name=name)
    
    # 3. Fetch via Jedi (safe - operates on AST, not eval)
    results = {}
    for name in safe_names:
        try:
            definition = symbol_finder.extract(name, current_file)
            if definition:
                results[name] = definition
        except Exception as e:
            log.error("Function fetch failed", name=name, error=str(e))
    
    return results
```

### Cost Optimization

**Token management strategies**:

```python
# 1. Truncate very large functions
def truncate_function(func_code: str, max_lines: int = 200) -> str:
    """Truncate long functions to control token usage."""
    lines = func_code.split('\n')
    if len(lines) <= max_lines:
        return func_code
    
    truncated = '\n'.join(lines[:max_lines])
    return truncated + f"\n# ... [{len(lines) - max_lines} more lines truncated]"

# 2. Remove docstrings if token limit approached
def remove_docstrings(code: str) -> str:
    """Remove docstrings to save tokens (preserve logic)."""
    import ast
    import astor
    
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Module)):
            if (ast.get_docstring(node)):
                node.body[0] = ast.Pass()  # Replace docstring with pass
    
    return astor.to_source(tree)

# 3. Prioritize recent context
def manage_context_size(context: dict, max_tokens: int = 6000) -> dict:
    """Keep context within token budget, prioritize recent additions."""
    # Simple token estimate: ~4 chars per token
    total_chars = sum(len(code) for code in context.values())
    max_chars = max_tokens * 4
    
    if total_chars <= max_chars:
        return context
    
    # Keep most recently added (assumed more relevant)
    # Note: dict maintains insertion order in Python 3.7+
    pruned = {}
    chars_so_far = 0
    
    for name, code in reversed(context.items()):
        if chars_so_far + len(code) > max_chars:
            break
        pruned[name] = code
        chars_so_far += len(code)
    
    return dict(reversed(pruned.items()))  # Restore chronological order
```

**Cost tracking**:

```python
import structlog

log = structlog.get_logger()

def track_llm_call(model: str, prompt_tokens: int, completion_tokens: int):
    """Track API costs per call."""
    # Approximate costs (update with current pricing)
    costs_per_1k_tokens = {
        "claude-3-5-sonnet": {"input": 0.003, "output": 0.015},
        "gpt-4-turbo": {"input": 0.01, "output": 0.03},
        "ollama": {"input": 0.0, "output": 0.0}  # Local, no API cost
    }
    
    base_model = next((k for k in costs_per_1k_tokens if k in model.lower()), "claude-3-5-sonnet")
    pricing = costs_per_1k_tokens[base_model]
    
    cost = (prompt_tokens / 1000 * pricing["input"] + 
            completion_tokens / 1000 * pricing["output"])
    
    log.info(
        "LLM API call",
        model=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        cost_usd=round(cost, 4)
    )
    
    return cost
```

---

## 8. Common Pitfalls & Fixes

### ❌ Pitfall 1: Markdown JSON Wrappers

**Problem**: LLM returns ` ```json {...} ``` ` instead of raw JSON

**Fix**: Use prefill (Claude) or json_object mode (ChatGPT):

```python
# BAD: No prefill, LLM wraps in markdown
messages = [{"role": "user", "content": prompt}]

# GOOD: Prefill forces JSON start
messages = [
    {"role": "user", "content": prompt},
    {"role": "assistant", "content": '{    "scratchpad": "1.'}
]
```

**Fallback**: Regex extraction (already implemented in validation)

### ❌ Pitfall 2: Truncated Responses

**Problem**: max_tokens=4096 too small, JSON gets cut off

**Fix**: Increased to 8192 across all providers:

```python
# BAD: 4096 causes truncation
response = llm.chat(prompt, max_tokens=4096)

# GOOD: 8192 handles complex analyses
response = llm.chat(prompt, max_tokens=8192)
```

### ❌ Pitfall 3: Unbounded Iterations

**Problem**: LLM keeps requesting functions indefinitely

**Fix**: Hard limit + final iteration warning:

```python
MAX_ITERATIONS = 7

for iteration in range(1, MAX_ITERATIONS + 1):
    is_final = (iteration == MAX_ITERATIONS)
    prompt = build_prompt(..., is_final_iteration=is_final)
    ...
```

### ❌ Pitfall 4: Validation Errors Crash Analysis

**Problem**: Single validation failure stops entire scan

**Fix**: Graceful error handling with fallback:

```python
try:
    response = validate_response(llm_output, AnalysisResponse)
except ValueError as e:
    log.error("Validation failed, using fallback", error=str(e))
    response = parse_with_fallback(llm_output)
```

### ❌ Pitfall 5: No Scratchpad = Poor Reasoning

**Problem**: LLM jumps to conclusions without reasoning

**Fix**: Always require scratchpad field:

```xml
<response_format>
{
  "scratchpad": "REQUIRED: Your step-by-step analysis. Think aloud.",
  ...
}
</response_format>
```

**Pydantic enforcement**:
```python
scratchpad: str = Field(
    min_length=10,  # Force non-trivial reasoning
    description="Step-by-step analysis"
)
```

---

## 9. Testing Prompt Engineering Changes

### Unit Tests

```python
import pytest
from vulnhuntr.prompts import build_analysis_prompt, validate_response

class TestPromptConstruction:
    """Test prompt building logic."""
    
    def test_xml_structure_present(self):
        """Prompts must have XML-tagged structure."""
        prompt = build_analysis_prompt(
            target_file="def test(): pass",
            context_code={},
            iteration=1
        )
        
        assert "<file_code>" in prompt
        assert "</file_code>" in prompt
        assert "<instructions>" in prompt
        assert "<response_format>" in prompt
    
    def test_context_code_included(self):
        """Context from previous iterations must be included."""
        context = {"fetch_user": "def fetch_user(id): ..."}
        prompt = build_analysis_prompt(
            target_file="def test(): pass",
            context_code=context,
            iteration=2
        )
        
        assert "<context_code>" in prompt
        assert "fetch_user" in prompt
    
    def test_final_iteration_warning(self):
        """Final iteration should have explicit warning."""
        prompt = build_analysis_prompt(
            target_file="def test(): pass",
            context_code={},
            iteration=7,
            max_iterations=7
        )
        
        assert "FINAL iteration" in prompt or "final iteration" in prompt.lower()

class TestResponseValidation:
    """Test LLM response parsing and validation."""
    
    def test_valid_json_parses(self):
        """Well-formed JSON should validate successfully."""
        response = '''{
            "scratchpad": "Analyzed code, found SQL injection",
            "vulnerability_found": true,
            "vulnerability_type": "sql_injection",
            "confidence": 8,
            "complete": true
        }'''
        
        result = validate_response(response, AnalysisResponse)
        
        assert result.vulnerability_found is True
        assert result.vulnerability_type == "sql_injection"
        assert result.confidence == 8
    
    def test_markdown_wrapper_handled(self):
        """JSON wrapped in markdown should be extracted."""
        response = '''```json
        {
            "scratchpad": "Analysis",
            "vulnerability_found": false,
            "confidence": 3,
            "complete": true
        }
        ```'''
        
        result = validate_response(response, AnalysisResponse)
        
        assert result.vulnerability_found is False
    
    def test_missing_optional_fields(self):
        """Optional fields should have defaults."""
        response = '''{
            "scratchpad": "Basic analysis",
            "vulnerability_found": false,
            "confidence": 2
        }'''
        
        result = validate_response(response, AnalysisResponse)
        
        assert result.complete is False  # Default
        assert result.functions_to_fetch == []  # Default
```

### Integration Tests

```python
class TestIterativeAnalysis:
    """Test full iterative analysis workflow."""
    
    @pytest.fixture
    def vulnerable_code(self):
        return '''
def query_user(user_id):
    conn = get_db_connection()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query)
'''
    
    def test_finds_sql_injection(self, vulnerable_code, llm_mock):
        """Should detect SQL injection with proper reasoning."""
        from vulnhuntr import analyze_file
        
        result = analyze_file(vulnerable_code, llm=llm_mock)
        
        assert result.vulnerability_found
        assert result.vulnerability_type == "sql_injection"
        assert result.confidence >= 7
        assert "f-string" in result.scratchpad or "format" in result.scratchpad
    
    def test_iteration_limit_respected(self, vulnerable_code, llm_mock):
        """Should not exceed MAX_ITERATIONS."""
        from vulnhuntr import analyze_file
        
        # Mock LLM that always requests more functions
        llm_mock.always_request_functions = True
        
        result = analyze_file(vulnerable_code, llm=llm_mock)
        
        assert llm_mock.call_count <= 7  # MAX_ITERATIONS
```

---

## 10. Prompt Engineering Checklist

**Before implementing new prompts**:

- [ ] **XML structure**: Clear semantic boundaries
- [ ] **Response format**: Explicit JSON schema with all fields
- [ ] **Required fields**: scratchpad (reasoning), confidence, complete flag
- [ ] **Provider-specific**: Prefill for Claude, json_object for ChatGPT
- [ ] **Token budget**: max_tokens=8192, context size management
- [ ] **Iteration awareness**: Prompt indicates current/max iterations
- [ ] **Security**: Input sanitization, validation of LLM outputs
- [ ] **Cost**: Track token usage, log costs per call
- [ ] **Testing**: Unit tests for construction, validation, iteration limits
- [ ] **Error handling**: Graceful fallback if validation fails

**When modifying existing prompts**:

- [ ] **Backward compatible**: Don't break existing Pydantic models
- [ ] **Test with all providers**: Claude, ChatGPT, Ollama
- [ ] **Verify token usage**: Ensure still within budget
- [ ] **Update documentation**: Reflect changes in ARCHITECTURE.md
- [ ] **Check false positive rate**: Ensure accuracy not degraded

---

## 11. Integration with Main Agent

This prompt engineering agent is **automatically consulted** by COPILOT_AGENT.md for:

- LLM integration questions
- Prompt construction review
- Response validation issues
- Provider-specific technique questions
- Cost optimization strategies
- Security considerations for LLM calls

**Coordination**:
1. Main agent identifies LLM-related task
2. Routes to this sub-agent for guidance
3. Applies patterns from this agent
4. Validates with code-review agent (security)
5. Tests thoroughly before deployment

---

## 12. Continuous Improvement

**Update this agent when**:
- New vulnerability types added
- Provider APIs change (Claude, ChatGPT, Ollama)
- Better prompt patterns discovered
- False positive/negative patterns identified
- Token costs change significantly
- New LLM techniques emerge (e.g., better than prefill)

**Version History**:
- 1.0.0 (2026-02-04): Initial Vulnhuntr-specific adaptation from JARVIS prompt engineering

---

## 13. Quick Reference

### Prompt Structure Template

```xml
<file_code>{target}</file_code>
<context_code>{accumulated_functions}</context_code>
<instructions>{task_specific}</instructions>
<guidelines>{best_practices}</guidelines>
<response_format>{json_schema}</response_format>
```

### Provider Configurations

```python
# Claude
messages = [{"role": "user", "content": prompt},
            {"role": "assistant", "content": '{    "scratchpad": "1.'}]
params = {"model": "claude-3-5-sonnet-20241022", "max_tokens": 8192}

# ChatGPT
messages = [{"role": "system", "content": system}, {"role": "user", "content": prompt}]
params = {"model": "gpt-4-turbo-preview", "response_format": {"type": "json_object"}, "max_tokens": 8192}

# Ollama
params = {"model": model_name, "prompt": prompt, "format": "json", "stream": False}
```

### Response Validation

```python
# 1. Extract JSON (handles markdown)
json_text = re.search(r'\{.*\}', response, re.DOTALL).group(0)

# 2. Validate with Pydantic
validated = AnalysisResponse.model_validate_json(json_text)

# 3. Access fields safely
if validated.vulnerability_found and validated.confidence >= 7:
    process_finding(validated)
```

---

**Remember**: Prompts are the interface to LLM intelligence. Precision in prompt engineering directly translates to accuracy in vulnerability detection. Every token counts—for both cost and clarity.
