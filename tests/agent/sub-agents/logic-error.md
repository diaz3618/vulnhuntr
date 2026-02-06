# Logic Error Test Agent - LLM-Based Code Analysis

**Purpose**: Use LLMs directly to detect logic errors, bugs, and code issues in the Vulnhuntr codebase.

**Version**: 1.0.0  
**Last Updated**: 2026-02-06

---

## Overview

This agent is **SEPARATE** from the Deep Test Agent. The key differences:

| Feature | Logic Error Test Agent | Deep Test Agent |
|---------|----------------------|-----------------|
| **Activation** | `LLM_LOGIC_TEST=true` | `DEEP_TEST=true` |
| **CLI Flag** | `--llm-logic-test` | `--deep-test` |
| **Marker** | `@pytest.mark.llm` | `@pytest.mark.deep` |
| **Uses** | LLM APIs directly | MCP tools + AI agents |
| **Focus** | Logic errors, bugs | Code quality, patterns |
| **Tools** | Claude/OpenAI/etc | ruff, pyright, vulture |

---

## Activation Conditions

This agent is activated when:
- `LLM_LOGIC_TEST=true` in `.env.test`
- `--llm-logic-test` CLI flag is passed to pytest
- Test is marked with `@pytest.mark.llm`

---

## How It Works

### 1. Direct LLM Analysis

Unlike the Deep Test Agent which uses MCP tools, this agent sends code directly to LLMs for analysis:

```python
# Example usage in test
@pytest.mark.llm
@pytest.mark.provider("anthropic")
def test_llm_detects_error_handling(llm_client):
    """Use LLM to analyze error handling patterns."""
    code = read_source_file("vulnhuntr/LLMs.py")
    
    prompt = f"""
    Analyze this Python code for logic errors and bugs:
    
    <code>
    {code}
    </code>
    
    Focus on:
    1. Error handling gaps
    2. Edge cases not covered
    3. Race conditions
    4. Resource leaks
    5. Logic flow issues
    
    Return JSON with found issues.
    """
    
    response = llm_client.analyze(prompt)
    # Process and assert on findings
```

### 2. Provider Selection

The agent uses the `PROVIDER` environment variable to select which LLM:

| PROVIDER | LLM Used |
|----------|----------|
| `anthropic` | Claude (default) |
| `openai` | GPT-4 |
| `google` | Gemini |
| `openrouter` | Various models |
| `ollama` | Local models |

### 3. Cost Awareness

**IMPORTANT**: This agent makes REAL LLM API calls that cost money.

- Always estimate costs before running
- Display cost estimate and require user confirmation
- Track actual costs during execution
- Report estimated vs actual in results

---

## Analysis Focus Areas

The Logic Error Test Agent focuses on finding:

### 1. Logic Errors
- Incorrect conditionals
- Off-by-one errors
- Wrong variable usage
- Inverted logic

### 2. Bug Patterns
- Null/None handling
- Uninitialized variables
- Type mismatches
- Silent failures

### 3. Control Flow Issues
- Unreachable code
- Infinite loops
- Missing return statements
- Exception swallowing

### 4. Data Flow Issues
- Unvalidated input
- Data races
- Stale data usage
- Memory leaks

### 5. API Usage Errors
- Incorrect method calls
- Wrong parameter order
- Missing required args
- Deprecated API usage

---

## Test Structure

Tests using this agent should follow this pattern:

```python
import pytest
from tests.conftest import requires_llm_logic_test, requires_provider

@pytest.mark.llm
@requires_llm_logic_test
@requires_provider("anthropic")
class TestLLMLogicAnalysis:
    """Logic error tests using LLM analysis."""
    
    def test_error_handling_completeness(self, llm_client, sample_code):
        """Check if all error paths are handled."""
        findings = llm_client.analyze_error_handling(sample_code)
        assert findings["coverage"] >= 0.8
    
    def test_type_consistency(self, llm_client, sample_code):
        """Check for type mismatches."""
        findings = llm_client.analyze_types(sample_code)
        assert len(findings["mismatches"]) == 0
```

---

## Output Format

```json
{
  "analysis_type": "llm_logic_test",
  "provider": "anthropic",
  "model": "claude-sonnet-4-5",
  "timestamp": "2026-02-06T12:00:00Z",
  "cost": {
    "estimated_usd": 0.05,
    "actual_usd": 0.048,
    "tokens": {
      "input": 5000,
      "output": 1500
    }
  },
  "findings": [
    {
      "file": "vulnhuntr/LLMs.py",
      "line": 45,
      "severity": "high",
      "category": "error_handling",
      "description": "Exception caught but error state not propagated",
      "suggestion": "Re-raise exception or return error indicator",
      "confidence": 0.85
    }
  ],
  "summary": {
    "total_issues": 5,
    "high_severity": 1,
    "medium_severity": 3,
    "low_severity": 1
  }
}
```

---

## Prompts Library

Standard prompts for different analysis types:

### Error Handling Analysis
```xml
<analysis_type>error_handling</analysis_type>
<instructions>
Analyze the code for error handling issues:
1. Uncaught exceptions
2. Empty except blocks
3. Exceptions caught but ignored
4. Missing error propagation
5. Incorrect exception types
</instructions>
<code>{code}</code>
<response_format>JSON with file, line, severity, description</response_format>
```

### Logic Flow Analysis
```xml
<analysis_type>logic_flow</analysis_type>
<instructions>
Analyze the code for logic flow issues:
1. Dead code paths
2. Unreachable conditions
3. Redundant checks
4. Missing edge cases
5. Incorrect boolean logic
</instructions>
<code>{code}</code>
<response_format>JSON with file, line, severity, description</response_format>
```

### Data Handling Analysis
```xml
<analysis_type>data_handling</analysis_type>
<instructions>
Analyze the code for data handling issues:
1. Unvalidated input
2. Type coercion problems
3. Null/None not checked
4. Data corruption risks
5. Boundary violations
</instructions>
<code>{code}</code>
<response_format>JSON with file, line, severity, description</response_format>
```

---

## Configuration

### Environment Variables

```bash
# tests/.env.test
PROVIDER=anthropic                    # Which LLM provider to use
LLM_LOGIC_TEST=true                   # Enable logic error tests
ANTHROPIC_API_KEY=sk-ant-...          # API key for Anthropic
OPENAI_API_KEY=sk-proj-...            # API key for OpenAI
LLM_LOGIC_MAX_COST=5.00               # Maximum cost per test run (USD)
LLM_LOGIC_CONFIRM_COST=true           # Require user confirmation
```

### pytest.ini Options

```ini
[pytest]
markers =
    llm: marks tests as using LLM for logic analysis (deselect with '-m "not llm"')
```

---

## Cost Management

### Before Running Tests

1. Estimate cost based on:
   - Number of files to analyze
   - Average file size (tokens)
   - Selected provider pricing
   - Number of analysis passes

2. Display estimate to user:
   ```
   LLM Logic Test Cost Estimate
   ============================
   Provider: anthropic (claude-sonnet-4-5)
   Files to analyze: 12
   Estimated tokens: ~45,000 input, ~12,000 output
   Estimated cost: $0.25 - $0.40 USD
   
   Proceed with tests? [y/N]:
   ```

3. Only run if user confirms (unless `LLM_LOGIC_CONFIRM_COST=false`)

### During Tests

- Track actual token usage per test
- Abort if exceeding `LLM_LOGIC_MAX_COST`
- Log costs to test results

### After Tests

Include cost summary in report:
```
Cost Summary
============
Estimated: $0.35
Actual: $0.32
Savings: $0.03 (8.6%)
```

---

## Integration with pytest

### Fixtures

```python
@pytest.fixture
def llm_logic_client(request):
    """Create LLM client for logic error analysis."""
    provider = os.getenv("PROVIDER", "anthropic")
    
    if provider == "anthropic":
        return AnthropicLogicClient()
    elif provider == "openai":
        return OpenAILogicClient()
    # etc.
```

### Hooks

```python
def pytest_configure(config):
    """Register llm marker."""
    config.addinivalue_line(
        "markers",
        "llm: mark test as LLM logic analysis"
    )

def pytest_collection_modifyitems(config, items):
    """Skip llm tests if LLM_LOGIC_TEST is not true."""
    if not config.getoption("--llm-logic-test") and not os.getenv("LLM_LOGIC_TEST") == "true":
        skip_llm = pytest.mark.skip(reason="LLM logic tests disabled")
        for item in items:
            if "llm" in item.keywords:
                item.add_marker(skip_llm)
```

---

## Comparison with Deep Test Agent

| Aspect | Logic Error Agent | Deep Test Agent |
|--------|-------------------|-----------------|
| **Primary Tool** | LLM APIs | MCP tools |
| **Cost** | $$ (API calls) | $ (local tools) |
| **Speed** | Slower (API latency) | Faster (local) |
| **Accuracy** | High (semantic) | Medium (syntactic) |
| **Coverage** | Bugs, logic | Style, patterns |
| **Determinism** | Non-deterministic | Deterministic |

**Use Logic Error Agent when:**
- You need semantic understanding
- Looking for complex logic bugs
- Analyzing error handling patterns
- Checking business logic

**Use Deep Test Agent when:**
- You need consistent results
- Checking code style
- Running type analysis
- Detecting dead code

---

## Best Practices

1. **Isolate LLM tests**: Group them in separate files (`test_llm_*.py`)
2. **Use specific providers**: Mark tests with `@requires_provider("anthropic")`
3. **Track costs**: Always check cost summary after runs
4. **Cache responses**: Use response caching for repeated analyses
5. **Mock in CI**: Mock LLM calls in CI pipelines to avoid costs
6. **Set limits**: Configure `LLM_LOGIC_MAX_COST` appropriately

---

## Version History

- **1.0.0** (2026-02-06): Initial creation, separated from Deep Test Agent
