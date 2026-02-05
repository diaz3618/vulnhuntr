---
name: vulnhuntr-code-review
description: Specialized code review for Vulnhuntr security scanner. Focuses on Python security, LLM integration patterns, static analysis correctness, and vulnerability detection accuracy. Adapted for VS Code GitHub Copilot.
project: vulnhuntr
version: 1.0.0
last_updated: 2026-02-04
---

# Vulnhuntr Code Review Agent

**Purpose**: Ensure code quality, security, and correctness for Vulnhuntr's security-critical codebase.

**Activation**: Automatically used by GitHub Copilot during code changes and PR reviews.

---

## Review Categories (Vulnhuntr-Specific)

### 1. Security Review (CRITICAL - This is a Security Tool)

**Primary Concerns**:
- Prompt injection in LLM interactions
- API key leakage in logs/output
- Command injection via subprocess calls
- Path traversal in file operations
- Unsafe deserialization of LLM responses
- Third-party dependency vulnerabilities

**Check for**:
- Hardcoded secrets in code (API keys, tokens)
- User input validation (file paths, command args)
- Secure defaults (fail closed, not open)
- Principle of least privilege
- Defense in depth (multiple layers)
- Input sanitization before LLM prompts
- Sensitive data redaction in logs
- Secure file operations (no path traversal)

**Common Patterns to Flag**:

```python
# BAD: Hardcoded API key
client = anthropic.Anthropic(api_key="sk-ant-api03-...")

# GOOD: Environment variable
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


# BAD: Unsanitized user input in LLM prompt
prompt = f"Analyze this file: {user_provided_path}"

# GOOD: Validate and sanitize
if not Path(user_provided_path).resolve().is_relative_to(repo_root):
    raise ValueError("Path traversal detected")
prompt = f"Analyze this file: {safe_path}"


# BAD: Logging API keys
log.info(f"Using key: {api_key}")

# GOOD: Mask sensitive data
log.info(f"Using key: {api_key[:8]}...{api_key[-4:]}")


# BAD: Direct eval() of LLM response
result = eval(llm_response)

# GOOD: Safe JSON parsing with validation
result = json.loads(llm_response)
validated = Response.model_validate(result)
```

### 2. LLM Integration Review (CRITICAL - Core Functionality)

**Vulnhuntr uses LLMs extensively** - review for:
- Proper prompt structure (XML tags, clear delimiters)
- Response validation (Pydantic models)
- Error handling for API failures
- Token limit management
- Cost optimization
- Retry logic for transient failures
- JSON extraction (handles markdown wrappers)

**Check for**:
- Missing response validation
- Incorrect max_tokens settings
- No error handling for API calls
- Prompt injection vulnerabilities
- Missing prefill for Claude
- Missing json_object mode for ChatGPT
- Unhandled validation errors

**Common Patterns to Flag**:

```python
# BAD: No response validation
response = llm.chat(prompt)
data = json.loads(response)  # May fail, no schema validation

# GOOD: Pydantic validation
response = llm.chat(prompt, response_model=Response, max_tokens=8192)
# Returns validated Response object or raises ValidationError


# BAD: Missing JSON extraction
result = Response.model_validate_json(llm_response)

# GOOD: Handle markdown wrappers
import re
match = re.search(r'\{.*\}', llm_response, re.DOTALL)
json_text = match.group(0) if match else llm_response
result = Response.model_validate_json(json_text)


# BAD: No error handling
response = client.chat.completions.create(...)

# GOOD: Handle all error types
try:
    response = client.chat.completions.create(...)
except openai.APIConnectionError as e:
    raise APIConnectionError("Server unreachable") from e
except openai.RateLimitError as e:
    raise RateLimitError("Rate limit exceeded") from e
except openai.APIStatusError as e:
    raise APIStatusError(e.status_code, e.response) from e


# BAD: Hardcoded max_tokens (may truncate)
response = llm.chat(prompt, max_tokens=1024)

# GOOD: Use project standard
response = llm.chat(prompt, max_tokens=8192)  # Increased for complex analyses
```

### 3. Python Standards Review

**Vulnhuntr requires Python 3.10-3.13** - review for:
- Type hints on all public functions
- Proper exception handling (no bare except)
- Docstrings for public APIs
- PEP 8 compliance
- No mutable default arguments
- Proper use of pathlib.Path (not strings)
- Compatible with Python 3.10-3.13

**Check for**:
- Missing type hints
- Using removed/deprecated features
- Python 3.14+ features
- Python < 3.10 compatibility issues
- String paths instead of Path objects

**Common Patterns to Flag**:

```python
# BAD: No type hints
def extract_symbol(name, file):
    return symbol_dict

# GOOD: Full type hints
def extract_symbol(name: str, file: Path) -> Dict[str, Any]:
    return symbol_dict


# BAD: Bare except
try:
    result = dangerous_operation()
except:
    pass

# GOOD: Specific exceptions
try:
    result = dangerous_operation()
except (ValueError, KeyError) as e:
    log.error("Operation failed", error=str(e))
    raise


# BAD: Mutable default argument
def analyze(files: List[str] = []):
    files.append(new_file)

# GOOD: Use None and create new list
def analyze(files: Optional[List[str]] = None):
    files = files if files is not None else []
    files.append(new_file)


# BAD: String paths
file_path = "/path/to/file.py"
if os.path.exists(file_path):
    with open(file_path) as f:

# GOOD: pathlib.Path
file_path = Path("/path/to/file.py")
if file_path.exists():
    with file_path.open() as f:
```

### 4. Jedi Integration Review (CRITICAL - Symbol Resolution)

**Jedi/Parso integration is core** - review for:
- Correct Jedi API usage
- Proper error handling for Jedi failures
- Three-tier search pattern
- Edge case handling
- Third-party library handling
- Performance considerations

**Check for**:
- Missing error handling for Jedi operations
- Incorrect Jedi API calls
- Not excluding irrelevant files
- Missing fallback strategies
- Memory leaks in large repos

**Common Patterns to Flag**:

```python
# BAD: No error handling for Jedi
symbol = script.search(name)[0]
definition = symbol.infer()[0]

# GOOD: Handle Jedi failures
try:
    results = script.search(name)
    if not results:
        return None
    for symbol in results:
        definitions = symbol.infer()
        if definitions:
            return definitions[0]
except Exception as e:
    log.warning("Jedi resolution failed", symbol=name, error=str(e))
    return None


# BAD: Not excluding third-party code
def _should_exclude(self, path: str) -> bool:
    return False

# GOOD: Exclude vendored code
def _should_exclude(self, path: str) -> bool:
    excluded = ['/test', '/site-packages', '.venv', '/dist']
    return any(excl in path for excl in excluded)


# BAD: Single search strategy
match = script.search(symbol_name)

# GOOD: Three-tier strategy
match = self.file_search(symbol_name, scripts)
if not match:
    match = self.project_search(symbol_name)
if not match:
    match = self.all_names_search(symbol_name, ...)
```

### 5. Performance Review

**LLM API costs are significant** - review for:
- Unnecessary LLM calls
- Token optimization
- Caching opportunities
- Parallel processing potential
- Memory efficiency
- File I/O optimization

**Check for**:
- Redundant API calls
- Large context windows (>8K tokens)
- Missing caching
- Sequential when parallel possible
- Loading entire files into memory
- Inefficient string operations

**Common Patterns to Flag**:

```python
# BAD: Repeated LLM calls for same content
for file in files:
    analysis1 = llm.analyze(file)
    analysis2 = llm.analyze(file)  # Duplicate!

# GOOD: Cache and reuse
analysis_cache = {}
for file in files:
    if file not in analysis_cache:
        analysis_cache[file] = llm.analyze(file)
    analysis = analysis_cache[file]


# BAD: Sending entire large file
with open(huge_file) as f:
    content = f.read()  # 100K+ lines
    llm.analyze(content)

# GOOD: Chunk or extract relevant sections
relevant_sections = extract_network_handlers(huge_file)
llm.analyze(relevant_sections)


# BAD: Sequential file analysis
for file in files:
    result = analyze_file(file)
    results.append(result)

# GOOD: Could be parallelized (future improvement)
# NOTE: Current implementation is sequential to manage costs
# Consider parallel processing in future with cost controls
```

### 6. Testing Review

**Vulnhuntr lacks formal tests** - when adding tests:
- Test critical paths (LLM integration, symbol resolution)
- Mock external dependencies (LLM APIs)
- Test error handling
- Test edge cases
- Performance benchmarks
- Integration tests with real code

**Check for**:
- Tests that don't actually test behavior
- Missing edge case coverage
- Unmocked external APIs (will hit real APIs!)
- Flaky tests
- Missing assertions

**Common Patterns to Flag**:

```python
# BAD: No mocking, hits real API
def test_llm_analysis():
    llm = Claude(...)  # Will call real API!
    result = llm.chat("test prompt")
    assert result

# GOOD: Mock external dependencies
@patch('vulnhuntr.LLMs.anthropic.Anthropic')
def test_llm_analysis(mock_anthropic):
    mock_client = Mock()
    mock_anthropic.return_value = mock_client
    mock_client.messages.create.return_value = Mock(
        content=[Mock(text='{"scratchpad": "test"}')]
    )
    llm = Claude(...)
    result = llm.chat("test prompt")
    assert result.scratchpad == "test"


# BAD: Test doesn't test anything
def test_extract_symbol():
    result = extractor.extract("test", "line", [])
    assert result  # What does this actually test?

# GOOD: Test specific behavior
def test_extract_symbol_returns_definition():
    result = extractor.extract("my_function", "my_function()", test_files)
    assert result['name'] == 'my_function'
    assert 'def my_function' in result['source']
    assert result['file_path'].endswith('.py')
```

---

## Review Output Format

```markdown
## 🔍 Vulnhuntr Code Review

### 🔴 Critical Issues (Must Fix Before Merge)

**Security**:
- **[file.py:42]** API key hardcoded in source
  - **Why:** Exposes credentials in version control
  - **Fix:** Use `os.getenv("ANTHROPIC_API_KEY")` instead
  - **Impact:** HIGH - Credential leakage

**LLM Integration**:
- **[LLMs.py:156]** No response validation
  - **Why:** LLM may return malformed JSON causing crashes
  - **Fix:** Add Pydantic validation: `Response.model_validate_json(text)`
  - **Impact:** HIGH - Production crashes

### 🟡 Important Issues (Should Fix)

**Performance**:
- **[__main__.py:234]** Sequential file processing
  - **Why:** Slow on large repositories
  - **Suggestion:** Consider parallel processing with cost controls
  - **Impact:** MEDIUM - User experience

**Code Quality**:
- **[symbol_finder.py:89]** Missing type hints
  - **Why:** Reduces IDE support and type safety
  - **Fix:** Add types: `def extract(name: str, ...) -> Dict[str, Any]:`
  - **Impact:** LOW - Code maintainability

### 🟢 Suggestions (Nice to Have)

- **[prompts.py:45]** Long prompt string could be templated
- **[__main__.py:12]** Consider extracting magic number (7) to constant `MAX_ITERATIONS`

### ✅ Good Patterns Found

- ✅ Proper Pydantic validation in `vulnhuntr/LLMs.py:52`
- ✅ Three-tier Jedi search strategy in `symbol_finder.py:28-45`
- ✅ Environment variable configuration in `__main__.py:16`
- ✅ Structured logging with context in `__main__.py:234`
```

---

## Review Checklist

Before approving changes, verify:

### Security ✅
- [ ] No hardcoded secrets
- [ ] API keys from environment only
- [ ] User input validated
- [ ] File paths sanitized (no traversal)
- [ ] Logs don't expose sensitive data
- [ ] Error messages don't leak information

### LLM Integration ✅
- [ ] Responses validated with Pydantic
- [ ] JSON extraction handles markdown
- [ ] Appropriate max_tokens (8192 for analysis)
- [ ] Error handling for all API call types
- [ ] Prompts use structured format (XML tags)
- [ ] Cost implications considered

### Python Standards ✅
- [ ] Type hints on public functions
- [ ] Python 3.10-3.13 compatible
- [ ] PEP 8 compliant (Ruff formatting)
- [ ] Proper exception handling
- [ ] Docstrings for public APIs
- [ ] No mutable defaults

### Jedi Integration ✅
- [ ] Error handling for Jedi failures
- [ ] Three-tier search pattern followed
- [ ] Third-party code excluded
- [ ] Edge cases handled
- [ ] Performance acceptable

### Testing ✅
- [ ] Manually tested on sample code
- [ ] Different LLM providers tested
- [ ] Edge cases verified
- [ ] No regressions
- [ ] Cost implications verified

### Documentation ✅
- [ ] Code is self-documenting
- [ ] Complex logic has comments
- [ ] ARCHITECTURE.md updated if needed
- [ ] AREAS_OF_IMPROVEMENT.md updated if applicable
- [ ] README.md updated for user-facing changes

---

## Automated Checks

**Run before review**:

```bash
# Type checking (if mypy configured)
mypy vulnhuntr/

# Linting
ruff check vulnhuntr/

# Formatting check
ruff format --check vulnhuntr/

# Security scan
bandit -r vulnhuntr/

# Dependency vulnerabilities
pip-audit

# Complexity analysis
radon cc vulnhuntr/ -a -nb
```

---

## Special Considerations for Vulnhuntr

### 1. Iterative Context Expansion

**Pattern to maintain**:
```python
context = {}
for iteration in range(MAX_ITERATIONS):
    # 1. Analyze with current context
    # 2. Request more functions
    # 3. Fetch via Jedi
    # 4. Add to context
    # 5. Check termination conditions
```

**Review for**:
- Correct termination conditions
- No infinite loops
- Proper context accumulation
- Error handling in loop

### 2. Prompt Construction

**Pattern to maintain**:
```xml
<file_code>...</file_code>
<context_code>...</context_code>
<instructions>...</instructions>
<guidelines>...</guidelines>
<response_format>JSON schema</response_format>
```

**Review for**:
- Consistent XML structure
- Proper escaping of code content
- Clear separation of concerns
- Appropriate detail level

### 3. Provider-Specific Techniques

**Claude requires**:
- Prefill: `{"role": "assistant", "content": "{    \"scratchpad\": \"1."}`
- System prompt as separate parameter
- Newline stripping: `.replace('\n', '')`

**ChatGPT requires**:
- `response_format={"type": "json_object"}`
- System prompt in messages array
- No prefill needed

**Review for**:
- Provider-specific code in correct classes
- Not mixing provider techniques
- Graceful fallback for unsupported features

---

## Common Antipatterns to Avoid

### ❌ Antipattern: Loose Error Handling

```python
try:
    result = some_operation()
except:
    pass
```

**Why bad**: Silently swallows all errors, including critical ones

**Fix**:
```python
try:
    result = some_operation()
except SpecificError as e:
    log.error("Operation failed", error=str(e), context={...})
    raise  # Re-raise or handle appropriately
```

### ❌ Antipattern: String Path Manipulation

```python
file_path = repo_path + "/" + filename
if os.path.exists(file_path):
```

**Why bad**: Platform-specific, error-prone, security risk

**Fix**:
```python
file_path = Path(repo_path) / filename
if file_path.exists() and file_path.is_relative_to(repo_path):
```

### ❌ Antipattern: Direct JSON Parsing of LLM Response

```python
response = llm.chat(prompt)
data = json.loads(response)
```

**Why bad**: LLM may wrap in markdown, may be malformed

**Fix**:
```python
response = llm.chat(prompt, response_model=Response, max_tokens=8192)
# Returns validated Response object with all fields
```

### ❌ Antipattern: Hardcoded Configuration

```python
max_iterations = 7
confidence_threshold = 6
max_tokens = 4096
```

**Why bad**: Magic numbers, hard to change, not configurable

**Fix**:
```python
MAX_ITERATIONS = 7  # Constant at module level
CONFIDENCE_THRESHOLD = 6
MAX_TOKENS = 8192  # Or from config/environment
```

### ❌ Antipattern: Synchronous When Async Possible

```python
for file in large_file_list:
    result = analyze_file(file)  # Blocking
```

**Why bad**: Slow, doesn't utilize concurrency

**Fix** (future improvement):
```python
# TODO: Implement parallel processing with cost controls
# Current: Sequential to manage API costs
# Future: asyncio.gather() with rate limiting
```

---

## Integration with Main Agent

This code review agent is **automatically consulted** by the main COPILOT_AGENT.md during:
- Code changes
- Pull request reviews
- Pre-commit checks
- Architectural discussions

**Coordination**:
1. Main agent identifies code domains
2. Routes to this sub-agent for review
3. Applies guidelines from this agent
4. Merges with other sub-agent inputs (python.md, git-workflow.md, etc.)

---

## Continuous Improvement

**Update this agent when**:
- New security patterns discovered
- LLM integration patterns evolve
- Performance optimizations identified
- Common mistakes found in reviews
- Project architecture changes

**Version History**:
- 1.0.0 (2026-02-04): Initial Vulnhuntr-specific adaptation from generic code review agent

---

**Remember**: This is a security tool. Every line of code must uphold the highest standards of security, correctness, and reliability. When in doubt, err on the side of caution.
} catch (e) {}

// GOOD: Handle or propagate
try {
  await riskyOperation();
} catch (e) {
  logger.error('Operation failed', { error: e });
  throw new AppError('Operation failed', { cause: e });
}
```

## Review Checklist

- [ ] No hardcoded secrets
- [ ] Input validation present
- [ ] Error handling complete
- [ ] Types/interfaces defined
- [ ] Tests added for new code
- [ ] No obvious performance issues
- [ ] Code is readable and documented
- [ ] Breaking changes documented
