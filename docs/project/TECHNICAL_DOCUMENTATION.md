# Vulnhuntr: Technical Documentation

## Overview

Vulnhuntr is an innovative security analysis tool that leverages Large Language Models (LLMs) to automatically discover complex, multi-step security vulnerabilities in Python codebases. Unlike traditional static analysis tools that rely on pattern matching, Vulnhuntr uses AI to understand code semantics and trace data flow from user input to potentially dangerous operations.

---

## How It Works: The Big Picture

### Core Concept

Vulnhuntr analyzes your code by:
1. **Finding Entry Points**: Identifies where user input enters the application (HTTP routes, API endpoints, etc.)
2. **Following the Data**: Traces how user-controlled data flows through the codebase
3. **Detecting Sinks**: Identifies dangerous operations where untrusted data could cause harm
4. **Building Context**: Requests additional code context iteratively to complete the analysis
5. **Generating Reports**: Produces detailed vulnerability reports with proof-of-concept exploits

### The Innovation

Traditional static analysis tools look for patterns like `eval(user_input)`. Vulnhuntr understands that even if `eval()` isn't directly called with user input, a chain like:
```
user_input → sanitize() → transform() → wrapper_function() → eval()
```
might still be exploitable if the sanitization is bypassable.

---

## Architecture

### Component Overview

```
vulnhuntr/
├── __main__.py          # Main entry point and orchestration
├── LLMs.py              # LLM client abstractions (Claude, GPT, Ollama)
├── prompts.py           # Prompt templates for vulnerability detection
├── symbol_finder.py     # Code symbol extraction and resolution
└── __init__.py          # Package initialization
```

### Data Flow

```
User Command
    ↓
RepoOps.get_relevant_py_files()
    ↓
RepoOps.get_network_related_files()
    ↓
[For each file]
    ↓
Initial Analysis (General vulnerability scan)
    ↓
[If vulnerabilities found]
    ↓
Secondary Analysis (Vulnerability-specific deep dive)
    ↓
SymbolExtractor.extract() (Get more context)
    ↓
[Repeat until complete or max iterations]
    ↓
Generate Report
```

---

## Key Components Explained

### 1. Main Orchestrator (`__main__.py`)

**Purpose**: Coordinates the entire analysis workflow

**Key Classes**:

- **`VulnType`**: Enum defining supported vulnerability types (RCE, LFI, XSS, SQLI, SSRF, AFO, IDOR)
- **`Response`**: Pydantic model for structured LLM responses containing:
  - `scratchpad`: LLM's reasoning process
  - `analysis`: Final vulnerability assessment
  - `poc`: Proof-of-concept exploit
  - `confidence_score`: 0-10 confidence rating
  - `vulnerability_types`: List of detected vulnerability types
  - `context_code`: Additional code context requested

- **`RepoOps`**: Repository operations class
  - Finds Python files in the repository
  - Filters out test/doc/example files
  - Identifies network-related files (files with HTTP endpoints)
  - Uses regex patterns to detect web frameworks (Flask, FastAPI, Django, etc.)

**Main Workflow**:

```python
def run():
    1. Parse command-line arguments
    2. Initialize repository operations
    3. Get README summary (for context)
    4. Get files to analyze
    5. For each file:
        a. Initial analysis (scan for all vulnerability types)
        b. If vulnerabilities found:
            For each vulnerability type:
                - Deep dive analysis
                - Request additional context code
                - Iteratively refine understanding (up to 7 iterations)
    6. Output results
```

**Key Functions**:

- `initialize_llm()`: Creates appropriate LLM client based on config
- `extract_between_tags()`: Parses XML-tagged responses
- `print_readable()`: Formats analysis results for console output

---

### 2. LLM Abstraction (`LLMs.py`)

**Purpose**: Provides unified interface for different LLM providers

**Base Class: `LLM`**

Common functionality for all LLM implementations:
- Message history management
- Response validation with Pydantic models
- Error handling
- Logging

**Key Method**:
```python
def chat(user_prompt, response_model=None, max_tokens=4096):
    """
    Send prompt to LLM and optionally validate response
    
    Args:
        user_prompt: The prompt to send
        response_model: Pydantic model for structured response
        max_tokens: Maximum tokens in response
    
    Returns:
        Validated Pydantic model or raw string
    """
```

**Implementation: `Claude`**

- Uses Anthropic's Claude API
- Implements "prefilling" technique to force JSON output:
  ```python
  # Sends partial JSON to force Claude to complete it
  {"role": "assistant", "content": "{    \"scratchpad\": \"1."}
  ```
- Strips newlines from responses for cleaner parsing

**Implementation: `ChatGPT`**

- Uses OpenAI's GPT-4 API
- Utilizes native JSON mode: `response_format={"type": "json_object"}`
- Includes system prompt in message format

**Implementation: `Ollama`**

- For local LLM inference
- Uses HTTP POST to Ollama API
- Currently experimental with mixed results

**Error Handling**:
- `RateLimitError`: When API rate limits are hit
- `APIConnectionError`: Network/server issues
- `APIStatusError`: HTTP error codes
- `LLMError`: General LLM failures

**Response Validation Fix** (Recently Added):
```python
# Strips markdown code blocks from responses
import re
match = re.search(r'\{.*\}', response_text, re.DOTALL)
if match:
    response_text = match.group(0)
```

---

### 3. Prompt Engineering (`prompts.py`)

**Purpose**: Contains carefully crafted prompts for vulnerability detection

**Structure**:

Each vulnerability type has:
1. **Prompt Template**: Instructions for analyzing that specific vulnerability
2. **Bypass Techniques**: Common ways security controls are evaded

**Example Structure**:
```python
RCE_TEMPLATE = """
Combine code in <file_code> and <context_code> then analyze for RCE...

RCE-Specific Focus Areas:
1. High-Risk Functions: eval(), exec(), subprocess...
2. Indirect Code Execution: dynamic imports, template injection...
3. Command Injection Vectors: shell command composition...
4. Deserialization Vulnerabilities: pickle.loads()...
5. Example Bypass Techniques...
"""

RCE_BYPASSES = [
    "eval(''.join(['__im', 'port__']('os').system('whoami')))",
    "exec(__import__('base64').b64decode(user_input))",
    # ... more examples
]
```

**Supported Vulnerability Types**:

1. **RCE (Remote Code Execution)**
   - Focus: eval(), exec(), subprocess, pickle, yaml
   - Bypasses: Base64 encoding, string concatenation, reflection

2. **LFI (Local File Inclusion)**
   - Focus: open(), file operations, path traversal
   - Bypasses: Path normalization, null bytes, encoding

3. **XSS (Cross-Site Scripting)**
   - Focus: HTML rendering, unescaped output
   - Bypasses: HTML entity encoding, JavaScript contexts

4. **SQLI (SQL Injection)**
   - Focus: Database queries, ORM misuse
   - Bypasses: String concatenation, second-order injection

5. **SSRF (Server-Side Request Forgery)**
   - Focus: HTTP requests, URL handling
   - Bypasses: URL parsing confusion, DNS rebinding

6. **AFO (Arbitrary File Overwrite)**
   - Focus: File write operations, path manipulation
   - Bypasses: Symlink attacks, TOCTOU races

7. **IDOR (Insecure Direct Object Reference)**
   - Focus: Authorization checks, ID handling
   - Bypasses: Parameter tampering, enumeration

**Common Prompt Components**:

- `INITIAL_ANALYSIS_PROMPT_TEMPLATE`: First-pass analysis instructions
- `ANALYSIS_APPROACH_TEMPLATE`: Methodology for tracing data flow
- `GUIDELINES_TEMPLATE`: General analysis guidelines
- `VULN_SPECIFIC_BYPASSES_AND_PROMPTS`: Dictionary mapping vulns to their prompts/bypasses

---

### 4. Symbol Extraction (`symbol_finder.py`)

**Purpose**: Resolves code symbols (functions, classes, variables) to their definitions

**Why This Matters**:

When the LLM sees:
```python
result = process_user_input(data)
```

It needs to see the definition of `process_user_input()` to understand if it's safe. The `SymbolExtractor` finds and retrieves that code.

**Main Class: `SymbolExtractor`**

```python
def __init__(self, repo_path):
    self.project = jedi.Project(repo_path)  # Jedi for Python parsing
```

**Core Method: `extract(symbol_name, code_line, filtered_files)`**

Finds the definition of a symbol using multiple strategies:

1. **File Search**: Searches in files matching the code_line
2. **Project Search**: Uses Jedi's project-wide search
3. **All Names Search**: Examines all names in relevant files

**Edge Cases Handled**:

```python
# 1. Method call on variable
end_node.call_stream(call_data)

# 2. Class instance variable
multi_agents = MultiAgents()
multi_agents.method()

# 3. Aliased import
from service import Service as FlowService

# 4. Module symbol
from api.apps import app

# 5. Nested attributes
DocumentService.update_progress.d
```

**Search Strategies**:

```python
def file_search(symbol_name, scripts):
    """Search in specific files using Jedi.Script.search()"""
    # Handles: functions, classes, instances, statements, modules
    
def project_search(symbol_name):
    """Project-wide search using Jedi.Project.search()"""
    # Finds class instance variables
    
def all_names_search(symbol_name, symbol_parts, scripts, code_line):
    """Examines all names in files"""
    # Handles method calls on variables
```

**Return Format**:

```python
{
    'name': 'function_name',
    'context_name_requested': 'original_search_term',
    'file_path': '/path/to/file.py',
    'source': 'def function_name():\n    ...'
}
```

**Jedi Integration**:

Jedi is a Python static analysis library that:
- Parses Python code into AST
- Resolves imports and references
- Infers types
- Finds definitions and usages

---

## Analysis Workflow in Detail

### Phase 1: Initial Analysis

**Goal**: Get a broad overview of potential vulnerabilities

**Input to LLM**:
```xml
<file_code>
    <file_path>/path/to/file.py</file_path>
    <file_source>... entire file ...</file_source>
</file_code>

<instructions>
    Analyze for ALL vulnerability types...
</instructions>

<analysis_approach>
    1. Find entry points
    2. Trace data flow
    3. Identify sinks
    ...
</analysis_approach>

<guidelines>
    - Focus on remote exploitation
    - Consider security control bypasses
    ...
</guidelines>

<response_format>
    {
        "scratchpad": "...",
        "analysis": "...",
        "poc": "...",
        "confidence_score": 0-10,
        "vulnerability_types": [...],
        "context_code": [...]
    }
</response_format>
```

**LLM Output**:
```json
{
    "scratchpad": "1. Found route /api/upload accepting file parameter...",
    "analysis": "Potential LFI in file upload handler...",
    "poc": "POST /api/upload with filename=../../../../etc/passwd",
    "confidence_score": 7,
    "vulnerability_types": ["LFI"],
    "context_code": [
        {
            "name": "save_file",
            "reason": "Need to see how filename is validated",
            "code_line": "save_file(request.files['file'])"
        }
    ]
}
```

### Phase 2: Secondary Analysis

**Goal**: Deep dive into specific vulnerability types with additional context

**For each detected vulnerability type**:

1. **Iteration 1**: Analyze with vulnerability-specific prompt
2. **Iterations 2-7**: 
   - LLM requests more context (functions/classes it needs to see)
   - SymbolExtractor retrieves the requested code
   - LLM analyzes with growing context
   - Repeat until:
     - No new context requested
     - Maximum iterations reached
     - Complete call chain established

**Context Accumulation**:

```python
stored_code_definitions = {}

# Each iteration
for context_item in llm_response.context_code:
    if context_item.name not in stored_code_definitions:
        match = symbol_extractor.extract(
            context_item.name, 
            context_item.code_line, 
            all_files
        )
        if match:
            stored_code_definitions[context_item.name] = match
```

**Secondary Analysis Input**:
```xml
<file_code>Original file</file_code>

<context_code>
    <code>
        <name>save_file</name>
        <file_path>/utils/files.py</file_path>
        <source>
            def save_file(uploaded_file):
                filename = secure_filename(uploaded_file.filename)
                ...
        </source>
    </code>
    <code>
        <name>secure_filename</name>
        ...
    </code>
</context_code>

<example_bypasses>
    - Path traversal with ../
    - Null byte injection
    ...
</example_bypasses>

<instructions>
    Analyze specifically for LFI...
</instructions>

<previous_analysis>
    Previous iteration's analysis...
</previous_analysis>
```

**Why Multiple Iterations?**

The LLM might see:
1. First iteration: "Calls `sanitize_path(user_input)`"
2. Second iteration: "Sees `sanitize_path()` removes `../` but not `..\` (Windows)"
3. Third iteration: "Confirms no Windows path handling"
4. Conclusion: Vulnerable to Windows path traversal

### Phase 3: Reporting

**Output Formats**:

1. **Console Output** (Rich formatting):
   ```
   Analyzing /path/to/file.py
   ----------------------------------------
   
   scratchpad:
     1. Found entry point...
   
   analysis:
     The endpoint is vulnerable...
   
   poc:
     curl -X POST ...
   
   confidence_score:
     8
   
   vulnerability_types:
     - RCE
   ```

2. **Log File** (`vulnhuntr.log`):
   ```json
   {
       "event": "Initial analysis complete",
       "report": {...},
       "timestamp": "..."
   }
   ```

---

## Configuration

### Environment Variables

```bash
# Claude (recommended)
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-sonnet-4-5  # Default: claude-3-5-sonnet-latest
ANTHROPIC_BASE_URL=https://api.anthropic.com  # Default

# OpenAI GPT
OPENAI_API_KEY=sk-...
OPENAI_MODEL=chatgpt-4o-latest  # Default
OPENAI_BASE_URL=https://api.openai.com/v1  # Default

# Ollama (local)
OLLAMA_MODEL=llama3  # Default
OLLAMA_BASE_URL=http://127.0.0.1:11434/api/generate  # Default
```

### `.env` File Support

Create `.env` in project root:
```bash
ANTHROPIC_API_KEY=your-key-here
ANTHROPIC_MODEL=claude-sonnet-4-5
```

The tool automatically loads it via `python-dotenv`.

---

## Command-Line Interface

### Basic Usage

```bash
# Analyze entire repository
vulnhuntr -r /path/to/repo

# Analyze specific file or subdirectory
vulnhuntr -r /path/to/repo -a server.py
vulnhuntr -r /path/to/repo -a api/

# Use different LLM
vulnhuntr -r /path/to/repo -l gpt
vulnhuntr -r /path/to/repo -l ollama

# Increase verbosity
vulnhuntr -r /path/to/repo -v     # Show secondary analysis
vulnhuntr -r /path/to/repo -vv    # Show context code details
```

### Arguments

- `-r, --root`: **(Required)** Path to repository root
- `-a, --analyze`: Specific file or directory to analyze (default: entire repo)
- `-l, --llm`: LLM provider: `claude` (default), `gpt`, or `ollama`
- `-v, --verbosity`: Increase output verbosity (can be repeated)

---

## Understanding the Output

### Confidence Scores

- **0-4**: Likely false positive, needs human verification
- **5-6**: Possible vulnerability, investigate further
- **7-8**: Probable vulnerability, should be reviewed
- **9-10**: High confidence, likely exploitable

### Scratchpad Section

The LLM's "thinking out loud":
- Entry point identification
- Data flow tracing
- Security control analysis
- Decision-making process

**Purpose**: Helps you understand how the tool reached its conclusion

### Analysis Section

The final verdict:
- Is there a vulnerability?
- What type is it?
- How severe is it?
- What makes it exploitable?

### PoC (Proof of Concept)

Concrete exploit demonstration:
```python
# HTTP request
POST /api/upload HTTP/1.1
Content-Type: multipart/form-data

filename=../../../../etc/passwd

# Or Python code
import requests
response = requests.post(
    'http://target/api/upload',
    files={'file': ('../../../../etc/passwd', b'content')}
)
```

### Context Code

Functions and classes the LLM examined:
```
Name: secure_filename
Context search: secure_filename
File Path: /utils/validation.py
First two lines from source: def secure_filename(filename):
    return filename.replace('../', '')
```

---

## Limitations and Constraints

### 1. Python Only

- Uses Jedi/Parso which are Python-specific
- Cannot analyze JavaScript, Java, Go, etc.

### 2. Static Analysis

- No runtime execution
- Cannot detect timing-based vulnerabilities
- May miss context-dependent issues

### 3. Incomplete Context

- Cannot analyze third-party library internals
- Limited to repository code
- May miss vulnerabilities in dependencies

### 4. LLM Limitations

- Non-deterministic (results may vary between runs)
- Subject to LLM hallucinations
- Limited by training data and context window
- Expensive (API costs)

### 5. Complexity Bounds

- Maximum 7 iterations per vulnerability type
- Context window limits on LLMs
- May not handle extremely large files well

---

## Best Practices

### For Users

1. **Start Small**: Analyze specific files before entire repositories
2. **Monitor Costs**: Set API spending limits
3. **Verify Findings**: Always manually verify high-confidence results
4. **Prioritize**: Focus on files handling user input first
5. **Iterate**: Use findings to improve your code, then re-scan

### For Developers Extending Vulnhuntr

1. **Add Tests**: Write tests for new vulnerability types
2. **Document Prompts**: Explain reasoning behind prompt changes
3. **Version Control**: Track changes to prompts and their effectiveness
4. **Benchmark**: Test against known vulnerable code
5. **Follow Patterns**: Use existing vulnerability templates as guides

---

## Troubleshooting

### Common Issues

#### "ValidationError: Invalid JSON"
- **Cause**: LLM returned malformed JSON
- **Fix**: ✅ Already fixed with regex extraction
- **Manual fix**: Check `vulnhuntr.log` for raw response

#### "No such file or directory: .../grammar313.txt"
- **Cause**: Jedi/Parso don't support Python 3.13
- **Fix**: Upgrade to jedi>=0.19.2, parso>=0.8.5

#### "404 Error: model not found"
- **Cause**: Invalid model name
- **Fix**: Set `ANTHROPIC_MODEL=claude-sonnet-4-5`

#### "RateLimitError"
- **Cause**: Exceeded API rate limits
- **Fix**: Add delays, reduce parallelization, increase tier

#### High costs
- **Cause**: Analyzing large files with many iterations
- **Fix**: Use `-a` to focus on specific files, reduce max iterations

### Debug Mode

Enable detailed logging:
```python
# In code
import structlog
structlog.configure(
    processors=[
        structlog.dev.ConsoleRenderer()  # Human-readable
    ]
)
```

Check `vulnhuntr.log` for structured logs:
```json
{
    "event": "Initial analysis complete",
    "report": {...},
    "timestamp": "2024-01-01T12:00:00"
}
```

---

## Dependencies

### Core Dependencies

- **anthropic**: Claude API client
- **openai**: GPT API client
- **requests**: Ollama HTTP requests
- **jedi**: Python code analysis
- **parso**: Python parser
- **pydantic**: Data validation
- **pydantic-xml**: XML serialization
- **rich**: Terminal formatting
- **structlog**: Structured logging
- **python-dotenv**: Environment variable loading

### Compatibility

- Python: 3.10+ (3.12+ recommended for Jedi 0.19+)
- OS: Linux, macOS, Windows
- Memory: 4GB+ recommended for large repositories

---

## Performance Characteristics

### Time Complexity

- **Per File**: O(n × m × k)
  - n = number of vulnerability types found
  - m = number of iterations (up to 7)
  - k = average LLM response time

- **Per Repository**: O(f × n × m × k)
  - f = number of relevant Python files

### API Usage

Average per file analysis:
- Initial analysis: 1 API call (~2000-8000 tokens)
- Secondary analysis: n × m API calls (~4000-16000 tokens each)
- Total: 1 + (n × m) API calls

Example for file with 2 vulnerabilities, 4 iterations each:
- API calls: 1 + (2 × 4) = 9 calls
- Estimated cost (Claude): ~$0.50-2.00

### Optimization Tips

1. **Use `-a` flag**: Analyze specific files, not entire repo
2. **Filter files**: Tool already filters test/example files
3. **Set budgets**: Monitor API usage closely
4. **Cache results**: Save analysis results to avoid re-analysis
5. **Parallelize**: (Not currently implemented) Analyze files in parallel

---

## Real-World Impact

### Discovered Vulnerabilities

Vulnhuntr has found 0-days in major projects:

| Project | Stars | CVEs |
|---------|-------|------|
| gpt_academic | 67k | CVE-2024-10100 (LFI), CVE-2024-10101 (XSS) |
| ComfyUI | 66k | CVE-2024-10099 (XSS) |
| Ragflow | 31k | CVE-2024-10131 (RCE) |
| FastChat | 37k | CVE-2024-10044 (SSRF) |
| LLaVA | 21k | CVE-2024-9309 (SSRF) |

### Success Factors

1. **LLM Understanding**: Can reason about complex multi-step vulnerabilities
2. **Context Building**: Iteratively gathers necessary code context
3. **Bypass Awareness**: Knows common security control evasion techniques
4. **Semantic Analysis**: Understands code intent, not just patterns

---

## Future Directions

See [AREAS_OF_IMPROVEMENT.md](AREAS_OF_IMPROVEMENT.md) for detailed roadmap.

### Short Term
- Multi-language support
- Better performance and caching
- Enhanced reporting (SARIF, HTML)

### Long Term
- Local LLM optimization
- Automated PoC verification
- IDE integration
- ML-based false positive reduction

---

## Contributing

### Development Setup

```bash
# Clone repository
git clone https://github.com/protectai/vulnhuntr
cd vulnhuntr

# Create virtual environment
python3.12 -m venv .venv
source .venv/bin/activate

# Install in editable mode
pip install -e .

# Install development dependencies
pip install pytest black mypy ruff
```

### Adding New Vulnerability Types

1. Add enum to `VulnType` in `__main__.py`
2. Create prompt template in `prompts.py`
3. Add bypass techniques
4. Test with known vulnerable code
5. Update documentation

### Code Style

- Use type hints
- Follow PEP 8
- Document complex logic
- Write tests for new features

---

## Conclusion

Vulnhuntr represents a paradigm shift in static security analysis by leveraging LLM reasoning capabilities to detect complex vulnerabilities that traditional tools miss. By understanding code semantics and tracing data flow through multiple files and function calls, it achieves results comparable to expert security researchers.

While it has limitations (Python-only, API costs, false positives), its ability to find real 0-day vulnerabilities in popular open-source projects demonstrates its effectiveness as a security tool.

For questions, issues, or contributions, visit: https://github.com/protectai/vulnhuntr
