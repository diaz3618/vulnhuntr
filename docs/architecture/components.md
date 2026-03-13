# Components

## Entry Point (`__main__.py`)

The main pipeline: parse args → init RepoOps → filter files → summarize README → initial analysis → iterative secondary analysis → report.

`run()` coordinates everything. `initialize_llm()` is a factory for Claude/GPT/Ollama/OpenRouter clients. `print_readable()` formats output for the terminal.

---

## LLM Clients (`llms.py`)

Abstracts the LLM providers behind a common interface.

### Base Class: `LLM`

```python
class LLM:
    system_prompt: str
    history: List[Dict[str, str]]
    prev_prompt: Union[str, None]
    prev_response: Union[str, None]
    prefill: Union[str, None]
```

`chat()` is the main interface. Under the hood, `_validate_response()` strips markdown code fences, parses JSON, and validates against a Pydantic model.

**Response Validation Flow**:

```
LLM Response (text)
         │
         v
┌──────────────────┐
│  Add prefill if  │
│  it exists       │
└────────┬─────────┘
         │
         v
┌──────────────────┐
│ Regex extract    │
│ JSON from        │
│ markdown blocks  │  (Strip ```json...```)
└────────┬─────────┘
         │
         v
┌──────────────────┐
│ Pydantic model   │
│ validation       │
└────────┬─────────┘
         │
         v
   Validated JSON
```

### Claude Client

- Uses Anthropic's Messages API
- Implements **prefill technique**: starts the assistant response with `{"scratchpad": "1."`
- Does NOT use prefill for README summary requests
- System prompt passed separately from messages
- Returns response from `content[0].text` after stripping newlines

**API Configuration**:

```
ANTHROPIC_BASE_URL = https://api.anthropic.com (default)
ANTHROPIC_API_KEY = <required>
ANTHROPIC_MODEL = claude-sonnet-4-5 (recommended)
```

**Message Structure**:

```python
# Regular analysis (with prefill)
messages = [
    {"role": "user", "content": user_prompt},
    {"role": "assistant", "content": "{    \"scratchpad\": \"1."}
]

# README summary (no prefill)
messages = [
    {"role": "user", "content": user_prompt}
]
```

### ChatGPT Client

- Uses OpenAI's Chat Completions API
- System prompt included in messages array
- Supports `response_format` parameter for JSON mode
- When `response_model` provided: `{"type": "json_object"}`
- Returns response from `choices[0].message.content`

**API Configuration**:

```
OPENAI_BASE_URL = https://api.openai.com/v1 (default)
OPENAI_API_KEY = <required>
OPENAI_MODEL = chatgpt-4o-latest (recommended)
```

**Message Structure**:

```python
messages = [
    {"role": "system", "content": system_prompt},
    {"role": "user", "content": user_prompt}
]

# Parameters
{
    "model": model,
    "messages": messages,
    "max_tokens": max_tokens,
    "response_format": {"type": "json_object"}  # if response_model
}
```

### Ollama Client

- Uses Ollama's local generate API
- Does NOT use chat completions endpoint — uses `/api/generate` with a prompt field
- System prompt passed in options
- Experimental — structured output unreliable

**API Configuration**:

```
OLLAMA_BASE_URL = http://127.0.0.1:11434/api/generate (default)
OLLAMA_MODEL = llama3 (default)
OPENAI_API_KEY = not required
```

**Request Structure**:

```python
{
    "model": model,
    "prompt": user_prompt,  # Not messages array
    "options": {
        "temperature": 1,
        "system": system_prompt
    },
    "stream": False
}
```

### Error Handling

All clients raise standardized exceptions:

- `APIConnectionError`: Server unreachable
- `RateLimitError`: Request rate-limited
- `APIStatusError`: Non-200 status code
- `LLMError`: Generic/validation errors

---

## Symbol Resolution (`symbol_finder.py`)

Uses Jedi to locate Python symbol definitions across the target codebase.

### SymbolExtractor

```python
class SymbolExtractor:
    repo_path: pathlib.Path
    project: jedi.Project
    parsed_symbols: None
    ignore: List[str] = ['/test', '_test/', '/docs', '/example']
```

The main method is `extract(symbol_name, code_line, filtered_files)`. It tries three search strategies in order:

1. **File Search** (`file_search()`):
   - Grep for `code_line` in files to narrow scope
   - Use `jedi.Script.search()` on matching files
   - Handles: functions, classes, statements, instances, modules
   - Returns immediately on first match

2. **Project Search** (`project_search()`):
   - Use `jedi.Project.search()` for workspace-wide search
   - Handles class instance variables: `var = ClassName(); var.method()`
   - Infers types and follows references

3. **All Names Search** (`all_names_search()`):
   - Fallback: `jedi.Script.get_names(all_scopes=True)`
   - Matches based on `full_name` or last part of symbol
   - Special case: matches code_line within name descriptions

**Edge Cases Handled**:

- Method calls on variables: `end_node = cast(BaseOperator, leaf_nodes[0]); end_node.call_stream()`
- Class instance variables: `multi_agents = MultiAgents(); multi_agents.method()`
- Aliased imports: `from service import Service as FlowService`
- Module symbols: `from api.apps import app`
- Code in name descriptions

**Return Format**:

```python
{
    'name': 'function_name',
    'context_name_requested': 'original_symbol_requested',
    'file_path': '/path/to/file.py',
    'source': 'def function_name():\n    ...'
}
```

**Special Handling**:

- Third-party libraries: Returns placeholder message
- No source available: Returns `'None'`
- Excluded paths: Skips test/docs/examples

---

## Prompt System (`prompts.py`)

Provides structured, vulnerability-specific prompts and bypass examples for each analysis phase.

### Prompt Templates

| Template | Purpose | Usage |
|----------|---------|-------|
| `SYS_PROMPT_TEMPLATE` | System-level instructions | Claude/GPT system prompt |
| `README_SUMMARY_PROMPT_TEMPLATE` | README summarization | Initial context gathering |
| `INITIAL_ANALYSIS_PROMPT_TEMPLATE` | First-pass analysis | Identify potential vulnerabilities |
| `GUIDELINES_TEMPLATE` | Reporting standards | Included in all analysis prompts |
| `ANALYSIS_APPROACH_TEMPLATE` | Analysis methodology | Included in all analysis prompts |
| Vulnerability-specific templates | Focused analysis | Secondary analysis phase |

### Vulnerability-Specific Prompts

Structure in `VULN_SPECIFIC_BYPASSES_AND_PROMPTS`:

```python
{
    "LFI": {
        "prompt": LFI_TEMPLATE,
        "bypasses": ["../../../../etc/passwd", "/proc/self/environ", ...]
    },
    "RCE": {
        "prompt": RCE_TEMPLATE,
        "bypasses": ["__import__('os').system('id')", ...]
    },
    # ... SSRF, AFO, SQLI, XSS, IDOR
}
```

Each vulnerability-specific template lists high-risk functions, common exploitation vectors, security controls to look for, and bypass examples.

---

## Repository Operations (`RepoOps`)

Scans the target repo, excludes tests/docs/venv, and identifies network entry points for analysis.

### File Filtering

**Exclusions**:

```python
to_exclude = {
    '/setup.py', '/test', '/example', '/docs',
    '/site-packages', '.venv', 'virtualenv', '/dist'
}
file_names_to_exclude = ['test_', 'conftest', '_test.py']
```

**Network Entry Point Detection** (210+ regex patterns):

- **Web Frameworks**: Flask, FastAPI, Django, Pyramid, Bottle, Tornado, Sanic, Falcon, CherryPy, Quart, Starlette, Responder, Hug, Dash
- **Async Frameworks**: aiohttp, Sanic, Quart
- **WebSockets**: websockets, Tornado WebSocketHandler
- **GraphQL**: graphene, strawberry
- **UI Frameworks**: Gradio
- **Cloud Functions**: AWS Lambda, Azure Functions, Google Cloud Functions
- **Server Startup**: uvicorn, gunicorn, hypercorn, daphne, waitress, gevent, grpc

Main methods: `get_readme_content()`, `get_relevant_py_files()`, `get_network_related_files()`, `get_files_to_analyze()`.
