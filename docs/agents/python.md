# Python Guidelines for Vulnhuntr

**Project**: Vulnhuntr - LLM-Powered Vulnerability Scanner  
**Version**: 1.0.0  
**Last Updated**: 2026-02-04

---

## Requirements

- **Python 3.10-3.13 STRICT** (Jedi/Parso compatibility requirement)
- **Python 3.14+**: NOT supported (Jedi/Parso not ready)
- **Python <3.10**: NOT supported (missing features)
- Follow [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
- **ALWAYS use type hints** for all public functions
- **Security-first**: This is a security tool, every line matters

## Linting & Formatting

Use `ruff` for both:

```bash
ruff check --fix                # Lint with auto-fix
ruff check --select I --fix     # Sort imports
ruff format                     # Format code
ruff check --select I --fix .   # Fix import sorting project-wide
```

## Testing

Vulnhuntr **lacks formal test suite** (as of 1.0.0). When adding tests:

- Use `pytest` for test framework
- Mock LLM calls (use `unittest.mock` or `pytest-mock`)
- Test Jedi integration carefully (can be slow)
- Test all vulnerability types
- Measure cost implications

```bash
# Run tests (when implemented)
pytest tests/ -v

# With coverage
pytest tests/ --cov=vulnhuntr --cov-report=html

# Specific test file
pytest tests/test_symbol_finder.py -v
```

## Best Practices

- **Keep dependencies minimal** - Every dependency increases attack surface
- **Pin critical versions** - Jedi 0.19.2+, Parso 0.8.5+ (see pyproject.toml)
- **Security-first thinking** - This tool finds vulnerabilities, must be secure itself
- **Type hints everywhere** - Public functions MUST have type hints
- **Test manually** - Use scripts/ directory for integration tests
- **Document constraints** - If Python version matters, document why

## Critical Dependencies

**Version-locked (DO NOT change without testing)**:

```toml
# pyproject.toml
python = "^3.10"  # STRICT: 3.10-3.13 only
jedi = "^0.19.2"  # Python 3.10-3.13 support
parso = "^0.8.5"  # AST parsing for Jedi
anthro= "^0.77.1" # Claude API
openai = "^1.109.1"  # OpenAI/compatible APIs
pydantic = "^2.8.0"  # Response validation
structlog = "*"   # Structured logging
```

**Why the strict Python version**:
- Jedi 0.19.2 supports Python 3.10-3.13
- Parso 0.8.5 parses Python 3.10-3.13 syntax
- Python 3.14+ not supported yet
- Python <3.10 missing features (match/case, etc.)

## Vulnhuntr Code Patterns

### Pattern 1: LLM Client Interface

```python
from abc import ABC, abstractmethod
from typing import Optional
from pydantic import BaseModel

class LLMClientInterface(ABC):
    """Abstract interface for LLM providers."""
    
    @abstractmethod
    def chat(
        self,
        prompt: str,
        response_model: type[BaseModel],
        max_tokens: int = 8192
    ) -> BaseModel:
        """Send prompt, return validated response."""
        pass
```

### Pattern 2: Pydantic Response Models

```python
from pydantic import BaseModel, Field
from typing import Literal, Optional

class AnalysisResponse(BaseModel):
    """LLM response with validation."""
    
    scratchpad: str = Field(
        min_length=10,
        description="Step-by-step reasoning"
    )
    vulnerability_found: bool
    confidence: int = Field(ge=0, le=10)
    complete: bool = Field(default=False)
```

### Pattern 3: Jedi Symbol Resolution

```python
import jedi
from pathlib import Path
from typing import Optional, Dict, Any

def extract_symbol(
    name: str,
    file_path: Path,
    project_path: Path
) -> Optional[Dict[str, Any]]:
    """Extract symbol definition via Jedi.
    
    Args:
        name: Symbol name to find
        file_path: File to search in
        project_path: Project root for context
        
    Returns:
        Symbol info dict or None if not found
    """
    try:
        project = jedi.Project(path=project_path)
        script = jedi.Script(path=file_path, project=project)
        
        # Three-tier search: file → project → all names
        matches = script.search(name)
        if not matches:
            return None
            
        for match in matches:
            definitions = match.infer()
            if definitions:
                return {
                    "name": name,
                    "source": definitions[0].get_line_code(),
                    "file": definitions[0].module_path,
                    "line": definitions[0].line
                }
    except Exception as e:
        log.error("Jedi resolution failed", symbol=name, error=str(e))
        return None
```

### Pattern 4: Structured Logging

```python
import structlog

log = structlog.get_logger()

# Good - structured context
log.info(
    "Analysis complete",
    file=str(file_path),
    vulnerabilities=len(results),
    iterations=iteration_count,
    cost_usd=round(total_cost, 4)
)

# Bad - string formatting (loses structure)
log.info(f"Analysis complete for {file_path}: {len(results)} vulns")
```

## Anti-Patterns to Avoid

### ❌ Mutable Default Arguments

```python
# BAD
def analyze(files: List[str] = []):
    files.append(new_file)  # Modifies shared list!

# GOOD
def analyze(files: Optional[List[str]] = None):
    files = files if files is not None else []
    files.append(new_file)
```

### ❌ String Paths

```python
# BAD
file_path = "/path/to/file.py"
if os.path.exists(file_path):
    with open(file_path) as f:

# GOOD
from pathlib import Path
file_path = Path("/path/to/file.py")
if file_path.exists():
    with file_path.open() as f:
```

### ❌ Bare Except

```python
# BAD
try:
    result = jedi_operation()
except:
    pass  # Swallows all errors!

# GOOD
try:
    result = jedi_operation()
except (JediException, ValueError) as e:
    log.error("Jedi failed", error=str(e))
    return None
```

## Integration with Main Agent

This Python agent is consulted by COPILOT_AGENT.md for:
- Python version compatibility questions
- Code style and type hint reviews
- Dependency management decisions
- Jedi/Parso integration patterns
- Security-conscious Python patterns

**Version History**:
- 1.0.0 (2026-02-04): Adapted from Promptfoo to Vulnhuntr-specific guidelines
