# Vulnhuntr Modular Architecture Refactor

## Problem Statement

The current codebase suffers from several architectural issues:
- `__main__.py` is 900+ lines with mixed concerns (CLI parsing, analysis logic, reporting)
- Poor separation of concerns makes testing difficult
- Tight coupling between components
- Difficult to extend or maintain

## Proposed New Structure

Based on Python best practices from:
- [The Hitchhiker's Guide to Python - Structure](https://docs.python-guide.org/writing/structure/)
- [Real Python - Application Layouts](https://realpython.com/python-application-layouts/)

### Package Layout

```
vulnhuntr/
├── __init__.py                    # Package init with version
├── __main__.py                    # Entry point: `python -m vulnhuntr`
│
├── core/                          # Core domain logic
│   ├── __init__.py
│   ├── models.py                  # Data models: VulnType, Response, ContextCode
│   ├── xml_models.py              # XML/Pydantic models for prompts
│   ├── repo.py                    # RepoOps: repository operations
│   └── analysis.py                # VulnerabilityAnalyzer: main analysis orchestrator
│
├── cli/                           # Command-line interface
│   ├── __init__.py
│   ├── parser.py                  # Argument parsing
│   ├── output.py                  # Console output formatting
│   └── runner.py                  # CLI execution logic
│
├── llm/                           # LLM clients (renamed from LLMs.py)
│   ├── __init__.py
│   ├── base.py                    # Base LLM client interface
│   ├── claude.py                  # Claude implementation
│   ├── openai.py                  # ChatGPT implementation
│   ├── ollama.py                  # Ollama implementation
│   └── factory.py                 # LLM client factory
│
├── cost/                          # Cost management (renamed from cost_tracker.py)
│   ├── __init__.py
│   ├── tracker.py                 # CostTracker class
│   ├── budget.py                  # BudgetEnforcer class
│   └── estimator.py               # Cost estimation functions
│
├── checkpoint/                    # Checkpointing (from checkpoint.py)
│   ├── __init__.py
│   └── checkpoint.py              # AnalysisCheckpoint class
│
├── reporters/                     # (existing - already well-structured)
│   ├── __init__.py
│   ├── base.py
│   ├── sarif.py
│   ├── html.py
│   ├── json_reporter.py
│   ├── csv_reporter.py
│   ├── markdown_reporter.py
│   └── orchestrator.py            # NEW: Coordinates all report generation
│
├── integrations/                  # (existing - already well-structured)
│   ├── __init__.py
│   ├── github_issues.py
│   └── webhook.py
│
├── prompts/                       # Prompt templates (from prompts.py)
│   ├── __init__.py
│   ├── templates.py               # Prompt templates
│   └── vuln_specific.py           # Vulnerability-specific prompts
│
├── config/                        # Configuration (from config.py)
│   ├── __init__.py
│   └── config.py
│
├── utils/                         # Utility functions
│   ├── __init__.py
│   ├── logging.py                 # Logging configuration
│   └── helpers.py                 # General helpers
│
└── symbol_finder.py               # Keep as is (well-scoped)
```

## Key Design Principles

### 1. Single Responsibility Principle
Each module has one clear purpose:
- `core/analysis.py` - Orchestrates vulnerability analysis
- `cli/parser.py` - Parses CLI arguments
- `cli/runner.py` - Executes CLI commands
- `reporters/orchestrator.py` - Coordinates report generation

### 2. Dependency Inversion
- Core modules don't depend on CLI or reporters
- CLI and reporters depend on core
- Use dependency injection for LLM clients

### 3. Interface Segregation
- Define clear interfaces for LLM clients
- Use protocols or ABCs where appropriate

### 4. Clean Entry Point
`__main__.py` should be minimal:
```python
from vulnhuntr.cli.runner import main

if __name__ == "__main__":
    main()
```

## Migration Plan

### Phase 1: Create Core Module
1. Create `core/models.py` - Move VulnType, ContextCode, Response
2. Create `core/xml_models.py` - Move XML/Pydantic models
3. Create `core/repo.py` - Move RepoOps class
4. Create `core/analysis.py` - Extract analysis logic

### Phase 2: Create CLI Module
1. Create `cli/parser.py` - Extract argument parsing
2. Create `cli/output.py` - Extract print_readable and console output
3. Create `cli/runner.py` - Main execution logic

### Phase 3: Refactor LLM Module
1. Split `LLMs.py` into `llm/` package
2. Create base class in `llm/base.py`
3. Move each provider to separate file

### Phase 4: Refactor Cost Module
1. Split `cost_tracker.py` into `cost/` package
2. Separate tracker, budget, and estimation

### Phase 5: Create Reporters Orchestrator
1. Add `reporters/orchestrator.py`
2. Centralize all report generation logic

### Phase 6: Update Entry Point
1. Slim down `__main__.py`
2. Update all imports
3. Test everything

## Benefits

1. **Testability**: Each module can be tested in isolation
2. **Maintainability**: Changes are localized to specific modules
3. **Extensibility**: Easy to add new reporters, LLM providers, etc.
4. **Readability**: Clear structure makes navigation easy
5. **Reusability**: Core components can be used programmatically

## Backward Compatibility

- Keep the same CLI interface
- Keep the same import paths where possible
- Use `__init__.py` to re-export for backward compatibility
