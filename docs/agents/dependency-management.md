# Dependency Management for Vulnhuntr

**Project**: Vulnhuntr - LLM-Powered Vulnerability Scanner  
**Version**: 1.0.0  
**Last Updated**: 2026-02-04

---

## Critical Dependencies

Vulnhuntr has **STRICT version requirements** for Python and core libraries:

```toml
# pyproject.toml
[tool.poetry.dependencies]
python = "^3.10"              # STRICT: 3.10-3.13 only
jedi = "^0.19.2"              # Python 3.10-3.13 support
parso = "^0.8.5"              # AST parsing for Jedi
anthropic = "^0.77.1"         # Claude API
openai = "^1.109.1"           # OpenAI/compatible APIs
pydantic = "^2.8.0"           # Response validation
structlog = "*"               # Structured logging
```

## Why Version Constraints Matter

**Python 3.10-3.13 STRICT**:
- Jedi 0.19.2+ only supports Python 3.10-3.13
- Parso 0.8.5+ parses Python 3.10-3.13 syntax
- Python 3.14+ not yet supported (Jedi/Parso not ready)
- Python <3.10 missing features (match/case, union types)

**Breaking these constraints WILL break symbol resolution.**

## Safe Update Workflow

### Using pip-audit for Security

```bash
# Check for vulnerabilities
pip-audit

# Fix vulnerabilities automatically
pip-audit --fix

# Check specific requirements file
pip-audit -r requirements.txt
```

### Using poetry (if migrated)

```bash
# Update patch versions only (safe)
poetry update --lock

# Update specific package
poetry update anthropic

# Show outdated packages
poetry show --outdated

# Add new dependency
poetry add requests

# Add dev dependency
poetry add --group dev pytest
```

### Using pip directly

```bash
# Install from requirements.txt
pip install -r requirements.txt

# Upgrade specific package
pip install --upgrade anthropic

# Check outdated packages
pip list --outdated

# Freeze current versions
pip freeze > requirements.txt
```

## Critical Rules

1. **NEVER update Python beyond 3.13** - Jedi/Parso not compatible with 3.14+
2. **NEVER downgrade Jedi below 0.19.2** - Breaks Python 3.10-3.13 support
3. **NEVER downgrade Parso below 0.8.5** - AST parsing will fail
4. **Pin LLM client versions** - anthropic and openai APIs change frequently
5. **Test symbol resolution after updates** - Jedi/Parso are critical
6. **Check cost implications** - LLM client updates may change pricing
7. **Validate Pydantic models** - Schema changes can break response validation

## Testing After Updates

**Always test** after dependency updates:

```bash
# 1. Lint and format
ruff check --fix .
ruff format .

# 2. Test symbol resolution
python -m vulnhuntr --help  # Basic smoke test

# 3. Test with real vulnerable code
python -m vulnhuntr /path/to/test/repo

# 4. Check Python version compatibility
python --version  # Verify 3.10-3.13

# 5. Test Jedi import
python -c "import jedi; print(jedi.__version__)"  # Should be 0.19.2+

# 6. Test Parso import
python -c "import parso; print(parso.__version__)"  # Should be 0.8.5+

# 7. Run tests (if implemented)
pytest tests/ -v
```

## Major Updates

**Proceed with extreme caution** for major version updates:

```bash
# Check for major updates
pip list --outdated
```

**Major updates require**:
- Read the changelog for breaking changes
- Look for migration guides
- Test symbol resolution extensively
- Check LLM API compatibility
- Verify cost implications
- Test all vulnerability types
- Manual validation on real code

**Example: Jedi Major Update**
```bash
# If Jedi releases 0.20.0 with Python 3.14 support
# 1. Check if Parso also updated
# 2. Test Python 3.14 compatibility
# 3. Verify AST parsing works
# 4. Test on multiple codebases
# 5. Update pyproject.toml constraints
```

## Virtual Environment Management

Vulnhuntr uses virtual environments to isolate dependencies:

### Creating Virtual Environment

```bash
# Using venv (built-in)
python3.12 -m venv .venv
source .venv/bin/activate  # Linux/Mac
# or
.venv\Scripts\activate  # Windows

# Using conda
conda create -n vulnhuntr python=3.12
conda activate vulnhuntr
```

### Installing Dependencies

```bash
# Activate environment first
source .venv/bin/activate

# Install from requirements.txt
pip install -r requirements.txt

# Or install package in development mode
pip install -e .
```

### Dependency Checking Tools

```bash
# Check for security vulnerabilities
pip-audit

# Check for outdated packages
pip list --outdated

# Show dependency tree
pipdeptree

# Check for unused dependencies (if tool exists)
# pip-autoremove --list
```

## Integration with Main Agent

This dependency management agent is consulted by COPILOT_AGENT.md for:
- Python version compatibility decisions
- Jedi/Parso update considerations
- LLM client update impacts
- Security vulnerability handling
- Virtual environment setup

**Version History**:
- 1.0.0 (2026-02-04): Adapted from npm to Python pip/poetry for Vulnhuntr
