# GitHub Copilot Instructions for Vulnhuntr

**IMPORTANT**: This file configures GitHub Copilot to automatically use the comprehensive agent system for all interactions in this workspace.

---

## Agent System Overview

This project uses a **main coordinator agent** with **specialized sub-agents** for different domains. All agents are located in this repository and should be consulted automatically.

### Main Coordinator

**File**: [`AGENT.md`](../AGENT.md)

The main agent coordinates all interactions and routes to specialized sub-agents as needed. It contains:
- Project overview and architecture
- Critical constraints (Python 3.10-3.13 strict)
- Development workflow
- Knowledge refresh protocol
- Decision-making framework
- Emergency procedures

### Sub-Agents

**Always consult these sub-agents** for domain-specific questions:

1. **[docs/agents/code-review/SKILL.md](../docs/agents/code-review/SKILL.md)**
   - Security review (prompt injection, API key protection)
   - LLM integration review
   - Python standards (type hints, PEP 8)
   - Jedi integration patterns
   - Performance and cost optimization

2. **[docs/agents/prompt-engineering.md](../docs/agents/prompt-engineering.md)**
   - Vulnerability detection prompts
   - XML prompt structure
   - Provider-specific techniques (Claude prefill, ChatGPT json_object)
   - Response validation with Pydantic
   - Iterative context expansion

3. **[docs/agents/python.md](../docs/agents/python.md)**
   - Python 3.10-3.13 strict compatibility
   - Jedi/Parso patterns
   - Type hints and security patterns
   - ruff linting and formatting

4. **[docs/agents/git-workflow.md](../docs/agents/git-workflow.md)**
   - Branch protection rules
   - Python-focused commands (ruff, pytest)
   - Merge workflow (only when explicitly requested)

5. **[docs/agents/logging.md](../docs/agents/logging.md)**
   - structlog patterns
   - Sensitive data sanitization
   - Cost tracking

7. **[docs/agents/dependency-management.md](../docs/agents/dependency-management.md)**
   - Python version constraints
   - Jedi/Parso strict versioning
   - Security vulnerability handling

---

## MCP Server Integration

This project uses **Model Context Protocol (MCP) servers** for enhanced capabilities:

### Available MCP Servers

1. **memory-bank-mcp** (CRITICAL - Context Management)
   - **Purpose**: Maintain project context across sessions
   - **Location**: `memory-bank/` directory (gitignored)
   - **Files**: product-context.md, active-context.md, progress.md, decision-log.md, system-patterns.md
   - **Usage**: The agent MUST use this to maintain long-term memory
   - **⚠️ Known Issue**: Path nesting bug - manually edit files instead of using write tool
   - **Workaround**: Use `replace_string_in_file` for memory-bank files, not `mcp_memory-bank-m_write_memory_bank_file`

2. **mcp-server-analyzer** (Code Analysis)
   - **Purpose**: Python code analysis with ruff and vulture
   - **Tools**: 
     - `mcp_analyzer_analyze-code`: Comprehensive linting + dead code detection
     - `mcp_analyzer_ruff-check`: RUFF linting only
     - `mcp_analyzer_ruff-format`: RUFF formatting
     - `mcp_analyzer_vulture-scan`: Dead code detection
     - `mcp_analyzer_ruff-check-ci`: CI/CD output formats
   - **Usage**: Use before committing code to catch issues

3. **mcp-github** (GitHub Integration)
   - **Purpose**: GitHub repository operations
   - **Tools**: create_or_update_file, push_files, create_pull_request, fork_repository, etc.
   - **Usage**: For GitHub operations (currently not heavily used)

4. **mcp-pylance-mcp-s** (Pylance Documentation)
   - **Purpose**: Search Pylance/Python documentation
   - **Tools**: 
     - `mcp_pylance_mcp_s_pylanceDocuments`: Search Python language server help
     - `mcp_pylance_mcp_s_pylanceInvokeRefactoring`: Apply automated refactorings
   - **Usage**: For Python language server questions and automated refactorings

5. **python-lsp-mcp** (Python LSP Analysis)
   - **Purpose**: Advanced Python code analysis via LSP (diagnostics, search, symbols)
   - **Tools**:
     - `mcp_python-lsp-mc_diagnostics`: Get type errors and warnings for a file or directory (uses Pyright)
     - `mcp_python-lsp-mc_search`: Regex search in files using ripgrep
     - `mcp_python-lsp-mc_status`: Get MCP server status
     - `mcp_python-lsp-mc_set_backend`: Switch between rope/pyright backends
     - `mcp_python-lsp-mc_set_python_path`: Set Python interpreter path
     - `mcp_python-lsp-mc_update_document`: Update file content for incremental analysis
     - `mcp_python-lsp-mc_reload_modules`: Reload modules during development
   - **Usage**: For type checking, finding type errors, advanced code search, and Python analysis

### MCP Server Configuration

Configuration is in `.vscode/mcp.json`:

```json
{
  "servers": {
    "analyzer": {
      "command": "uvx",
      "args": ["mcp-server-analyzer"]
    },
    "memory-bank-mcp": {
      "type": "stdio",
      "command": "npx",
      "args": [
        "@aakarsh-sasi/memory-bank-mcp@1.1.4",
        "--mode", "code",
        "--path", "/home/diaz/workspace/CS5374/vulnhuntr",
        "--folder", "memory-bank"
      ]
    },
    "python-lsp-mcp": {
      "command": "uvx",
      "args": [
        "python-lsp-mcp@latest"
      ]
    }
  }
}
```

### Memory Bank Best Practices

1. **ALWAYS update memory-bank** after significant changes
2. **Use direct file edits** (replace_string_in_file) due to path nesting bug
3. **Keep context current** - update active-context.md with ongoing tasks
4. **Log decisions** in decision-log.md with rationale
5. **Track progress** in progress.md chronologically
6. **Document patterns** in system-patterns.md for consistency

### When to Use Each MCP Server

- **memory-bank-mcp**: After commits, architectural changes, major milestones
- **mcp-server-analyzer**: Before commits, during code review (ruff linting, dead code)
- **mcp-pylance-mcp-s**: When refactoring Python code, searching language features
- **python-lsp-mcp**: For type checking (Pyright), advanced diagnostics, ripgrep search
- **mcp-github**: For repository operations (less common in this workflow)

---

## Critical Project Constraints

**NEVER VIOLATE THESE**:

1. **Python 3.10-3.13 ONLY** - Jedi/Parso compatibility requirement
2. **All LLM responses MUST be validated** with Pydantic models
3. **Security first** - This is a security tool, must be secure itself
4. **max_tokens=8192** for LLM calls (increased from 4096)
5. **Never guess** - Always research or consult documentation
6. **Always consider cost** - LLM API calls are expensive

---

## Deployment & Setup

**For deployment/setup questions**: Consult [`AGENT.md`](../AGENT.md) "Environment Setup" section and [`QUICKSTART.md`](../QUICKSTART.md).

**Critical deployment constraints**:
- Python 3.10-3.13 ONLY (3.14+ breaks Jedi/Parso)
- Shell env vars override `.env` (run `unset ANTHROPIC_API_KEY OPENAI_API_KEY`)
- Common issues: JSON validation (fixed at max_tokens=8192), wrong API key (env override), model 404 (deprecated names)

---

## Workflow for All Interactions

### 1. Before Answering Any Question

- **Identify domain** - Which sub-agent is relevant?
- **Read [`AGENT.md`](../AGENT.md)** for project context (if needed for architecture, constraints, or complex questions)
- **Consult sub-agent** - Read the appropriate docs/agents/ file **only if domain-specific** (don't load all agents)
- **Check constraints** - Especially Python version, LLM integration patterns
- **Research if unsure** - Never guess, always verify

**Routing Guide** (load sub-agents **only when relevant**):
- **Security/LLM code review** → Load `docs/agents/code-review/SKILL.md`
- **Prompt engineering/vulnerability detection** → Load `docs/agents/prompt-engineering.md`
- **Python compatibility/Jedi questions** → Load `docs/agents/python.md`
- **Git workflow/commits** → Load `docs/agents/git-workflow.md`
- **Logging/structlog** → Load `docs/agents/logging.md`
- **Dependencies/versions** → Load `docs/agents/dependency-management.md`
- **Deployment/setup** → Load `AGENT.md` + `QUICKSTART.md`

### 2. Knowledge Refresh Triggers

**Re-read core files** when:
- After 20+ interactions
- Before major architectural changes
- When unfamiliar with recent code
- When encountering repeated failures
- When project constraints change

**Core files to re-read**:
- `AGENT.md` (main coordinator)
- `vulnhuntr/__main__.py` (entry point)
- `vulnhuntr/LLMs.py` (LLM clients)
- `vulnhuntr/symbol_finder.py` (Jedi integration)
- `vulnhuntr/prompts.py` (prompt templates)
- `docs/ARCHITECTURE.md` (design decisions)
- `docs/AREAS_OF_IMPROVEMENT.md` (known issues, roadmap)

### 3. Decision-Making Framework

**Evaluate every decision** on:
1. **Research** - Is this based on facts or assumptions?
2. **Context** - Does this fit the project's architecture?
3. **Security** - Is this secure for a security tool?
4. **Cost** - What's the LLM API cost impact?
5. **Maintainability** - Can this be maintained long-term?

### 4. Code Changes

**Before any code change**:
- [ ] Understand why current code is the way it is
- [ ] Check if change affects LLM integration (consult prompt-engineering agent)
- [ ] Verify Python 3.10-3.13 compatibility
- [ ] Consider cost implications (token usage, API calls)
- [ ] Review security impact (consult code-review agent)
- [ ] Ensure Pydantic validation still works
- [ ] Test manually with real vulnerable code

**After code change**:
- [ ] Run `ruff check --fix . && ruff format .`
- [ ] Test symbol resolution (Jedi integration)
- [ ] Verify LLM calls still work (all providers)
- [ ] Check cost impact (if LLM-related)
- [ ] Update documentation if needed

---

## Common Pitfalls to Avoid

**Based on [`AGENT.md`](../AGENT.md) Emergency Procedures**:

1. **Don't update Python beyond 3.13** - Jedi/Parso won't work
2. **Don't skip Pydantic validation** - LLMs are unreliable
3. **Don't use max_tokens=4096** - Use 8192 (truncation issues)
4. **Don't forget Claude prefill** - Reduces JSON wrapping issues
5. **Don't skip response sanitization** - API keys, paths must be redacted
6. **Don't ignore cost tracking** - LLM calls are expensive
7. **Don't guess dependencies** - Check pyproject.toml and documentation

---

## Integration Points

### Architecture Documentation

- **[docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md)** - Design patterns, decisions
- **[docs/AREAS_OF_IMPROVEMENT.md](../docs/AREAS_OF_IMPROVEMENT.md)** - Known issues, future work
- **[docs/MCP_SERVERS.md](../docs/MCP_SERVERS.md)** - Potential MCP integrations

### Testing & Debugging

- **[scripts/llm_api_test.py](../scripts/llm_api_test.py)** - Debug LLM integration
- **[scripts/README.md](../scripts/README.md)** - Testing documentation
- **[docs/archive/](../docs/archive/)** - Historical issues and solutions

---

## For Users (Repository Maintainers)

**This configuration ensures**:
- Copilot automatically references all agent guidelines
- Code suggestions follow project patterns
- Security is never compromised
- Python version constraints are respected
- LLM integration best practices are applied
- Cost implications are considered

**Automatic Loading**: This file (`.github/copilot-instructions.md`) is **automatically loaded** by GitHub Copilot in all contexts:
- ✅ **GitHub Copilot Chat** - References agents in every conversation
- ✅ **GitHub Copilot Code Completions** - Follows patterns in suggestions
- ✅ **GitHub Copilot Code Review** - Applies guidelines to PR reviews
- ✅ **Copilot Coding Agent** - Uses instructions for autonomous tasks

No configuration needed! The file location (`.github/copilot-instructions.md`) is the standard for repository-wide instructions.

**To verify it's working**:
1. **Open GitHub Copilot Chat** in VS Code (or GitHub.com)
2. **Ask**: "What are the critical constraints for this project?"
3. **Expected response**: Should mention Python 3.10-3.13, Pydantic validation, max_tokens=8192, security-first, never guess
4. **Check references**: Expand the "References" section at the top of the response
5. **Verify**: `.github/copilot-instructions.md` should be listed as a reference

**If not working**:
- ✅ Ensure GitHub Copilot is enabled in VS Code
- ✅ Restart VS Code to reload configuration  
- ✅ Check that `.github/copilot-instructions.md` exists in repository root
- ✅ Verify file is committed to repository (not just locally)
- ✅ Open Copilot Diagnostics: Right-click in Chat → Diagnostics → Check "Custom Instructions" section

**Troubleshooting**:
- Run: `git status` to ensure file is tracked
- Run: `ls -la .github/` to verify file exists
- Check Copilot settings: VS Code → Settings → GitHub Copilot → Custom Instructions (should be enabled by default)
- View diagnostics: Right-click in Copilot Chat panel → Select "Diagnostics"

---

## Version History

- **1.0.0** (2026-02-04): Initial comprehensive agent system configuration
  - Main coordinator (AGENT.md): 27KB
  - Code review agent: 15KB (security, LLM, Python, Jedi, performance)
  - Prompt engineering agent: 20KB (vulnerability prompts, validation, iteration)
  - Python agent: Adapted for 3.10-3.13 strict
  - Git workflow: Python-focused (ruff, pytest)
  - PR conventions: Vulnhuntr scopes (llm, analysis, prompts)
  - Logging: structlog, sanitization, cost tracking
  - Dependency management: Python constraints, Jedi/Parso versioning

---

**Remember**: This is a security tool analyzing code for vulnerabilities. Every suggestion must uphold the highest standards of security, correctness, and reliability.
