# Vulnhuntr Agent System

**Version**: 1.0.0  
**Completed**: February 4, 2026  
**Status**: ✅ Production Ready

---

## Quick Start

This repository has a **comprehensive agent system** that GitHub Copilot uses automatically.

### What This Means

When you ask GitHub Copilot questions in this workspace:
1. It **automatically references** [AGENT.md](../AGENT.md)
2. It **consults specialized sub-agents** for domain-specific guidance
3. It **enforces project constraints** (Python 3.10-3.13, security-first, cost-aware)
4. It **maintains context** through knowledge refresh protocol
5. It **never guesses** - researches before answering

### To Verify It's Working

Ask GitHub Copilot: *"What are the critical constraints for this project?"*

It should mention:
- Python 3.10-3.13 strict (Jedi/Parso compatibility)
- LLM response validation with Pydantic
- max_tokens=8192 (not 4096)
- Security-first approach
- Cost tracking

---

## Agent Architecture

```
📄 AGENT.md (27KB)
   Main coordinator - routes to specialists
   ├── 🔒 code-review/SKILL.md (15KB)
   │   Security, LLM integration, Python, Jedi, performance
   ├── 🎯 prompt-engineering.md (20KB)
   │   Vulnerability prompts, XML structure, validation
   ├── 🐍 python.md
   │   Python 3.10-3.13, type hints, security patterns
   ├── 🌿 git-workflow.md
   │   Branch protection, ruff, pytest
   ├── 📝 pr-conventions.md
   │   Conventional commits, Vulnhuntr scopes
   ├── 📊 logging.md
   │   structlog, sanitization, cost tracking
   └── 📦 dependency-management.md
       pip, Jedi/Parso versioning, security
```

**Auto-Activation**: [.github/copilot-instructions.md](../.github/copilot-instructions.md)

---

## Critical Constraints (Never Violate)

1. **Python 3.10-3.13 ONLY**
   - Jedi 0.19.2+ requires this range
   - Python 3.14+ not supported yet
   - Python <3.10 missing features

2. **All LLM Responses MUST Be Validated**
   - Use Pydantic models
   - Handle markdown JSON wrappers
   - Graceful fallback on validation errors

3. **Security First**
   - This tool finds vulnerabilities
   - Must be secure itself
   - Sanitize all sensitive data in logs

4. **Cost Awareness**
   - max_tokens=8192 (not 4096)
   - Track all LLM API calls
   - Optimize token usage

5. **Never Guess**
   - Research before answering
   - Consult documentation
   - Read existing code patterns

---

## How to Use the Agents

### For Development

**Before Making Changes**:
```bash
# 1. Check which agents are relevant
# LLM changes? → prompt-engineering.md
# Symbol resolution? → python.md, code-review/SKILL.md
# Dependencies? → dependency-management.md

# 2. Read the relevant agent
# Copilot does this automatically, but you can too

# 3. Make changes following agent guidance

# 4. Run quality checks
ruff check --fix .
ruff format .

# 5. Test manually
python -m vulnhuntr /path/to/test/repo
```

### For Code Review

The code-review agent checks:
- ✅ Security (prompt injection, API keys, sanitization)
- ✅ LLM integration (validation, error handling, cost)
- ✅ Python standards (type hints, PEP 8, compatibility)
- ✅ Jedi integration (error handling, three-tier search)
- ✅ Performance (token optimization, caching)
- ✅ Testing (mocking, edge cases)

### For Pull Requests

Follow [pr-conventions.md](docs/agents/pr-conventions.md):

```bash
# Create feature branch
git checkout -b feat/my-feature

# Make changes
git add specific-files
git commit -m "feat(llm): add Ollama support"

# Quality checks
ruff check --fix .
ruff format .

# Push and create draft PR
git push -u origin feat/my-feature
gh pr create --draft --title "feat(llm): add Ollama local model support"
```

---

## Agent Specializations

### 🔒 Code Review ([code-review/SKILL.md](docs/agents/code-review/SKILL.md))

**Consult for**:
- Security reviews
- LLM integration patterns
- Python best practices
- Jedi symbol resolution
- Performance optimization

**Example Questions**:
- "Review this LLM integration for security issues"
- "Is this Jedi usage correct?"
- "How can I optimize token usage here?"

### 🎯 Prompt Engineering ([prompt-engineering.md](docs/agents/prompt-engineering.md))

**Consult for**:
- Vulnerability detection prompts
- XML prompt structure
- Provider-specific techniques
- Response validation
- Iterative context expansion

**Example Questions**:
- "How should I structure this vulnerability prompt?"
- "What's the Claude prefill pattern?"
- "How do I validate LLM responses?"

### 🐍 Python ([python.md](docs/agents/python.md))

**Consult for**:
- Python version compatibility
- Type hints and patterns
- Jedi/Parso constraints
- Security-conscious Python

**Example Questions**:
- "Is this Python 3.10-3.13 compatible?"
- "What type hints should I use here?"
- "How do I handle Jedi failures?"

### 🌿 Git Workflow ([git-workflow.md](docs/agents/git-workflow.md))

**Consult for**:
- Branch protection rules
- Commit workflow
- Quality checks before PR

**Example Questions**:
- "What's the correct git workflow?"
- "What commands should I run before pushing?"

### 📝 PR Conventions ([pr-conventions.md](docs/agents/pr-conventions.md))

**Consult for**:
- Commit message format
- Scope selection
- Type selection

**Example Questions**:
- "What scope should I use for an LLM change?"
- "Is this a feat or a fix?"
- "How do I format breaking changes?"

### 📊 Logging ([logging.md](docs/agents/logging.md))

**Consult for**:
- structlog patterns
- Sensitive data sanitization
- Cost tracking

**Example Questions**:
- "How do I log API keys safely?"
- "What log level should I use?"
- "How do I track LLM costs?"

### 📦 Dependency Management ([dependency-management.md](docs/agents/dependency-management.md))

**Consult for**:
- Version constraints
- Security updates
- Testing after updates

**Example Questions**:
- "Can I update Jedi to 0.20.0?"
- "How do I check for security vulnerabilities?"
- "What dependencies are version-locked?"

---

## Knowledge Refresh Protocol

**Triggers** (agent automatically re-reads core files):
- After 20+ interactions
- Before major architectural changes
- When unfamiliar with recent code
- When encountering repeated failures
- When project constraints change

**Core Files to Refresh**:
1. `AGENT.md` - Main coordinator
2. `vulnhuntr/__main__.py` - Entry point
3. `vulnhuntr/LLMs.py` - LLM clients
4. `vulnhuntr/symbol_finder.py` - Jedi integration
5. `vulnhuntr/prompts.py` - Prompt templates
6. `docs/ARCHITECTURE.md` - Design decisions
7. `docs/AREAS_OF_IMPROVEMENT.md` - Roadmap

---

## Troubleshooting

### Agent Not Working?

1. **Restart VS Code** - Reloads configuration
2. **Check file exists**: `.github/copilot-instructions.md`
3. **Test with question**: "What are this project's constraints?"
4. **Verify GitHub Copilot is enabled** in VS Code

### Agent Giving Wrong Advice?

1. **Check agent version** in file headers
2. **Update agents** if codebase has changed significantly
3. **Re-read AGENT.md** - May need manual refresh
4. **Consult AREAS_OF_IMPROVEMENT.md** - Known limitations

### Need to Update Agents?

See [AGENT_STATUS.md](docs/AGENT_STATUS.md) for:
- Current version of each agent
- When to update
- How to update
- Testing checklist

---

## Statistics

- **Total Agents**: 10 (1 main, 7 sub-agents, 1 auto-activation, 1 archived)
- **Total Documentation**: ~90KB
- **Implementation Time**: ~8 hours
- **Languages**: Python 3.10-3.13
- **Focus**: Security, LLM integration, cost optimization

---

## Version History

- **1.0.0** (2026-02-04): Initial complete implementation
  - Main coordinator (27KB)
  - 7 specialized sub-agents
  - Auto-activation configured
  - All Vulnhuntr-specific

---

## For Maintainers

### Updating Agents

When project changes significantly:

1. **Identify affected agents**
   - LLM changes → prompt-engineering.md
   - New Python version → python.md, dependency-management.md
   - New vulnerability type → prompt-engineering.md, code-review/SKILL.md

2. **Update agent content**
   - Add new patterns
   - Update examples
   - Revise constraints if needed

3. **Update version number** in agent file

4. **Test with Copilot**
   - Ask questions that should reference new content
   - Verify guidance is correct

5. **Update AGENT_STATUS.md**
   - Document changes
   - Update version history

### Adding New Agents

1. Create in `docs/agents/`
2. Follow existing structure
3. Add reference in `AGENT.md`
4. Add reference in `.github/copilot-instructions.md`
5. Update `AGENT_STATUS.md`
6. Test with Copilot

---

## Support

- **Main Coordinator**: [AGENT.md](../AGENT.md)
- **Status Tracking**: [docs/AGENT_STATUS.md](docs/AGENT_STATUS.md)
- **Architecture**: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- **Roadmap**: [docs/AREAS_OF_IMPROVEMENT.md](docs/AREAS_OF_IMPROVEMENT.md)

---

**Remember**: This is a security tool. Every change must uphold the highest standards of security, correctness, and reliability. The agents are here to help you maintain these standards.
