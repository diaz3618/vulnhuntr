# Vulnhuntr Quick Start Guide

Get up and running with Vulnhuntr in minutes. This guide covers the essential steps to set up and run the vulnerability scanner successfully.

---

## Prerequisites

- **Python 3.12 or 3.13** (earlier versions may have compatibility issues)
- **API Key** from Anthropic (Claude) or OpenAI
- **Git** (for cloning if needed)
- **Target repository** to scan (Python codebase recommended)

---

## Step 1: Clone or Navigate to Project

```bash
cd /path/to/vulnhuntr
```

---

## Step 2: Create Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

## Step 3: Install Dependencies

### Option A: Install from requirements.txt (Recommended)

```bash
pip install -r requirements.txt
```

### Option B: Install in editable mode

```bash
pip install -e .
```

### Common Issues & Fixes

**Issue: Python 3.13 compatibility errors with jedi/parso**

If you see errors about `jedi` or `parso`, upgrade them:

```bash
pip install --upgrade jedi>=0.19.2 parso>=0.8.5
```

**Issue: Missing packages**

If you get import errors, install these explicitly:

```bash
pip install anthropic openai pydantic rich python-dotenv requests
```

---

## Step 4: Configure API Keys

Create a `.env` file in the project root:

```bash
touch .env
```

### For Claude (Anthropic) - Recommended

Add to `.env`:

```dotenv
ANTHROPIC_BASE_URL=https://api.anthropic.com
ANTHROPIC_API_KEY=sk-ant-api03-YOUR_KEY_HERE
ANTHROPIC_MODEL=claude-sonnet-4-5
```

### For OpenAI (GPT)

Add to `.env`:

```dotenv
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=chatgpt-4o-latest
OPENAI_API_KEY=sk-proj-YOUR_KEY_HERE
```

### For Custom Endpoints

You can use custom OpenAI-compatible endpoints:

```dotenv
OPENAI_BASE_URL=https://your-custom-endpoint.com/v1
OPENAI_MODEL=your-model-name
OPENAI_API_KEY=your-custom-key
```

---

## Step 5: Clear Conflicting Environment Variables

**CRITICAL STEP**: If you have API keys set as shell environment variables, they will override your `.env` file.

Check for conflicts:

```bash
env | grep -E "ANTHROPIC_API_KEY|OPENAI_API_KEY"
```

If you see old/wrong keys, unset them:

```bash
unset ANTHROPIC_API_KEY
unset OPENAI_API_KEY
```

**Make it permanent** by removing these from your shell config files:
- `~/.bashrc`
- `~/.bash_profile`
- `~/.profile`
- `~/.zshrc` (if using zsh)

---

## Step 6: Verify Installation

Check that vulnhuntr is accessible:

```bash
vulnhuntr -h
```

You should see the help menu with usage instructions.

---

## Step 7: Run Your First Scan

### Basic Scan (Using Claude)

```bash
vulnhuntr -r /path/to/target/repository
```

### Scan with Verbose Output

```bash
vulnhuntr -r /path/to/target/repository -v
```

### Scan with OpenAI/GPT

```bash
vulnhuntr -r /path/to/target/repository -l gpt
```

### Scan Specific Vulnerabilities

```bash
vulnhuntr -r /path/to/target/repository --vuln-types sqli,xss,ssrf
```

---

## Common Issues & Solutions

### 1. JSON Validation Errors

**Error:**
```
ValidationError: Invalid JSON: EOF while parsing a list
```

**Cause:** LLM response is being truncated (max_tokens too small).

**Solution:** The code has been patched to use 8192 tokens. If you still see this, check [vulnhuntr/__main__.py](vulnhuntr/__main__.py) lines 395 and 464:

```python
# Should have max_tokens=8192
initial_analysis_report: Response = llm.chat(user_prompt, response_model=Response, max_tokens=8192)
secondary_analysis_report: Response = llm.chat(vuln_specific_user_prompt, response_model=Response, max_tokens=8192)
```

### 2. Markdown-Wrapped JSON Responses

**Error:**
```
ValidationError: Invalid JSON (markdown code blocks)
```

**Cause:** Claude sometimes wraps JSON in ```json ... ``` blocks.

**Solution:** Already patched in [vulnhuntr/LLMs.py](vulnhuntr/LLMs.py) line 47. The code strips markdown:

```python
# Strip markdown code blocks if present
import re
match = re.search(r'\{.*\}', response_text, re.DOTALL)
if match:
    response_text = match.group(0)
```

### 3. Wrong API Key Being Used

**Symptom:** Your `.env` file has the right key but wrong one is used.

**Cause:** Shell environment variable overrides `.env`.

**Solution:** See Step 5 above - unset environment variables.

### 4. Model Not Found (404 Error)

**Error:**
```
APIStatusError: Received non-200 status code: 404
```

**Cause:** Using deprecated model names like `claude-sonnet-4` or old model identifiers.

**Solution:** Update your `.env` to use current model names:

```dotenv
# Claude
ANTHROPIC_MODEL=claude-sonnet-4-5

# OpenAI
OPENAI_MODEL=chatgpt-4o-latest
```

### 5. API Authentication Errors

**Error:**
```
APIConnectionError or 401 Unauthorized
```

**Solution:**
- Verify your API key is valid and not expired
- Check that you have credits/access to the model
- Ensure `.env` is in the project root (not in `.venv/`)
- Restart your terminal session after updating `.env`

### 6. Python Version Incompatibility

**Error:**
```
ImportError or syntax errors in dependencies
```

**Solution:** 
- Use Python 3.12 or 3.13
- Upgrade jedi and parso: `pip install --upgrade jedi parso`

### 7. Rate Limiting

**Error:**
```
RateLimitError: Request was rate-limited
```

**Solution:**
- Wait a few minutes and try again
- Use a different API key if available
- Consider using a paid tier for higher limits

---

## Understanding the Output

### Verbose Mode (`-v`)

Shows real-time analysis including:
- Files being analyzed
- Vulnerability types being checked
- Confidence scores (1-10)
- Context code snippets
- Analysis reasoning ("scratchpad")

### Report File

Vulnhuntr generates a JSON report file with:
- Detected vulnerabilities
- File paths and line numbers
- Confidence scores
- Proof-of-concept exploits
- Remediation suggestions

### Log File

Check `vulnhuntr.log` for detailed debugging information:

```bash
tail -f vulnhuntr.log  # Watch logs in real-time
```

---

## Performance Tips

1. **Start Small**: Test on a small repository first (< 10 files)
2. **Use Specific Vuln Types**: Don't scan for everything at once
3. **Monitor Costs**: Claude/GPT API calls can be expensive for large codebases
4. **Save Logs**: Keep logs for debugging and analysis

---

## Example Workflow

```bash
# 1. Activate environment
source .venv/bin/activate

# 2. Verify configuration
cat .env | grep API_KEY

# 3. Clear any conflicting env vars
unset OPENAI_API_KEY ANTHROPIC_API_KEY

# 4. Test on a small target
vulnhuntr -r ~/my-small-project -v

# 5. For larger projects, target specific vulnerabilities
vulnhuntr -r ~/large-project --vuln-types sqli,xss -v

# 6. Review the results
cat vulnhuntr_report_*.json | jq '.'
```

---

## Command Reference

### Basic Usage

```bash
vulnhuntr -r <repository_path> [options]
```

### Common Options

| Option | Description |
|--------|-------------|
| `-r, --root` | Path to target repository (required) |
| `-v, --verbosity` | Increase output verbosity (use -v, -vv, -vvv) |
| `-l, --llm` | LLM to use: `claude` (default) or `gpt` |
| `--vuln-types` | Comma-separated list of vulnerability types |
| `-h, --help` | Show help message |

### Supported Vulnerability Types

- `sqli` - SQL Injection
- `xss` - Cross-Site Scripting
- `ssrf` - Server-Side Request Forgery
- `idor` - Insecure Direct Object Reference
- `lfi` - Local File Inclusion
- `rce` - Remote Code Execution
- `afo` - Arbitrary File Overwrite
- And more...

---

## Advanced Configuration

### Using Local LLM (Ollama)

```dotenv
OPENAI_BASE_URL=http://localhost:11434/v1
OPENAI_MODEL=codellama
OPENAI_API_KEY=not-needed
```

### Custom System Prompts

Edit [vulnhuntr/prompts.py](vulnhuntr/prompts.py) to customize analysis behavior.

### Adjusting Token Limits

Edit [vulnhuntr/__main__.py](vulnhuntr/__main__.py) to change `max_tokens` values if needed.

---

## Troubleshooting Checklist

- [ ] Python 3.12+ installed?
- [ ] Virtual environment activated?
- [ ] All dependencies installed?
- [ ] `.env` file exists in project root?
- [ ] Valid API key in `.env`?
- [ ] No conflicting environment variables?
- [ ] Model name is current (not deprecated)?
- [ ] Target repository path is correct?
- [ ] Sufficient API credits available?

---

## Quick Reference Card

```bash
# Setup (one-time)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
unset ANTHROPIC_API_KEY OPENAI_API_KEY

# Run (every time)
source .venv/bin/activate
vulnhuntr -r /path/to/repo -v

# Deactivate when done
deactivate
```