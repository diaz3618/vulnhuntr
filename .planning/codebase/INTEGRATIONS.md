# External Integrations

**Analysis Date:** 2026-04-08

## APIs & External Services

**LLM Providers:**
- Anthropic Claude — primary LLM for vulnerability analysis
  - SDK/Client: `anthropic` (class `Claude` in `vulnhuntr/llms.py`)
  - Auth: `ANTHROPIC_API_KEY` env var; base URL `ANTHROPIC_BASE_URL`
  - Model: `ANTHROPIC_MODEL` env var (default: `claude-3-5-sonnet-latest`)

- OpenAI ChatGPT — secondary provider
  - SDK/Client: `openai` (class `ChatGPT` in `vulnhuntr/llms.py`)
  - Auth: `OPENAI_API_KEY` env var; base URL `OPENAI_BASE_URL`
  - Model: `OPENAI_MODEL` env var (default: `chatgpt-4o-latest`)

- OpenRouter — OpenAI-compatible API proxy (free models)
  - SDK/Client: `openai` reused with custom base URL (class `OpenRouter` in `vulnhuntr/llms.py`)
  - Auth: `OPENROUTER_API_KEY` env var; base URL `OPENROUTER_BASE_URL`
  - Model: `OPENROUTER_MODEL` env var (default: `qwen/qwen3-coder:free`)

- Ollama — local inference via HTTP
  - SDK/Client: `requests` (class `Ollama` in `vulnhuntr/llms.py`)
  - Auth: None (local)
  - Base URL: `OLLAMA_BASE_URL` (default: `http://127.0.0.1:11434/api/generate`)
  - Model: `OLLAMA_MODEL` env var (default: `llama3`)

**MCP Servers (optional):**
- Any MCP-compatible server configured in `.vulnhuntr.yaml`
  - Client: `vulnhuntr/mcp/client.py` (`MCPClientManager`, async context manager)
  - Auth: per-server env vars in `MCPServerConfig.env`
  - Transports: stdio, streamable-http, sse (config: `vulnhuntr/mcp/config.py`)
  - **Status: NOT integrated into main analysis pipeline** (client exists but is standalone)

## Data Storage

**Databases:**
- None — Vulnhuntr is stateless; no database required

**File Storage:**
- Local filesystem only
  - Checkpoint files: `.vulnhuntr_checkpoint/` directory (JSON, managed by `vulnhuntr/checkpoint.py`)
  - Reports: output paths specified via CLI flags (HTML, SARIF, JSON, CSV, Markdown)

**Caching:**
- No external cache; Jedi project object is reused within a single run

## Authentication & Identity

**Auth Provider:**
- None
- All provider auth is via API keys in environment variables

## Monitoring & Observability

**Error Tracking:**
- None (no external error tracking service)

**Logs:**
- Structured JSON via `structlog` (all modules)
- Log level controlled by `-v`/`-vv` CLI flags
- Output to stderr only (no log files by default)

## CI/CD & Deployment

**Hosting:**
- PyPI (package distribution)
- Docker (optional, `Dockerfile` present)

**CI Pipeline:**
- GitHub Actions (`.github/workflows/`)
  - `test.yml` — pytest suite
  - `codeql.yml` — GitHub CodeQL security scan
  - `semgrep.yml` — Semgrep SAST
  - `trivy.yml` — container/dependency vulnerability scan
  - `publish.yml` — PyPI publish
  - `release.yml` — semantic release

## Outbound Integrations

**GitHub Issues (optional):**
- Class `GitHubIssueCreator` in `vulnhuntr/integrations/github_issues.py`
- SDK: `requests` via REST API (`https://api.github.com`)
- Auth: `GITHUB_TOKEN` env var (passed in `GitHubConfig.token`)
- Opt-in — not enabled by default

**Webhooks (optional):**
- Class `WebhookNotifier` in `vulnhuntr/integrations/webhook.py`
- SDK: `requests`
- Signing: HMAC-SHA256 (`hashlib`, `hmac`) with configurable secret
- Formats: JSON, Slack, Discord, Microsoft Teams (`PayloadFormat` enum)
- Retry: exponential backoff, configurable `max_retries` / `retry_delay`
- Opt-in — not enabled by default

## Environment Configuration

**Required env vars (by provider):**
- Claude: `ANTHROPIC_API_KEY`
- GPT: `OPENAI_API_KEY`
- OpenRouter: `OPENROUTER_API_KEY`
- Ollama: none (local)

**Optional env vars:**
- `ANTHROPIC_MODEL`, `OPENAI_MODEL`, `OPENROUTER_MODEL`, `OLLAMA_MODEL`
- `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, `OPENROUTER_BASE_URL`, `OLLAMA_BASE_URL`
- `GITHUB_TOKEN` (for GitHub issue integration)

**Secrets location:**
- `.env` file (gitignored) loaded by `dotenv.load_dotenv()` at startup
- Shell environment can override `.env` values

---

*Integration audit: 2026-04-08*
