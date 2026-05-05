# Technology Stack

**Project:** Vulnhuntr — AI CLI tool integration
**Researched:** 2026-05-01
**Milestone context:** Expand current `v1.0` milestone without removing API-key providers

## Current Stack To Keep

| Technology | Role | Status |
|------------|------|--------|
| Python 3.10–3.13 | Runtime | Keep |
| `anthropic` SDK | Claude API provider | Keep |
| `openai` SDK | OpenAI + OpenRouter providers | Keep |
| `requests` | HTTP integrations | Keep |
| `structlog` | Structured diagnostics | Keep |
| `pydantic` | Response validation | Keep |
| `python-dotenv` | `.env` loading | Keep |
| `mcp` extra | Vulnhuntr-managed MCP client | Keep and integrate |

## Recommended Additions

### Production code

| Technology | Purpose | Why |
|------------|---------|-----|
| `subprocess` / `asyncio.subprocess` (stdlib) | Headless CLI provider execution | Prefer no new runtime dependency for first-class CLI backends |
| `shutil.which` (stdlib) | Provider capability probe | Detect installed tools before scan start |
| `tempfile` / `pathlib` (stdlib) | Isolated workdirs per provider | Needed for safe session and artifact handling |
| `importlib.metadata` (stdlib) | Optional provider version detection | Surface actionable diagnostics and capability gating |

### Optional only if justified during implementation

| Technology | Purpose | Why optional |
|------------|---------|-------------|
| Provider SDKs (`claude-code` SDK, Codex SDK, etc.) | Deeper native integration | Start with headless CLI transport first; SDKs add maintenance surface |
| `packaging` | Version comparison helpers | Only needed if provider version gating becomes complex |

## Provider Research Highlights

### Claude Code

- Official CLI supports print mode, JSON output, explicit permission modes, MCP config loading, and `--continue` / `--resume`.
- Strong fit for account-auth and session reuse.
- Good candidate for a first provider because this repo already has a local experiment proving a transport swap.

### Gemini CLI

- Official docs describe OAuth sign-in, API-key mode, MCP support, Google Search grounding, checkpointing, and non-interactive mode.
- Docs also describe JSON output, but the upstream repo has had version drift around `--output-format json`; Vulnhuntr should probe capabilities at runtime instead of assuming them.

### Codex CLI

- OpenAI’s current docs confirm local terminal execution, ChatGPT sign-in or API-key authentication, approval modes, MCP support, and scripting via `codex exec`.
- Good fit for tool use and coding-agent workflows, but sandbox behavior varies enough that Vulnhuntr should treat sandbox/approval settings as explicit config, not hidden defaults.

### Qwen Code

- Official docs describe headless mode, JSON and stream-json output, `--continue` / `--resume`, MCP server config, and multiple auth paths.
- Important differentiator: it can operate as a CLI frontend to third-party APIs, which makes it both a direct backend and a bridge for users who still want API-key-based execution through a mature local agent.

## Config Surface That Should Be Added To `.vulnhuntr.yaml`

Recommended shape:

```yaml
llm:
  provider: claude-code
  model: opus
  fallback1: qwen-code:qwen3-coder-plus
  fallback2: openrouter:qwen/qwen3-coder:free

cli:
  timeout_seconds: 300
  workdir: .vulnhuntr/cli
  auth_mode: auto
  session_mode: stateless
  resume_session: null
  approval_mode: read_only
  sandbox_mode: provider-default
  max_turns: 4
  capture_transcript: true
  capability_probe: true
  mcp_mode: hybrid

providers:
  claude_code:
    continue_session: false
    permission_mode: plan
  gemini_cli:
    use_google_search: false
  codex:
    reasoning_effort: medium
  qwen_code:
    approval_mode: auto_edit
```

## `.env` / Environment Variables To Document

Vulnhuntr should continue loading `.env`, but it must document that some tools also use their own config dirs.

Core env vars to document:

- `ANTHROPIC_API_KEY`
- `OPENAI_API_KEY`
- `OPENROUTER_API_KEY`
- `GEMINI_API_KEY`
- `GOOGLE_CLOUD_PROJECT`
- `DASHSCOPE_API_KEY`
- `BAILIAN_CODING_PLAN_API_KEY`
- `ANTHROPIC_MODEL`
- `OPENAI_MODEL`
- `OPENROUTER_MODEL`
- `OLLAMA_MODEL`

Recommended Vulnhuntr-specific additions:

- `VULNHUNTR_CLI_TIMEOUT_SECONDS`
- `VULNHUNTR_CLI_WORKDIR`
- `VULNHUNTR_CLI_AUTH_MODE`
- `VULNHUNTR_CLI_SESSION_MODE`
- `VULNHUNTR_CLI_RESUME_SESSION`
- `VULNHUNTR_CLI_APPROVAL_MODE`
- `VULNHUNTR_CLI_SANDBOX_MODE`
- `VULNHUNTR_CLI_MAX_TURNS`
- `VULNHUNTR_CLI_MCP_MODE`

## Sources

- Claude Code CLI reference: https://code.claude.com/docs/en/cli-reference
- Claude Code sessions: https://code.claude.com/docs/en/agent-sdk/sessions
- Codex CLI docs: https://developers.openai.com/codex/cli
- Gemini CLI repo/docs: https://github.com/google-gemini/gemini-cli
- Qwen Code auth: https://qwenlm.github.io/qwen-code-docs/en/users/configuration/auth/
- Qwen Code headless mode: https://qwenlm.github.io/qwen-code-docs/en/users/features/headless/
