# Architecture

Vulnhuntr combines Jedi-based static analysis with LLM reasoning to identify remotely exploitable vulnerabilities in Python codebases. It traces complete code call chains from remote user input to server output, surfacing complex vulnerabilities that pattern-matching tools miss.

## Vulnerability Types

- Local File Inclusion (LFI)
- Arbitrary File Overwrite (AFO)
- Remote Code Execution (RCE)
- Cross-Site Scripting (XSS)
- SQL Injection (SQLI)
- Server-Side Request Forgery (SSRF)
- Insecure Direct Object Reference (IDOR)

## LLM Providers

- Anthropic Claude (recommended)
- OpenAI GPT
- OpenRouter
- Ollama (experimental)

## Technical Stack

- Python 3.10–3.13 — Jedi/Parso compatibility requirement
- `jedi` 0.19.2+, `parso` 0.8.5+: static analysis and symbol resolution
- `anthropic` 0.77.1+, `openai` 1.51.2+: API clients
- `pydantic` 2.8.0+, `pydantic-xml`: response validation and prompt serialization
- `structlog`, `rich`: logging and terminal output

## Component Overview

| Component | Responsibility | Input | Output |
|-----------|---------------|-------|--------|
| **CLI Entry** (`__main__.py`) | Parse arguments, orchestrate flow | Command-line args | Execution control |
| **RepoOps** | Repository scanning, file filtering | Repository path | Filtered file list |
| **LLM Factory** | Instantiate appropriate LLM client | LLM choice, config | LLM client instance |
| **Symbol Extractor** | Resolve Python symbols via Jedi | Symbol names, code lines | Code definitions |
| **Prompt Templates** | Provide structured analysis prompts | Analysis type | XML-formatted prompts |
| **LLM Clients** | Communicate with LLM APIs | Prompts, schemas | Structured responses |
| **Analysis Pipeline** | Iterative vulnerability analysis | File code, context | Vulnerability reports |

## Design Decisions

- Python 3.10–3.13 only (Jedi/Parso compatibility)
- `max_tokens=8192` prevents JSON truncation in long responses
- 7 iteration cap per vulnerability type balances thoroughness with API cost
- Claude prefill technique forces JSON output structure
- Network-related file filtering focuses analysis on the attack surface
- Third-party libraries are handled via LLM knowledge rather than source fetching

## Files

- [components.md](components.md) — Detailed component implementations
- [analysis-pipeline.md](analysis-pipeline.md) — Data flow and iterative context expansion algorithm
- [data-models.md](data-models.md) — Pydantic models and data types
- [configuration.md](configuration.md) — Environment variables, CLI arguments, logging
- [diagrams.md](diagrams.md) — Process flow diagrams
