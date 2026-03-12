# Vulnhuntr: AI-Assisted Vulnerability Scanning

**Course**: CS5374 — Trustworthy AI  
**Semester**: Spring 2026

## Project Group

- Daniel Diaz Santiago
- Luke Josiah

## Executive Summary

Vulnhuntr is a Python security scanner that combines static code navigation (using Jedi/Parso) with LLM reasoning (Claude, GPT, and Ollama) to trace remotely reachable call chains from user input to dangerous sinks.

In its original state, it prints results to the terminal and writes structured JSON logs, but it does not produce persistent, standards-based report files. It also warns that LLM usage can "rack up hefty bills", yet has no built-in cost estimation, budgeting, or methods to limit LLM API usage.

This project improves trustworthiness by adding cost governance (predictable spending, and limits) and auditable reporting/integration. The goal is to make LLM-assisted security analysis safer to operate, easier to review, and easier to integrate with newer tools that might improve its functionality — for example, MCP servers, extending it past Python only, and possibly isolating it in containers to avoid MCP servers overreaching and causing damage to the user's file system.

## First-Round Deliverables

1. Add token/cost tracking around LLM calls and a summary at the end of a run.
2. Add a dry-run mode to estimate token usage and dollar cost before spending.
3. Add budget enforcement (warn + hard stop) to prevent runaway costs.
4. Add checkpointing and resume to recover from interruptions without restarting.
5. Add minimal configuration support (e.g., optional project config file) and document the new flags.

## Second-Round Deliverables

1. Generate persistent report artifacts: SARIF (CI/Code Scanning), plus human-readable HTML.
2. Add additional exports for triage workflows (JSON/CSV/Markdown) without changing core analysis logic.
3. Add optional integrations to route findings to external systems (e.g., GitHub Issues and/or generic webhooks).
4. MCP server integration to expand Vulnhuntr's abilities. Current considerations include: Filesystem MCP server, Ripgrep MCP server, Tree-sitter MCP server, CodeQL MCP server, Process MCP server. Some may be integrated directly, while others will be added through a config file.
5. Provide usage examples and verification steps showing baseline upstream behavior vs. the new trustworthy-operational controls.
6. Improve documentation.
7. Possible refactor to make the codebase more modular and easier to maintain; the current codebase concentrates large amounts of code in a few .py files.

## References

1. Protect AI. "Vulnhuntr: Zero Shot Vulnerability Discovery Using LLMs." GitHub, 2024. <https://github.com/protectai/vulnhuntr>
2. Protect AI. "Vulnhuntr: The First 0-Day Vulnerabilities Discovered by AI." Blog post, 2024.
3. CVE Details. "CVE-2024-10100, CVE-2024-10101, CVE-2024-10099, CVE-2024-10131, CVE-2024-10044, CVE-2024-9309." <https://www.cvedetails.com/>
4. Anthropic. "Claude 3.5 Sonnet Model Documentation." 2024.
5. OpenAI. "GPT-4 Technical Report." 2024.
6. OWASP. "OWASP Top 10." 2021. <https://owasp.org/www-project-top-ten/>
7. Pearce et al. "Can Large Language Models Find And Fix Vulnerable Software?" arXiv:2308.10345, 2023.
