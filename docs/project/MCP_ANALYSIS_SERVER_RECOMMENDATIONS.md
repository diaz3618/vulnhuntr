# MCP Analysis Server Recommendations for Vulnhuntr

> **Last updated**: 2025-07-19
> **Research sources**: [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers), [GitHub Topics](https://github.com/topics/mcp-server), [mcp.so](https://mcp.so/servers?category=security)

This document catalogues MCP servers that can enhance Vulnhuntr's vulnerability
analysis when connected via the optional MCP analysis integration
(`vulnhuntr/mcp/`). Servers are grouped by category with install commands,
relevance notes, and risk assessments.

## How Vulnhuntr Uses MCP Servers

When `analysis.mode` is set to `auto` or `force` in `mcp_config.yaml`, the LLM
can request tool calls from connected MCP servers during its analysis iterations.
This lets the model:

- Cross-reference discovered vulnerabilities against CVE databases
- Scan dependencies for known vulnerabilities
- Detect hardcoded secrets in analyzed code
- Run static analysis with additional engines
- Look up exploit intelligence and EPSS scores

Servers listed here are **recommendations only** — none are hardcoded. Users
configure whichever servers they want in their `mcp_config.yaml`.

---

## Tier 1 — Highly Recommended

These servers directly complement Vulnhuntr's vulnerability analysis capabilities.

### Snyk (Official Integration)

| Field | Value |
|-------|-------|
| **Repository** | [snyk/snyk-ls](https://github.com/snyk/snyk-ls/blob/main/mcp_extension/README.md) |
| **Install** | Part of Snyk Language Server; requires Snyk account |
| **Capabilities** | SCA, SAST, container scanning, IaC scanning |
| **Auth** | Snyk API token required |
| **Why for Vulnhuntr** | Cross-validate discovered vulnerabilities with Snyk's vulnerability DB. The LLM can check whether a dependency flagged during analysis has known CVEs. |
| **Risk** | Low — read-only scanning; established vendor. Requires API key. |
| **Suggested mode** | `auto` |

### GitGuardian (Official Integration)

| Field | Value |
|-------|-------|
| **Repository** | [GitGuardian/gg-mcp](https://github.com/GitGuardian/gg-mcp) |
| **Install** | `pip install ggshield` + API key |
| **Capabilities** | 500+ secret detectors, credential leak prevention, incident remediation |
| **Auth** | GitGuardian API key required |
| **Why for Vulnhuntr** | Detect hardcoded secrets (API keys, tokens, passwords) in analyzed source code — a common vulnerability class Vulnhuntr already tracks. |
| **Risk** | Low — read-only scanning. Code snippets sent to GitGuardian API. |
| **Suggested mode** | `auto` |

### BoostSecurity (Official Integration)

| Field | Value |
|-------|-------|
| **Repository** | [boost-community/boost-mcp](https://github.com/boost-community/boost-mcp) |
| **Install** | See repo README |
| **Capabilities** | Dependency vulnerability guardrails, malware detection, typosquatting detection |
| **Auth** | Free tier available |
| **Why for Vulnhuntr** | Guard against introducing dependencies with known vulnerabilities or malware — especially useful when analyzing dependency-heavy projects. |
| **Risk** | Low — dependency metadata sent to BoostSecurity. |
| **Suggested mode** | `auto` |

### Contrast Security (Official Integration)

| Field | Value |
|-------|-------|
| **Repository** | [Contrast-Security-OSS/mcp-contrast](https://github.com/Contrast-Security-OSS/mcp-contrast) |
| **Install** | See repo README |
| **Capabilities** | Vulnerability data, SCA data, remediation context |
| **Auth** | Contrast Security account required |
| **Why for Vulnhuntr** | Brings runtime vulnerability data and SCA findings into the analysis loop, letting the LLM cross-reference static findings with known exploitable patterns. |
| **Risk** | Low — read-only; established vendor. |
| **Suggested mode** | `auto` |

### CVE Intelligence Server

| Field | Value |
|-------|-------|
| **Repository** | [gnlds/mcp-cve-intelligence-server-lite](https://github.com/gnlds/mcp-cve-intelligence-server-lite) |
| **Install** | `npx mcp-cve-intelligence-server-lite` |
| **Capabilities** | Multi-source CVE data (NVD, CISA KEV), EPSS risk scoring, exploit discovery |
| **Auth** | None required (uses public APIs) |
| **Why for Vulnhuntr** | The LLM can look up CVE details and EPSS scores for vulnerabilities it discovers, enriching findings with real-world exploit probability data. |
| **Risk** | Very low — queries public databases only. No code sent externally. |
| **Suggested mode** | `auto` |

### SineWave Agent Security Scanner

| Field | Value |
|-------|-------|
| **Repository** | [sinewaveai/agent-security-scanner-mcp](https://github.com/sinewaveai/agent-security-scanner-mcp) |
| **Install** | See repo README |
| **Capabilities** | Prompt injection firewall, package hallucination detection (4.3M+ packages), 1000+ vulnerability rules, AST & taint analysis, auto-fix |
| **Auth** | None required |
| **Why for Vulnhuntr** | Complementary SAST engine with taint analysis — can validate Vulnhuntr's findings with an independent rule set. Prompt injection detection is especially relevant. |
| **Risk** | Low — local analysis. JavaScript-based. |
| **Suggested mode** | `auto` |

---

## Tier 2 — Strong Complements

These servers add valuable capabilities but serve more specialized use cases.

### Codacy (Official Integration)

| Field | Value |
|-------|-------|
| **Repository** | [codacy/codacy-mcp-server](https://github.com/codacy/codacy-mcp-server/) |
| **Install** | See repo README |
| **Capabilities** | Code quality issues, vulnerabilities, coverage insights |
| **Auth** | Codacy account required |
| **Why for Vulnhuntr** | Provides additional code quality context that can help distinguish real vulnerabilities from false positives. |
| **Risk** | Low — read-only API queries. |
| **Suggested mode** | `auto` |

### Endor Labs (Official Integration)

| Field | Value |
|-------|-------|
| **Repository** | [docs.endorlabs.com/deployment/ide/mcp/](https://docs.endorlabs.com/deployment/ide/mcp/) |
| **Install** | See docs |
| **Capabilities** | Code vulnerability scanning, secret leak detection |
| **Auth** | Endor Labs account required |
| **Why for Vulnhuntr** | Scans for vulnerabilities and secret leaks with a different detection engine, providing independent verification. |
| **Risk** | Low — established vendor. |
| **Suggested mode** | `auto` |

### SafeDep (Official Integration)

| Field | Value |
|-------|-------|
| **Repository** | [safedep/vet](https://github.com/safedep/vet/blob/main/docs/mcp.md) |
| **Install** | `vet-mcp` (see docs) |
| **Capabilities** | Vet open source packages for vulnerabilities, malware, and security risks |
| **Auth** | None for basic usage |
| **Why for Vulnhuntr** | Especially useful for AI-generated code suggestions that may reference vulnerable packages. |
| **Risk** | Low — package metadata queries. |
| **Suggested mode** | `auto` |

### Cycode (Official Integration)

| Field | Value |
|-------|-------|
| **Repository** | [cycodehq/cycode-cli](https://github.com/cycodehq/cycode-cli#mcp-command-experiment) |
| **Install** | `pip install cycode` then `cycode mcp` |
| **Capabilities** | SAST, SCA, Secrets scanning, IaC scanning |
| **Auth** | Cycode account (free tier available) |
| **Why for Vulnhuntr** | Multi-dimensional security scanning in a single tool — SAST + SCA + secrets + IaC. |
| **Risk** | Low — established vendor. Experimental MCP support. |
| **Suggested mode** | `auto` |

### Mobb Vibe Shield (Official Integration)

| Field | Value |
|-------|-------|
| **Repository** | [mobb-dev/bugsy](https://github.com/mobb-dev/bugsy?tab=readme-ov-file#model-context-protocol-mcp-server) |
| **Install** | See repo README |
| **Capabilities** | Identifies and remediates vulnerabilities in human and AI-written code |
| **Auth** | Required |
| **Why for Vulnhuntr** | Provides automated remediation suggestions alongside detection — useful for generating fix recommendations. |
| **Risk** | Low — code sent to Mobb for analysis. |
| **Suggested mode** | `auto` |

### SonarQube (Official Integration)

| Field | Value |
|-------|-------|
| **Repository** | [SonarSource/sonarqube-mcp-server](https://github.com/SonarSource/sonarqube-mcp-server) |
| **Install** | See repo README |
| **Capabilities** | Code quality analysis, vulnerability detection, code snippet analysis |
| **Auth** | SonarQube Server or Cloud instance required |
| **Why for Vulnhuntr** | Industry-standard code quality / security scanner. Provides independent vulnerability validation. |
| **Risk** | Low — established vendor. |
| **Suggested mode** | `auto` |

### Fluid Attacks (Official Integration)

| Field | Value |
|-------|-------|
| **Repository** | [fluidattacks/mcp](https://github.com/fluidattacks/mcp) |
| **Install** | See repo README |
| **Capabilities** | Vulnerability management, organization insights, GraphQL query execution |
| **Auth** | Fluid Attacks account required |
| **Why for Vulnhuntr** | If the target codebase is already tracked by Fluid Attacks, the LLM can pull existing vulnerability data into its analysis context. |
| **Risk** | Low — read-only API access. |
| **Suggested mode** | `auto` |

---

## Tier 3 — Specialized / Situational

These servers are useful in specific scenarios or for extended security workflows.

### Shodan MCP

| Field | Value |
|-------|-------|
| **Repository** | [Vorota-ai/shodan-mcp](https://github.com/Vorota-ai/shodan-mcp) |
| **Install** | See repo README |
| **Capabilities** | 20 tools for passive recon, CVE/CPE intelligence, DNS analysis, device search. 4 tools work without API key. |
| **Auth** | Shodan API key (optional for basic tools) |
| **Why for Vulnhuntr** | CVE/CPE lookup for network-facing vulnerabilities discovered in code. Useful when analyzing server-side applications. |
| **Risk** | Medium — sends queries to Shodan. No source code sent. |
| **Suggested mode** | `auto` |

### Nikto MCP

| Field | Value |
|-------|-------|
| **Repository** | [weldpua2008/nikto-mcp](https://github.com/weldpua2008/nikto-mcp) |
| **Install** | `npx nikto-mcp` or Docker |
| **Capabilities** | Web server vulnerability scanning via Nikto |
| **Auth** | None |
| **Why for Vulnhuntr** | Can scan live web servers for vulnerabilities. Useful when Vulnhuntr is used alongside a running instance of the target application. |
| **Risk** | **High** — actively scans targets. Must be used only against authorized targets. Enable `allow_destructive_tools: true` cautiously. |
| **Suggested mode** | `force` (with explicit target authorization) |

### CrowdStrike Falcon

| Field | Value |
|-------|-------|
| **Repository** | [CrowdStrike/falcon-mcp](https://github.com/CrowdStrike) |
| **Install** | See CrowdStrike docs |
| **Capabilities** | Detections, incidents, threat intelligence, hosts, vulnerabilities, identity protection |
| **Auth** | CrowdStrike Falcon account required |
| **Why for Vulnhuntr** | Enterprise threat intelligence integration — correlate code vulnerabilities with active threat data. |
| **Risk** | Low — read-only queries to Falcon platform. |
| **Suggested mode** | `auto` |

### Burp Suite (Official Integration)

| Field | Value |
|-------|-------|
| **Repository** | [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server) |
| **Install** | Burp Suite extension |
| **Capabilities** | Burp Suite integration for web security testing |
| **Auth** | Burp Suite Professional license |
| **Why for Vulnhuntr** | Connect Vulnhuntr's static analysis findings with Burp Suite's dynamic testing. The LLM could correlate source-code vulnerabilities with exploitable endpoints. |
| **Risk** | Medium — interacts with Burp Suite (which actively scans). |
| **Suggested mode** | `force` |

### StackHawk (Official Integration)

| Field | Value |
|-------|-------|
| **Repository** | [stackhawk/stackhawk-mcp](https://github.com/stackhawk/stackhawk-mcp) |
| **Install** | See repo README |
| **Capabilities** | Application security testing, vulnerability detection and remediation |
| **Auth** | StackHawk account required |
| **Why for Vulnhuntr** | DAST integration — test and fix security problems in running applications. |
| **Risk** | Medium — performs active testing. |
| **Suggested mode** | `force` |

### vulnicheck

| Field | Value |
|-------|-------|
| **Repository** | [andrasfe/vulnicheck](https://github.com/andrasfe/vulnicheck) |
| **Install** | See repo README |
| **Capabilities** | Real-time Python package vulnerability scanning against OSV and NVD databases, CVE details, lock file support |
| **Auth** | None |
| **Why for Vulnhuntr** | Python-specific package vulnerability scanning — directly relevant since Vulnhuntr primarily analyzes Python codebases. |
| **Risk** | Very low — queries public vulnerability databases. |
| **Suggested mode** | `auto` |

### Code Pathfinder

| Field | Value |
|-------|-------|
| **Repository** | [shivasurya/code-pathfinder](https://github.com/shivasurya/code-pathfinder) |
| **Install** | See repo README |
| **Capabilities** | AI-native static code analysis, structural search, vulnerability detection with MCP support |
| **Auth** | None |
| **Why for Vulnhuntr** | Independent SAST engine for cross-validation. Go-based, so provides a different perspective than Python-based tools. |
| **Risk** | Low — local analysis. |
| **Suggested mode** | `auto` |

### Grype MCP

| Field | Value |
|-------|-------|
| **Repository** | [ahmetak4n/grype-mcp](https://mcp.so/server/grype-mcp/ahmetak4n) |
| **Install** | See repo README |
| **Capabilities** | Container and filesystem vulnerability scanning via Grype |
| **Auth** | None |
| **Why for Vulnhuntr** | SCA for container images and filesystems — useful when analyzing Dockerized applications. |
| **Risk** | Low — local scanning. |
| **Suggested mode** | `auto` |

---

## Already Available in This Workspace

These MCP servers are already configured in `.vscode/mcp.json` and can be used
with the analysis integration:

| Server | Package | Analysis Use |
|--------|---------|--------------|
| **analyzer** | `mcp-server-analyzer` | Ruff linting, vulture dead code detection |
| **ripgrep** | `mcp-ripgrep` | Fast text search across codebase |
| **sequential-thinking** | `@modelcontextprotocol/server-sequential-thinking` | Structured multi-step reasoning for complex vulnerability chains |
| **python-lsp-mcp** | `python-lsp-mcp` | Pyright diagnostics, code navigation, symbol search |

These can serve as analysis tools if configured as MCP servers in
`mcp_config.yaml` (separate from the VS Code workspace configuration).

---

## Configuration Example

A recommended starter configuration for vulnerability analysis:

```yaml
# mcp_config.yaml
mcp:
  analysis:
    mode: auto
    max_tool_calls_per_iteration: 3
    allow_destructive_tools: false
    tool_timeout_seconds: 30

  servers:
    cve-intel:
      transport: stdio
      command: npx
      args: ["mcp-cve-intelligence-server-lite"]

    vulnicheck:
      transport: stdio
      command: uvx
      args: ["vulnicheck"]

    # Requires API key
    # snyk:
    #   transport: stdio
    #   command: snyk-ls
    #   env:
    #     SNYK_TOKEN: "${SNYK_TOKEN}"
```

---

## Selection Criteria

When choosing which servers to configure, consider:

1. **Relevance** — Does the server provide data useful for vulnerability analysis?
2. **Auth requirements** — Free/public API servers have lower barrier to entry
3. **Data privacy** — Some servers send code snippets externally; evaluate for sensitive codebases
4. **Latency** — Each tool call adds latency to analysis iterations (30s timeout default)
5. **Cost** — Some services have API call limits or paid tiers
6. **Destructive potential** — Active scanners (Nikto, Burp) must only target authorized systems

## Security Considerations

- **Never enable `allow_destructive_tools: true`** unless you understand exactly which tools will be called and have authorization to scan the target
- **API keys** should be stored in environment variables, never in config files
- **Review tool outputs** — MCP server responses are injected into LLM context; ensure servers return trustworthy data
- **Network access** — Some servers make outbound requests; ensure your network policy permits this
- **Untrusted servers** — Community servers are unvetted; audit source code before use
