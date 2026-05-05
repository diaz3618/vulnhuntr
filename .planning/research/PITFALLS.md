# Domain Pitfalls

**Domain:** AI CLI integration for Vulnhuntr
**Researched:** 2026-05-01

## Critical Pitfalls

### Pitfall 1: Treating CLI tools like HTTP APIs

CLI tools have local auth state, sessions on disk, sandbox behavior, and versioned flag support. If Vulnhuntr models them as simple `provider + model`, it will hide the failure modes users most need to control.

Prevention:

- add explicit runtime policy fields
- capability-probe before scan
- log binary path/version in metadata

### Pitfall 2: Trusting JSON mode without runtime verification

Provider docs and real released binaries can drift. Gemini is the clearest example: official docs describe JSON output, but the project has already had upstream issues about flag behavior mismatches.

Prevention:

- probe JSON support at startup
- fail closed if structured mode is unavailable
- keep parser tests per provider/version family

### Pitfall 3: Double tool planes causing non-deterministic scans

If provider-native tools and Vulnhuntr’s internal MCP both operate without a clear policy, results become hard to reproduce and debug.

Prevention:

- add `mcp_mode` / tool ownership config
- record which tool plane was active in scan metadata

### Pitfall 4: Leaking credentials into subprocess providers

Some providers can use account auth, some can use API keys, and some can do both. Passing the entire parent environment through subprocesses can produce surprising auth precedence and secret leakage.

Prevention:

- sanitize subprocess env intentionally
- support explicit `auth_mode`
- document precedence between `.env`, shell env, and provider-owned config dirs

### Pitfall 5: Session resume assumptions breaking across hosts

Claude Code, Qwen Code, and other tools persist project-scoped session state locally. That does not mean a session can be resumed safely from a different host or workdir.

Prevention:

- model sessions as best-effort local state unless provider docs guarantee more
- keep stateless mode available
- record session IDs and cwd in metadata when resuming

### Pitfall 6: Weak oracles passing semantically wrong behavior

A provider can execute the right command, receive the right tool output, and still interpret it incorrectly. Final-output-only tests will miss this.

Prevention:

- add trace-based assertions
- verify semantic handling of tool responses and fallback reasons
- require behavior-level checks for critical multi-step scans

### Pitfall 7: State-dependent bugs hiding behind happy-path tests

Resume logic, fallback routing, and MCP/tool permissions are transition-heavy. Straight-line tests will not expose invalid transitions or unreachable safety checks.

Prevention:

- model critical execution states explicitly
- test guarded transitions and forbidden transitions
- add repeated-trial and multi-step scenario coverage

## Moderate Pitfalls

### Pitfall 8: Subscription-backed cost reporting is ambiguous

Token counts may be available while true marginal USD cost is not. For some providers, the right output is “usage known, cost not attributable,” not fake zero-cost accounting.

### Pitfall 9: Provider-native autonomy can mutate files

These tools are designed to read, write, and run commands. Vulnhuntr is an analyzer. If approval/sandbox defaults are too permissive, the scan backend can mutate the target repo.

Prevention:

- use explicit approval/sandbox defaults
- make read-only/stateless the default scan posture where supported

### Pitfall 10: Coverage numbers can look healthy while critical flows stay untested

A high overall percentage can still miss edge partitions, branch guards, DU paths, and state transitions in the provider pipeline.

Prevention:

- add branch, state-transition, and data-flow-aware tests around high-risk modules
- treat coverage as adequacy evidence, not only a threshold

### Pitfall 11: Retry/fallback can mask parser or invariant regressions

If provider A returns an unparseable envelope and Vulnhuntr silently falls back to provider B, users may think provider A works when it does not.

Prevention:

- distinguish transport failure, parse failure, auth failure, invariant failure, and model refusal in logs and reports

## Sources

- official vendor docs
- internal experiment notes
- current Vulnhuntr config/runner design
- Internal verification and testing notes reviewed on 2026-05-01
