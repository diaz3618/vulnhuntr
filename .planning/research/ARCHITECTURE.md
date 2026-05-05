# Architecture Patterns

**Domain:** AI CLI integration for Vulnhuntr
**Researched:** 2026-05-01
**Milestone context:** Expand existing `v1.0` roadmap

## Current Architecture Assessment

The codebase already has the right high-level separation:

- `cli/` chooses the backend and orchestrates scans
- `llms.py` defines the current transport abstraction
- `core/analysis.py` depends on a provider that can return validated `Response` objects

That means the safest design is not a product rewrite. It is a transport expansion that preserves the analysis pipeline.

## Recommended Patterns

### Pattern 1: Provider-neutral CLI transport layer

Add a new module dedicated to CLI-backed providers rather than forcing vendor-specific logic into `llms.py`.

Suggested shape:

```python
class CLIToolLLM(LLM):
    provider_name: str

    def probe_capabilities(self) -> ProviderCapabilities: ...
    def build_command(self, prompt: str) -> list[str]: ...
    def parse_envelope(self, stdout: str, stderr: str) -> ProviderResult: ...
```

Why:

- keeps HTTP SDK providers stable
- isolates subprocess/session/sandbox concerns
- makes per-provider parsing testable

### Pattern 2: Capability probe before scan start

Do not assume every installed version supports the same flags.

Suggested probe outputs:

- binary path
- detected version
- supports JSON output
- supports session resume
- supports configurable sandbox/approval mode
- supports MCP loading

This probe should run during initialization and fail early with actionable guidance.

### Pattern 3: Unified runtime policy object

Current config only knows provider/model/fallbacks. CLI tools need more runtime policy.

Suggested internal model:

```python
@dataclass
class CLIRuntimePolicy:
    timeout_seconds: int
    workdir: Path | None
    auth_mode: str
    session_mode: str
    resume_session: str | None
    approval_mode: str
    sandbox_mode: str
    max_turns: int | None
    mcp_mode: str
```

Why:

- avoids scattering provider-specific config reads throughout `runner.py`
- creates one place to merge CLI args, YAML config, env, and provider defaults

### Pattern 4: Explicit tool/MCP ownership policy

Vulnhuntr will have two possible tool planes:

1. Vulnhuntr-managed MCP in the analysis pipeline
2. provider-native tools/MCP inside Claude Code, Gemini CLI, Codex, or Qwen Code

This must be explicit in config. Recommended modes:

- `disabled`
- `native`
- `vulnhuntr`
- `hybrid`

Without this, scans become hard to reason about and hard to reproduce.

### Pattern 5: Session adapter separate from transport adapter

Provider transport and provider session lifecycle are related but not identical.

Suggested split:

```python
class ProviderSessionAdapter:
    def start(self) -> SessionInfo: ...
    def continue_latest(self) -> SessionInfo: ...
    def resume(self, session_id: str) -> SessionInfo: ...
```

Why:

- some providers support stateless mode well
- some persist to disk automatically
- cross-host resume portability differs materially

### Pattern 6: Explicit state machine for orchestration

The remaining milestone work is stateful enough that the orchestration contract should be described as states and guarded transitions, even if implemented with ordinary Python.

Key transitions to model and test:

- provider probe → provider ready / provider blocked
- session policy selected → stateless / continue / resume
- model response received → validated / parse-repair / fallback / fail
- MCP requested → executed / timed out / denied
- fallback attempted → next provider / terminal failure

Why:

- makes tests target transitions instead of only end results
- clarifies allowed versus forbidden execution paths
- reduces ambiguity in retry and resume behavior

### Pattern 7: Traceable execution model

The system should emit enough structured events to reconstruct why a scan succeeded or failed.

Minimum trace events:

- provider probe result
- command invocation metadata
- response validation outcome
- tool/MCP invocation and result
- fallback decision and reason
- session continuation or resume metadata

Why:

- behavior-level testing needs internal evidence, not just final findings
- failures can be localized to transport, semantics, or routing

## Build Order

1. Expand config and runtime models
2. Add capability probe + common CLI base
3. Introduce explicit orchestration-state and trace contracts
4. Integrate first two providers with the clearest contracts
5. Add remaining providers
6. Layer in sessions, native tools, MCP ownership rules, and invariant checks
7. Harden fallback, cost reporting, and evaluation

## Sources

- `vulnhuntr/cli/runner.py`
- `vulnhuntr/llms.py`
- `vulnhuntr/config.py`
- internal Claude Code experiment
- official vendor docs listed in `SUMMARY.md`
- Internal verification and orchestration notes reviewed on 2026-05-01
