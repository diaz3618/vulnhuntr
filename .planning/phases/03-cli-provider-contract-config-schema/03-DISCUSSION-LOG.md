# Phase 3: CLI Provider Contract & Config Schema - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-01
**Phase:** 03-cli-provider-contract-config-schema
**Areas discussed:** CLI Base Class Architecture, Capability Probe Behavior, Config Schema Structure, Module Organization

---

## CLI Base Class Architecture

| Option | Description | Selected |
|--------|-------------|----------|
| Intermediate CLIProviderLLM(LLM) base | Phase 3 adds CLIProviderLLM between LLM and individual providers. Subprocess execution, timeout, env-stripping, output parsing, and error classification all live in CLIProviderLLM. Phases 4/5 subclass it. | ✓ |
| Direct LLM subclass per provider | Each provider subclasses LLM directly (same pattern as Claude, ChatGPT). Phase 3 defines shared utilities but not a common parent. | |
| ABC/Protocol alongside LLM | Define a CLIProvider protocol/ABC that CLI providers implement without inheriting from LLM. Keeps full implementation flexibility. | |

**User's choice:** Intermediate CLIProviderLLM(LLM) base
**Notes:** User selected the recommended approach. Shared subprocess, timeout, env-strip, and error classification logic lives in the base; `get_response()` and `_extract_usage()` are abstract.

---

## Capability Probe Behavior

| Option | Description | Selected |
|--------|-------------|----------|
| Startup probe via runner | CLIProviderLLM.probe() is called from _init_providers() before the scan starts. Returns a CapabilityResult. Runner exits with diagnostic message if probe fails. | ✓ |
| Probe at instantiation (__init__) | probe() is called inside CLIProviderLLM.__init__. Raises LLMError immediately if the provider is unusable. | |
| Lazy probe at first chat() call | probe() is called inside chat() before the first real invocation. Zero overhead if provider is never used. | |

**User's choice:** Startup probe via runner
**Notes:** User selected the recommended approach. `CapabilityResult` has fields: `ok`, `binary_found`, `version`, `auth_valid` (None = can't check statically), `diagnostic_message`.

---

## Config Schema Structure

| Option | Description | Selected |
|--------|-------------|----------|
| Nested CLIPolicy sub-object | VulnhuntrConfig gains a `cli: CLIPolicy` field. CLIPolicy holds timeout, workdir, auth_mode, session_mode, approval_mode, sandbox_mode, max_turns, mcp_mode. Per-provider overrides in CLIPolicy.overrides dict. | ✓ |
| Flat fields on VulnhuntrConfig | All CLI fields added directly to VulnhuntrConfig (same level as budget, checkpoint). Simpler but the dataclass grows wide. | |
| Pydantic model (replace dataclass) | Migrate VulnhuntrConfig from dataclass to Pydantic BaseModel. Nested CLIPolicy becomes a Pydantic sub-model with validation. | |

**User's choice:** Nested CLIPolicy sub-object
**Notes:** User selected the recommended approach. YAML key is `cli:`. Existing `.vulnhuntr.yaml` files without `cli:` are unaffected. Provider-specific overrides via `cli.overrides.claude-code:` dict.

---

## Module Organization

| Option | Description | Selected |
|--------|-------------|----------|
| New vulnhuntr/cli_providers/ package | Phase 3 adds cli_providers/base.py (CLIProviderLLM, CapabilityResult). Phase 4/5 add claude_code.py, gemini_cli.py, etc. as new files. HTTP providers in llms.py are untouched. | ✓ |
| Extend llms.py | CLIProviderLLM and CapabilityResult added directly to llms.py alongside existing Claude, ChatGPT classes. | |
| New vulnhuntr/providers/ unified package | Phase 3 creates a unified providers/ package and moves both CLI and API providers into it. | |

**User's choice:** New vulnhuntr/cli_providers/ package
**Notes:** User selected the recommended approach. `llms.py` is not modified. Structure: `cli_providers/__init__.py` + `cli_providers/base.py`. Phases 4/5 add provider-specific files as new modules.

---

## Claude's Discretion

- Exact abstract method signatures for `get_response()` and `_extract_usage()` in `CLIProviderLLM`
- Whether `CLIProviderLLM.chat()` fully overrides `LLM.chat()` or calls `super().chat()`
- Exact env-stripping logic (which vars to remove per provider type)
- Test file location: new `tests/test_cli_providers.py` vs. extending `tests/test_cli.py`

## Deferred Ideas

None — discussion stayed within phase scope.
