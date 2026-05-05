# Phase 5: Codex & Qwen Code - Discussion Log

**Date:** 2026-05-04
**Mode:** --all --analyze (all areas auto-selected, trade-off tables before each question)
**Areas discussed:** 4 / 4

---

## Area 1: Codex auth model

**Question asked:** Should `CodexLLM` strip `OPENAI_API_KEY` by default (forcing session/OAuth auth), or leave it in the environment (supporting API-key auth too)?

**Options presented:**
1. Strip `OPENAI_API_KEY` by default — operator adds it back if they want API-key mode ✓ **Selected**
2. Don't strip — let Codex use whatever auth it finds (API key or session)
3. Strip `OPENAI_API_KEY` AND `OPENAI_ORG_ID` — full session-only enforcement
4. Other

**Decision captured:** D-01 — `_STRIP_ENV_VARS = ("OPENAI_API_KEY",)` by default, matching Claude Code's `ANTHROPIC_API_KEY` stripping pattern.

---

## Area 2: Codex sandbox → tool_mode flag mapping

**Question asked:** How should `tool_mode` map to Codex's `--approval-mode` flag, and should Phase 5 add any Codex-specific sandbox config to `CLIPolicy`?

**Options presented:**
1. Map tool_mode to `--approval-mode` (suggest/auto-edit/full-auto); no new CLIPolicy fields in Phase 5 ✓ **Selected**
2. Map tool_mode AND add a `codex_sandbox` field to CLIPolicy now (network-disabled, fully-isolated)
3. Use `--approval-mode` for tool_mode but also wire `--sandbox` flag when `tool_mode` is `"none"`
4. Other

**Decision captured:** D-02, D-03 — direct mapping: `"none"` → `suggest`, `"read-only"` → `auto-edit`, `"full"` → `full-auto`; no new CLIPolicy fields in Phase 5; sandbox policy deferred to Phase 6.

---

## Area 3: Qwen Code API bridge mode configuration

**Question asked:** How should the Qwen Code API bridge (routing to OpenRouter / OpenAI-compatible endpoints) be configured in Phase 5?

**Options presented:**
1. `overrides["qwen-code"]["base_url"]` injected as `OPENAI_BASE_URL` env var — no new CLIPolicy fields ✓ **Selected**
2. Add `qwen_base_url: str | None` field to CLIPolicy — clearly typed and documented
3. `QwenCodeLLM` reads `QWEN_BASE_URL` env var directly (operator sets it, no CLIPolicy involvement)
4. Defer API bridge to Phase 7 (MCP/Routing) — just implement direct Qwen mode now
5. Other

**Decision captured:** D-05 — bridge mode config via `CLIPolicy.overrides["qwen-code"]["base_url"]` injected as `OPENAI_BASE_URL`; no new CLIPolicy fields.

---

## Area 4: Qwen Code binary name, minimum version, and JSON output format

**Question asked:** What approach should we take for the Qwen Code binary name, version gate, and output parsing (batch vs streaming JSON)?

**Options presented:**
1. Researcher confirms binary name + min version; Phase 5 adds `_MIN_VERSION` gate; batch JSON only (no streaming) ✓ **Selected**
2. Assume binary is `qwen`, no version gate needed, batch JSON only
3. Assume binary is `qwen-code`, no version gate, implement stream-json parsing too
4. Other — I have specific info about the Qwen Code binary

**Decision captured:** D-06, D-07, D-08 — researcher confirms all Qwen Code CLI specifics before implementation; `_MIN_VERSION` gate required; no streaming in Phase 5.

---

## Deferred Ideas

None raised during this discussion.

---

## Notes

- Phase 4 established all the infrastructure Phase 5 builds on. Both providers are genuinely thin adapters.
- The key asymmetry: Codex env-stripping closely mirrors Claude Code; Qwen Code's bridge mode needs OPENAI_API_KEY kept (not stripped) when in bridge mode.
- Researcher gate on Qwen Code specifics is a hard prerequisite — implementation should not proceed without confirmed binary name, version, and JSON envelope fields.
