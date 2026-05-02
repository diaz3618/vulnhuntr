---
phase: 03-cli-provider-contract-config-schema
plan: 02
status: complete
commit: 0eb4be9
---

## What Was Built

Extended `vulnhuntr/config.py` with the `CLIPolicy` dataclass and wired it into `VulnhuntrConfig`:

- `CLIPolicy` dataclass: 9 fields (`timeout`, `workdir`, `auth_mode`, `session_mode`, `approval_mode`, `sandbox_mode`, `max_turns`, `mcp_mode`, `overrides`) all with safe defaults so existing YAML configs without a `cli:` section continue to work unchanged.
- `VulnhuntrConfig.cli` field: `CLIPolicy = field(default_factory=CLIPolicy)` — backward compatible.
- `from_dict()` extended: parses optional `cli:` section into a `CLIPolicy` instance; unknown keys are ignored.
- `to_dict()` extended: `"cli": dataclasses.asdict(self.cli)` — checkpoint round-trips work correctly.

## Tests Added

57 config tests pass (36 existing + 21 new):
- `TestCLIPolicyDefaults` (9 tests) — one per field, verifies default values
- `TestCLIPolicy` (7 tests) — from_dict() parsing of individual cli: section keys
- `TestCLIPolicyOverrides` (4 tests) — per-provider overrides dict including isolation test
- `TestFromDictFlat::test_cli_provider_string` — "claude-code" accepted as provider string
- `TestToDict::test_cli_key_present` + `test_cli_round_trip` — to_dict() serialization verified

## Requirements Closed

- CONFIG-01: `provider: claude-code` accepted by `from_dict()` without error
- CONFIG-02: `CLIPolicy` fields parsed from `cli:` section
- CONFIG-03: Missing `cli:` section gives default `CLIPolicy()` — no regression for existing configs
