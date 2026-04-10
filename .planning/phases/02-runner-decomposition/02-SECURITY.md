---
phase: 2
slug: runner-decomposition
status: verified
threats_open: 0
asvs_level: 1
created: 2026-04-10
---

# Phase 2 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| CLI args → `_collect_files()` | `args.analyze` and `args.root` are user-supplied paths; path traversal guard enforced by `validate_args()` (INFRA-02, Phase 1) | File system paths |
| caller → `llm_factory` | Callable supplied by caller; `None` in production, test lambdas in unit tests only — no untrusted caller can set this via the CLI | Callable reference (test-scoped) |
| `_dispatch_integrations()` → GitHub / webhook | Findings forwarded to external services; env-var credential handling and HMAC signing unchanged from pre-refactor | Vulnerability findings |
| test code → `_dispatch_integrations` | Tests mock `_create_github_issues` and `_send_webhook`; no real credentials or external calls | Mocked test data |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-02-01 | Tampering | `_init_providers()` parameter forwarding | accept | Function is internal; all inputs come from `run_analysis()` which receives validated `args`. No new trust boundary introduced. | closed |
| T-02-02 | Elevation of Privilege | `_collect_files()` path handling | accept | `validate_args()` already enforces `is_relative_to()` check (INFRA-02, Phase 1). `_collect_files()` is pure extraction — no new path construction. | closed |
| T-02-03 | Information Disclosure | Module-level private functions | accept | Functions use `_` prefix (private). No new public API surface. Module is not a library API. | closed |
| T-02-04 | Tampering | `llm_factory` callable injection | accept | Factory is only used at test time; production code path keeps `llm_factory=None`. No untrusted caller can set this via the CLI. | closed |
| T-02-05 | Denial of Service | `_analyze_files()` budget_enforcer bypass | accept | `budget_enforcer.check()` is called before each file; extraction preserves this guard exactly — no behavioral change. | closed |
| T-02-06 | Information Disclosure | `_analyze_files()` error logging | accept | `log.error` uses structlog; no user-controlled data injected into log keys beyond already-present `file=str(py_f)`. | closed |
| T-02-07 | Information Disclosure | `_dispatch_integrations()` — findings to external services | accept | Behavior identical to pre-refactor; no new data flows introduced. Existing guards (env var checks in `_create_github_issues`, HMAC in `_send_webhook`) unchanged. | closed |
| T-02-08 | Tampering | `_dispatch_reports` alias | accept | Alias is read-only at module level; cannot be reassigned by untrusted callers via the CLI. | closed |
| T-02-09 | Information Disclosure | Test fixtures containing finding data | accept | Test-only data; no real repo paths or credentials. Fixtures use hardcoded strings. | closed |
| T-02-10 | Tampering | `llm_factory` in tests bypasses real LLM init | accept | Factory is a test-scoped lambda; production entry point still uses `llm_factory=None` by default. | closed |

*Status: open · closed*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-02-01 | T-02-01 | Internal function, inputs validated upstream by `validate_args()` | gsd-secure-phase | 2026-04-10 |
| AR-02-02 | T-02-02 | Path traversal guard pre-exists in Phase 1 (INFRA-02); extraction adds no new path construction | gsd-secure-phase | 2026-04-10 |
| AR-02-03 | T-02-03 | Private `_` prefix convention; module is not a public library API | gsd-secure-phase | 2026-04-10 |
| AR-02-04 | T-02-04 | `llm_factory` is None in production; only test-scoped lambdas pass non-None values | gsd-secure-phase | 2026-04-10 |
| AR-02-05 | T-02-05 | `budget_enforcer.check()` call preserved verbatim in extracted `_analyze_files()` | gsd-secure-phase | 2026-04-10 |
| AR-02-06 | T-02-06 | structlog structured logging; no format-string injection possible; `file=` key was already present pre-refactor | gsd-secure-phase | 2026-04-10 |
| AR-02-07 | T-02-07 | Pure extraction refactor — all external dispatch logic unchanged; existing HMAC/env-var guards retained | gsd-secure-phase | 2026-04-10 |
| AR-02-08 | T-02-08 | Module-level alias is immutable from CLI callers | gsd-secure-phase | 2026-04-10 |
| AR-02-09 | T-02-09 | Test fixtures are hardcoded strings with no real credentials or sensitive paths | gsd-secure-phase | 2026-04-10 |
| AR-02-10 | T-02-10 | `llm_factory=None` default ensures production path is unaffected by test-scoped injection | gsd-secure-phase | 2026-04-10 |

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-04-10 | 10 | 10 | 0 | gsd-secure-phase (inline) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-04-10
