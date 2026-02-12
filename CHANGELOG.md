# CHANGELOG

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.3] - 2026-02-11

### Fixed
- All Pyright/mypy type errors across 14 files
- Bandit B113: Added timeout to requests.post calls
- Security: Bumped actions/download-artifact to v4
- Security: Bumped minimum certifi to >=2024.7.4

### Added
- `to_xml_bytes()` helper for proper bytes typing from pydantic-xml
- Memory-bank sub-agent to copilot-instructions.md
- `.venv-*/` pattern to gitignore

### Verified
- ruff: All checks passed (27 files)
- Pyright: 0 errors
- bandit: 0 Medium/High issues
- semgrep: 0 findings (843 rules)
- grype: All vulnerabilities fixed

## [1.1.2] - 2026-02-11

### Added
- Maintainer attribution in README with original Protect AI authors credited
- License section in README explaining AGPL-3.0 requirements

### Fixed
- Corrected license metadata from MIT to AGPL-3.0-or-later (matching LICENSE file)
- Removed deprecated license classifier per PEP 639
- Fixed package publishing configuration

## [1.1.1] - 2026-02-11

### Fixed
- License metadata corrections (superseded by 1.1.2)

## [1.1.0] - 2026-02-11

### Added
- Multi-language support foundation
- Enhanced documentation structure
- MCP integration for memory bank
- Cost tracking and budget management

### Fixed
- Deprecated datetime.utcnow() usage

## [1.0.0] - 2025-XX-XX

### Added
- Initial release
- Claude, GPT-4, Ollama, OpenRouter support
- Iterative vulnerability analysis
- SARIF, HTML, JSON, CSV, Markdown report formats
- Checkpoint/resume functionality
