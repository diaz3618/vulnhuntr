# CHANGELOG

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial PyPI publishing workflow with GitHub Actions
- Semantic versioning with python-semantic-release
- Automated CHANGELOG generation
- Makefile for development and release automation

### Changed
- Migrated from Poetry to PEP 621 pyproject.toml format

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
