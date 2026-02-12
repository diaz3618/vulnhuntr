# Vulnhuntr Makefile
# Usage:
#   make test          - Run tests
#   make lint          - Run ruff linter
#   make format        - Format code with ruff
#   make build         - Build distribution packages
#   make publish-test  - Publish to TestPyPI
#   make publish       - Publish to PyPI
#   make release V=1.2.0 - Bump version, commit, tag, and push

.PHONY: help test lint format build clean publish publish-test release changelog version install-dev check

# Default target
help:
	@echo "Vulnhuntr Development Commands"
	@echo "=============================="
	@echo "Development:"
	@echo "  make test          - Run pytest"
	@echo "  make lint          - Run ruff linter"
	@echo "  make format        - Format code with ruff"
	@echo "  make check         - Run all checks before release"
	@echo ""
	@echo "Building & Publishing:"
	@echo "  make build         - Build distribution packages"
	@echo "  make clean         - Remove build artifacts"
	@echo "  make publish-test  - Publish to TestPyPI (local testing)"
	@echo "  make publish       - Publish to PyPI (local publishing)"
	@echo ""
	@echo "Releases:"
	@echo "  make release       - Auto-version, changelog, tag, push (recommended)"
	@echo "  make changelog     - Preview next version and changelog"
	@echo "  make version       - Show current version"
	@echo ""
	@echo "Setup:"
	@echo "  make install-dev   - Install in development mode"
	@echo ""
	@echo "Example workflows:"
	@echo "  make check && make release              # Full release with semantic versioning"
	@echo "  make changelog                          # Preview what will be released"
	@echo "  make publish-test                       # Test local PyPI publishing"
	@echo ""
	@echo "Commit message conventions:"
	@echo "  feat: new feature         -> minor version bump (1.1.0 -> 1.2.0)"
	@echo "  fix: bug fix              -> patch version bump (1.1.0 -> 1.1.1)"
	@echo "  BREAKING CHANGE: ...      -> major version bump (1.0.0 -> 2.0.0)"

# Development
test:
	pytest tests/ -v

lint:
	ruff check vulnhuntr/

format:
	ruff check --fix vulnhuntr/
	ruff format vulnhuntr/

# Build
build: clean
	python -m build

clean:
	rm -rf dist/ build/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

# Publishing (uses ~/.pypirc credentials)
publish-test: build
	@echo "Publishing to TestPyPI..."
	twine upload --repository testpypi dist/*
	@echo ""
	@echo "Test installation with:"
	@echo "  pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ vulnhuntr"

publish: build
	@echo "Publishing to PyPI..."
	twine upload --repository pypi dist/*
	@echo ""
	@echo "Install with: pip install vulnhuntr"

# Semantic Release (Recommended)
# Automatically determines version from conventional commits
release:
	@echo "Running semantic-release..."
	@echo "This will:"
	@echo "  1. Analyze commits since last release"
	@echo "  2. Determine next version (major/minor/patch)"
	@echo "  3. Update version in __init__.py"
	@echo "  4. Generate/update CHANGELOG.md"
	@echo "  5. Commit, tag, and push to GitHub"
	@echo ""
	semantic-release version
	@echo ""
	@echo "✓ Release complete! GitHub Actions will publish to PyPI."

changelog:
	@echo "Previewing next release..."
	@echo ""
	semantic-release version --print
	@echo ""
	@echo "Run 'make release' to execute this release"

# Show current version
version:
	@grep -Po '__version__ = "\K[^"]+' vulnhuntr/__init__.py

# Install for development
install-dev:
	pip install -e ".[dev]"
	@echo ""
	@echo "✓ Installed vulnhuntr in development mode"
	@echo "  Test with: vulnhuntr --help"
	@echo "  Run release: make release"

# Check before release
check: lint test build
	twine check dist/*
	@echo "All checks passed!"
