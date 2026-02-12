# Vulnhuntr Makefile
# Usage:
#   make test          - Run tests
#   make lint          - Run ruff linter
#   make format        - Format code with ruff
#   make build         - Build distribution packages
#   make publish-test  - Publish to TestPyPI
#   make publish       - Publish to PyPI
#   make release V=1.2.0 - Bump version, commit, tag, and push

.PHONY: help test lint format build clean publish publish-test release version-bump

# Default target
help:
	@echo "Vulnhuntr Development Commands"
	@echo "=============================="
	@echo "Development:"
	@echo "  make test          - Run pytest"
	@echo "  make lint          - Run ruff linter"
	@echo "  make format        - Format code with ruff"
	@echo ""
	@echo "Building & Publishing:"
	@echo "  make build         - Build distribution packages"
	@echo "  make clean         - Remove build artifacts"
	@echo "  make publish-test  - Publish to TestPyPI"
	@echo "  make publish       - Publish to PyPI"
	@echo ""
	@echo "Semantic Releases (Recommended):"
	@echo "  make release       - Auto-version, changelog, tag, push (uses conventional commits)"
	@echo "  make changelog     - Preview next version and changelog"
	@echo "  make version       - Show current version"
	@echo ""
	@echo "Manual Releases:"
	@echo "  make release-patch - Bump patch version (1.2.3 -> 1.2.4)"
	@echo "  make release-minor - Bump minor version (1.2.3 -> 1.3.0)"
	@echo "  make release-major - Bump major version (1.2.3 -> 2.0.0)"
	@echo "  make release-manual V=x.y.z - Set specific version"
	@echo ""
	@echo "Example workflows:"
	@echo "  make test lint && make release      # Auto-release with semantic versioning"
	@echo "  make changelog                      # Preview what will be released"
	@echo ""
	@echo "Commit message conventions:"
	@echo "  feat: new feature         -> minor version bump"
	@echo "  fix: bug fix              -> patch version bump"
	@echo "  BREAKING CHANGE: ...      -> major version bump"

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

# Manual semantic version bumping (fallback)
release-patch:
	@$(MAKE) _bump-and-release PART=patch

release-minor:
	@$(MAKE) _bump-and-release PART=minor

release-major:
	@$(MAKE) _bump-and-release PART=major

release-manual:
ifndef V
	$(error VERSION is required. Usage: make release-manual V=1.2.0)
endif
	@echo "Manually releasing version $(V)..."
	@# Update version in __init__.py
	sed -i 's/__version__ = "[^"]*"/__version__ = "$(V)"/' vulnhuntr/__init__.py
	@# Stage changes
	git add vulnhuntr/__init__.py
	@# Commit
	git commit -m "release: v$(V)"
	@# Create tag
	git tag -a "v$(V)" -m "Release v$(V)"
	@# Push
	git push --follow-tags origin main
	@echo ""
	@echo "✓ Version $(V) released. GitHub Actions will publish to PyPI."

_bump-and-release:
	@# Get current version
	$(eval CURRENT := $(shell grep -Po '__version__ = "\K[^"]+' vulnhuntr/__init__.py))
	@# Calculate new version
	$(eval NEW_VERSION := $(shell python3 -c "import sys; v = '$(CURRENT)'.split('.'); parts = {'major': (int(v[0])+1, 0, 0), 'minor': (int(v[0]), int(v[1])+1, 0), 'patch': (int(v[0]), int(v[1]), int(v[2])+1)}; print('.'.join(map(str, parts['$(PART)'])))"))
	@echo "Bumping version: $(CURRENT) -> $(NEW_VERSION) ($(PART))"
	@# Update version
	sed -i 's/__version__ = "[^"]*"/__version__ = "$(NEW_VERSION)"/' vulnhuntr/__init__.py
	@# Stage and commit
	git add vulnhuntr/__init__.py
	git commit -m "release: v$(NEW_VERSION)"
	git tag -a "v$(NEW_VERSION)" -m "Release v$(NEW_VERSION)"
	@# Push
	git push --follow-tags origin main
	@echo ""
	@echo "✓ Version bumped to $(NEW_VERSION). GitHub Actions will publish to PyPI."

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
