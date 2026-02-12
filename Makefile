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
	@echo "  make test          - Run pytest"
	@echo "  make lint          - Run ruff linter"
	@echo "  make format        - Format code with ruff"
	@echo "  make build         - Build distribution packages"
	@echo "  make clean         - Remove build artifacts"
	@echo "  make publish-test  - Publish to TestPyPI"
	@echo "  make publish       - Publish to PyPI (use after publish-test)"
	@echo "  make release V=x.y.z - Full release: bump version, commit, tag, push"
	@echo ""
	@echo "Example release workflow:"
	@echo "  make test && make lint && make release V=1.2.0"

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

# Release automation
# Usage: make release V=1.2.0
release:
ifndef V
	$(error VERSION is required. Usage: make release V=1.2.0)
endif
	@echo "Releasing version $(V)..."
	@# Update version in __init__.py
	sed -i 's/__version__ = "[^"]*"/__version__ = "$(V)"/' vulnhuntr/__init__.py
	@# Stage changes
	git add vulnhuntr/__init__.py
	@# Commit
	git commit -m "release: v$(V)"
	@# Create tag
	git tag -a "v$(V)" -m "Release v$(V)"
	@echo ""
	@echo "Version $(V) committed and tagged."
	@echo "To push: git push origin main --tags"
	@echo "Or run: make push-release"

push-release:
	git push origin main --tags
	@echo "Pushed to origin. GitHub Actions will create release and publish to PyPI."

# Version bump helpers (without full release)
version-bump:
ifndef V
	$(error VERSION is required. Usage: make version-bump V=1.2.0)
endif
	sed -i 's/__version__ = "[^"]*"/__version__ = "$(V)"/' vulnhuntr/__init__.py
	@echo "Version bumped to $(V) in vulnhuntr/__init__.py"

# Show current version
version:
	@grep -Po '__version__ = "\K[^"]+' vulnhuntr/__init__.py

# Install for development
install-dev:
	pip install -e ".[dev]"
	pip install build twine

# Check before release
check: lint test build
	twine check dist/*
	@echo "All checks passed!"
