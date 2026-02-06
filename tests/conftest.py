"""
Shared Fixtures and Test Utilities for Vulnhuntr
=================================================

Provides reusable mock objects, factory functions, and temp-directory
helpers that every test module can import via standard pytest fixture
injection.  No real LLM calls are made by any fixture here.

Environment Variables (from .env.test):
- PROVIDER: LLM provider (anthropic, openai, google, openrouter, ollama)
- LLM_LOGIC_TEST: Enable LLM-based logic error detection tests (true/false)
- DEEP_TEST: Enable AI agent-based deep analysis (true/false)
"""

import json
import os
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from unittest.mock import MagicMock

import pytest

from vulnhuntr.core.models import ContextCode, Response, VulnType
from vulnhuntr.reporters.base import Finding, FindingSeverity

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parent.parent
TESTS_DIR = Path(__file__).resolve().parent
ENV_TEST_FILE = TESTS_DIR / ".env.test"
TEST_RESULTS_DIR = TESTS_DIR / "test_results"
AGENT_DIR = TESTS_DIR / "agent"

# Global storage for test results (accessed by hooks)
_test_results_storage = None
_test_config = None


# ---------------------------------------------------------------------------
# Environment Configuration
# ---------------------------------------------------------------------------


def _load_env_config() -> Dict[str, str]:
    """Load environment configuration from .env.test.
    
    Returns:
        Dictionary of environment variables
    """
    import dotenv
    
    config = {}
    if ENV_TEST_FILE.exists():
        config = dotenv.dotenv_values(ENV_TEST_FILE)
    return config


def _get_env_bool(key: str, default: bool = False) -> bool:
    """Get a boolean environment variable.
    
    Args:
        key: Environment variable name
        default: Default value if not set
        
    Returns:
        Boolean value
    """
    value = os.getenv(key, "").lower()
    if value in ("true", "1", "yes", "on"):
        return True
    if value in ("false", "0", "no", "off"):
        return False
    return default


# ---------------------------------------------------------------------------
# pytest configuration
# ---------------------------------------------------------------------------


def pytest_addoption(parser):
    """Register CLI options for tests."""
    parser.addoption(
        "--env-file",
        action="store",
        default=str(ENV_TEST_FILE),
        help="Path to .env.test for live API tests (default: tests/.env.test)",
    )
    parser.addoption(
        "--no-export",
        action="store_true",
        default=False,
        help="Disable automatic test result export to tests/test_results/",
    )
    parser.addoption(
        "--llm-logic-test",
        action="store_true",
        default=False,
        help="Run LLM-based logic error detection tests (can also set LLM_LOGIC_TEST=true in .env.test)",
    )
    parser.addoption(
        "--deep-test",
        action="store_true",
        default=False,
        help="Run AI agent-based deep analysis tests (can also set DEEP_TEST=true in .env.test)",
    )
    parser.addoption(
        "--provider",
        action="store",
        default=None,
        help="LLM provider to use (anthropic, openai, google, openrouter, ollama)",
    )
    parser.addoption(
        "--no-cost-confirm",
        action="store_true",
        default=False,
        help="Skip cost confirmation prompt for LLM tests",
    )


def pytest_configure(config):
    """Register custom markers so pytest doesn't warn about them."""
    global _test_results_storage, _test_config
    
    config.addinivalue_line("markers", "live: marks tests that call real LLM APIs")
    config.addinivalue_line("markers", "slow: marks tests that are slow to run")
    config.addinivalue_line("markers", "llm: marks tests requiring LLM_LOGIC_TEST=true (logic error detection)")
    config.addinivalue_line("markers", "deep: marks tests requiring DEEP_TEST=true (AI agent analysis)")
    config.addinivalue_line("markers", "provider(name): marks tests for specific LLM provider")
    
    _test_config = config
    
    # Load environment from .env.test
    env_file = Path(config.getoption("--env-file"))
    if env_file.exists():
        import dotenv
        dotenv.load_dotenv(str(env_file), override=True)
    
    # Initialize test results storage
    _test_results_storage = {
        "summary": {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "errors": 0,
            "warnings": 0,
            "duration": 0.0,
        },
        "tests": [],
        "warnings": [],
        "llm_costs": {
            "estimated_usd": 0.0,
            "actual_usd": 0.0,
            "provider": os.getenv("PROVIDER", "unknown"),
        },
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
    }


def pytest_collection_modifyitems(config, items):
    """Skip tests based on environment configuration."""
    # Determine if LLM logic error tests should run
    llm_logic_test_enabled = (
        config.getoption("--llm-logic-test") 
        or _get_env_bool("LLM_LOGIC_TEST")
    )
    
    # Determine if deep tests should run
    deep_test_enabled = (
        config.getoption("--deep-test")
        or _get_env_bool("DEEP_TEST")
    )
    
    # Get provider from CLI or env
    provider = config.getoption("--provider") or os.getenv("PROVIDER", "anthropic")
    
    skip_llm_logic = pytest.mark.skip(reason="LLM logic tests disabled (set LLM_LOGIC_TEST=true or use --llm-logic-test)")
    skip_deep = pytest.mark.skip(reason="Deep tests disabled (set DEEP_TEST=true or use --deep-test)")
    skip_provider = pytest.mark.skip(reason=f"Test requires different provider (current: {provider})")
    
    for item in items:
        # Skip LLM logic error tests if not enabled
        if "llm" in item.keywords and not llm_logic_test_enabled:
            item.add_marker(skip_llm_logic)
        
        # Skip deep tests if not enabled  
        if "deep" in item.keywords and not deep_test_enabled:
            item.add_marker(skip_deep)
        
        # Skip provider-specific tests
        provider_markers = [m for m in item.iter_markers(name="provider")]
        for marker in provider_markers:
            required_provider = marker.args[0] if marker.args else None
            if required_provider and required_provider.lower() != provider.lower():
                item.add_marker(skip_provider)
    
    # Cost estimation for LLM logic tests (confirmation is done in pytest_sessionstart)
    if llm_logic_test_enabled:
        llm_logic_tests = [item for item in items if "llm" in item.keywords]
        if llm_logic_tests:
            _store_llm_cost_estimate(llm_logic_tests, provider)


def _estimate_llm_test_cost(num_tests: int, provider: str) -> float:
    """Estimate total cost for LLM tests.
    
    Args:
        num_tests: Number of LLM tests to run
        provider: LLM provider name
        
    Returns:
        Estimated cost in USD
    """
    # Cost per test (conservative estimates based on typical token usage)
    # Each test might use ~2000 input tokens and ~1000 output tokens
    COST_PER_TEST = {
        "anthropic": 0.02,  # ~$20/1M input, $60/1M output for Sonnet
        "openai": 0.03,     # ~$30/1M input, $60/1M output for GPT-4
        "google": 0.005,    # ~$1.25/1M input, $5/1M output for Gemini Pro
        "openrouter": 0.02, # Varies by model, assume Claude-like
        "ollama": 0.00,     # Local, no API cost
    }
    
    cost_per_test = COST_PER_TEST.get(provider.lower(), 0.02)
    return round(num_tests * cost_per_test, 4)


def _store_llm_cost_estimate(llm_tests: list, provider: str) -> None:
    """Store cost estimate for LLM tests.
    
    Args:
        llm_tests: List of LLM test items
        provider: LLM provider name
    """
    global _test_results_storage
    
    num_tests = len(llm_tests)
    estimated_cost = _estimate_llm_test_cost(num_tests, provider)
    
    # Store estimated cost for report
    if _test_results_storage:
        _test_results_storage["llm_costs"]["estimated_usd"] = estimated_cost
        _test_results_storage["llm_costs"]["provider"] = provider
        _test_results_storage["llm_costs"]["num_tests"] = num_tests


def pytest_sessionstart(session):
    """Show cost estimate and ask for confirmation before LLM logic tests run."""
    config = session.config
    
    # Check if LLM logic tests are enabled
    llm_logic_test_enabled = (
        config.getoption("--llm-logic-test", default=False)
        or _get_env_bool("LLM_LOGIC_TEST")
    )
    
    if not llm_logic_test_enabled:
        return
    
    # Skip confirmation if --no-cost-confirm or running in CI
    if config.getoption("--no-cost-confirm", default=False):
        return
    
    if os.getenv("CI") or os.getenv("GITHUB_ACTIONS"):
        return
    
    provider = config.getoption("--provider") or os.getenv("PROVIDER", "anthropic")
    
    # Estimate cost (we'll refine this after collection)
    # For now, show a warning that LLM logic tests will incur costs
    print("\n" + "=" * 60)
    print("💰 LLM LOGIC TEST MODE ENABLED")
    print("=" * 60)
    print(f"  Provider: {provider}")
    print("  Note: LLM logic error tests will incur API costs.")
    print("  Use --no-cost-confirm to skip this prompt.")
    print("=" * 60)
    
    try:
        import sys
        # Check if stdin is interactive
        if sys.stdin.isatty():
            response = input("\n⚠️  Continue with LLM logic tests? [y/N]: ").strip().lower()
            if response not in ("y", "yes"):
                print("   LLM logic tests cancelled by user.")
                raise pytest.UsageError("LLM logic tests cancelled by user")
            print("   Proceeding with LLM logic tests.\n")
    except (EOFError, KeyboardInterrupt, OSError):
        # Non-interactive, proceed
        print("   (Non-interactive mode, proceeding)\n")


def pytest_runtest_logreport(report):
    """Collect test results for each test phase."""
    global _test_results_storage
    
    if _test_results_storage is None:
        return
    
    if report.when == "call" or (report.when == "setup" and report.outcome == "skipped"):
        result = {
            "nodeid": report.nodeid,
            "outcome": report.outcome,
            "duration": round(report.duration, 4),
            "file": str(report.fspath) if hasattr(report, "fspath") and report.fspath else report.nodeid.split("::")[0],
        }
        
        # Add failure/error details
        if report.outcome == "failed":
            result["longrepr"] = str(report.longrepr) if report.longrepr else None
        
        # Add skip reason
        if report.outcome == "skipped" and hasattr(report, "longrepr"):
            if report.longrepr and len(report.longrepr) >= 3:
                result["skip_reason"] = str(report.longrepr[2])
        
        _test_results_storage["tests"].append(result)


def pytest_warning_recorded(warning_message, when, nodeid, location):
    """Capture warnings during test execution."""
    global _test_results_storage
    
    if _test_results_storage is None:
        return
    
    warning_info = {
        "message": str(warning_message.message),
        "category": warning_message.category.__name__ if warning_message.category else "Warning",
        "filename": str(warning_message.filename) if warning_message.filename else None,
        "lineno": warning_message.lineno,
        "nodeid": nodeid,
        "when": when,
    }
    
    # Add source location if available
    if location:
        warning_info["location"] = {
            "file": str(location[0]) if location[0] else None,
            "line": location[1],
            "function": location[2] if len(location) > 2 else None,
        }
    
    _test_results_storage["warnings"].append(warning_info)


def pytest_sessionfinish(session, exitstatus):
    """Generate test reports after all tests complete."""
    global _test_results_storage, _test_config
    
    if session.config.getoption("--no-export", default=False):
        return
    
    if _test_results_storage is None:
        return
    
    results = _test_results_storage
    results["finished_at"] = datetime.now(timezone.utc).isoformat()
    
    # Calculate summary
    for test in results["tests"]:
        results["summary"]["total"] += 1
        results["summary"]["duration"] += test["duration"]
        if test["outcome"] == "passed":
            results["summary"]["passed"] += 1
        elif test["outcome"] == "failed":
            results["summary"]["failed"] += 1
        elif test["outcome"] == "skipped":
            results["summary"]["skipped"] += 1
        else:
            results["summary"]["errors"] += 1
    
    results["summary"]["duration"] = round(results["summary"]["duration"], 2)
    results["summary"]["warnings"] = len(results.get("warnings", []))
    results["exit_status"] = exitstatus
    
    # Ensure output directory exists
    TEST_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Generate JSON report
    json_path = TEST_RESULTS_DIR / "test_results.json"
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    
    # Generate Markdown report
    md_path = TEST_RESULTS_DIR / "test_results.md"
    _generate_markdown_report(results, md_path)


def _generate_markdown_report(results: dict, output_path: Path) -> None:
    """Generate a Markdown test report."""
    summary = results["summary"]
    llm_costs = results.get("llm_costs", {})
    
    # Determine overall status emoji
    if summary["failed"] == 0 and summary["errors"] == 0:
        status_emoji = "✅"
        status_text = "ALL TESTS PASSED"
    else:
        status_emoji = "❌"
        status_text = "SOME TESTS FAILED"
    
    lines = [
        f"# {status_emoji} Vulnhuntr Test Results",
        "",
        f"**Status:** {status_text}",
        f"**Run Date:** {results['started_at'][:19].replace('T', ' ')} UTC",
        f"**Duration:** {summary['duration']}s",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "|--------|-------|",
        f"| Total Tests | {summary['total']} |",
        f"| ✅ Passed | {summary['passed']} |",
        f"| ❌ Failed | {summary['failed']} |",
        f"| ⏭️ Skipped | {summary['skipped']} |",
        f"| ⚠️ Errors | {summary['errors']} |",
        f"| ⚠️ Warnings | {summary.get('warnings', 0)} |",
        "",
    ]
    
    # Add LLM costs section if there was any LLM usage
    if llm_costs.get("actual_usd", 0) > 0 or llm_costs.get("estimated_usd", 0) > 0:
        lines.extend([
            "## LLM Cost Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Provider | {llm_costs.get('provider', 'N/A')} |",
            f"| Estimated Cost | ${llm_costs.get('estimated_usd', 0):.4f} |",
            f"| Actual Cost | ${llm_costs.get('actual_usd', 0):.4f} |",
        ])
        
        # Calculate accuracy if both values exist
        estimated = llm_costs.get("estimated_usd", 0)
        actual = llm_costs.get("actual_usd", 0)
        if estimated > 0 and actual > 0:
            accuracy = (1 - abs(estimated - actual) / estimated) * 100
            lines.append(f"| Estimation Accuracy | {accuracy:.1f}% |")
        
        lines.append("")
    
    # Add warnings section if any
    warnings = results.get("warnings", [])
    if warnings:
        lines.append("## Warnings")
        lines.append("")
        lines.append(f"**{len(warnings)} warnings** were recorded during test execution.")
        lines.append("")
        
        # Group warnings by category
        warnings_by_category: Dict[str, List[dict]] = {}
        for w in warnings:
            cat = w.get("category", "Warning")
            if cat not in warnings_by_category:
                warnings_by_category[cat] = []
            warnings_by_category[cat].append(w)
        
        for category in sorted(warnings_by_category.keys()):
            cat_warnings = warnings_by_category[category]
            lines.append(f"### {category} ({len(cat_warnings)})")
            lines.append("")
            
            # Deduplicate warnings by message
            seen_messages: Dict[str, dict] = {}
            for w in cat_warnings:
                msg = w.get("message", "")
                if msg not in seen_messages:
                    seen_messages[msg] = {"warning": w, "count": 1, "nodeids": [w.get("nodeid", "")]}
                else:
                    seen_messages[msg]["count"] += 1
                    if w.get("nodeid") and w.get("nodeid") not in seen_messages[msg]["nodeids"]:
                        seen_messages[msg]["nodeids"].append(w.get("nodeid"))
            
            lines.append("<details>")
            lines.append(f"<summary>Show {len(seen_messages)} unique warnings</summary>")
            lines.append("")
            
            for msg, info in seen_messages.items():
                w = info["warning"]
                count = info["count"]
                lines.append(f"**Occurrences:** {count}")
                if w.get("filename") and w.get("lineno"):
                    lines.append(f"**Source:** `{w['filename']}:{w['lineno']}`")
                lines.append("```")
                # Truncate very long messages
                display_msg = msg[:500] + "..." if len(msg) > 500 else msg
                lines.append(display_msg)
                lines.append("```")
                if len(info["nodeids"]) <= 5:
                    lines.append(f"**Triggered by:** {', '.join(f'`{n}`' for n in info['nodeids'] if n)}")
                else:
                    lines.append(f"**Triggered by:** {len(info['nodeids'])} tests")
                lines.append("")
            
            lines.append("</details>")
            lines.append("")
    
    # Group tests by file
    tests_by_file: Dict[str, List[dict]] = {}
    for test in results["tests"]:
        file_path = test.get("file", "unknown")
        if isinstance(file_path, str):
            # Extract just the filename
            file_name = Path(file_path).name if "/" in file_path or "\\" in file_path else file_path.split("::")[0]
        else:
            file_name = str(file_path.basename) if hasattr(file_path, "basename") else str(file_path)
        
        if file_name not in tests_by_file:
            tests_by_file[file_name] = []
        tests_by_file[file_name].append(test)
    
    # Add test details by file
    lines.append("## Test Details")
    lines.append("")
    
    for file_name in sorted(tests_by_file.keys()):
        file_tests = tests_by_file[file_name]
        passed = sum(1 for t in file_tests if t["outcome"] == "passed")
        failed = sum(1 for t in file_tests if t["outcome"] == "failed")
        skipped = sum(1 for t in file_tests if t["outcome"] == "skipped")
        
        status = "✅" if failed == 0 else "❌"
        lines.append(f"### {status} {file_name}")
        lines.append(f"**{passed} passed** | **{failed} failed** | **{skipped} skipped**")
        lines.append("")
        
        # List failed tests with details
        failed_tests = [t for t in file_tests if t["outcome"] == "failed"]
        if failed_tests:
            lines.append("<details>")
            lines.append("<summary>❌ Failed Tests</summary>")
            lines.append("")
            for test in failed_tests:
                test_name = test["nodeid"].split("::")[-1] if "::" in test["nodeid"] else test["nodeid"]
                lines.append(f"#### `{test_name}`")
                if test.get("longrepr"):
                    lines.append("```")
                    # Truncate long error messages
                    error_msg = test["longrepr"]
                    if len(error_msg) > 1000:
                        error_msg = error_msg[:1000] + "\n... (truncated)"
                    lines.append(error_msg)
                    lines.append("```")
                lines.append("")
            lines.append("</details>")
            lines.append("")
        
        # List skipped tests
        skipped_tests = [t for t in file_tests if t["outcome"] == "skipped"]
        if skipped_tests:
            lines.append("<details>")
            lines.append("<summary>⏭️ Skipped Tests</summary>")
            lines.append("")
            for test in skipped_tests:
                test_name = test["nodeid"].split("::")[-1] if "::" in test["nodeid"] else test["nodeid"]
                reason = test.get("skip_reason", "No reason provided")
                lines.append(f"- `{test_name}`: {reason}")
            lines.append("")
            lines.append("</details>")
            lines.append("")
    
    # Footer
    lines.extend([
        "---",
        "",
        f"*Report generated by Vulnhuntr test suite*",
    ])
    
    output_path.write_text("\n".join(lines))


# ---------------------------------------------------------------------------
# Environment fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def env_file_path(request):
    """Resolve the .env.test path from the CLI flag."""
    return Path(request.config.getoption("--env-file"))


@pytest.fixture()
def load_env(env_file_path):
    """Load variables from .env.test into the process environment.

    Automatically restores the original env when the test finishes.
    """
    import dotenv

    original = os.environ.copy()
    if env_file_path.exists():
        dotenv.load_dotenv(str(env_file_path), override=True)
    yield
    # Restore
    os.environ.clear()
    os.environ.update(original)


# ---------------------------------------------------------------------------
# LLM Configuration Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def llm_provider(request) -> str:
    """Get the current LLM provider from config.
    
    Returns:
        Provider name (anthropic, openai, google, openrouter, ollama)
    """
    return request.config.getoption("--provider") or os.getenv("PROVIDER", "anthropic")


@pytest.fixture()
def llm_logic_test_enabled(request) -> bool:
    """Check if LLM logic error tests are enabled.
    
    Returns:
        True if LLM logic tests should run
    """
    return (
        request.config.getoption("--llm-logic-test")
        or _get_env_bool("LLM_LOGIC_TEST")
    )


@pytest.fixture()
def deep_test_enabled(request) -> bool:
    """Check if deep analysis tests are enabled.
    
    Returns:
        True if deep tests should run
    """
    return (
        request.config.getoption("--deep-test")
        or _get_env_bool("DEEP_TEST")
    )


@pytest.fixture()
def llm_config(llm_provider) -> Dict[str, str]:
    """Get LLM configuration for the current provider.
    
    Returns:
        Dictionary with base_url, api_key, model keys
    """
    provider = llm_provider.lower()
    
    configs = {
        "anthropic": {
            "base_url": os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com"),
            "api_key": os.getenv("ANTHROPIC_API_KEY", ""),
            "model": os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5"),
            "deep_model": os.getenv("ANTHROPIC_MODEL_DEEP_TEST", "claude-opus-4-5"),
        },
        "openai": {
            "base_url": os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            "api_key": os.getenv("OPENAI_API_KEY", ""),
            "model": os.getenv("OPENAI_MODEL", "chatgpt-4o-latest"),
            "deep_model": os.getenv("OPENAI_MODEL", "chatgpt-4o-latest"),
        },
        "google": {
            "base_url": os.getenv("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai"),
            "api_key": os.getenv("GOOGLE_API_KEY", ""),
            "model": os.getenv("GEMINI_MODEL", "gemini-2.0-flash"),
            "deep_model": os.getenv("GEMINI_MODEL", "gemini-2.0-flash"),
        },
        "openrouter": {
            "base_url": os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
            "api_key": os.getenv("OPENROUTER_API_KEY", ""),
            "model": os.getenv("OPENROUTER_MODEL", "qwen/qwen3-coder:free"),
            "deep_model": os.getenv("OPENROUTER_MODEL", "qwen/qwen3-coder:free"),
        },
        "ollama": {
            "base_url": os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434/api/generate"),
            "api_key": os.getenv("OLLAMA_API_KEY", ""),
            "model": os.getenv("OLLAMA_MODEL", "llama3"),
            "deep_model": os.getenv("OLLAMA_MODEL", "llama3"),
        },
    }
    
    return configs.get(provider, configs["anthropic"])


# ---------------------------------------------------------------------------
# Temporary file-system structures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_repo(tmp_path):
    """Create a minimal Python repo under *tmp_path* with a few files.

    Returns the root ``Path`` of the fake repo.
    """
    (tmp_path / "README.md").write_text("# Test Project\nA web API.\n")

    views = tmp_path / "myapp" / "views.py"
    views.parent.mkdir(parents=True)
    views.write_text(
        textwrap.dedent("""\
        from flask import Flask, request
        app = Flask(__name__)

        @app.route("/search")
        def search():
            query = request.args.get("q", "")
            return f"Results for {query}"
        """)
    )

    utils = tmp_path / "myapp" / "utils.py"
    utils.write_text(
        textwrap.dedent("""\
        import os

        def read_file(name):
            with open(name) as f:
                return f.read()
        """)
    )

    (tmp_path / "myapp" / "__init__.py").write_text("")

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_views.py").write_text("def test_placeholder(): pass\n")

    return tmp_path


@pytest.fixture()
def tmp_checkpoint_dir(tmp_path):
    """Return a clean temp directory for checkpoint files."""
    d = tmp_path / "checkpoints"
    d.mkdir()
    return d


# ---------------------------------------------------------------------------
# Mock LLM factories
# ---------------------------------------------------------------------------


def _build_response_json(
    scratchpad: str = "Step 1: read code. Step 2: look for sinks.",
    analysis: str = "Found potential SQL injection via unsanitized user input.",
    poc: Optional[str] = "curl http://target/search?q=' OR 1=1--",
    confidence: int = 8,
    vuln_types: Optional[List[str]] = None,
    context_code: Optional[List[Dict]] = None,
) -> str:
    """Return a valid JSON string that matches the ``Response`` Pydantic model."""
    if vuln_types is None:
        vuln_types = ["SQLI"]
    if context_code is None:
        context_code = []
    payload = {
        "scratchpad": scratchpad,
        "analysis": analysis,
        "poc": poc,
        "confidence_score": confidence,
        "vulnerability_types": vuln_types,
        "context_code": context_code,
    }
    return json.dumps(payload)


@pytest.fixture()
def sample_response_json():
    """Ready-made JSON matching the ``Response`` schema."""
    return _build_response_json()


@pytest.fixture()
def sample_response():
    """Pre-validated ``Response`` object for use in unit tests."""
    return Response(
        scratchpad="Step 1: reviewed code. Step 2: traced user input to sink.",
        analysis="SQL injection in search endpoint via unsanitized query param.",
        poc="curl 'http://target/search?q=%27%20OR%201%3D1--'",
        confidence_score=8,
        vulnerability_types=[VulnType.SQLI],
        context_code=[],
    )


@pytest.fixture()
def sample_response_with_context():
    """A ``Response`` that requests additional context (for iteration tests)."""
    return Response(
        scratchpad="Need to see the database helper to confirm injection.",
        analysis="Potential SQLI — need db_query function source to confirm.",
        poc=None,
        confidence_score=5,
        vulnerability_types=[VulnType.SQLI],
        context_code=[
            ContextCode(
                name="db_query",
                reason="Verify if parameterized queries are used",
                code_line="result = db_query(user_input)",
            )
        ],
    )


@pytest.fixture()
def no_vuln_response():
    """A ``Response`` indicating no vulnerabilities found."""
    return Response(
        scratchpad="Checked all sinks. Input is properly escaped.",
        analysis="No remotely exploitable vulnerabilities detected.",
        poc=None,
        confidence_score=0,
        vulnerability_types=[],
        context_code=[],
    )


@pytest.fixture()
def mock_llm(sample_response_json):
    """Return a ``MagicMock`` that behaves like an ``LLM`` subclass.

    - ``chat()`` returns a pre-validated ``Response`` by default.
    - Adjust ``mock_llm.chat.return_value`` in individual tests if needed.
    """
    llm = MagicMock()
    llm.chat.return_value = Response.model_validate_json(sample_response_json)
    llm.system_prompt = "You are a security expert."
    llm.history = []
    llm.prev_prompt = None
    llm.prev_response = None
    llm.prefill = None
    llm.set_context = MagicMock()
    return llm


# ---------------------------------------------------------------------------
# Finding factories
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_finding():
    """A ``Finding`` instance for reporter tests."""
    return Finding(
        rule_id="SQLI-001",
        title="SQL Injection in search endpoint",
        file_path="/app/views.py",
        start_line=10,
        end_line=15,
        description="User input flows to raw SQL query without parameterization.",
        analysis="The search() handler passes request.args['q'] directly into an f-string SQL query.",
        scratchpad="Traced input from request.args through to cursor.execute.",
        poc="curl 'http://target/search?q=%27%20OR%201%3D1--'",
        confidence_score=8,
        severity=FindingSeverity.HIGH,
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        context_code=[{"db_query": "def db_query(sql): cursor.execute(sql)"}],
        metadata={"vuln_type": "SQLI", "iterations": 3},
    )


@pytest.fixture()
def multiple_findings(sample_finding):
    """Three findings with different severity levels for summary tests."""
    f1 = sample_finding

    f2 = Finding(
        rule_id="XSS-001",
        title="Reflected XSS in profile page",
        file_path="/app/profile.py",
        start_line=22,
        end_line=28,
        description="User-controlled data rendered without escaping.",
        analysis="The profile name is rendered in an HTML template with |safe filter.",
        scratchpad="Traced user.name into Jinja2 template.",
        poc="<script>alert(1)</script>",
        confidence_score=7,
        severity=FindingSeverity.HIGH,
        cwe_id="CWE-79",
        cwe_name="Cross-site Scripting",
    )

    f3 = Finding(
        rule_id="SSRF-001",
        title="Potential SSRF in webhook handler",
        file_path="/app/webhooks.py",
        start_line=45,
        end_line=50,
        description="User-supplied URL fetched server-side without validation.",
        analysis="The callback_url parameter is passed to requests.get() directly.",
        scratchpad="Checked for URL validation — none found.",
        poc="curl -X POST http://target/webhook -d 'url=http://169.254.169.254/'",
        confidence_score=5,
        severity=FindingSeverity.MEDIUM,
        cwe_id="CWE-918",
        cwe_name="Server-Side Request Forgery",
    )

    return [f1, f2, f3]


# ---------------------------------------------------------------------------
# Helpers available to all tests (import directly)
# ---------------------------------------------------------------------------

def build_response_json(**kwargs) -> str:
    """Module-level helper so tests can ``from conftest import build_response_json``."""
    return _build_response_json(**kwargs)
