"""
Shared Fixtures and Test Utilities for Vulnhuntr
=================================================

Provides reusable mock objects, factory functions, and temp-directory
helpers that every test module can import via standard pytest fixture
injection.  No real LLM calls are made by any fixture here.
"""

import json
import os
import textwrap
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


# ---------------------------------------------------------------------------
# pytest configuration
# ---------------------------------------------------------------------------


def pytest_addoption(parser):
    """Register --env-file CLI option for live integration tests."""
    parser.addoption(
        "--env-file",
        action="store",
        default=str(ENV_TEST_FILE),
        help="Path to .env.test for live API tests (default: tests/.env.test)",
    )


def pytest_configure(config):
    """Register custom markers so pytest doesn't warn about them."""
    config.addinivalue_line("markers", "live: marks tests that call real LLM APIs")
    config.addinivalue_line("markers", "slow: marks tests that are slow to run")


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
        lines=(10, 15),
        description="User input flows to raw SQL query without parameterization.",
        analysis="The search() handler passes request.args['q'] directly into an f-string SQL query.",
        scratchpad="Traced input from request.args through to cursor.execute.",
        poc="curl 'http://target/search?q=%27%20OR%201%3D1--'",
        confidence_score=8,
        severity=FindingSeverity.HIGH,
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        context_code={"db_query": "def db_query(sql): cursor.execute(sql)"},
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
        lines=(22, 28),
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
        lines=(45, 50),
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
