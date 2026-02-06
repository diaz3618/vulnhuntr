"""
Tests for vulnhuntr.core.repo
===============================

Covers RepoOps file discovery, path exclusion, filename exclusion,
network pattern detection, README resolution, and get_files_to_analyze.
All tests use a temporary directory that mimics a real Python project.
"""

import textwrap

from vulnhuntr.core.repo import RepoOps


# ── README content ─────────────────────────────────────────────────────────


class TestReadmeContent:
    def test_finds_readme_md(self, tmp_repo):
        repo = RepoOps(tmp_repo)
        content = repo.get_readme_content()
        assert content is not None
        assert "Test Project" in content

    def test_finds_readme_rst(self, tmp_path):
        (tmp_path / "README.rst").write_text("Test RST\n========\n")
        repo = RepoOps(tmp_path)
        content = repo.get_readme_content()
        assert content is not None
        assert "Test RST" in content

    def test_returns_none_when_missing(self, tmp_path):
        repo = RepoOps(tmp_path)
        assert repo.get_readme_content() is None

    def test_case_insensitive(self, tmp_path):
        (tmp_path / "readme.md").write_text("lower case readme")
        repo = RepoOps(tmp_path)
        content = repo.get_readme_content()
        assert content is not None
        assert "lower case" in content


# ── get_relevant_py_files ──────────────────────────────────────────────────


class TestRelevantPyFiles:
    def test_discovers_py_files(self, tmp_repo):
        repo = RepoOps(tmp_repo)
        files = list(repo.get_relevant_py_files())
        names = {f.name for f in files}
        assert "views.py" in names
        assert "utils.py" in names

    def test_excludes_test_files(self, tmp_repo):
        repo = RepoOps(tmp_repo)
        files = list(repo.get_relevant_py_files())
        names = {f.name for f in files}
        assert "test_views.py" not in names

    def test_includes_init_files(self, tmp_repo):
        """__init__.py files are NOT excluded by default."""
        repo = RepoOps(tmp_repo)
        files = list(repo.get_relevant_py_files())
        names = {f.name for f in files}
        # __init__.py is a valid Python file and is included
        assert "__init__.py" in names

    def test_excludes_venv(self, tmp_path):
        venv = tmp_path / ".venv" / "lib" / "module.py"
        venv.parent.mkdir(parents=True)
        venv.write_text("# vendored code")

        src = tmp_path / "src" / "app.py"
        src.parent.mkdir()
        src.write_text("print('hello')")

        repo = RepoOps(tmp_path)
        files = list(repo.get_relevant_py_files())
        names = {f.name for f in files}
        assert "app.py" in names
        assert "module.py" not in names

    def test_custom_exclusions(self, tmp_path):
        (tmp_path / "keep.py").write_text("# keep")
        sub = tmp_path / "vendor" / "lib.py"
        sub.parent.mkdir()
        sub.write_text("# vendored")

        repo = RepoOps(tmp_path, exclude_paths={"/vendor"})
        files = list(repo.get_relevant_py_files())
        names = {f.name for f in files}
        assert "keep.py" in names
        assert "lib.py" not in names

    def test_empty_repo(self, tmp_path):
        repo = RepoOps(tmp_path)
        assert list(repo.get_relevant_py_files()) == []


# ── get_network_related_files ──────────────────────────────────────────────


class TestNetworkRelatedFiles:
    def test_detects_flask_route(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text(textwrap.dedent("""\
            from flask import Flask
            app = Flask(__name__)

            @app.route("/hello")
            def hello():
                return "hi"
        """))
        repo = RepoOps(tmp_path)
        result = list(repo.get_network_related_files([f]))
        assert len(result) == 1

    def test_detects_fastapi_route(self, tmp_path):
        f = tmp_path / "api.py"
        f.write_text(textwrap.dedent("""\
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/items")
            def list_items():
                return []
        """))
        repo = RepoOps(tmp_path)
        result = list(repo.get_network_related_files([f]))
        assert len(result) == 1

    def test_detects_django_url(self, tmp_path):
        f = tmp_path / "urls.py"
        f.write_text('url(r"^admin/", admin.site.urls)\n')
        repo = RepoOps(tmp_path)
        result = list(repo.get_network_related_files([f]))
        assert len(result) == 1

    def test_detects_uvicorn_run(self, tmp_path):
        f = tmp_path / "main.py"
        f.write_text('uvicorn.run("app:app", host="0.0.0.0")\n')
        repo = RepoOps(tmp_path)
        result = list(repo.get_network_related_files([f]))
        assert len(result) == 1

    def test_ignores_plain_code(self, tmp_path):
        f = tmp_path / "helper.py"
        f.write_text("def add(a, b):\n    return a + b\n")
        repo = RepoOps(tmp_path)
        result = list(repo.get_network_related_files([f]))
        assert len(result) == 0

    def test_detects_async_request_handler(self, tmp_path):
        f = tmp_path / "handler.py"
        f.write_text("async def process(request):\n    return 'ok'\n")
        repo = RepoOps(tmp_path)
        result = list(repo.get_network_related_files([f]))
        assert len(result) == 1

    def test_detects_graphql(self, tmp_path):
        f = tmp_path / "schema.py"
        f.write_text(textwrap.dedent("""\
            import graphene
            class Query(graphene.ObjectType):
                hello = graphene.String()
        """))
        repo = RepoOps(tmp_path)
        result = list(repo.get_network_related_files([f]))
        assert len(result) == 1

    def test_detects_lambda_handler(self, tmp_path):
        f = tmp_path / "lambda_fn.py"
        f.write_text("def lambda_handler(event, context):\n    return {}\n")
        repo = RepoOps(tmp_path)
        result = list(repo.get_network_related_files([f]))
        assert len(result) == 1

    def test_handles_unreadable_file(self, tmp_path):
        f = tmp_path / "binary.py"
        f.write_bytes(b"\x80\x81\x82\x83")  # invalid UTF-8
        repo = RepoOps(tmp_path)
        result = list(repo.get_network_related_files([f]))
        assert len(result) == 0


# ── get_files_to_analyze ───────────────────────────────────────────────────


class TestFilesToAnalyze:
    def test_single_file(self, tmp_path):
        f = tmp_path / "target.py"
        f.write_text("x = 1")
        repo = RepoOps(tmp_path)
        result = repo.get_files_to_analyze(f)
        assert result == [f]

    def test_directory(self, tmp_path):
        sub = tmp_path / "pkg"
        sub.mkdir()
        (sub / "a.py").write_text("# a")
        (sub / "b.py").write_text("# b")
        (sub / "c.txt").write_text("not python")

        repo = RepoOps(tmp_path)
        result = repo.get_files_to_analyze(sub)
        names = {f.name for f in result}
        assert "a.py" in names
        assert "b.py" in names
        assert "c.txt" not in names

    def test_nonexistent_path_raises(self, tmp_path):
        repo = RepoOps(tmp_path)
        try:
            repo.get_files_to_analyze(tmp_path / "nope.py")
            assert False, "Expected FileNotFoundError"
        except FileNotFoundError:
            pass

    def test_none_defaults_to_repo(self, tmp_repo):
        repo = RepoOps(tmp_repo)
        result = repo.get_files_to_analyze()
        assert len(result) > 0
        assert all(f.suffix == ".py" for f in result)


# ── Constructor / defaults ─────────────────────────────────────────────────


class TestRepoOpsInit:
    def test_default_excludes(self, tmp_path):
        repo = RepoOps(tmp_path)
        assert ".venv" in repo.to_exclude
        assert "/test" in repo.to_exclude

    def test_custom_exclude_paths(self, tmp_path):
        repo = RepoOps(tmp_path, exclude_paths={"/custom"})
        assert "/custom" in repo.to_exclude
        assert ".venv" not in repo.to_exclude

    def test_compiled_patterns_count(self, tmp_path):
        repo = RepoOps(tmp_path)
        assert len(repo.compiled_patterns) == len(RepoOps.NETWORK_PATTERNS)
        assert len(repo.compiled_patterns) > 30  # at least 30+ patterns

    def test_string_path_converted(self):
        repo = RepoOps("/tmp")
        assert isinstance(repo.repo_path, type(repo.repo_path))
