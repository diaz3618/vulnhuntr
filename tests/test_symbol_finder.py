"""
Tests for vulnhuntr.symbol_finder
==================================

Covers SymbolExtractor including the 3-tier jedi fallback search strategy
(file_search → project_search → all_names_search) and 5 documented edge cases.
Uses temporary Python files to test real jedi behavior.
"""

import textwrap
from pathlib import Path

import pytest

from vulnhuntr.symbol_finder import SymbolExtractor


# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def sample_project(tmp_path):
    """Create a minimal Python project for symbol resolution tests."""
    pkg = tmp_path / "myapp"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")

    # Module with a simple function
    (pkg / "utils.py").write_text(textwrap.dedent("""\
        def helper(x):
            \"\"\"Helper function.\"\"\"
            return x * 2

        class Calculator:
            def add(self, a, b):
                return a + b
    """))

    # Module importing utils
    (pkg / "main.py").write_text(textwrap.dedent("""\
        from myapp.utils import helper, Calculator

        def run():
            calc = Calculator()
            result = calc.add(1, 2)
            return helper(result)
    """))

    # Module with aliased import
    (pkg / "aliased.py").write_text(textwrap.dedent("""\
        from myapp.utils import Calculator as Calc

        def use_alias():
            c = Calc()
            return c.add(5, 5)
    """))

    return tmp_path


@pytest.fixture
def extractor(sample_project):
    """Create a SymbolExtractor for the sample project."""
    return SymbolExtractor(sample_project)


# ── SymbolExtractor initialization ─────────────────────────────────────────


class TestSymbolExtractorInit:
    def test_creates_jedi_project(self, extractor, sample_project):
        assert extractor.repo_path == sample_project
        assert extractor.project is not None

    def test_default_ignore_patterns(self, extractor):
        assert "/test" in extractor.ignore
        assert "/docs" in extractor.ignore
        assert "/example" in extractor.ignore

    def test_string_path_converted(self, tmp_path):
        ext = SymbolExtractor(str(tmp_path))
        assert isinstance(ext.repo_path, Path)


# ── file_search ────────────────────────────────────────────────────────────


class TestFileSearch:
    def test_finds_function_definition(self, extractor, sample_project):
        files = list((sample_project / "myapp").glob("*.py"))
        result = extractor.extract("helper", "helper(result)", files)
        assert result is not None
        assert result["name"] == "helper"
        assert "def helper" in result["source"]

    def test_finds_class_definition(self, extractor, sample_project):
        files = list((sample_project / "myapp").glob("*.py"))
        result = extractor.extract("Calculator", "Calculator()", files)
        assert result is not None
        assert result["name"] == "Calculator"
        assert "class Calculator" in result["source"]

    def test_returns_none_for_missing_symbol(self, extractor, sample_project):
        files = list((sample_project / "myapp").glob("*.py"))
        result = extractor.extract("nonexistent_func", "nonexistent_func()", files)
        assert result is None


# ── project_search ─────────────────────────────────────────────────────────


class TestProjectSearch:
    def test_finds_symbol_project_wide(self, extractor, sample_project):
        result = extractor.project_search("helper")
        assert result is not None
        assert result["name"] == "helper"

    def test_finds_class_definition(self, extractor, sample_project):
        """project_search finds top-level symbols like classes."""
        result = extractor.project_search("Calculator")
        assert result is not None
        assert result["name"] == "Calculator"


# ── all_names_search ───────────────────────────────────────────────────────


class TestAllNamesSearch:
    def test_fallback_search_finds_symbol(self, extractor, sample_project):
        import jedi

        files = list((sample_project / "myapp").glob("*.py"))
        scripts = [
            jedi.Script(path=f, project=extractor.project)
            for f in files
        ]
        result = extractor.all_names_search("helper", ["helper"], scripts, "helper(result)")
        assert result is not None
        assert result["name"] == "helper"


# ── Edge cases ─────────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_method_call_on_variable(self, extractor, sample_project):
        """Edge case #1: end_node = cast(BaseOperator, leaf_nodes[0]); end_node.call_stream()"""
        files = list((sample_project / "myapp").glob("*.py"))
        result = extractor.extract("add", "calc.add(1, 2)", files)
        assert result is not None
        assert "add" in result["name"] or "add" in result["source"]

    def test_aliased_import(self, extractor, sample_project):
        """Edge case #3: from service import Service as FlowService"""
        files = list((sample_project / "myapp").glob("*.py"))
        result = extractor.extract("Calc", "Calc()", files)
        # Should resolve to the actual Calculator class or aliased reference
        assert result is not None


# ── Helper methods ─────────────────────────────────────────────────────────


class TestHelperMethods:
    def test_should_exclude_test_paths(self, extractor):
        assert extractor._should_exclude("/path/to/test/file.py") is True
        assert extractor._should_exclude("/path/to/docs/file.py") is True
        assert extractor._should_exclude("/path/to/example/file.py") is True
        assert extractor._should_exclude("/path/to/src/file.py") is False

    def test_search_string_in_file(self, tmp_path, extractor):
        f = tmp_path / "code.py"
        f.write_text("def foo():\n    return 42\n")
        assert extractor._search_string_in_file(f, "return 42") is True
        assert extractor._search_string_in_file(f, "return 999") is False

    def test_search_ignores_whitespace(self, tmp_path, extractor):
        f = tmp_path / "code.py"
        f.write_text("x = [\n    1,\n    2,\n]\n")
        assert extractor._search_string_in_file(f, "x=[1,2,]") is True

    def test_get_definition_source(self, tmp_path, extractor):
        f = tmp_path / "code.py"
        f.write_text("line1\nline2\nline3\nline4\n")
        source = extractor._get_definition_source(f, (2, 0), (3, 5))
        assert "line2" in source

    def test_get_definition_source_full_file(self, tmp_path, extractor):
        f = tmp_path / "code.py"
        f.write_text("x = 1\ny = 2\n")
        source = extractor._get_definition_source(f, None, None)
        assert "x = 1" in source
        assert "y = 2" in source


# ── _create_match_obj ──────────────────────────────────────────────────────


class TestCreateMatchObj:
    def test_returns_dict_structure(self, extractor, sample_project):
        files = list((sample_project / "myapp").glob("*.py"))
        result = extractor.extract("helper", "helper(result)", files)
        assert result is not None
        assert "name" in result
        assert "context_name_requested" in result
        assert "file_path" in result
        assert "source" in result

    def test_third_party_placeholder(self, extractor):
        """Third-party libraries get placeholder message."""
        # Simulate a third-party path
        class MockName:
            name = "requests"
            full_name = "requests.get"
            module_path = "/third_party/requests/__init__.py"

            def get_definition_start_position(self):
                return None

            def get_definition_end_position(self):
                return None

        result = extractor._create_match_obj(MockName(), "requests.get")
        assert "Third party library" in result["source"]


# ── is_exact_match ─────────────────────────────────────────────────────────


class TestIsExactMatch:
    def test_single_part_match(self, extractor):
        class MockName:
            name = "helper"
            full_name = "myapp.utils.helper"

        assert extractor._is_exact_match(MockName(), ["helper"]) is True

    def test_multi_part_match(self, extractor):
        class MockName:
            name = "add"
            full_name = "myapp.utils.Calculator.add"

        assert extractor._is_exact_match(MockName(), ["Calculator", "add"]) is True

    def test_no_match(self, extractor):
        class MockName:
            name = "helper"
            full_name = "myapp.utils.helper"

        assert extractor._is_exact_match(MockName(), ["other"]) is False
