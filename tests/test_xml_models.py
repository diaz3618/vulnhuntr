"""
Tests for vulnhuntr.core.xml_models
=====================================

Exercises every pydantic-xml model to confirm correct XML tag names,
element structure, serialization and deserialization round-trips, and
container behaviour for nested definitions.
"""

from vulnhuntr.core.xml_models import (
    AnalysisApproach,
    CodeDefinition,
    CodeDefinitions,
    ExampleBypasses,
    FileCode,
    Guidelines,
    Instructions,
    PreviousAnalysis,
    ReadmeContent,
    ReadmeSummary,
    ResponseFormat,
)


# ── Helpers ────────────────────────────────────────────────────────────────


def _xml_round_trip(model_class, **kwargs):
    """Serialize to XML bytes and parse back; return the restored instance."""
    instance = model_class(**kwargs)
    xml_bytes = instance.to_xml()
    restored = model_class.from_xml(xml_bytes)
    return instance, restored


# ── Simple wrapper models ──────────────────────────────────────────────────


class TestReadmeContent:
    def test_tag_name(self):
        obj = ReadmeContent(content="hello")
        xml = obj.to_xml()
        assert b"<readme_content>" in xml

    def test_round_trip(self):
        original, restored = _xml_round_trip(ReadmeContent, content="Project overview.")
        assert restored.content == original.content


class TestReadmeSummary:
    def test_tag_name(self):
        obj = ReadmeSummary(readme_summary="summary text")
        assert b"<readme_summary>" in obj.to_xml()

    def test_round_trip(self):
        original, restored = _xml_round_trip(
            ReadmeSummary, readme_summary="A short summary."
        )
        assert restored.readme_summary == original.readme_summary


class TestInstructions:
    def test_round_trip(self):
        original, restored = _xml_round_trip(
            Instructions, instructions="Analyze for SQLI."
        )
        assert restored.instructions == original.instructions


class TestResponseFormat:
    def test_round_trip(self):
        schema = '{"scratchpad": "string"}'
        original, restored = _xml_round_trip(
            ResponseFormat, response_format=schema
        )
        assert restored.response_format == original.response_format


class TestAnalysisApproach:
    def test_round_trip(self):
        original, restored = _xml_round_trip(
            AnalysisApproach, analysis_approach="Trace from source to sink."
        )
        assert restored.analysis_approach == original.analysis_approach


class TestGuidelines:
    def test_round_trip(self):
        original, restored = _xml_round_trip(
            Guidelines, guidelines="Focus on user-controlled input."
        )
        assert restored.guidelines == original.guidelines


class TestPreviousAnalysis:
    def test_round_trip(self):
        original, restored = _xml_round_trip(
            PreviousAnalysis, previous_analysis="Iteration 1 found potential SSRF."
        )
        assert restored.previous_analysis == original.previous_analysis


class TestExampleBypasses:
    def test_round_trip(self):
        original, restored = _xml_round_trip(
            ExampleBypasses, example_bypasses="../../../../etc/passwd"
        )
        assert restored.example_bypasses == original.example_bypasses


# ── FileCode (element-based fields) ───────────────────────────────────────


class TestFileCode:
    def test_elements_present(self):
        fc = FileCode(file_path="/app/views.py", file_source="def index(): pass")
        xml = fc.to_xml()
        assert b"<file_path>" in xml
        assert b"<file_source>" in xml

    def test_round_trip(self):
        original, restored = _xml_round_trip(
            FileCode,
            file_path="src/handler.py",
            file_source='def handle(req):\n    return req.args["q"]',
        )
        assert restored.file_path == original.file_path
        assert restored.file_source == original.file_source


# ── CodeDefinition / CodeDefinitions ──────────────────────────────────────


class TestCodeDefinition:
    def test_tag_is_code(self):
        cd = CodeDefinition(
            name="my_func",
            context_name_requested="my_func",
            file_path="utils.py",
            source="def my_func(): ...",
        )
        xml = cd.to_xml()
        assert b"<code>" in xml

    def test_round_trip(self):
        original, restored = _xml_round_trip(
            CodeDefinition,
            name="validate",
            context_name_requested="validate",
            file_path="auth.py",
            source="def validate(token): return True",
        )
        assert restored.name == original.name
        assert restored.source == original.source


class TestCodeDefinitions:
    def test_empty_container(self):
        cd = CodeDefinitions()
        xml = cd.to_xml()
        assert b"<context_code" in xml
        assert cd.definitions == []

    def test_with_definitions(self):
        items = [
            CodeDefinition(
                name="a", context_name_requested="a",
                file_path="x.py", source="def a(): ..."
            ),
            CodeDefinition(
                name="b", context_name_requested="b",
                file_path="y.py", source="def b(): ..."
            ),
        ]
        cd = CodeDefinitions(definitions=items)
        xml = cd.to_xml()
        assert xml.count(b"<code>") == 2

    def test_round_trip_nested(self):
        items = [
            CodeDefinition(
                name="func_one",
                context_name_requested="func_one",
                file_path="a.py",
                source="def func_one(): pass",
            ),
        ]
        original = CodeDefinitions(definitions=items)
        xml_bytes = original.to_xml()
        restored = CodeDefinitions.from_xml(xml_bytes)
        assert len(restored.definitions) == 1
        assert restored.definitions[0].name == "func_one"
