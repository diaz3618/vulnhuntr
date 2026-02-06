"""
Tests for vulnhuntr.core.analysis
=================================

Tests the vulnerability analysis engine including initial analysis,
secondary analysis with context expansion, and iteration control.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vulnhuntr.core.analysis import (
    AnalysisConfig,
    AnalysisResult,
    VulnerabilityAnalyzer,
)
from vulnhuntr.core.models import ContextCode, Response, VulnType


# ── AnalysisConfig ─────────────────────────────────────────────────────────


class TestAnalysisConfig:
    def test_defaults(self):
        config = AnalysisConfig()
        assert config.max_iterations == 7
        assert config.min_confidence_for_finding == 5
        assert config.verbosity == 0

    def test_custom_values(self):
        config = AnalysisConfig(
            max_iterations=10,
            min_confidence_for_finding=8,
            verbosity=2,
        )
        assert config.max_iterations == 10
        assert config.min_confidence_for_finding == 8
        assert config.verbosity == 2


# ── AnalysisResult ─────────────────────────────────────────────────────────


class TestAnalysisResult:
    def test_creation(self, sample_response):
        result = AnalysisResult(
            file_path=Path("/test/file.py"),
            initial_report=sample_response,
        )
        assert result.file_path == Path("/test/file.py")
        assert result.initial_report == sample_response
        assert result.findings == {}
        assert result.context_code == {}

    def test_with_findings(self, sample_response):
        result = AnalysisResult(
            file_path=Path("/test/file.py"),
            initial_report=sample_response,
            findings={VulnType.SQLI: sample_response},
            context_code={"get_user": "def get_user(): pass"},
        )
        assert VulnType.SQLI in result.findings
        assert "get_user" in result.context_code

    def test_has_vulnerabilities_true(self, sample_response):
        result = AnalysisResult(
            file_path=Path("/test/file.py"),
            initial_report=sample_response,
            findings={VulnType.XSS: sample_response},
        )
        assert result.has_vulnerabilities is True

    def test_has_vulnerabilities_false(self, sample_response):
        result = AnalysisResult(
            file_path=Path("/test/file.py"),
            initial_report=sample_response,
        )
        assert result.has_vulnerabilities is False


# ── VulnerabilityAnalyzer ──────────────────────────────────────────────────


class TestVulnerabilityAnalyzerInit:
    def test_default_config(self):
        mock_llm = MagicMock()
        mock_extractor = MagicMock()

        analyzer = VulnerabilityAnalyzer(mock_llm, mock_extractor)

        assert analyzer.llm == mock_llm
        assert analyzer.code_extractor == mock_extractor
        assert isinstance(analyzer.config, AnalysisConfig)
        assert analyzer.prompt_templates == {}
        assert analyzer.vuln_specific_data == {}

    def test_custom_config(self):
        mock_llm = MagicMock()
        mock_extractor = MagicMock()
        config = AnalysisConfig(max_iterations=5)

        analyzer = VulnerabilityAnalyzer(mock_llm, mock_extractor, config=config)

        assert analyzer.config.max_iterations == 5


class TestVulnerabilityAnalyzerCallbacks:
    def test_set_iteration_callback(self):
        mock_llm = MagicMock()
        mock_extractor = MagicMock()
        analyzer = VulnerabilityAnalyzer(mock_llm, mock_extractor)

        callback = MagicMock()
        analyzer.set_iteration_callback(callback)

        assert analyzer._on_iteration == callback

    def test_set_continue_check(self):
        mock_llm = MagicMock()
        mock_extractor = MagicMock()
        analyzer = VulnerabilityAnalyzer(mock_llm, mock_extractor)

        callback = MagicMock(return_value=True)
        analyzer.set_continue_check(callback)

        assert analyzer._should_continue == callback


class TestSummarizeReadme:
    @patch("vulnhuntr.prompts.README_SUMMARY_PROMPT_TEMPLATE", "Summarize this:")
    def test_summarize_readme(self):
        mock_llm = MagicMock()
        mock_llm.chat.return_value = "<summary>Test summary</summary>"
        mock_extractor = MagicMock()

        analyzer = VulnerabilityAnalyzer(mock_llm, mock_extractor)
        result = analyzer.summarize_readme("# Project README\n\nThis is a test project.")

        assert result == "Test summary"
        mock_llm.set_context.assert_called_once()
        mock_llm.chat.assert_called_once()

    @patch("vulnhuntr.prompts.README_SUMMARY_PROMPT_TEMPLATE", "Summarize this:")
    def test_summarize_readme_no_tags(self):
        mock_llm = MagicMock()
        mock_llm.chat.return_value = "Plain response without tags"
        mock_extractor = MagicMock()

        analyzer = VulnerabilityAnalyzer(mock_llm, mock_extractor)
        result = analyzer.summarize_readme("# README")

        assert result == ""  # No summary extracted


class TestAnalyzeFile:
    def test_analyze_file_no_vulnerabilities(self, tmp_path):
        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text("def hello(): return 'world'")

        # Mock LLM response with no vulnerabilities
        mock_response = Response(
            scratchpad="Analysis complete",
            analysis="No vulnerabilities found",
            poc="",
            confidence_score=0,
            vulnerability_types=[],
            context_code=[],
        )

        mock_llm = MagicMock()
        mock_llm.chat.return_value = mock_response
        mock_extractor = MagicMock()

        analyzer = VulnerabilityAnalyzer(mock_llm, mock_extractor)

        with patch.object(analyzer, "_build_initial_prompt", return_value="prompt"):
            result = analyzer.analyze_file(test_file, [test_file])

        assert result.file_path == test_file
        assert result.initial_report == mock_response
        assert result.has_vulnerabilities is False

    def test_analyze_file_with_vulnerabilities(self, tmp_path):
        # Create test file
        test_file = tmp_path / "vuln.py"
        test_file.write_text("def query(user_input): execute(user_input)")

        # Mock initial response with vulnerability
        initial_response = Response(
            scratchpad="Found SQL injection",
            analysis="Potential SQL injection",
            poc="' OR 1=1 --",
            confidence_score=7,
            vulnerability_types=[VulnType.SQLI],
            context_code=[],
        )

        # Mock secondary response
        secondary_response = Response(
            scratchpad="Confirmed SQL injection",
            analysis="Confirmed vulnerability",
            poc="' OR 1=1 --",
            confidence_score=8,
            vulnerability_types=[VulnType.SQLI],
            context_code=[],
        )

        mock_llm = MagicMock()
        mock_llm.chat.side_effect = [initial_response, secondary_response]
        mock_extractor = MagicMock()

        config = AnalysisConfig(min_confidence_for_finding=5)
        analyzer = VulnerabilityAnalyzer(mock_llm, mock_extractor, config=config)

        with patch.object(analyzer, "_build_initial_prompt", return_value="prompt"):
            with patch.object(
                analyzer, "_build_secondary_prompt", return_value="secondary"
            ):
                result = analyzer.analyze_file(test_file, [test_file])

        assert result.has_vulnerabilities is True
        assert VulnType.SQLI in result.findings

    def test_analyze_file_empty_file(self, tmp_path):
        test_file = tmp_path / "empty.py"
        test_file.write_text("")

        mock_llm = MagicMock()
        mock_extractor = MagicMock()
        analyzer = VulnerabilityAnalyzer(mock_llm, mock_extractor)

        with pytest.raises(ValueError, match="Empty file"):
            analyzer.analyze_file(test_file, [test_file])

    def test_analyze_file_nonexistent(self, tmp_path):
        test_file = tmp_path / "nonexistent.py"

        mock_llm = MagicMock()
        mock_extractor = MagicMock()
        analyzer = VulnerabilityAnalyzer(mock_llm, mock_extractor)

        with pytest.raises(OSError):
            analyzer.analyze_file(test_file, [test_file])


class TestSecondaryAnalysis:
    def test_context_expansion(self, tmp_path):
        test_file = tmp_path / "test.py"
        test_file.write_text("code")

        # First iteration requests context
        response1 = Response(
            scratchpad="Need more context",
            analysis="Analyzing",
            poc="",
            confidence_score=5,
            vulnerability_types=[VulnType.SQLI],
            context_code=[
                ContextCode(
                    name="get_user", reason="Need implementation", code_line="get_user()"
                )
            ],
        )

        # Second iteration, no more context needed
        response2 = Response(
            scratchpad="Analysis complete",
            analysis="Confirmed vulnerability",
            poc="exploit",
            confidence_score=8,
            vulnerability_types=[VulnType.SQLI],
            context_code=[],  # No more context
        )

        mock_llm = MagicMock()
        mock_llm.chat.side_effect = [response1, response2]

        mock_extractor = MagicMock()
        mock_extractor.extract.return_value = {
            "name": "get_user",
            "context_name_requested": "get_user",
            "file_path": str(test_file),
            "source": "def get_user(): pass"
        }

        analyzer = VulnerabilityAnalyzer(mock_llm, mock_extractor)

        final_report, context = analyzer._secondary_analysis(
            file_path=test_file,
            content="code",
            vuln_type=VulnType.SQLI,
            all_files=[test_file],
            vuln_data={"bypasses": [], "prompt": "test"},
            analysis_approach="approach",
            guidelines="guidelines",
        )

        assert final_report.confidence_score == 8
        assert "get_user" in context
        assert mock_llm.chat.call_count == 2

    def test_max_iterations_limit(self, tmp_path):
        test_file = tmp_path / "test.py"
        test_file.write_text("code")

        # Response that always requests more context
        endless_response = Response(
            scratchpad="Need more",
            analysis="Still analyzing",
            poc="",
            confidence_score=5,
            vulnerability_types=[VulnType.RCE],
            context_code=[
                ContextCode(name="func", reason="Need it", code_line="func()")
            ],
        )

        mock_llm = MagicMock()
        mock_llm.chat.return_value = endless_response

        mock_extractor = MagicMock()
        mock_extractor.extract.return_value = {
            "name": "func",
            "context_name_requested": "func",
            "file_path": str(test_file),
            "source": "def func(): pass"
        }

        config = AnalysisConfig(max_iterations=3)
        analyzer = VulnerabilityAnalyzer(mock_llm, mock_extractor, config=config)

        final_report, _ = analyzer._secondary_analysis(
            file_path=test_file,
            content="code",
            vuln_type=VulnType.RCE,
            all_files=[test_file],
            vuln_data={"bypasses": [], "prompt": "test"},
            analysis_approach="approach",
            guidelines="guidelines",
        )

        # Should stop at max_iterations (3)
        assert mock_llm.chat.call_count == 3

    def test_same_context_twice_stops(self, tmp_path):
        test_file = tmp_path / "test.py"
        test_file.write_text("code")

        # Response always requests same context
        same_context_response = Response(
            scratchpad="Need more",
            analysis="Analyzing",
            poc="",
            confidence_score=5,
            vulnerability_types=[VulnType.XSS],
            context_code=[
                ContextCode(name="escape", reason="Need it", code_line="escape()")
            ],
        )

        mock_llm = MagicMock()
        mock_llm.chat.return_value = same_context_response

        mock_extractor = MagicMock()
        # Return None - context not found
        mock_extractor.extract.return_value = None

        analyzer = VulnerabilityAnalyzer(mock_llm, mock_extractor)

        final_report, _ = analyzer._secondary_analysis(
            file_path=test_file,
            content="code",
            vuln_type=VulnType.XSS,
            all_files=[test_file],
            vuln_data={"bypasses": [], "prompt": "test"},
            analysis_approach="approach",
            guidelines="guidelines",
        )

        # Should stop after detecting same context requested twice
        # Initial + 2 more (same_context_count triggers at 2)
        assert mock_llm.chat.call_count <= 4

    def test_continue_callback_stops_analysis(self, tmp_path):
        test_file = tmp_path / "test.py"
        test_file.write_text("code")

        response = Response(
            scratchpad="Analyzing",
            analysis="Analysis",
            poc="",
            confidence_score=5,
            vulnerability_types=[VulnType.LFI],
            context_code=[ContextCode(name="func", reason="r", code_line="func()")],
        )

        mock_llm = MagicMock()
        mock_llm.chat.return_value = response
        mock_extractor = MagicMock()

        analyzer = VulnerabilityAnalyzer(mock_llm, mock_extractor)
        # Stop after first iteration - callback called at start of each iteration
        # side_effect=[True, False] means: iteration 0 proceeds, iteration 1 stops before LLM call
        analyzer.set_continue_check(MagicMock(side_effect=[True, False]))

        final_report, _ = analyzer._secondary_analysis(
            file_path=test_file,
            content="code",
            vuln_type=VulnType.LFI,
            all_files=[test_file],
            vuln_data={"bypasses": [], "prompt": "test"},
            analysis_approach="approach",
            guidelines="guidelines",
        )

        # Should stop after callback returns False (only 1 LLM call made)
        assert mock_llm.chat.call_count == 1

    def test_iteration_callback_called(self, tmp_path):
        test_file = tmp_path / "test.py"
        test_file.write_text("code")

        response = Response(
            scratchpad="Done",
            analysis="Complete",
            poc="",
            confidence_score=5,
            vulnerability_types=[VulnType.SSRF],
            context_code=[],
        )

        mock_llm = MagicMock()
        mock_llm.chat.return_value = response
        mock_extractor = MagicMock()

        iteration_callback = MagicMock()
        analyzer = VulnerabilityAnalyzer(mock_llm, mock_extractor)
        analyzer.set_iteration_callback(iteration_callback)

        analyzer._secondary_analysis(
            file_path=test_file,
            content="code",
            vuln_type=VulnType.SSRF,
            all_files=[test_file],
            vuln_data={"bypasses": [], "prompt": "test"},
            analysis_approach="approach",
            guidelines="guidelines",
        )

        iteration_callback.assert_called_once_with(0, response)


class TestBuildPrompts:
    def test_build_initial_prompt(self, tmp_path):
        test_file = tmp_path / "test.py"

        mock_llm = MagicMock()
        mock_extractor = MagicMock()
        analyzer = VulnerabilityAnalyzer(mock_llm, mock_extractor)

        prompt = analyzer._build_initial_prompt(
            file_path=test_file,
            content="def test(): pass",
            initial_prompt_template="Analyze this code",
            analysis_approach="Systematic approach",
            guidelines="Follow security guidelines",
        )

        assert "test.py" in prompt
        assert "def test(): pass" in prompt
        assert "Analyze this code" in prompt
        assert "Systematic approach" in prompt
        assert "Follow security guidelines" in prompt

    def test_build_secondary_prompt(self, tmp_path):
        from vulnhuntr.core.xml_models import CodeDefinitions

        test_file = tmp_path / "test.py"

        mock_llm = MagicMock()
        mock_extractor = MagicMock()
        analyzer = VulnerabilityAnalyzer(mock_llm, mock_extractor)

        prompt = analyzer._build_secondary_prompt(
            file_path=test_file,
            content="def query(): pass",
            definitions=CodeDefinitions(definitions=[]),
            bypasses=["' OR 1=1 --"],
            vuln_prompt="Check for SQL injection",
            analysis_approach="Deep analysis",
            previous_analysis="Initial findings",
            guidelines="Security first",
        )

        assert "test.py" in prompt
        assert "def query(): pass" in prompt
        assert "' OR 1=1 --" in prompt
        assert "SQL injection" in prompt


class TestExtractBetweenTags:
    def test_extract_single_tag(self):
        text = "<summary>This is the summary</summary>"
        result = VulnerabilityAnalyzer._extract_between_tags("summary", text)
        assert result == ["This is the summary"]

    def test_extract_multiple_tags(self):
        text = "<item>First</item><item>Second</item>"
        result = VulnerabilityAnalyzer._extract_between_tags("item", text)
        assert result == ["First", "Second"]

    def test_extract_no_match(self):
        text = "No tags here"
        result = VulnerabilityAnalyzer._extract_between_tags("tag", text)
        assert result == []

    def test_extract_with_strip(self):
        text = "<data>  whitespace  </data>"
        result = VulnerabilityAnalyzer._extract_between_tags("data", text, strip=True)
        assert result == ["whitespace"]

    def test_extract_multiline(self):
        text = "<code>\ndef test():\n    pass\n</code>"
        result = VulnerabilityAnalyzer._extract_between_tags("code", text)
        assert "def test():" in result[0]
