"""
Tests for vulnhuntr.cli
========================

Covers CLI argument parsing, output formatting, and runner orchestration.
"""

import argparse
from pathlib import Path
from unittest.mock import patch

import pytest

from vulnhuntr.cli.parser import (
    create_argument_parser,
    normalize_args,
    validate_args,
)
from vulnhuntr.cli.output import (
    print_readable,
    print_dry_run_report,
    print_cost_summary,
    print_findings_summary,
    print_report_status,
    print_analysis_progress,
)
from vulnhuntr.cli.runner import (
    initialize_llm,
    get_model_name,
)


# ── Argument Parser ────────────────────────────────────────────────────────


class TestCreateArgumentParser:
    def test_creates_parser(self):
        parser = create_argument_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_root_required(self):
        parser = create_argument_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])  # Missing --root

    def test_parses_root(self, tmp_path):
        parser = create_argument_parser()
        args = parser.parse_args(["--root", str(tmp_path)])
        assert args.root == str(tmp_path)

    def test_parses_short_root(self, tmp_path):
        parser = create_argument_parser()
        args = parser.parse_args(["-r", str(tmp_path)])
        assert args.root == str(tmp_path)

    def test_parses_analyze(self, tmp_path):
        parser = create_argument_parser()
        args = parser.parse_args(["--root", str(tmp_path), "--analyze", "subdir"])
        assert args.analyze == "subdir"

    def test_parses_llm_choices(self, tmp_path):
        parser = create_argument_parser()
        for llm in ["claude", "gpt", "ollama"]:
            args = parser.parse_args(["--root", str(tmp_path), "--llm", llm])
            assert args.llm == llm

    def test_llm_default(self, tmp_path):
        parser = create_argument_parser()
        args = parser.parse_args(["--root", str(tmp_path)])
        assert args.llm == "claude"

    def test_verbosity_count(self, tmp_path):
        parser = create_argument_parser()
        args = parser.parse_args(["--root", str(tmp_path), "-v"])
        assert args.verbosity == 1

        args = parser.parse_args(["--root", str(tmp_path), "-vv"])
        assert args.verbosity == 2


class TestCostArgs:
    def test_dry_run(self, tmp_path):
        parser = create_argument_parser()
        args = parser.parse_args(["--root", str(tmp_path), "--dry-run"])
        assert args.dry_run is True

    def test_budget(self, tmp_path):
        parser = create_argument_parser()
        args = parser.parse_args(["--root", str(tmp_path), "--budget", "5.0"])
        assert args.budget == 5.0

    def test_resume_default(self, tmp_path):
        parser = create_argument_parser()
        args = parser.parse_args(["--root", str(tmp_path), "--resume"])
        assert args.resume == ".vulnhuntr_checkpoint"

    def test_resume_custom(self, tmp_path):
        parser = create_argument_parser()
        args = parser.parse_args(
            ["--root", str(tmp_path), "--resume", "/custom/checkpoint"]
        )
        assert args.resume == "/custom/checkpoint"

    def test_no_checkpoint(self, tmp_path):
        parser = create_argument_parser()
        args = parser.parse_args(["--root", str(tmp_path), "--no-checkpoint"])
        assert args.no_checkpoint is True


class TestReportArgs:
    def test_sarif(self, tmp_path):
        parser = create_argument_parser()
        args = parser.parse_args(["--root", str(tmp_path), "--sarif", "out.sarif"])
        assert args.sarif == "out.sarif"

    def test_html(self, tmp_path):
        parser = create_argument_parser()
        args = parser.parse_args(["--root", str(tmp_path), "--html", "report.html"])
        assert args.html == "report.html"

    def test_json_report(self, tmp_path):
        parser = create_argument_parser()
        args = parser.parse_args(["--root", str(tmp_path), "--json", "findings.json"])
        assert args.json == "findings.json"

    def test_csv(self, tmp_path):
        parser = create_argument_parser()
        args = parser.parse_args(["--root", str(tmp_path), "--csv", "findings.csv"])
        assert args.csv == "findings.csv"

    def test_markdown(self, tmp_path):
        parser = create_argument_parser()
        args = parser.parse_args(
            ["--root", str(tmp_path), "--markdown", "SECURITY.md"]
        )
        assert args.markdown == "SECURITY.md"

    def test_export_all(self, tmp_path):
        parser = create_argument_parser()
        args = parser.parse_args(["--root", str(tmp_path), "--export-all", "reports"])
        assert args.export_all == "reports"


class TestIntegrationArgs:
    def test_create_issues(self, tmp_path):
        parser = create_argument_parser()
        args = parser.parse_args(["--root", str(tmp_path), "--create-issues"])
        assert args.create_issues is True

    def test_webhook(self, tmp_path):
        parser = create_argument_parser()
        args = parser.parse_args(
            ["--root", str(tmp_path), "--webhook", "https://hooks.example.com"]
        )
        assert args.webhook == "https://hooks.example.com"

    def test_webhook_format(self, tmp_path):
        parser = create_argument_parser()
        for fmt in ["json", "slack", "discord", "teams"]:
            args = parser.parse_args(
                ["--root", str(tmp_path), "--webhook-format", fmt]
            )
            assert args.webhook_format == fmt


# ── Argument Validation ────────────────────────────────────────────────────


class TestValidateArgs:
    def test_valid_args(self, tmp_path):
        args = argparse.Namespace(
            root=str(tmp_path),
            analyze=None,
            budget=None,
            sarif=None,
            html=None,
            json=None,
            csv=None,
            markdown=None,
        )
        error = validate_args(args)
        assert error is None

    def test_nonexistent_root(self):
        args = argparse.Namespace(
            root="/nonexistent/path",
            analyze=None,
            budget=None,
            sarif=None,
            html=None,
            json=None,
            csv=None,
            markdown=None,
        )
        error = validate_args(args)
        assert error is not None
        assert "does not exist" in error

    def test_root_not_directory(self, tmp_path):
        file_path = tmp_path / "file.txt"
        file_path.write_text("test")
        args = argparse.Namespace(
            root=str(file_path),
            analyze=None,
            budget=None,
            sarif=None,
            html=None,
            json=None,
            csv=None,
            markdown=None,
        )
        error = validate_args(args)
        assert error is not None
        assert "not a directory" in error

    def test_invalid_budget(self, tmp_path):
        args = argparse.Namespace(
            root=str(tmp_path),
            analyze=None,
            budget=-1.0,
            sarif=None,
            html=None,
            json=None,
            csv=None,
            markdown=None,
        )
        error = validate_args(args)
        assert error is not None
        assert "positive" in error


# ── Argument Normalization ─────────────────────────────────────────────────


class TestNormalizeArgs:
    def test_root_absolute(self, tmp_path):
        args = argparse.Namespace(
            root=str(tmp_path),
            analyze=None,
            sarif=None,
            html=None,
            json=None,
            csv=None,
            markdown=None,
            export_all=None,
            resume=None,
        )
        normalized = normalize_args(args)
        assert Path(normalized.root).is_absolute()

    def test_analyze_relative_to_root(self, tmp_path):
        (tmp_path / "subdir").mkdir()
        args = argparse.Namespace(
            root=str(tmp_path),
            analyze="subdir",
            sarif=None,
            html=None,
            json=None,
            csv=None,
            markdown=None,
            export_all=None,
            resume=None,
        )
        normalized = normalize_args(args)
        assert "subdir" in normalized.analyze
        assert Path(normalized.analyze).is_absolute()

    def test_report_paths_absolute(self, tmp_path):
        args = argparse.Namespace(
            root=str(tmp_path),
            analyze=None,
            sarif="report.sarif",
            html=None,
            json=None,
            csv=None,
            markdown=None,
            export_all=None,
            resume=None,
        )
        normalized = normalize_args(args)
        assert Path(normalized.sarif).is_absolute()


# ── Output Functions ───────────────────────────────────────────────────────


class TestPrintReadable:
    def test_prints_response_attrs(self, sample_response, capsys):
        print_readable(sample_response)
        captured = capsys.readouterr()
        assert "scratchpad" in captured.out
        assert "analysis" in captured.out


class TestPrintDryRunReport:
    def test_prints_estimate(self, capsys):
        estimate = {
            "file_count": 10,
            "model": "claude-3-5-sonnet",
            "estimated_total_tokens": 50000,
            "estimated_input_tokens": 40000,
            "estimated_output_tokens": 10000,
            "estimated_cost_usd": 0.50,
            "estimated_cost_range": {"low": 0.40, "high": 0.60},
        }
        print_dry_run_report(estimate)
        captured = capsys.readouterr()
        assert "DRY RUN" in captured.out
        assert "10" in captured.out  # file_count
        assert "0.50" in captured.out or "$0.5" in captured.out


class TestPrintCostSummary:
    def test_prints_summary(self, capsys):
        summary = {
            "total_cost": 1.23,
            "total_input_tokens": 10000,
            "total_output_tokens": 5000,
            "total_calls": 15,
            "files_analyzed": 5,
        }
        print_cost_summary(summary)
        captured = capsys.readouterr()
        assert "COST SUMMARY" in captured.out
        assert "1.23" in captured.out


class TestPrintFindingsSummary:
    def test_no_findings(self, capsys):
        print_findings_summary([], 10)
        captured = capsys.readouterr()
        assert "No vulnerabilities" in captured.out

    def test_with_findings(self, multiple_findings, capsys):
        print_findings_summary(multiple_findings, 10)
        captured = capsys.readouterr()
        assert "3" in captured.out  # 3 findings
        assert "potential vulnerabilities" in captured.out


class TestPrintReportStatus:
    def test_success(self, capsys):
        print_report_status("SARIF", "/path/to/report.sarif", success=True)
        captured = capsys.readouterr()
        assert "✓" in captured.out
        assert "SARIF" in captured.out

    def test_failure(self, capsys):
        print_report_status(
            "HTML", "/path/to/report.html", success=False, error="Permission denied"
        )
        captured = capsys.readouterr()
        assert "✗" in captured.out
        assert "Permission denied" in captured.out


class TestPrintAnalysisProgress:
    def test_basic_progress(self, tmp_path, capsys):
        print_analysis_progress(
            current_file=tmp_path / "file.py",
            file_index=3,
            total_files=10,
            current_cost=0.15,
        )
        captured = capsys.readouterr()
        assert "[3/10]" in captured.out
        assert "0.15" in captured.out

    def test_with_budget(self, tmp_path, capsys):
        print_analysis_progress(
            current_file=tmp_path / "file.py",
            file_index=5,
            total_files=10,
            current_cost=2.50,
            budget=5.00,
        )
        captured = capsys.readouterr()
        assert "2.50" in captured.out
        assert "5.00" in captured.out


# ── Runner Functions ───────────────────────────────────────────────────────


class TestGetModelName:
    def test_claude_default(self):
        with patch.dict("os.environ", {}, clear=True):
            name = get_model_name("claude")
            assert "claude" in name.lower() or "sonnet" in name.lower()

    def test_gpt_default(self):
        with patch.dict("os.environ", {}, clear=True):
            name = get_model_name("gpt")
            assert "gpt" in name.lower() or "chatgpt" in name.lower()

    def test_ollama_default(self):
        with patch.dict("os.environ", {}, clear=True):
            name = get_model_name("ollama")
            assert "llama" in name.lower()

    def test_env_override(self):
        with patch.dict("os.environ", {"ANTHROPIC_MODEL": "claude-opus-test"}):
            name = get_model_name("claude")
            assert name == "claude-opus-test"


class TestInitializeLLM:
    def test_invalid_llm(self):
        with pytest.raises(ValueError, match="Invalid LLM"):
            initialize_llm("invalid-provider")

    @patch("vulnhuntr.LLMs.Claude")
    def test_claude_init(self, mock_claude):
        initialize_llm("claude", "system prompt")
        mock_claude.assert_called_once()

    @patch("vulnhuntr.LLMs.ChatGPT")
    def test_gpt_init(self, mock_gpt):
        initialize_llm("gpt", "system prompt")
        mock_gpt.assert_called_once()

    @patch("vulnhuntr.LLMs.Ollama")
    def test_ollama_init(self, mock_ollama):
        initialize_llm("ollama", "system prompt")
        mock_ollama.assert_called_once()

    @patch("vulnhuntr.LLMs.Claude")
    def test_case_insensitive(self, mock_claude):
        initialize_llm("CLAUDE", "system prompt")
        mock_claude.assert_called_once()

        mock_claude.reset_mock()
        initialize_llm("Claude", "system prompt")
        mock_claude.assert_called_once()
