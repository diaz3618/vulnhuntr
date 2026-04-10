"""
Tests for vulnhuntr.cli

Covers CLI argument parsing, output formatting, and runner orchestration.
"""

import argparse
import json as json_mod
from pathlib import Path
from unittest.mock import patch

import pytest

from vulnhuntr.cli.output import (
    print_analysis_progress,
    print_cost_summary,
    print_dry_run_report,
    print_findings_summary,
    print_readable,
    print_report_status,
)
from vulnhuntr.cli.parser import (
    create_argument_parser,
    normalize_args,
    validate_args,
)
from unittest.mock import MagicMock

from vulnhuntr.cli.runner import (
    _analyze_files,
    _collect_files,
    _dispatch_integrations,
    _dispatch_reports,
    _generate_reports,
    _init_providers,
    get_model_name,
    initialize_llm,
    parse_fallback_spec,
    run_analysis,
)
from vulnhuntr.cost_tracker import CostTracker


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
        assert args.llm is None  # Default is None; resolved to 'claude' at runtime if config doesn't set provider

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
        args = parser.parse_args(["--root", str(tmp_path), "--resume", "/custom/checkpoint"])
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
        args = parser.parse_args(["--root", str(tmp_path), "--markdown", "SECURITY.md"])
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
        args = parser.parse_args(["--root", str(tmp_path), "--webhook", "https://hooks.example.com"])
        assert args.webhook == "https://hooks.example.com"

    def test_webhook_format(self, tmp_path):
        parser = create_argument_parser()
        for fmt in ["json", "slack", "discord", "teams"]:
            args = parser.parse_args(["--root", str(tmp_path), "--webhook-format", fmt])
            assert args.webhook_format == fmt


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

    def test_analyze_within_root_is_accepted(self, tmp_path):
        target = tmp_path / "sub" / "module.py"
        target.parent.mkdir()
        target.write_text("x = 1")
        args = argparse.Namespace(
            root=str(tmp_path),
            analyze=str(target),
            budget=None,
            sarif=None,
            html=None,
            json=None,
            csv=None,
            markdown=None,
        )
        error = validate_args(args)
        assert error is None

    def test_analyze_outside_root_is_rejected(self, tmp_path):
        root = tmp_path / "project"
        root.mkdir()
        outside = tmp_path / "secret.py"
        outside.write_text("password = 'hunter2'")
        args = argparse.Namespace(
            root=str(root),
            analyze=str(outside),
            budget=None,
            sarif=None,
            html=None,
            json=None,
            csv=None,
            markdown=None,
        )
        error = validate_args(args)
        assert error is not None
        assert "outside" in error

    def test_analyze_traversal_via_dotdot_is_rejected(self, tmp_path):
        root = tmp_path / "project"
        root.mkdir()
        outside = tmp_path / "other.py"
        outside.write_text("x = 1")
        # Use a dotdot path that resolves outside root
        traversal_path = str(root / ".." / "other.py")
        args = argparse.Namespace(
            root=str(root),
            analyze=traversal_path,
            budget=None,
            sarif=None,
            html=None,
            json=None,
            csv=None,
            markdown=None,
        )
        error = validate_args(args)
        assert error is not None
        assert "outside" in error

    def test_analyze_inside_root(self, tmp_path):
        target = tmp_path / "app.py"
        target.write_text("x = 1\n")
        args = argparse.Namespace(
            root=str(tmp_path),
            analyze=str(target),
            budget=None,
            sarif=None,
            html=None,
            json=None,
            csv=None,
            markdown=None,
        )
        error = validate_args(args)
        assert error is None

    def test_analyze_outside_root(self, tmp_path):
        # Sibling directory that is NOT inside tmp_path
        outside = tmp_path.parent / "outside_dir"
        outside.mkdir(exist_ok=True)
        target = outside / "evil.py"
        target.write_text("x = 1\n")
        args = argparse.Namespace(
            root=str(tmp_path),
            analyze=str(target),
            budget=None,
            sarif=None,
            html=None,
            json=None,
            csv=None,
            markdown=None,
        )
        error = validate_args(args)
        assert error is not None
        assert "outside" in error


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
            reports_dir=None,
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
            reports_dir=None,
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
            reports_dir=None,
        )
        normalized = normalize_args(args)
        assert Path(normalized.sarif).is_absolute()


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
        print_report_status("HTML", "/path/to/report.html", success=False, error="Permission denied")
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

    @patch("vulnhuntr.llms.Claude")
    def test_claude_init(self, mock_claude):
        initialize_llm("claude", "system prompt")
        mock_claude.assert_called_once()

    @patch("vulnhuntr.llms.ChatGPT")
    def test_gpt_init(self, mock_gpt):
        initialize_llm("gpt", "system prompt")
        mock_gpt.assert_called_once()

    @patch("vulnhuntr.llms.Ollama")
    def test_ollama_init(self, mock_ollama):
        initialize_llm("ollama", "system prompt")
        mock_ollama.assert_called_once()

    @patch("vulnhuntr.llms.Claude")
    def test_case_insensitive(self, mock_claude):
        initialize_llm("CLAUDE", "system prompt")
        mock_claude.assert_called_once()

        mock_claude.reset_mock()
        initialize_llm("Claude", "system prompt")
        mock_claude.assert_called_once()


class TestParseFallbackSpec:
    """Tests for parse_fallback_spec provider/model parsing logic."""

    @patch("vulnhuntr.llms.OpenRouter")
    def test_explicit_provider_prefix(self, mock_or):
        """'openrouter:model-name:free' parses provider correctly."""
        parse_fallback_spec("openrouter:deepseek/deepseek-r1-0528:free", "sys")
        mock_or.assert_called_once()
        # model arg should be 'deepseek/deepseek-r1-0528:free'
        model_arg = mock_or.call_args[0][0]
        assert model_arg == "deepseek/deepseek-r1-0528:free"

    @patch("vulnhuntr.llms.Claude")
    def test_explicit_claude_prefix(self, mock_claude):
        """'claude:claude-haiku-4-5' parses correctly."""
        parse_fallback_spec("claude:claude-haiku-4-5", "sys")
        mock_claude.assert_called_once()
        assert mock_claude.call_args[0][0] == "claude-haiku-4-5"

    @patch("vulnhuntr.llms.OpenRouter")
    def test_model_only_with_slash_infers_openrouter(self, mock_or):
        """'qwen/qwen3-next:free' (no provider prefix) infers openrouter from slash."""
        parse_fallback_spec("qwen/qwen3-next-80b-a3b-instruct:free", "sys")
        mock_or.assert_called_once()
        # Entire spec used as model name
        model_arg = mock_or.call_args[0][0]
        assert model_arg == "qwen/qwen3-next-80b-a3b-instruct:free"

    @patch("vulnhuntr.llms.OpenRouter")
    def test_model_only_with_default_provider(self, mock_or):
        """Uses default_provider when spec has no valid provider prefix."""
        parse_fallback_spec(
            "qwen/qwen3-next-80b-a3b-instruct:free",
            "sys",
            default_provider="openrouter",
        )
        mock_or.assert_called_once()

    @patch("vulnhuntr.llms.Claude")
    def test_model_only_with_default_provider_claude(self, mock_claude):
        """default_provider='claude' used for a bare model name without slash."""
        parse_fallback_spec("claude-haiku-4-5", "sys", default_provider="claude")
        mock_claude.assert_called_once()
        assert mock_claude.call_args[0][0] == "claude-haiku-4-5"

    def test_bare_model_no_slash_no_default_raises(self):
        """Bare model name without slash or default_provider raises ValueError."""
        with pytest.raises(ValueError, match="Cannot determine provider"):
            parse_fallback_spec("some-random-model", "sys")

    @patch("vulnhuntr.llms.OpenRouter")
    def test_openrouter_model_with_free_suffix(self, mock_or):
        """OpenRouter models ending in :free should work with explicit prefix."""
        parse_fallback_spec("openrouter:meta-llama/llama-3.3-70b-instruct:free", "sys")
        mock_or.assert_called_once()
        assert mock_or.call_args[0][0] == "meta-llama/llama-3.3-70b-instruct:free"

    @patch("vulnhuntr.llms.ChatGPT")
    def test_gpt_explicit_prefix(self, mock_gpt):
        """'gpt:gpt-4o' parses correctly."""
        parse_fallback_spec("gpt:gpt-4o", "sys")
        mock_gpt.assert_called_once()
        assert mock_gpt.call_args[0][0] == "gpt-4o"

    @patch("vulnhuntr.llms.OpenRouter")
    def test_case_insensitive_provider(self, mock_or):
        """Provider prefix is case-insensitive."""
        parse_fallback_spec("OpenRouter:meta-llama/llama-3.3-70b-instruct:free", "sys")
        mock_or.assert_called_once()


class TestCollectFiles:
    """Unit tests for _collect_files() — RUNNER-02.

    Pure function: no checkpoint awareness. Exercises network-related,
    absolute analyze, and relative analyze code paths.
    """

    def _make_args(self, root, analyze=None):
        return argparse.Namespace(root=str(root), analyze=analyze)

    def test_no_analyze_returns_network_related_files(self, tmp_path):
        """When args.analyze is None, returns network-related files from repo."""
        from unittest.mock import MagicMock

        repo = MagicMock()
        repo.get_relevant_py_files.return_value = [tmp_path / "a.py"]
        network_files = [tmp_path / "net.py"]
        repo.get_network_related_files.return_value = network_files

        args = self._make_args(tmp_path, analyze=None)
        files, files_to_analyze = _collect_files(args, repo)

        assert files == [tmp_path / "a.py"]
        assert files_to_analyze == network_files
        repo.get_network_related_files.assert_called_once_with([tmp_path / "a.py"])

    def test_absolute_analyze_path(self, tmp_path):
        """Absolute --analyze path passed directly to get_files_to_analyze."""
        from unittest.mock import MagicMock

        repo = MagicMock()
        repo.get_relevant_py_files.return_value = []
        target = tmp_path / "module.py"
        target.touch()
        repo.get_files_to_analyze.return_value = [target]

        args = self._make_args(tmp_path, analyze=str(target))
        _, files_to_analyze = _collect_files(args, repo)

        repo.get_files_to_analyze.assert_called_once_with(target)
        assert files_to_analyze == [target]

    def test_relative_analyze_path_resolved_against_root(self, tmp_path):
        """Relative --analyze path is joined with args.root before calling get_files_to_analyze."""
        from unittest.mock import MagicMock

        repo = MagicMock()
        repo.get_relevant_py_files.return_value = []
        repo.get_files_to_analyze.return_value = []

        args = self._make_args(tmp_path, analyze="subdir/mod.py")
        _collect_files(args, repo)

        expected_path = Path(str(tmp_path)) / "subdir/mod.py"
        repo.get_files_to_analyze.assert_called_once_with(expected_path)

    def test_returns_tuple_of_two_lists(self, tmp_path):
        """Return type is always a 2-tuple (files, files_to_analyze)."""
        from unittest.mock import MagicMock

        repo = MagicMock()
        repo.get_relevant_py_files.return_value = []
        repo.get_network_related_files.return_value = []

        result = _collect_files(self._make_args(tmp_path), repo)
        assert isinstance(result, tuple) and len(result) == 2


class TestInitProviders:
    """Unit tests for _init_providers() — RUNNER-01.

    Exercises the two call patterns: no system_prompt (README pass)
    and with system_prompt (analysis pass).
    """

    def _make_args(self, **kwargs):
        defaults = dict(llm="claude", fallback1=None, fallback2=None)
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    @patch("vulnhuntr.cli.runner.initialize_llm")
    @patch("vulnhuntr.cli.runner.wrap_with_fallbacks")
    def test_no_system_prompt_passes_empty_string(self, mock_wrap, mock_init):
        """README-summarization pass: empty system_prompt forwarded to initialize_llm."""
        from types import SimpleNamespace

        config = SimpleNamespace(model=None, fallback1=None, fallback2=None, provider=None)
        args = self._make_args()
        _init_providers(args, config)
        mock_init.assert_called_once_with("claude", "", None, model_override=None)

    @patch("vulnhuntr.cli.runner.initialize_llm")
    @patch("vulnhuntr.cli.runner.wrap_with_fallbacks")
    def test_system_prompt_forwarded(self, mock_wrap, mock_init):
        """Analysis pass: system_prompt forwarded to both initialize_llm and wrap_with_fallbacks."""
        from types import SimpleNamespace

        config = SimpleNamespace(model=None, fallback1=None, fallback2=None, provider=None)
        args = self._make_args()
        _init_providers(args, config, system_prompt="<instructions/>")
        mock_init.assert_called_once_with("claude", "<instructions/>", None, model_override=None)
        mock_wrap.assert_called_once()
        # system_prompt is the 4th positional arg to wrap_with_fallbacks
        assert mock_wrap.call_args[0][3] == "<instructions/>"

    @patch("vulnhuntr.cli.runner.initialize_llm")
    @patch("vulnhuntr.cli.runner.wrap_with_fallbacks")
    def test_model_override_from_config(self, mock_wrap, mock_init):
        """config.model is passed as model_override to initialize_llm."""
        from types import SimpleNamespace

        config = SimpleNamespace(model="claude-opus-4-5", fallback1=None, fallback2=None, provider=None)
        args = self._make_args()
        _init_providers(args, config)
        mock_init.assert_called_once_with("claude", "", None, model_override="claude-opus-4-5")

    @patch("vulnhuntr.cli.runner.initialize_llm")
    @patch("vulnhuntr.cli.runner.wrap_with_fallbacks")
    def test_returns_wrap_with_fallbacks_result(self, mock_wrap, mock_init):
        """Return value is whatever wrap_with_fallbacks returns (may be FallbackLLM)."""
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        sentinel = MagicMock(name="fallback_llm")
        mock_wrap.return_value = sentinel
        config = SimpleNamespace(model=None, fallback1=None, fallback2=None, provider=None)
        result = _init_providers(self._make_args(), config)
        assert result is sentinel


class TestRunAnalysisIntegration:
    """End-to-end smoke test for run_analysis() with a fully mocked LLM.

    Uses llm_factory parameter (RUNNER-06) — no patch paths needed.
    """

    def _make_args(self, tmp_path, *, json_report=None):
        # Minimal fixture that exercises the LFI detection path
        target = tmp_path / "vuln.py"
        target.write_text("def read_file(name):\n    with open(name) as f:\n        return f.read()\n")
        return argparse.Namespace(
            root=str(tmp_path),
            analyze=str(target),
            llm="claude",
            budget=None,
            create_issues=False,
            csv=None,
            dry_run=False,
            export_all=None,
            fallback1=None,
            fallback2=None,
            html=None,
            json=json_report,
            markdown=None,
            no_checkpoint=True,
            resume=False,
            sarif=None,
            webhook=None,
            webhook_format="json",
            webhook_secret=None,
            reports_dir=None,
            verbosity=0,
        )

    def test_run_analysis_produces_finding(self, tmp_path, mock_llm):
        """D-11: verify a Finding is produced — not just exit code 0."""
        report_path = tmp_path / "report.json"
        run_analysis(
            self._make_args(tmp_path, json_report=str(report_path)),
            llm_factory=lambda *_: mock_llm,
        )
        assert report_path.exists(), "JSON report file must be written by run_analysis()"
        report = json_mod.loads(report_path.read_text())
        findings = report if isinstance(report, list) else report.get("findings", [])
        assert len(findings) >= 1, "At least one Finding must be present in the report"
        first = findings[0]
        score = first.get("confidence_score") if isinstance(first, dict) else getattr(first, "confidence_score", None)
        assert score is not None and score >= 1, f"Finding must have confidence_score >= 1, got: {score}"

    def test_run_analysis_returns_zero_exit_code(self, tmp_path, mock_llm):
        exit_code = run_analysis(
            self._make_args(tmp_path),
            llm_factory=lambda *_: mock_llm,
        )
        assert exit_code == 0

    def test_run_analysis_does_not_call_real_api(self, tmp_path, mock_llm):
        run_analysis(
            self._make_args(tmp_path),
            llm_factory=lambda *_: mock_llm,
        )
        # The mock LLM's chat() was called (pipeline ran)
        assert mock_llm.chat.called

    def test_run_analysis_no_checkpoint_file_created(self, tmp_path, mock_llm):
        run_analysis(
            self._make_args(tmp_path),
            llm_factory=lambda *_: mock_llm,
        )
        checkpoint_dir = tmp_path / ".vulnhuntr_checkpoint"
        assert not checkpoint_dir.exists()


class TestAnalyzeFiles:
    """Unit tests for _analyze_files() — RUNNER-03.

    Exercises the per-file loop independently: empty input, error handling,
    budget abort, and finding collection.
    """

    def _make_checkpoint(self):
        from unittest.mock import MagicMock

        cp = MagicMock()
        cp.set_current_file = MagicMock()
        cp.mark_file_complete = MagicMock()
        return cp

    def _make_analyzer(self, result=None):
        from unittest.mock import MagicMock
        from vulnhuntr.core.models import Response, VulnType

        if result is None:
            result = MagicMock()
            result.initial_report = Response(
                scratchpad="test",
                analysis="possible LFI",
                poc="curl ...",
                confidence_score=7,
                vulnerability_types=[VulnType.LFI],
                context_code=[],
            )
            result.findings = {}
            result.context_code = []

        analyzer = MagicMock()
        analyzer.analyze_file.return_value = result
        return analyzer

    def test_empty_list_returns_empty_success(self):
        """No files → ([], True) with no iterations."""
        from vulnhuntr.cli.runner import _analyze_files
        from unittest.mock import MagicMock

        findings, ok = _analyze_files(
            files_to_analyze=[],
            files=[],
            analyzer=self._make_analyzer(),
            checkpoint=self._make_checkpoint(),
            budget_enforcer=None,
            cost_tracker=MagicMock(),
        )
        assert findings == []
        assert ok is True

    def test_ioerror_logs_and_continues(self, tmp_path, capsys):
        """analyze_file raising OSError is caught; loop continues; success=True."""
        from vulnhuntr.cli.runner import _analyze_files
        from unittest.mock import MagicMock

        bad_file = tmp_path / "bad.py"
        bad_file.touch()

        analyzer = MagicMock()
        analyzer.analyze_file.side_effect = OSError("file not found")

        findings, ok = _analyze_files(
            files_to_analyze=[bad_file],
            files=[bad_file],
            analyzer=analyzer,
            checkpoint=self._make_checkpoint(),
            budget_enforcer=None,
            cost_tracker=MagicMock(),
        )
        assert findings == []
        assert ok is True

    def test_budget_abort_returns_false(self, tmp_path):
        """budget_enforcer returning False on first check sets analysis_success=False."""
        from vulnhuntr.cli.runner import _analyze_files
        from unittest.mock import MagicMock

        f = tmp_path / "a.py"
        f.touch()

        enforcer = MagicMock()
        enforcer.check.return_value = False

        cost_tracker = MagicMock()
        cost_tracker.total_cost = 10.0

        findings, ok = _analyze_files(
            files_to_analyze=[f],
            files=[f],
            analyzer=self._make_analyzer(),
            checkpoint=self._make_checkpoint(),
            budget_enforcer=enforcer,
            cost_tracker=cost_tracker,
        )
        assert findings == []
        assert ok is False

    def test_finding_appended(self, tmp_path):
        """A file producing a finding adds it to the returned list."""
        from vulnhuntr.cli.runner import _analyze_files
        from unittest.mock import MagicMock
        from vulnhuntr.core.models import Response, VulnType

        f = tmp_path / "vuln.py"
        f.touch()

        report = Response(
            scratchpad="traced input",
            analysis="LFI via open(name)",
            poc="curl ...",
            confidence_score=8,
            vulnerability_types=[VulnType.LFI],
            context_code=[],
        )
        result = MagicMock()
        result.initial_report = Response(
            scratchpad="initial",
            analysis="initial analysis",
            poc=None,
            confidence_score=3,
            vulnerability_types=[],
            context_code=[],
        )
        result.findings = {VulnType.LFI: report}
        result.context_code = []

        analyzer = MagicMock()
        analyzer.analyze_file.return_value = result

        cost_tracker = MagicMock()
        cost_tracker.total_cost = 0.0

        findings, ok = _analyze_files(
            files_to_analyze=[f],
            files=[f],
            analyzer=analyzer,
            checkpoint=self._make_checkpoint(),
            budget_enforcer=None,
            cost_tracker=cost_tracker,
        )
        assert len(findings) == 1
        assert ok is True


class TestDispatchIntegrations:
    """Unit tests for _dispatch_integrations() — RUNNER-05."""

    def _make_args(self, create_issues=False, webhook=None):
        return argparse.Namespace(
            create_issues=create_issues,
            webhook=webhook,
            webhook_format="json",
            webhook_secret=None,
        )

    def test_no_flags_no_integration_calls(self, multiple_findings):
        """Neither flag set — no external calls made."""
        with (
            patch("vulnhuntr.cli.runner._create_github_issues") as mock_gh,
            patch("vulnhuntr.cli.runner._send_webhook") as mock_wh,
        ):
            _dispatch_integrations(self._make_args(), multiple_findings, CostTracker(), [])
            mock_gh.assert_not_called()
            mock_wh.assert_not_called()

    def test_create_issues_calls_github(self, multiple_findings):
        """create_issues=True — _create_github_issues called with findings."""
        with patch("vulnhuntr.cli.runner._create_github_issues") as mock_gh:
            _dispatch_integrations(
                self._make_args(create_issues=True),
                multiple_findings,
                CostTracker(),
                [],
            )
            mock_gh.assert_called_once_with(multiple_findings)

    def test_webhook_calls_send_webhook(self, multiple_findings):
        """webhook set — _send_webhook called."""
        with patch("vulnhuntr.cli.runner._send_webhook") as mock_wh:
            args = self._make_args(webhook="https://example.com/hook")
            _dispatch_integrations(args, multiple_findings, CostTracker(), [])
            assert mock_wh.called


class TestDispatchReports:
    """Unit tests for _dispatch_reports alias — RUNNER-04."""

    def test_alias_is_generate_reports(self):
        """_dispatch_reports must be the same callable as _generate_reports."""
        assert _dispatch_reports is _generate_reports

    def test_no_findings_does_not_raise(self, tmp_path):
        """_dispatch_reports with empty findings list completes without error."""
        args = argparse.Namespace(
            root=str(tmp_path),
            sarif=None,
            html=None,
            json=None,
            csv=None,
            markdown=None,
            export_all=None,
            create_issues=False,
            webhook=None,
            webhook_format="json",
            webhook_secret=None,
        )
        _dispatch_reports(args, [], CostTracker(), [])  # should not raise
