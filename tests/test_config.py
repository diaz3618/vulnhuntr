"""
Tests for vulnhuntr.config

Covers VulnhuntrConfig defaults, flat and nested dict parsing, round-trip
serialisation, config file discovery, YAML loading, CLI merging, and
example config generation.
"""

from argparse import Namespace

import pytest

from vulnhuntr.config import (
    CLIPolicy,
    VulnhuntrConfig,
    create_example_config,
    find_config_file,
    load_config,
    merge_config_with_args,
)


class TestVulnhuntrConfigDefaults:
    """Every field should have a sane default so the tool works out of the box."""

    def test_budget_is_none(self):
        cfg = VulnhuntrConfig()
        assert cfg.budget is None

    def test_checkpoint_enabled(self):
        assert VulnhuntrConfig().checkpoint is True

    def test_checkpoint_interval(self):
        assert VulnhuntrConfig().checkpoint_interval == 300

    def test_provider_is_none(self):
        assert VulnhuntrConfig().provider is None

    def test_model_is_none(self):
        assert VulnhuntrConfig().model is None

    def test_verbosity(self):
        assert VulnhuntrConfig().verbosity == 0

    def test_dry_run(self):
        assert VulnhuntrConfig().dry_run is False

    def test_vuln_types_empty(self):
        assert VulnhuntrConfig().vuln_types == []

    def test_max_iterations(self):
        assert VulnhuntrConfig().max_iterations == 7

    def test_confidence_threshold(self):
        assert VulnhuntrConfig().confidence_threshold == 1


class TestFromDictFlat:
    def test_budget_parsed(self):
        cfg = VulnhuntrConfig.from_dict({"budget": 25.0})
        assert cfg.budget == 25.0

    def test_provider_parsed(self):
        cfg = VulnhuntrConfig.from_dict({"provider": "claude"})
        assert cfg.provider == "claude"

    def test_unknown_keys_ignored(self):
        cfg = VulnhuntrConfig.from_dict({"not_a_field": 99})
        assert not hasattr(cfg, "not_a_field")

    def test_vuln_types_as_list(self):
        cfg = VulnhuntrConfig.from_dict({"vuln_types": ["sqli", "xss"]})
        assert cfg.vuln_types == ["sqli", "xss"]

    def test_cli_provider_string(self):
        cfg = VulnhuntrConfig.from_dict({"provider": "claude-code"})
        assert cfg.provider == "claude-code"


class TestFromDictNested:
    def test_cost_section(self):
        cfg = VulnhuntrConfig.from_dict({"cost": {"budget": 50.0}})
        assert cfg.budget == 50.0

    def test_llm_section(self):
        cfg = VulnhuntrConfig.from_dict({"llm": {"provider": "gpt", "model": "gpt-4o"}})
        assert cfg.provider == "gpt"
        assert cfg.model == "gpt-4o"

    def test_analysis_section(self):
        cfg = VulnhuntrConfig.from_dict({"analysis": {"max_iterations": 3}})
        assert cfg.max_iterations == 3

    def test_nested_overrides_flat(self):
        cfg = VulnhuntrConfig.from_dict(
            {
                "budget": 10.0,
                "cost": {"budget": 99.0},
            }
        )
        assert cfg.budget == 99.0


class TestToDict:
    def test_round_trip(self):
        original = VulnhuntrConfig(budget=42.0, provider="claude", max_iterations=5)
        d = original.to_dict()
        restored = VulnhuntrConfig.from_dict(d)
        assert restored.budget == original.budget
        assert restored.provider == original.provider
        assert restored.max_iterations == original.max_iterations

    def test_cli_key_present(self):
        assert "cli" in VulnhuntrConfig().to_dict()

    def test_cli_round_trip(self):
        original = VulnhuntrConfig()
        original.cli.timeout = 600
        d = original.to_dict()
        restored = VulnhuntrConfig.from_dict(d)
        assert restored.cli.timeout == 600


class TestFindConfigFile:
    def test_finds_yaml_in_directory(self, tmp_path):
        cfg_file = tmp_path / ".vulnhuntr.yaml"
        cfg_file.write_text("budget: 10\n")
        assert find_config_file(tmp_path) == cfg_file

    def test_prefers_yaml_over_yml(self, tmp_path):
        (tmp_path / ".vulnhuntr.yaml").write_text("budget: 1\n")
        (tmp_path / ".vulnhuntr.yml").write_text("budget: 2\n")
        assert find_config_file(tmp_path).suffix == ".yaml"

    def test_falls_back_to_yml(self, tmp_path):
        cfg_file = tmp_path / ".vulnhuntr.yml"
        cfg_file.write_text("budget: 5\n")
        assert find_config_file(tmp_path) == cfg_file

    def test_returns_none_when_missing(self, tmp_path):
        assert find_config_file(tmp_path) is None


class TestLoadConfig:
    def test_explicit_path(self, tmp_path):
        f = tmp_path / "custom.yaml"
        f.write_text("budget: 77\nprovider: claude\n")
        cfg = load_config(config_path=f)
        assert cfg.budget == 77

    def test_missing_file_returns_defaults(self, tmp_path):
        cfg = load_config(config_path=tmp_path / "nope.yaml")
        assert cfg.budget is None

    def test_empty_file_returns_defaults(self, tmp_path):
        f = tmp_path / "empty.yaml"
        f.write_text("")
        cfg = load_config(config_path=f)
        assert cfg.budget is None

    def test_invalid_yaml_returns_defaults(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text(": : : not valid yaml\n")
        cfg = load_config(config_path=f)
        assert isinstance(cfg, VulnhuntrConfig)


class TestMergeConfigWithArgs:
    def test_cli_overrides_config(self):
        cfg = VulnhuntrConfig(budget=10.0)
        args = Namespace(budget=50.0)
        merged = merge_config_with_args(cfg, args)
        assert merged.budget == 50.0

    def test_config_used_when_cli_missing(self):
        cfg = VulnhuntrConfig(budget=10.0)
        args = Namespace()
        merged = merge_config_with_args(cfg, args)
        assert merged.budget == 10.0

    def test_cli_none_does_not_override(self):
        cfg = VulnhuntrConfig(provider="claude")
        args = Namespace(provider=None)
        merged = merge_config_with_args(cfg, args)
        assert merged.provider == "claude"

    def test_multiple_overrides(self):
        cfg = VulnhuntrConfig(budget=10.0, provider="claude", verbosity=0)
        args = Namespace(budget=99.0, verbosity=2)
        merged = merge_config_with_args(cfg, args)
        assert merged.budget == 99.0
        assert merged.verbosity == 2
        assert merged.provider == "claude"

    def test_empty_namespace(self):
        cfg = VulnhuntrConfig(max_iterations=5)
        merged = merge_config_with_args(cfg, Namespace())
        assert merged.max_iterations == 5


class TestCreateExampleConfig:
    def test_writes_file(self, tmp_path):
        out = tmp_path / ".vulnhuntr.yaml"
        create_example_config(out)
        assert out.exists()
        content = out.read_text()
        assert "budget" in content

    def test_contains_sections(self, tmp_path):
        out = tmp_path / "example.yaml"
        create_example_config(out)
        content = out.read_text()
        for keyword in ("cost", "llm", "analysis"):
            assert keyword in content


class TestCLIPolicyDefaults:
    def test_timeout_default(self):
        assert CLIPolicy().timeout == 300

    def test_workdir_default(self):
        assert CLIPolicy().workdir == "/tmp/vulnhuntr"

    def test_auth_mode_default(self):
        assert CLIPolicy().auth_mode == "auto"

    def test_session_mode_default(self):
        assert CLIPolicy().session_mode == "stateless"

    def test_approval_mode_default(self):
        assert CLIPolicy().approval_mode == "auto"

    def test_sandbox_mode_default(self):
        assert CLIPolicy().sandbox_mode == "none"

    def test_max_turns_default(self):
        assert CLIPolicy().max_turns == 10

    def test_mcp_mode_default(self):
        assert CLIPolicy().mcp_mode == "none"

    def test_overrides_default(self):
        assert CLIPolicy().overrides == {}


class TestCLIPolicy:
    def test_cli_section_timeout_parsed(self):
        cfg = VulnhuntrConfig.from_dict({"cli": {"timeout": 600}})
        assert cfg.cli.timeout == 600

    def test_cli_section_workdir_parsed(self):
        cfg = VulnhuntrConfig.from_dict({"cli": {"workdir": "/tmp/custom"}})
        assert cfg.cli.workdir == "/tmp/custom"

    def test_cli_section_auth_mode_parsed(self):
        cfg = VulnhuntrConfig.from_dict({"cli": {"auth_mode": "oauth"}})
        assert cfg.cli.auth_mode == "oauth"

    def test_cli_section_max_turns_parsed(self):
        cfg = VulnhuntrConfig.from_dict({"cli": {"max_turns": 20}})
        assert cfg.cli.max_turns == 20

    def test_cli_section_mcp_mode_parsed(self):
        cfg = VulnhuntrConfig.from_dict({"cli": {"mcp_mode": "vulnhuntr"}})
        assert cfg.cli.mcp_mode == "vulnhuntr"

    def test_no_cli_section_gives_defaults(self):
        cfg = VulnhuntrConfig.from_dict({"budget": 10.0})
        assert cfg.cli.timeout == 300

    def test_empty_dict_gives_defaults(self):
        cfg = VulnhuntrConfig.from_dict({})
        assert cfg.cli.workdir == "/tmp/vulnhuntr"


class TestCLIPolicyOverrides:
    def test_overrides_parsed(self):
        cfg = VulnhuntrConfig.from_dict({"cli": {"overrides": {"claude-code": {"timeout": 900}}}})
        assert cfg.cli.overrides == {"claude-code": {"timeout": 900}}

    def test_overrides_accessible_per_provider(self):
        cfg = VulnhuntrConfig.from_dict({"cli": {"overrides": {"claude-code": {"timeout": 900}}}})
        assert cfg.cli.overrides.get("claude-code", {}) == {"timeout": 900}

    def test_overrides_default_empty_when_missing(self):
        cfg = VulnhuntrConfig.from_dict({"cli": {}})
        assert cfg.cli.overrides == {}

    def test_overrides_isolation(self):
        p1 = CLIPolicy()
        p2 = CLIPolicy()
        p1.overrides["key"] = {"x": 1}
        assert "key" not in p2.overrides


class TestCLIPolicyToolModeAndStripEnvVars:
    """Tests for CLIPolicy.tool_mode and CLIPolicy.strip_env_vars fields (CLAUDECLI-01)."""

    def test_tool_mode_default(self):
        assert CLIPolicy().tool_mode == "none"

    def test_strip_env_vars_default(self):
        assert CLIPolicy().strip_env_vars == []

    def test_tool_mode_parsed_from_dict(self):
        cfg = VulnhuntrConfig.from_dict({"cli": {"tool_mode": "full"}})
        assert cfg.cli.tool_mode == "full"

    def test_strip_env_vars_parsed_from_dict(self):
        cfg = VulnhuntrConfig.from_dict({"cli": {"strip_env_vars": ["FOO"]}})
        assert cfg.cli.strip_env_vars == ["FOO"]

    def test_strip_env_vars_ignored_when_not_a_list(self):
        cfg = VulnhuntrConfig.from_dict({"cli": {"strip_env_vars": "not-a-list"}})
        assert cfg.cli.strip_env_vars == []

    def test_to_dict_includes_tool_mode(self):
        cfg = VulnhuntrConfig()
        d = cfg.to_dict()
        assert "tool_mode" in d["cli"]

    def test_to_dict_includes_strip_env_vars(self):
        cfg = VulnhuntrConfig()
        d = cfg.to_dict()
        assert "strip_env_vars" in d["cli"]


class TestCLIPolicyBoundaries:
    """EVAL-03: CLIPolicy.__post_init__ rejects out-of-range field values."""

    @pytest.mark.parametrize("session_mode", ["bad", "", "STATELESS", "Continue"])
    def test_invalid_session_mode_raises(self, session_mode):
        with pytest.raises(ValueError, match="session_mode"):
            CLIPolicy(session_mode=session_mode)

    @pytest.mark.parametrize("mcp_mode", ["all", "both-and-more", "on", "off"])
    def test_invalid_mcp_mode_raises(self, mcp_mode):
        with pytest.raises(ValueError, match="mcp_mode"):
            CLIPolicy(mcp_mode=mcp_mode)

    @pytest.mark.parametrize("tool_mode", ["write", "", "Full", "NONE"])
    def test_invalid_tool_mode_raises(self, tool_mode):
        with pytest.raises(ValueError, match="tool_mode"):
            CLIPolicy(tool_mode=tool_mode)

    def test_negative_timeout_raises(self):
        with pytest.raises(ValueError, match="timeout"):
            CLIPolicy(timeout=-1)

    def test_zero_timeout_allowed(self):
        policy = CLIPolicy(timeout=0)
        assert policy.timeout == 0

    def test_zero_max_turns_raises(self):
        with pytest.raises(ValueError, match="max_turns"):
            CLIPolicy(max_turns=0)

    def test_negative_max_turns_raises(self):
        with pytest.raises(ValueError, match="max_turns"):
            CLIPolicy(max_turns=-5)

    def test_valid_defaults_construct(self):
        policy = CLIPolicy()
        assert policy.session_mode == "stateless"
        assert policy.mcp_mode == "none"
        assert policy.tool_mode == "none"

    def test_all_valid_session_modes(self):
        for mode in ("stateless", "continue", "resume"):
            policy = CLIPolicy(session_mode=mode)
            assert policy.session_mode == mode

    def test_all_valid_mcp_modes(self):
        for mode in ("none", "vulnhuntr", "provider", "both"):
            policy = CLIPolicy(mcp_mode=mode)
            assert policy.mcp_mode == mode

    def test_all_valid_tool_modes(self):
        for mode in ("none", "read-only", "full"):
            policy = CLIPolicy(tool_mode=mode)
            assert policy.tool_mode == mode
