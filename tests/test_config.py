"""
Tests for vulnhuntr.config
============================

Covers VulnhuntrConfig defaults, flat and nested dict parsing, round-trip
serialisation, config file discovery, YAML loading, CLI merging, and
example config generation.
"""

from argparse import Namespace

from vulnhuntr.config import (
    VulnhuntrConfig,
    create_example_config,
    find_config_file,
    load_config,
    merge_config_with_args,
)


# ── VulnhuntrConfig defaults ──────────────────────────────────────────────


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


# ── from_dict (flat keys) ─────────────────────────────────────────────────


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


# ── from_dict (nested sections) ───────────────────────────────────────────


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
        cfg = VulnhuntrConfig.from_dict({
            "budget": 10.0,
            "cost": {"budget": 99.0},
        })
        assert cfg.budget == 99.0


# ── to_dict ────────────────────────────────────────────────────────────────


class TestToDict:
    def test_round_trip(self):
        original = VulnhuntrConfig(budget=42.0, provider="claude", max_iterations=5)
        d = original.to_dict()
        restored = VulnhuntrConfig.from_dict(d)
        assert restored.budget == original.budget
        assert restored.provider == original.provider
        assert restored.max_iterations == original.max_iterations


# ── find_config_file ───────────────────────────────────────────────────────


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


# ── load_config ────────────────────────────────────────────────────────────


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


# ── merge_config_with_args ─────────────────────────────────────────────────


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


# ── create_example_config ─────────────────────────────────────────────────


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
