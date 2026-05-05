"""Load .vulnhuntr.yaml config from project root or ~/.vulnhuntr.yaml."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

import structlog

log = structlog.get_logger(__name__)


@dataclass
class CLIPolicy:
    """Runtime policy for CLI-backed LLM providers.

    Applied to all providers unless overridden via ``overrides`` per provider
    (e.g. ``{"claude-code": {"timeout": 600}}``).

    tool_mode controls access to ALL provider-native tools during a scan:
    file-system reads/writes, shell execution, web browsing, computer-use
    actions, and MCP servers the provider manages on its own. It does NOT
    govern Vulnhuntr-managed MCP servers (that is mcp_mode).

      "none" (default) — disable all tools (safe default for scanning)
      "read-only"      — file reads only; shell, web, and computer-use disabled
      "full"           — all tools the provider supports are enabled (explicit opt-in)

    sandbox_mode is Codex-specific and maps to --sandbox read-only|workspace-write.
    No other provider uses this field. Set to "workspace-write" to allow Codex
    to write files in the workdir; leave as "none" or "read-only" for safe scanning.

    strip_env_vars is appended to each provider's class-level _STRIP_ENV_VARS
    before subprocess spawn — use this to scrub credentials the class doesn't
    know about.
    """

    timeout: int = 300
    workdir: str = "/tmp/vulnhuntr"
    auth_mode: str = "auto"
    session_mode: str = "stateless"
    approval_mode: str = "auto"
    sandbox_mode: str = "none"
    max_turns: int = 10
    mcp_mode: str = "none"
    overrides: dict[str, dict] = field(default_factory=dict)
    tool_mode: str = "none"
    strip_env_vars: list[str] = field(default_factory=list)

    _VALID_SESSION_MODES: ClassVar[frozenset[str]] = frozenset({"stateless", "continue", "resume"})
    _VALID_MCP_MODES: ClassVar[frozenset[str]] = frozenset({"none", "vulnhuntr", "provider", "both"})
    _VALID_TOOL_MODES: ClassVar[frozenset[str]] = frozenset({"none", "read-only", "full"})

    def __post_init__(self) -> None:
        if self.session_mode not in self._VALID_SESSION_MODES:
            raise ValueError(
                f"Invalid session_mode {self.session_mode!r}. Must be one of: {sorted(self._VALID_SESSION_MODES)}"
            )
        if self.mcp_mode not in self._VALID_MCP_MODES:
            raise ValueError(f"Invalid mcp_mode {self.mcp_mode!r}. Must be one of: {sorted(self._VALID_MCP_MODES)}")
        if self.tool_mode not in self._VALID_TOOL_MODES:
            raise ValueError(f"Invalid tool_mode {self.tool_mode!r}. Must be one of: {sorted(self._VALID_TOOL_MODES)}")
        if self.timeout < 0:
            raise ValueError(f"timeout must be >= 0, got {self.timeout}")
        if self.max_turns < 1:
            raise ValueError(f"max_turns must be >= 1, got {self.max_turns}")


# Try to import yaml, provide fallback if not available
try:
    import yaml  # type: ignore[import-untyped]

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    log.warning("PyYAML not installed. Config file support disabled. Install with: pip install pyyaml")


@dataclass
class VulnhuntrConfig:
    """Vulnhuntr configuration. Loaded from .vulnhuntr.yaml; merged with CLI args."""

    # Cost management
    budget: float | None = None
    checkpoint: bool = True
    checkpoint_interval: int = 300

    # LLM settings
    provider: str | None = None
    model: str | None = None
    fallback1: str | None = None  # format: 'provider:model'
    fallback2: str | None = None  # format: 'provider:model'

    # Output settings
    verbosity: int = 0
    dry_run: bool = False

    # Analysis settings
    vuln_types: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    include_paths: list[str] = field(default_factory=list)

    # Tuning
    max_iterations: int = 7
    confidence_threshold: int = 1

    # CLI provider policy
    cli: CLIPolicy = field(default_factory=CLIPolicy)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VulnhuntrConfig:
        """Create config from dictionary.

        Handles nested 'cost', 'llm', 'analysis' sections from YAML.

        Args:
            data: Dictionary from YAML file or other source

        Returns:
            VulnhuntrConfig instance
        """
        config = cls()

        # Handle flat keys (simple format)
        if "budget" in data:
            config.budget = float(data["budget"]) if data["budget"] is not None else None
        if "checkpoint" in data:
            config.checkpoint = bool(data["checkpoint"])
        if "checkpoint_interval" in data:
            config.checkpoint_interval = int(data["checkpoint_interval"])
        if "provider" in data:
            config.provider = str(data["provider"]) if data["provider"] else None
        if "model" in data:
            config.model = str(data["model"]) if data["model"] else None
        if "verbosity" in data:
            config.verbosity = int(data["verbosity"])
        if "dry_run" in data:
            config.dry_run = bool(data["dry_run"])
        if "vuln_types" in data and data["vuln_types"]:
            config.vuln_types = list(data["vuln_types"])
        if "exclude_paths" in data and data["exclude_paths"]:
            config.exclude_paths = list(data["exclude_paths"])
        if "include_paths" in data and data["include_paths"]:
            config.include_paths = list(data["include_paths"])
        if "max_iterations" in data:
            config.max_iterations = int(data["max_iterations"])
        if "confidence_threshold" in data:
            config.confidence_threshold = int(data["confidence_threshold"])

        # Handle nested sections (structured format)
        if "cost" in data and isinstance(data["cost"], dict):
            cost = data["cost"]
            if "budget" in cost:
                config.budget = float(cost["budget"]) if cost["budget"] is not None else None
            if "checkpoint" in cost:
                config.checkpoint = bool(cost["checkpoint"])
            if "checkpoint_interval" in cost:
                config.checkpoint_interval = int(cost["checkpoint_interval"])

        if "llm" in data and isinstance(data["llm"], dict):
            llm = data["llm"]
            if "provider" in llm:
                config.provider = str(llm["provider"]) if llm["provider"] else None
            if "model" in llm:
                config.model = str(llm["model"]) if llm["model"] else None
            if "fallback1" in llm:
                config.fallback1 = str(llm["fallback1"]) if llm["fallback1"] else None
            if "fallback2" in llm:
                config.fallback2 = str(llm["fallback2"]) if llm["fallback2"] else None

        if "analysis" in data and isinstance(data["analysis"], dict):
            analysis = data["analysis"]
            if "vuln_types" in analysis and analysis["vuln_types"]:
                config.vuln_types = list(analysis["vuln_types"])
            if "exclude_paths" in analysis and analysis["exclude_paths"]:
                config.exclude_paths = list(analysis["exclude_paths"])
            if "include_paths" in analysis and analysis["include_paths"]:
                config.include_paths = list(analysis["include_paths"])
            if "max_iterations" in analysis:
                config.max_iterations = int(analysis["max_iterations"])
            if "confidence_threshold" in analysis:
                config.confidence_threshold = int(analysis["confidence_threshold"])

        if "cli" in data and isinstance(data["cli"], dict):
            cli_data = data["cli"]
            kwargs: dict[str, Any] = {}
            if "timeout" in cli_data:
                kwargs["timeout"] = int(cli_data["timeout"])
            if "workdir" in cli_data:
                kwargs["workdir"] = str(cli_data["workdir"])
            if "auth_mode" in cli_data:
                kwargs["auth_mode"] = str(cli_data["auth_mode"])
            if "session_mode" in cli_data:
                kwargs["session_mode"] = str(cli_data["session_mode"])
            if "approval_mode" in cli_data:
                kwargs["approval_mode"] = str(cli_data["approval_mode"])
            if "sandbox_mode" in cli_data:
                kwargs["sandbox_mode"] = str(cli_data["sandbox_mode"])
            if "max_turns" in cli_data:
                kwargs["max_turns"] = int(cli_data["max_turns"])
            if "mcp_mode" in cli_data:
                kwargs["mcp_mode"] = str(cli_data["mcp_mode"])
            if "overrides" in cli_data and isinstance(cli_data["overrides"], dict):
                kwargs["overrides"] = dict(cli_data["overrides"])
            if "tool_mode" in cli_data:
                kwargs["tool_mode"] = str(cli_data["tool_mode"])
            if "strip_env_vars" in cli_data and isinstance(cli_data["strip_env_vars"], list):
                kwargs["strip_env_vars"] = list(cli_data["strip_env_vars"])
            config.cli = CLIPolicy(**kwargs)

        return config

    def to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary for serialization."""
        return {
            "budget": self.budget,
            "checkpoint": self.checkpoint,
            "checkpoint_interval": self.checkpoint_interval,
            "provider": self.provider,
            "model": self.model,
            "fallback1": self.fallback1,
            "fallback2": self.fallback2,
            "verbosity": self.verbosity,
            "dry_run": self.dry_run,
            "vuln_types": self.vuln_types,
            "exclude_paths": self.exclude_paths,
            "include_paths": self.include_paths,
            "max_iterations": self.max_iterations,
            "confidence_threshold": self.confidence_threshold,
            "cli": dataclasses.asdict(self.cli),
        }


def find_config_file(start_dir: Path | None = None) -> Path | None:
    """Find .vulnhuntr.yaml config file.

    Search order:
    1. Current directory / start_dir
    2. Parent directories up to filesystem root
    3. User home directory (~/.vulnhuntr.yaml)

    Args:
        start_dir: Directory to start searching from (default: cwd)

    Returns:
        Path to config file if found, None otherwise
    """
    config_name = ".vulnhuntr.yaml"
    alt_config_name = ".vulnhuntr.yml"

    start = start_dir or Path.cwd()

    # Search from start_dir up to root
    current = start.resolve()
    while current != current.parent:
        # Check both .yaml and .yml extensions
        yaml_path = current / config_name
        yml_path = current / alt_config_name

        if yaml_path.exists():
            return yaml_path
        if yml_path.exists():
            return yml_path

        current = current.parent

    # Check filesystem root
    for name in (config_name, alt_config_name):
        root_path = current / name
        if root_path.exists():
            return root_path

    # Check user home directory
    home = Path.home()
    for name in (config_name, alt_config_name):
        home_path = home / name
        if home_path.exists():
            return home_path

    return None


def load_config(config_path: Path | None = None, start_dir: Path | None = None) -> VulnhuntrConfig:
    """Load configuration from YAML file.

    If config_path is not provided, searches for .vulnhuntr.yaml
    in the current directory, parent directories, and user home.

    Args:
        config_path: Explicit path to config file (optional)
        start_dir: Directory to start searching from (optional)

    Returns:
        VulnhuntrConfig instance (default values if no config found)
    """
    # Return default config if YAML not available
    if not YAML_AVAILABLE:
        return VulnhuntrConfig()

    # Find config file
    path: Path | None
    if config_path:
        path = config_path
    else:
        path = find_config_file(start_dir)

    # Return default config if no file found
    if not path or not path.exists():
        log.debug("No config file found, using defaults")
        return VulnhuntrConfig()

    log.info("Loading config", path=str(path))

    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if data is None:
            log.warning("Config file is empty", path=str(path))
            return VulnhuntrConfig()

        config = VulnhuntrConfig.from_dict(data)
        log.debug(
            "Config loaded",
            budget=config.budget,
            checkpoint=config.checkpoint,
            provider=config.provider,
        )
        return config

    except yaml.YAMLError as e:
        log.error("Failed to parse config file", path=str(path), error=str(e))
        return VulnhuntrConfig()
    except Exception as e:
        log.error("Failed to load config file", path=str(path), error=str(e))
        return VulnhuntrConfig()


def merge_config_with_args(config: VulnhuntrConfig, args: Any) -> VulnhuntrConfig:
    """Merge config file settings with CLI arguments.

    CLI arguments take precedence over config file settings.

    Args:
        config: Configuration from config file
        args: Parsed CLI arguments (argparse.Namespace)

    Returns:
        Merged VulnhuntrConfig instance
    """
    # Budget: CLI overrides config
    if hasattr(args, "budget") and args.budget is not None:
        config.budget = args.budget

    # Dry run: CLI can enable (config can set default)
    if hasattr(args, "dry_run") and args.dry_run:
        config.dry_run = True

    # Checkpoint: CLI --no-checkpoint disables
    if hasattr(args, "no_checkpoint") and args.no_checkpoint:
        config.checkpoint = False

    # Provider: CLI overrides config (None means not specified on CLI)
    if hasattr(args, "llm") and args.llm is not None:
        config.provider = args.llm

    # Fallbacks: CLI overrides config
    if hasattr(args, "fallback1") and args.fallback1 is not None:
        config.fallback1 = args.fallback1
    if hasattr(args, "fallback2") and args.fallback2 is not None:
        config.fallback2 = args.fallback2

    # Verbosity: CLI overrides config
    if hasattr(args, "verbosity") and args.verbosity:
        config.verbosity = args.verbosity

    return config


def create_example_config(output_path: Path | None = None) -> str:
    """Generate example config file content.

    Args:
        output_path: If provided, writes example to this path

    Returns:
        Example YAML config as string
    """
    example = """# Vulnhuntr Configuration File
# Place this file as .vulnhuntr.yaml in your project root or home directory

# Cost Management
cost:
  # Maximum USD budget (analysis stops when exceeded)
  budget: 10.0

  # Enable checkpointing for resume after interruption
  checkpoint: true

  # Checkpoint save interval in seconds
  checkpoint_interval: 300

# LLM Settings
llm:
  # Provider: claude, gpt, or ollama
  provider: claude

  # Model override (uses environment variable if not set)
  # model: claude-sonnet-4-5

# Analysis Settings
analysis:
  # Vulnerability types to scan for (empty = all)
  vuln_types: []
  # vuln_types:
  #   - sqli
  #   - xss
  #   - ssrf
  #   - rce

  # Paths to exclude from analysis
  exclude_paths:
    - tests/
    - docs/
    - examples/
    - venv/
    - .venv/
    - node_modules/

  # Maximum secondary analysis iterations per vulnerability
  max_iterations: 7

  # Minimum confidence threshold to report (1-10)
  confidence_threshold: 1

# Output Settings
verbosity: 1  # 0=quiet, 1=normal, 2=verbose, 3=debug
dry_run: false  # Just estimate costs, don't run analysis
"""

    if output_path:
        output_path.write_text(example, encoding="utf-8")
        log.info("Example config written", path=str(output_path))

    return example
