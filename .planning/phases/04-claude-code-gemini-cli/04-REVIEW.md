---
phase: 04-claude-code-gemini-cli
reviewed: 2026-05-03T00:00:00Z
depth: standard
files_reviewed: 9
files_reviewed_list:
  - tests/test_cli_providers.py
  - tests/test_cli.py
  - tests/test_config.py
  - tests/test_runner.py
  - vulnhuntr/cli_providers/claude_code.py
  - vulnhuntr/cli_providers/gemini_cli.py
  - vulnhuntr/cli_providers/__init__.py
  - vulnhuntr/cli/runner.py
  - vulnhuntr/config.py
findings:
  critical: 2
  warning: 5
  info: 3
  total: 10
status: issues_found
---

# Phase 04: Code Review Report

**Reviewed:** 2026-05-03
**Depth:** standard
**Files Reviewed:** 9
**Status:** issues_found

## Summary

This phase introduces two CLI-backed LLM providers (`ClaudeCodeLLM`, `GeminiCLILLM`), a shared base class, a `CLIPolicy` configuration dataclass, and runner wiring for probe-before-use. The overall architecture is sound and the subprocess security model (list-form, `shell=False`) is correctly implemented.

Two critical defects were found: the system prompt accepted by both CLI providers is silently discarded — it is never forwarded to the subprocess, so vulnerability-analysis context (instructions + README summary) is lost for all CLI-provider runs. Second, `send_message` is called by the base `CLIProviderLLM.chat()` but is not declared `@abstractmethod`, giving no compile-time enforcement that subclasses implement it.

Five warnings cover a dead `workdir` field, an incorrect log field name, a config-search logic error, a version-gate edge case, and a flaky test pattern. Three info items flag test duplication and cosmetics.

---

## Critical Issues

### CR-01: System prompt silently discarded for all CLI providers

**File:** `vulnhuntr/cli_providers/claude_code.py:99-153`, `vulnhuntr/cli_providers/gemini_cli.py:129-180`

**Issue:** Both `ClaudeCodeLLM` and `GeminiCLILLM` accept a `system_prompt` argument (stored as `self.system_prompt` in the base `LLM` class) but never incorporate it into the subprocess command. `send_message()` only passes `user_prompt` via `-p`. In `run_analysis()`, the second `_init_providers()` call at line 527 passes a multi-kilobyte system prompt containing `SYS_PROMPT_TEMPLATE` + README summary — all of that context is silently dropped for CLI providers. The LLM receives no vulnerability-analysis instructions and no codebase context, degrading output to unprompted completions.

**Fix:** Prepend the system prompt to the user prompt (the approach the Claude Code CLI and Gemini CLI support through their own system-prompt flags or through manual concatenation). For Claude Code, use the `--system-prompt` flag if available in the target CLI version, or prepend it inside `send_message()`:

```python
# In ClaudeCodeLLM.send_message() — prepend stored system prompt when set
def send_message(self, user_prompt: str, max_tokens: int, response_model: Any = None) -> dict[str, Any]:
    del max_tokens, response_model
    # Combine system prompt + user prompt if system_prompt is set
    full_prompt = user_prompt
    if self.system_prompt:
        full_prompt = f"{self.system_prompt}\n\n{user_prompt}"
    ...
    cmd: list[str] = [
        "claude", "-p", full_prompt, ...
    ]
```

The same pattern applies to `GeminiCLILLM.send_message()`. If the respective CLI binary supports a dedicated system-prompt flag (`--system-prompt` for Claude Code), prefer that to avoid token budget concerns with prompt prepending.

---

### CR-02: `send_message` not declared `@abstractmethod` in `CLIProviderLLM`

**File:** `vulnhuntr/cli_providers/base.py:86-254`

**Issue:** `CLIProviderLLM.chat()` at line 239 calls `self.send_message(user_prompt, max_tokens, response_model)`, but `send_message` is NOT decorated `@abstractmethod` in `CLIProviderLLM`. A future provider subclass that implements `probe()` and `get_response()` (the only two abstract methods) but omits `send_message()` will instantiate successfully and only crash at runtime inside `chat()` with `NotImplementedError`. The same applies to `_extract_usage()` — it falls through to the base `LLM._extract_usage()` which silently returns zero tokens, breaking all cost tracking without any warning.

**Fix:** Declare both methods abstract in `CLIProviderLLM`:

```python
@abstractmethod
def send_message(
    self,
    user_prompt: str,
    max_tokens: int,
    response_model: Any = None,
) -> dict[str, Any]:
    """Build and execute the provider subprocess command."""

@abstractmethod
def _extract_usage(self, response: Any) -> LLMUsage:
    """Extract token usage from the provider response envelope."""
```

---

## Warnings

### WR-01: `workdir` stored but never passed as `cwd` to subprocess

**File:** `vulnhuntr/cli_providers/base.py:112`, `vulnhuntr/cli_providers/base.py:177-187`

**Issue:** `CLIProviderLLM.__init__()` stores `self.workdir = workdir` and both concrete providers receive it as a constructor argument. However, `_run_subprocess()` never passes `cwd=self.workdir` to `subprocess.run()`. The `CLIPolicy.workdir` defaults to `/tmp/vulnhuntr` and is propagated from `runner._init_providers()` — users and operators who configure this field expect it to control the subprocess working directory, but it has no effect.

**Fix:**
```python
result = subprocess.run(
    cmd,
    input=input_text,
    stdin=stdin_mode,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    timeout=self.timeout,
    env=env,
    shell=False,
    cwd=self.workdir,   # add this
)
```

---

### WR-02: `binary_path` log field logs a boolean, not a path

**File:** `vulnhuntr/cli/runner.py:344`

**Issue:** The log call after a successful probe logs `binary_path=result.binary_found`. `binary_found` is a `bool`, not a file path. Operators checking structured logs for the binary location will see `True` or `False` instead of a path string. This is a latent confusion when debugging "which claude/gemini binary is being used?"

**Fix:**
```python
log.info(
    "CLI provider capability check passed",
    provider=args.llm,
    binary_found=result.binary_found,   # keep as boolean
    version=result.version,
)
```
If the binary path is desired, `probe()` should return it in `CapabilityResult` (add a `binary_path: str | None` field), or retrieve it separately via `shutil.which()`.

---

### WR-03: Config search falls back to target repo only when BOTH `provider` and `budget` are `None`

**File:** `vulnhuntr/cli/runner.py:385-387`

**Issue:** The fallback config search logic reads:
```python
if config.provider is None and config.budget is None:
    config = load_config(start_dir=Path(args.root))
```
This means if the CWD config sets `budget` (but no `provider`), the target-repo config is silently skipped even though it may contain the `provider` key. Conversely, a CWD config that sets `provider` but no `budget` will also skip the target-repo config regardless of what the target-repo config has. The intent appears to be "if CWD config is empty/unhelpful, try the target repo" — but the condition is too restrictive and silently ignores useful target-repo configs.

**Fix:** Use a single canonical marker for "config was useful":
```python
config = load_config(start_dir=Path.cwd())
if config.provider is None:   # only provider absence means "not useful"
    repo_config = load_config(start_dir=Path(args.root))
    if repo_config.provider is not None:
        config = repo_config
```
Or simply: always search both and let `merge_config_with_args` resolve precedence.

---

### WR-04: Gemini version gate produces wrong result for 2-part version strings

**File:** `vulnhuntr/cli_providers/gemini_cli.py:101-119`

**Issue:** The regex `r"(\d+\.\d+\.\d+)"` requires exactly three dot-separated numeric groups. If `gemini --version` returns a 2-part string like `"0.6"`, the regex returns `None` and the fallback is `result.stdout.strip()` which evaluates to `"0.6"`. The parsing then runs:

```python
parsed = tuple(int(x) for x in "0.6".split(".", 2))  # => (0, 6)
(0, 6) < (0, 6, 0)  # True — shorter tuple is lexicographically less!
```

So a version `"0.6"` (which should pass `>= 0.6.0`) is incorrectly rejected. Python tuple comparison is lexicographic-length-aware: `(0, 6) < (0, 6, 0)` is `True` because a shorter tuple is considered less when all shared elements are equal.

**Fix:** Normalize the parsed tuple to 3 elements:
```python
parts = [int(x) for x in version_str.split(".", 2)]
# Pad to length 3 so (0, 6) becomes (0, 6, 0)
while len(parts) < 3:
    parts.append(0)
parsed = tuple(parts)
```

---

### WR-05: Flaky test — `test_build_env_strips_gemini_vars` mutates `os.environ` without `try/finally`

**File:** `tests/test_cli_providers.py:727-744`

**Issue:** The test sets three environment variables directly on `os.environ` before the assertions. If any `assert` fails, the cleanup `del os.environ[...]` at lines 742-744 is never reached, leaving those env vars (`GEMINI_API_KEY`, `GOOGLE_API_KEY`, `GOOGLE_GENAI_USE_VERTEXAI`) polluted for all subsequent tests in the process. This can cause spurious failures in env-sensitive tests. Compare with the correctly guarded patterns in `TestClaudeCodeLLMBuildEnv` (lines 467-476) which use `try/finally`.

**Fix:** Use `pytest`'s `monkeypatch` fixture or `unittest.mock.patch.dict`:
```python
def test_build_env_strips_gemini_vars(self, gemini):
    with patch.dict(os.environ, {
        "GEMINI_API_KEY": "key1",
        "GOOGLE_API_KEY": "key2",
        "GOOGLE_GENAI_USE_VERTEXAI": "true",
    }):
        env = gemini._build_env()
    assert "GEMINI_API_KEY" not in env
    assert "GOOGLE_API_KEY" not in env
    assert "GOOGLE_GENAI_USE_VERTEXAI" not in env
```

---

## Info

### IN-01: `send_message` declared with different first-argument semantics than the parent `LLM.send_message`

**File:** `vulnhuntr/cli_providers/base.py:239`, `vulnhuntr/llms.py:189`

**Issue:** `LLM.send_message(messages: Any, ...)` expects pre-formatted messages, while `CLIProviderLLM.chat()` calls `self.send_message(user_prompt: str, ...)` passing the raw prompt string. This is an intentional design divergence (CLI providers bypass `create_messages()`), but the signature mismatch means type checkers will flag all subclass `send_message` implementations as incompatible overrides. No runtime bug since `CLIProviderLLM.chat()` overrides `LLM.chat()` and owns the call, but it creates confusion for anyone implementing a new provider.

**Suggestion:** Add a comment or docstring to `CLIProviderLLM` clarifying that `send_message` intentionally overloads the base signature, or define an intermediate abstract method `send_message(self, user_prompt: str, ...)` in `CLIProviderLLM` to make the contract explicit.

---

### IN-02: Test duplication — `test_claude_code_returns_claude_code_llm` and `test_gemini_cli_returns_gemini_cli_llm` appear in both `tests/test_cli.py` and `tests/test_runner.py`

**File:** `tests/test_cli.py:1123-1135`, `tests/test_runner.py:39-55`

**Issue:** `TestInitializeLLMCLIStubs.test_claude_code_returns_claude_code_llm` and `test_gemini_cli_returns_gemini_cli_llm` exist in both files with identical behavior. Duplicate tests add maintenance burden — a fix to one copy may not be applied to the other.

**Suggestion:** Remove the duplicates from `tests/test_cli.py` (lines 1118-1151) since `tests/test_runner.py` covers the same cases with better coverage (including timeout override and `config=None` path).

---

### IN-03: `CLIPolicy.workdir` defaults to `/tmp/vulnhuntr` — world-writable temp path

**File:** `vulnhuntr/config.py:47`

**Issue:** The default `workdir` is `/tmp/vulnhuntr`, a directory under `/tmp` which is world-writable. While this only matters if/when `workdir` is actually passed as `cwd` to subprocess (currently it is not — see WR-01), the default is worth noting for when WR-01 is fixed. On Linux, `/tmp` is typically sticky-bit protected but still exposes subprocess working directory to other local users.

**Suggestion:** Default to a subdirectory under the user's home or a truly temporary directory:
```python
workdir: str = str(Path.home() / ".vulnhuntr" / "workspace")
```
Or leave as `None` (current effective behavior) so the subprocess inherits the process cwd.

---

_Reviewed: 2026-05-03_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
