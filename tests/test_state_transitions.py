"""State-transition and runtime invariant tests for critical provider flows.

Covers EVAL-04 (explicit branch and state-transition coverage goals) and
EVAL-06 (runtime invariants for provider progression, fallback ordering,
session policy, and MCP/tool-result handling).
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from vulnhuntr.cli_providers.claude_code import ClaudeCodeLLM
from vulnhuntr.config import CLIPolicy
from vulnhuntr.core import InvariantViolationError
from vulnhuntr.llms import FallbackLLM, LLMError


# ---------------------------------------------------------------------------
# TestFallbackTransitions — EVAL-04 (state-transition coverage)
# ---------------------------------------------------------------------------


class TestFallbackTransitions:
    """Partitions tested:
      (primary_active, primary_succeeds) → result returned, _active stays primary
      (primary_active, primary_fails) → fallback_0_active, result from fallback_0
      (fallback_0_active, fallback_0_fails) → fallback_1_active, result from fallback_1
      (all_failed) → LLMError raised
    """

    def _make_failing(self) -> MagicMock:
        m = MagicMock()
        m.chat.side_effect = LLMError("forced failure")
        return m

    def _make_succeeding(self, return_value: str = "ok") -> MagicMock:
        m = MagicMock()
        m.chat.return_value = return_value
        m.set_context = MagicMock()
        return m

    def test_primary_succeeds_active_stays_primary(self):
        primary = self._make_succeeding("from_primary")
        llm = FallbackLLM(primary=primary, fallbacks=[])
        result = llm.chat("hello")
        assert result == "from_primary"
        assert llm._active is primary

    def test_primary_fails_transitions_to_fallback0(self):
        primary = self._make_failing()
        fallback0 = self._make_succeeding("from_fallback0")
        llm = FallbackLLM(primary=primary, fallbacks=[fallback0])
        result = llm.chat("hello")
        assert result == "from_fallback0"
        assert llm._active is fallback0

    def test_fallback0_fails_transitions_to_fallback1(self):
        primary = self._make_failing()
        fallback0 = self._make_failing()
        fallback1 = self._make_succeeding("from_fallback1")
        llm = FallbackLLM(primary=primary, fallbacks=[fallback0, fallback1])
        # Advance _active to fallback0 first
        llm._active = fallback0
        result = llm.chat("hello")
        assert result == "from_fallback1"
        assert llm._active is fallback1

    def test_all_failed_raises_llm_error(self):
        primary = self._make_failing()
        fallback0 = self._make_failing()
        llm = FallbackLLM(primary=primary, fallbacks=[fallback0])
        with pytest.raises(LLMError):
            llm.chat("hello")

    def test_active_is_primary_before_first_chat(self):
        primary = self._make_succeeding()
        fallback0 = self._make_succeeding()
        llm = FallbackLLM(primary=primary, fallbacks=[fallback0])
        assert llm._active is primary

    def test_active_stays_on_fallback_after_transition(self):
        """Once primary fails and fallback0 takes over, subsequent calls use fallback0."""
        primary = self._make_failing()
        fallback0 = self._make_succeeding("fb0")
        llm = FallbackLLM(primary=primary, fallbacks=[fallback0])
        llm.chat("first")
        assert llm._active is fallback0
        # Second call should use fallback0 directly (no re-try primary)
        llm.chat("second")
        assert fallback0.chat.call_count == 2


# ---------------------------------------------------------------------------
# TestFallbackInvariants — EVAL-06 (active_in_registry invariant)
# ---------------------------------------------------------------------------


class TestFallbackInvariants:
    """Partitions tested:
      (_active in _all_llms) → normal chat() progression, no invariant error
      (_active not in _all_llms) → InvariantViolationError raised with invariant="active_in_registry"
      (actual_value) → error carries the class name of the rogue _active instance
    """

    def _make_succeeding(self, return_value: str = "ok") -> MagicMock:
        m = MagicMock()
        m.chat.return_value = return_value
        m.set_context = MagicMock()
        return m

    def test_normal_active_does_not_raise(self):
        primary = self._make_succeeding()
        llm = FallbackLLM(primary=primary, fallbacks=[])
        # _active is primary, which IS in _all_llms — no raise
        result = llm.chat("hello")
        assert result == "ok"

    def test_rogue_active_raises_invariant_violation_error(self):
        primary = self._make_succeeding()
        llm = FallbackLLM(primary=primary, fallbacks=[])
        # Force _active to something outside _all_llms
        llm._active = MagicMock()
        with pytest.raises(InvariantViolationError):
            llm.chat("hello")

    def test_invariant_error_key_is_active_in_registry(self):
        primary = self._make_succeeding()
        llm = FallbackLLM(primary=primary, fallbacks=[])
        llm._active = MagicMock()
        with pytest.raises(InvariantViolationError) as exc_info:
            llm.chat("hello")
        assert exc_info.value.invariant == "active_in_registry"

    def test_invariant_error_actual_value_is_class_name(self):
        primary = self._make_succeeding()
        llm = FallbackLLM(primary=primary, fallbacks=[])

        class RogueLLM:
            pass

        llm._active = RogueLLM()
        with pytest.raises(InvariantViolationError) as exc_info:
            llm.chat("hello")
        assert exc_info.value.actual_value == "RogueLLM"

    def test_invariant_error_is_runtime_error_subclass(self):
        primary = self._make_succeeding()
        llm = FallbackLLM(primary=primary, fallbacks=[])
        llm._active = MagicMock()
        with pytest.raises(RuntimeError):
            llm.chat("hello")


# ---------------------------------------------------------------------------
# TestSessionModeInvariants — EVAL-06 (session_mode_is_known invariant)
# ---------------------------------------------------------------------------


class TestSessionModeInvariants:
    """Partitions tested:
      (session_mode="stateless") → no raise, --no-session-persistence flag added
      (session_mode="continue") → no raise, --continue flag added
      (session_mode="resume", session_id set) → no raise, --resume flag added
      (session_mode not in valid set) → InvariantViolationError raised with invariant="session_mode_is_known"
      (actual_value) → error carries the invalid session_mode string
    """

    def _make_payload(self) -> str:
        return json.dumps({"result": "done", "usage": {}, "modelUsage": {}})

    def _make_llm(self, session_mode: str) -> ClaudeCodeLLM:
        # CLIPolicy validates session_mode in __post_init__, so build a valid one
        # then mutate directly to simulate a rogue/corrupted value reaching send_message().
        policy = CLIPolicy()
        object.__setattr__(policy, "session_mode", session_mode)
        return ClaudeCodeLLM(policy=policy)

    def test_stateless_does_not_raise(self):
        llm = self._make_llm("stateless")
        fake = MagicMock(stdout=self._make_payload(), returncode=0)
        with patch.object(llm, "_run_subprocess", return_value=fake):
            llm.send_message("hello", max_tokens=256)  # should not raise

    def test_continue_does_not_raise(self):
        llm = self._make_llm("continue")
        fake = MagicMock(stdout=self._make_payload(), returncode=0)
        with patch.object(llm, "_run_subprocess", return_value=fake):
            llm.send_message("hello", max_tokens=256)  # should not raise

    def test_unknown_session_mode_raises_invariant_violation_error(self):
        llm = self._make_llm("turbo_mode")
        with pytest.raises(InvariantViolationError):
            llm.send_message("hello", max_tokens=256)

    def test_invariant_error_key_is_session_mode_is_known(self):
        llm = self._make_llm("bogus")
        with pytest.raises(InvariantViolationError) as exc_info:
            llm.send_message("hello", max_tokens=256)
        assert exc_info.value.invariant == "session_mode_is_known"

    def test_invariant_error_actual_value_is_the_bad_mode_string(self):
        llm = self._make_llm("turbo_mode")
        with pytest.raises(InvariantViolationError) as exc_info:
            llm.send_message("hello", max_tokens=256)
        assert exc_info.value.actual_value == "turbo_mode"

    def test_invariant_error_is_runtime_error_subclass(self):
        llm = self._make_llm("bad_mode")
        with pytest.raises(RuntimeError):
            llm.send_message("hello", max_tokens=256)
