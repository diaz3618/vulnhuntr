"""Tests for vulnhuntr.core.trace — EVAL-01.

Covers TraceEvent dataclass shape and ExecutionTracer accumulation/filtering.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from vulnhuntr.core.trace import ExecutionTracer, TraceEvent


class TestTraceEvent:
    """Validate TraceEvent dataclass fields and types."""

    def _make_event(self, **kwargs) -> TraceEvent:
        defaults = dict(
            event_type="probe_result",
            provider="TestProvider",
            timestamp=datetime.now(timezone.utc),
            data={},
        )
        defaults.update(kwargs)
        return TraceEvent(**defaults)

    def test_event_type_field(self):
        e = self._make_event(event_type="fallback_triggered")
        assert e.event_type == "fallback_triggered"

    def test_provider_field(self):
        e = self._make_event(provider="ClaudeCodeLLM")
        assert e.provider == "ClaudeCodeLLM"

    def test_timestamp_is_datetime(self):
        e = self._make_event()
        assert isinstance(e.timestamp, datetime)

    def test_timestamp_is_utc(self):
        ts = datetime.now(timezone.utc)
        e = self._make_event(timestamp=ts)
        assert e.timestamp.tzinfo is not None
        assert e.timestamp.tzinfo.utcoffset(e.timestamp).total_seconds() == 0

    def test_data_is_dict(self):
        e = self._make_event(data={"ok": True, "version": "1.2.3"})
        assert e.data == {"ok": True, "version": "1.2.3"}

    def test_empty_data_allowed(self):
        e = self._make_event(data={})
        assert e.data == {}

    @pytest.mark.parametrize(
        "event_type",
        ["probe_result", "response_validated", "tool_call", "fallback_triggered", "session_decision"],
    )
    def test_all_event_types_accepted(self, event_type):
        e = self._make_event(event_type=event_type)
        assert e.event_type == event_type


class TestExecutionTracer:
    """Validate ExecutionTracer.emit() and .filter() behaviour."""

    def test_starts_empty(self):
        tracer = ExecutionTracer()
        assert tracer.events == []

    def test_emit_adds_event(self):
        tracer = ExecutionTracer()
        tracer.emit("probe_result", "ClaudeCodeLLM", ok=True, binary_found=True)
        assert len(tracer.events) == 1

    def test_emit_sets_event_type(self):
        tracer = ExecutionTracer()
        tracer.emit("probe_result", "GeminiCLILLM", ok=True)
        assert tracer.events[0].event_type == "probe_result"

    def test_emit_sets_provider(self):
        tracer = ExecutionTracer()
        tracer.emit("probe_result", "GeminiCLILLM", ok=True)
        assert tracer.events[0].provider == "GeminiCLILLM"

    def test_emit_sets_timestamp_utc(self):
        tracer = ExecutionTracer()
        tracer.emit("probe_result", "X")
        ts = tracer.events[0].timestamp
        assert ts.tzinfo is not None
        assert ts.tzinfo.utcoffset(ts).total_seconds() == 0

    def test_emit_stores_kwargs_as_data(self):
        tracer = ExecutionTracer()
        tracer.emit("probe_result", "X", ok=False, version="0.1.0")
        assert tracer.events[0].data == {"ok": False, "version": "0.1.0"}

    def test_multiple_emits_accumulate(self):
        tracer = ExecutionTracer()
        tracer.emit("probe_result", "A")
        tracer.emit("fallback_triggered", "B")
        tracer.emit("probe_result", "C")
        assert len(tracer.events) == 3

    def test_filter_returns_matching_events(self):
        tracer = ExecutionTracer()
        tracer.emit("probe_result", "A")
        tracer.emit("fallback_triggered", "B")
        tracer.emit("probe_result", "C")
        results = tracer.filter("probe_result")
        assert len(results) == 2
        assert all(e.event_type == "probe_result" for e in results)

    def test_filter_returns_empty_list_for_no_match(self):
        tracer = ExecutionTracer()
        tracer.emit("probe_result", "A")
        assert tracer.filter("tool_call") == []

    def test_filter_empty_tracer(self):
        tracer = ExecutionTracer()
        assert tracer.filter("session_decision") == []

    def test_filter_does_not_mutate_events(self):
        tracer = ExecutionTracer()
        tracer.emit("probe_result", "A")
        tracer.emit("fallback_triggered", "B")
        _ = tracer.filter("probe_result")
        assert len(tracer.events) == 2

    def test_emit_no_kwargs_stores_empty_data(self):
        tracer = ExecutionTracer()
        tracer.emit("session_decision", "Provider")
        assert tracer.events[0].data == {}
