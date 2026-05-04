"""Execution trace accumulator for Vulnhuntr provider flows."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from typing import Any, Literal

TraceEventType = Literal[
    "probe_result",
    "response_validated",
    "tool_call",
    "fallback_triggered",
    "session_decision",
]


@dataclasses.dataclass
class TraceEvent:
    event_type: TraceEventType
    provider: str  # class name or provider key
    timestamp: datetime  # UTC; always datetime.now(timezone.utc) at emission
    data: dict[str, Any]  # event-specific payload (see CONTEXT.md D-03 for schemas)


class ExecutionTracer:
    """Accumulates TraceEvent objects for a single scan session.

    Thread-safety is out of scope for Phase 8. One tracer per scan.
    Inject via optional kwarg; None means no-op throughout the codebase.
    """

    def __init__(self) -> None:
        self.events: list[TraceEvent] = []

    def emit(
        self,
        event_type: TraceEventType,
        provider: str,
        **data: Any,
    ) -> None:
        self.events.append(
            TraceEvent(
                event_type=event_type,
                provider=provider,
                timestamp=datetime.now(timezone.utc),
                data=data,
            )
        )

    def filter(self, event_type: TraceEventType) -> list[TraceEvent]:
        return [e for e in self.events if e.event_type == event_type]
