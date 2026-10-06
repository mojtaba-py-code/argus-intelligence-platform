"""Domain events: how one module tells the platform that something happened.

A module that produces events (research jobs, monitors, approvals) depends only on this
protocol; the notifications module implements it and decides who hears about the event and how
(in-app, e-mail). Producers never know the channels, and a failing channel never fails the
producer: emitting is best-effort and must not raise.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Literal, Protocol
from uuid import UUID

EventType = Literal[
    "research.job.completed",
    "research.job.failed",
    "approval.requested",
    "monitor.change.detected",
    "monitor.paused",
    "security.audit.integrity_failed",
    "security.kill_switch.engaged",
    "platform.export.ready",
]
EVENT_TYPES: Final[tuple[str, ...]] = (
    "research.job.completed",
    "research.job.failed",
    "approval.requested",
    "monitor.change.detected",
    "monitor.paused",
    "security.audit.integrity_failed",
    "security.kill_switch.engaged",
    "platform.export.ready",
)


@dataclass(frozen=True)
class Event:
    type: EventType
    organization_id: UUID
    title: str
    """One short, plain-text line (shown in-app and as the e-mail subject)."""
    body: str = ""
    """Plain text; may contain words from untrusted sources (already sanitised and defanged)."""
    project_id: UUID | None = None
    link: str | None = None
    """An application path (``/projects/.../research-jobs/...``), never an external URL."""
    recipients: tuple[UUID, ...] = ()
    """Users to notify in-app (and by e-mail when ``email`` is set)."""
    email: bool = False
    data: Mapping[str, Any] = field(default_factory=dict)
    """Identifiers and small values describing the event (for logs and future channels)."""


class EventSink(Protocol):
    async def emit(self, event: Event) -> None: ...


class NullSink:
    """Used where no notification channel is wired (tests, CLI tools)."""

    async def emit(self, event: Event) -> None:
        del event
