"""Time source abstraction so that expiry, lockout and lease logic is testable."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime:
        """Current time, timezone-aware, UTC."""
        ...

    def monotonic(self) -> float:
        """Monotonic seconds for measuring durations."""
        ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()


def utcnow() -> datetime:
    return datetime.now(UTC)
