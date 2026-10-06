"""A small, process-local circuit breaker.

States: CLOSED (calls flow; consecutive failures counted) → OPEN after ``failure_threshold``
failures (calls fail fast for ``reset_timeout_s``) → HALF_OPEN (one trial call; success closes,
failure re-opens). Process-local on purpose: each worker learns about a failing dependency from
its own traffic, and no shared store becomes a new single point of failure.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from enum import StrEnum


class BreakerState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(Exception):
    def __init__(self, name: str, retry_in_s: float) -> None:
        super().__init__(f"circuit {name!r} is open")
        self.name = name
        self.retry_in_s = retry_in_s


class CircuitBreaker:
    def __init__(
        self,
        name: str,
        *,
        failure_threshold: int = 5,
        reset_timeout_s: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.reset_timeout_s = reset_timeout_s
        self._clock = clock
        self._failures = 0
        self._opened_at: float | None = None
        self._trial_in_flight = False

    @property
    def state(self) -> BreakerState:
        if self._opened_at is None:
            return BreakerState.CLOSED
        if self._clock() - self._opened_at >= self.reset_timeout_s:
            return BreakerState.HALF_OPEN
        return BreakerState.OPEN

    def allow(self) -> bool:
        """Non-raising check used by routers to skip an open dependency."""
        state = self.state
        if state is BreakerState.CLOSED:
            return True
        return state is BreakerState.HALF_OPEN and not self._trial_in_flight

    def before_call(self) -> None:
        state = self.state
        if state is BreakerState.OPEN or (
            state is BreakerState.HALF_OPEN and self._trial_in_flight
        ):
            opened = self._opened_at or self._clock()
            raise CircuitOpenError(
                self.name, max(0.0, self.reset_timeout_s - (self._clock() - opened))
            )
        if state is BreakerState.HALF_OPEN:
            self._trial_in_flight = True

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = None
        self._trial_in_flight = False

    def record_failure(self) -> None:
        self._trial_in_flight = False
        if self.state is BreakerState.HALF_OPEN:
            self._opened_at = self._clock()
            return
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._opened_at = self._clock()


class BreakerRegistry:
    """Lazily created breakers keyed by dependency name (e.g. ``anthropic:claude-opus-5-5``)."""

    def __init__(self, *, failure_threshold: int, reset_timeout_s: float) -> None:
        self._threshold = failure_threshold
        self._reset = reset_timeout_s
        self._breakers: dict[str, CircuitBreaker] = {}

    def get(self, name: str) -> CircuitBreaker:
        breaker = self._breakers.get(name)
        if breaker is None:
            breaker = CircuitBreaker(
                name, failure_threshold=self._threshold, reset_timeout_s=self._reset
            )
            self._breakers[name] = breaker
        return breaker

    def snapshot(self) -> dict[str, str]:
        return {name: breaker.state.value for name, breaker in self._breakers.items()}
