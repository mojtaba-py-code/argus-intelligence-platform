"""Retry policy with exponential backoff and *full jitter*.

Full jitter (``sleep = random(0, min(cap, base * 2**attempt))``) spreads retries from many clients
across the window instead of synchronising them into waves (AWS architecture blog, "Exponential
Backoff and Jitter"). A server-provided ``Retry-After`` always wins when it is larger.

Only errors classified as retryable are retried; callers must not wrap non-idempotent operations
in :func:`retry_async` unless they carry an idempotency key.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay_s: float = 0.5
    max_delay_s: float = 30.0

    def backoff(self, attempt: int, *, retry_after_s: float | None = None) -> float:
        """Delay before attempt ``attempt + 1`` (``attempt`` counts from 1)."""
        ceiling = min(self.max_delay_s, self.base_delay_s * (2 ** max(0, attempt - 1)))
        delay = random.uniform(0, ceiling)  # noqa: S311  # nosec B311
        if retry_after_s is not None:
            delay = max(delay, min(retry_after_s, self.max_delay_s))
        return delay


class RetryableError(Exception):
    """Raise (or wrap) to signal a transient failure; ``retry_after_s`` is an optional hint."""

    def __init__(self, message: str, *, retry_after_s: float | None = None) -> None:
        super().__init__(message)
        self.retry_after_s = retry_after_s


async def retry_async[T](
    operation: Callable[[], Awaitable[T]],
    *,
    policy: RetryPolicy,
    is_retryable: Callable[[BaseException], bool] = lambda exc: isinstance(exc, RetryableError),
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> T:
    attempt = 0
    while True:
        attempt += 1
        try:
            return await operation()
        except Exception as exc:
            if attempt >= policy.max_attempts or not is_retryable(exc):
                raise
            hint = exc.retry_after_s if isinstance(exc, RetryableError) else None
            await sleep(policy.backoff(attempt, retry_after_s=hint))
