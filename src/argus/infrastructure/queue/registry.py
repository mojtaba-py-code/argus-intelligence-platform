"""Task definitions.

A task declares its payload schema (validated before the handler runs - a malformed payload is a
permanent failure, not something to retry), its queue, timeout, retry budget and whether it is
**idempotent**. Non-idempotent tasks get exactly one attempt: blindly retrying an operation that
may already have had its side effect is how duplicate e-mails and double charges happen.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from argus.core.retry import RetryPolicy


class NonRetryableJobError(Exception):
    """The job cannot succeed by retrying (bad input, missing resource, policy refusal)."""


@dataclass
class TaskContext:
    job_id: UUID
    attempt: int
    max_attempts: int
    organization_id: UUID | None
    services: Any
    """The process container (typed as ``Any`` here: infrastructure must not import apps)."""
    cancelled: Callable[[], bool] = field(default=lambda: False)


Handler = Callable[[TaskContext, Any], Awaitable[dict[str, Any] | None]]


@dataclass(frozen=True)
class TaskDefinition:
    name: str
    handler: Handler
    payload_model: type[BaseModel]
    queue: str = "default"
    timeout_s: int = 300
    max_attempts: int = 3
    idempotent: bool = True
    retry: RetryPolicy = field(default_factory=lambda: RetryPolicy(base_delay_s=5, max_delay_s=600))

    def __post_init__(self) -> None:
        if not self.idempotent and self.max_attempts != 1:
            msg = f"task {self.name}: non-idempotent tasks must have max_attempts=1"
            raise ValueError(msg)


class TaskRegistry:
    def __init__(self) -> None:
        self._tasks: dict[str, TaskDefinition] = {}

    def register(self, definition: TaskDefinition) -> None:
        if definition.name in self._tasks:
            msg = f"task {definition.name!r} registered twice"
            raise ValueError(msg)
        self._tasks[definition.name] = definition

    def get(self, name: str) -> TaskDefinition | None:
        return self._tasks.get(name)

    def names(self) -> list[str]:
        return sorted(self._tasks)

    def queues(self) -> tuple[str, ...]:
        return tuple(sorted({task.queue for task in self._tasks.values()}))
