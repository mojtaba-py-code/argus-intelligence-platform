"""Queue task: fetch one source (manual additions and monitor re-checks)."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from argus.core.scope import Actor, ActorType, TenantScope
from argus.infrastructure.queue import NonRetryableJobError, TaskContext, TaskDefinition
from argus.modules.sources.service import FETCH_TASK
from argus.security.ssrf import EgressBlocked


class FetchSourcePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: UUID
    project_id: UUID
    url: str
    user_id: UUID | None = None


async def fetch_source(ctx: TaskContext, payload: FetchSourcePayload) -> dict[str, Any]:
    scope = TenantScope(
        payload.organization_id,
        Actor(ActorType.SYSTEM, None, payload.user_id),
        payload.project_id,
    )
    try:
        outcome = await ctx.services.sources.collect(scope, payload.url, discovered_via="manual")
    except EgressBlocked as exc:
        raise NonRetryableJobError(f"blocked: {exc.reason}") from None
    return {
        "status": outcome.status,
        "error_code": outcome.error_code,
        "new_content": outcome.new_content,
    }


def source_tasks() -> list[TaskDefinition]:
    return [
        TaskDefinition(
            name=FETCH_TASK,
            handler=fetch_source,
            payload_model=FetchSourcePayload,
            queue="default",
            timeout_s=120,
            max_attempts=3,
            idempotent=True,  # snapshots are deduplicated by content hash
        )
    ]
