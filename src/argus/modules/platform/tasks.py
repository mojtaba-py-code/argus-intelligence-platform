"""Background work of the platform module."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from argus.infrastructure.queue import TaskContext, TaskDefinition
from argus.modules.platform.exports import EXPORT_TASK


class ExportPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    export_id: UUID


async def build_export(ctx: TaskContext, payload: ExportPayload) -> dict[str, Any]:
    if ctx.organization_id is None:
        return {"status": "skipped"}
    status = await ctx.services.exports.build(
        ctx.organization_id, payload.export_id, final_attempt=ctx.attempt >= ctx.max_attempts
    )
    return {"status": status}


def platform_tasks() -> list[TaskDefinition]:
    return [
        TaskDefinition(
            name=EXPORT_TASK,
            handler=build_export,
            payload_model=ExportPayload,
            queue="default",
            timeout_s=3600,
            max_attempts=2,
            idempotent=True,  # a pending export is rebuilt from scratch; a finished one is skipped
        )
    ]
