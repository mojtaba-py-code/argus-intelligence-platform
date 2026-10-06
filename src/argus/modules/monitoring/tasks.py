"""Queue task: run one monitor."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from argus.infrastructure.queue import TaskContext, TaskDefinition
from argus.modules.monitoring.service import RUN_TASK


class RunMonitorPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: UUID
    monitor_id: UUID


async def run_monitor(ctx: TaskContext, payload: RunMonitorPayload) -> dict[str, Any]:
    result: dict[str, Any] = await ctx.services.monitors.execute(
        payload.organization_id, payload.monitor_id
    )
    return result


def monitoring_tasks() -> list[TaskDefinition]:
    return [
        TaskDefinition(
            name=RUN_TASK,
            handler=run_monitor,
            payload_model=RunMonitorPayload,
            queue="monitoring",
            timeout_s=900,
            max_attempts=2,
            idempotent=True,  # each target's pointer moves in the same transaction as its change
        )
    ]
