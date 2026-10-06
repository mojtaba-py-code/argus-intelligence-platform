"""Queue task: run (or resume) a research job through the pipeline."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from argus.infrastructure.queue import TaskContext, TaskDefinition
from argus.modules.research.service import RESEARCH_TASK


class RunResearchPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_id: UUID
    organization_id: UUID


async def run_research(ctx: TaskContext, payload: RunResearchPayload) -> dict[str, Any]:
    pipeline = ctx.services.research_pipeline
    outcome = await pipeline.run(
        payload.organization_id,
        payload.job_id,
        services=ctx.services,
        cancelled=ctx.cancelled,
        final_attempt=ctx.attempt >= ctx.max_attempts,
    )
    return {"outcome": outcome}


def research_tasks(*, timeout_s: int) -> list[TaskDefinition]:
    return [
        TaskDefinition(
            name=RESEARCH_TASK,
            handler=run_research,
            payload_model=RunResearchPayload,
            queue="research",
            timeout_s=timeout_s,
            max_attempts=3,
            idempotent=True,  # stages are checkpointed and upsert by natural keys
        )
    ]
