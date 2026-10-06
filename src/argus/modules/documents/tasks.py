"""Queue tasks: process an uploaded document; delete a blob after its row was deleted."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from argus.infrastructure.queue import NonRetryableJobError, TaskContext, TaskDefinition
from argus.modules.documents.service import DELETE_BLOB_TASK, PROCESS_TASK


class ProcessDocumentPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: UUID
    document_id: UUID


class DeleteBlobPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: UUID
    key: str = Field(max_length=255)


async def process_document(ctx: TaskContext, payload: ProcessDocumentPayload) -> dict[str, Any]:
    # Scanner or storage outages raise and the job retries with backoff: a document is never
    # parsed or released without a clean scan.
    outcome = await ctx.services.documents.process(payload.organization_id, payload.document_id)
    return {"outcome": outcome}


async def delete_blob(ctx: TaskContext, payload: DeleteBlobPayload) -> dict[str, Any]:
    try:
        await ctx.services.documents.delete_blob(payload.organization_id, payload.key)
    except ValueError as exc:
        raise NonRetryableJobError(str(exc)) from None
    return {"deleted": True}


def document_tasks(*, process_timeout_s: int) -> list[TaskDefinition]:
    return [
        TaskDefinition(
            name=PROCESS_TASK,
            handler=process_document,
            payload_model=ProcessDocumentPayload,
            queue="documents",
            timeout_s=process_timeout_s,
            max_attempts=5,
            idempotent=True,  # finished documents are skipped; scan + parse are side-effect free
        ),
        TaskDefinition(
            name=DELETE_BLOB_TASK,
            handler=delete_blob,
            payload_model=DeleteBlobPayload,
            queue="default",
            timeout_s=60,
            max_attempts=10,
            idempotent=True,  # deleting a missing object succeeds
        ),
    ]
