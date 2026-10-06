"""A project's knowledge corpus version: bumped whenever its searchable content changes.

Retrieval caches include the version in their keys, so any document upload, re-index or deletion
invalidates every cached search over the project at once, without enumerating cache keys.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def bump_corpus_version(session: AsyncSession, project_id: UUID) -> None:
    await session.execute(
        text("UPDATE projects SET corpus_version = corpus_version + 1 WHERE id = :id"),
        {"id": project_id},
    )
