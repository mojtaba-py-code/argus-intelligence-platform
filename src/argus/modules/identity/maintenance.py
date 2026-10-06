"""Periodic clean-up of expired credentials (run by the scheduler)."""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import delete, or_

from argus.infrastructure.db import Database
from argus.modules.identity.models import OneTimeToken, RefreshToken, UserSession

_KEEP_FOR_FORENSICS = timedelta(days=30)


async def purge_expired_credentials(database: Database, now: datetime) -> dict[str, int]:
    """Delete long-dead tokens and sessions. Recent ones are kept for incident investigation."""
    cutoff = now - _KEEP_FOR_FORENSICS
    async with database.session() as session:
        tokens = await session.execute(
            delete(OneTimeToken).where(
                or_(OneTimeToken.expires_at < cutoff, OneTimeToken.consumed_at < cutoff)
            )
        )
        sessions = await session.execute(
            delete(UserSession).where(
                or_(UserSession.expires_at < cutoff, UserSession.revoked_at < cutoff)
            )
        )
        refresh = await session.execute(
            delete(RefreshToken).where(RefreshToken.expires_at < cutoff)
        )
    return {
        "one_time_tokens": int(tokens.rowcount),  # type: ignore[attr-defined]
        "sessions": int(sessions.rowcount),  # type: ignore[attr-defined]
        "refresh_tokens": int(refresh.rowcount),  # type: ignore[attr-defined]
    }
