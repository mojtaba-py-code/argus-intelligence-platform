"""Data access for identity tables (user-scoped, not tenant-scoped)."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from uuid import UUID

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from argus.modules.identity.models import (
    MfaRecoveryCode,
    MfaTotp,
    OneTimeToken,
    RefreshToken,
    User,
    UserSession,
)


class IdentityRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # ------------------------------------------------------------------ users
    async def user_by_email(self, email: str, *, for_update: bool = False) -> User | None:
        stmt = select(User).where(User.email == email)
        if for_update:
            stmt = stmt.with_for_update()
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def user_by_id(self, user_id: UUID, *, for_update: bool = False) -> User | None:
        stmt = select(User).where(User.id == user_id)
        if for_update:
            stmt = stmt.with_for_update()
        return (await self.session.execute(stmt)).scalar_one_or_none()

    def add(self, entity: object) -> None:
        self.session.add(entity)

    # --------------------------------------------------------------- sessions
    async def get_session(
        self, session_id: UUID, *, user_id: UUID | None = None, for_update: bool = False
    ) -> UserSession | None:
        stmt = select(UserSession).where(UserSession.id == session_id)
        if user_id is not None:
            stmt = stmt.where(UserSession.user_id == user_id)
        if for_update:
            stmt = stmt.with_for_update()
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def active_sessions(self, user_id: UUID, now: datetime) -> Sequence[UserSession]:
        stmt = (
            select(UserSession)
            .where(
                UserSession.user_id == user_id,
                UserSession.revoked_at.is_(None),
                UserSession.expires_at > now,
            )
            .order_by(UserSession.created_at.desc())
            .limit(100)
        )
        return (await self.session.execute(stmt)).scalars().all()

    async def revoke_session(self, session_id: UUID, *, reason: str, now: datetime) -> None:
        await self.session.execute(
            update(UserSession)
            .where(UserSession.id == session_id, UserSession.revoked_at.is_(None))
            .values(revoked_at=now, revoked_reason=reason)
        )
        await self.session.execute(
            update(RefreshToken)
            .where(RefreshToken.session_id == session_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )

    async def revoke_user_sessions(
        self, user_id: UUID, *, reason: str, now: datetime, keep: UUID | None = None
    ) -> list[UUID]:
        stmt = select(UserSession.id).where(
            UserSession.user_id == user_id, UserSession.revoked_at.is_(None)
        )
        if keep is not None:
            stmt = stmt.where(UserSession.id != keep)
        ids = list((await self.session.execute(stmt)).scalars().all())
        for session_id in ids:
            await self.revoke_session(session_id, reason=reason, now=now)
        return ids

    # ---------------------------------------------------------- refresh tokens
    async def refresh_token_by_hash(self, token_hash: bytes) -> RefreshToken | None:
        stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash).with_for_update()
        return (await self.session.execute(stmt)).scalar_one_or_none()

    # --------------------------------------------------------- one-time tokens
    async def one_time_token(self, token_hash: bytes, purpose: str) -> OneTimeToken | None:
        stmt = (
            select(OneTimeToken)
            .where(OneTimeToken.token_hash == token_hash, OneTimeToken.purpose == purpose)
            .with_for_update()
        )
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def consume_user_tokens(self, user_id: UUID, purpose: str, now: datetime) -> None:
        """Invalidate every outstanding token of one purpose (issuing a new one or using one)."""
        await self.session.execute(
            update(OneTimeToken)
            .where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == purpose,
                OneTimeToken.consumed_at.is_(None),
            )
            .values(consumed_at=now)
        )

    # --------------------------------------------------------------------- MFA
    async def totp(self, user_id: UUID, *, for_update: bool = False) -> MfaTotp | None:
        stmt = select(MfaTotp).where(MfaTotp.user_id == user_id)
        if for_update:
            stmt = stmt.with_for_update()
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def delete_mfa(self, user_id: UUID) -> None:
        await self.session.execute(delete(MfaTotp).where(MfaTotp.user_id == user_id))
        await self.session.execute(
            delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user_id)
        )

    async def recovery_code(self, user_id: UUID, code_hash: bytes) -> MfaRecoveryCode | None:
        stmt = (
            select(MfaRecoveryCode)
            .where(
                MfaRecoveryCode.user_id == user_id,
                MfaRecoveryCode.code_hash == code_hash,
                MfaRecoveryCode.used_at.is_(None),
            )
            .with_for_update()
        )
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def replace_recovery_codes(self, user_id: UUID, hashes: Sequence[bytes]) -> None:
        await self.session.execute(
            delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user_id)
        )
        for code_hash in hashes:
            self.session.add(MfaRecoveryCode(user_id=user_id, code_hash=code_hash))
