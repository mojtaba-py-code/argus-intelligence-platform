"""Identity tables. Global (not tenant-scoped): a user can belong to many organisations.

Credentials are never stored in a usable form: passwords as Argon2id hashes, refresh / one-time
tokens and recovery codes as SHA-256 / HMAC digests, TOTP secrets AES-GCM encrypted with the user
id as associated data.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    false,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from argus.infrastructure.db.base import Base, CreatedAt, Timestamps, UUIDPrimaryKey, sql_in

USER_STATUSES = ("active", "disabled")
TOKEN_PURPOSES = ("email_verification", "password_reset", "mfa_challenge")


class User(Base, UUIDPrimaryKey, Timestamps):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), unique=True)
    full_name: Mapped[str] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="active", server_default="active")
    email_verified_at: Mapped[datetime | None]
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    is_platform_admin: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    locked_until: Mapped[datetime | None]
    last_login_at: Mapped[datetime | None]
    password_changed_at: Mapped[datetime]

    __table_args__ = (
        CheckConstraint("email = lower(email)", name="email_lowercase"),
        CheckConstraint(f"status IN {sql_in(USER_STATUSES)}", name="status"),
    )


class UserSession(Base, UUIDPrimaryKey, CreatedAt):
    __tablename__ = "user_sessions"

    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    last_seen_at: Mapped[datetime]
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]
    revoked_reason: Mapped[str | None] = mapped_column(String(32))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(256))
    auth_method: Mapped[str] = mapped_column(String(32))
    mfa_verified: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())

    __table_args__ = (Index("ix_user_sessions_user_active", "user_id", "revoked_at"),)


class RefreshToken(Base, UUIDPrimaryKey, CreatedAt):
    __tablename__ = "refresh_tokens"

    session_id: Mapped[UUID] = mapped_column(
        ForeignKey("user_sessions.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    parent_id: Mapped[UUID | None]
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]


class OneTimeToken(Base, UUIDPrimaryKey, CreatedAt):
    __tablename__ = "one_time_tokens"

    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    purpose: Mapped[str] = mapped_column(String(32))
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    expires_at: Mapped[datetime]
    consumed_at: Mapped[datetime | None]
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")

    __table_args__ = (CheckConstraint(f"purpose IN {sql_in(TOKEN_PURPOSES)}", name="purpose"),)


class MfaTotp(Base, CreatedAt):
    __tablename__ = "mfa_totp"

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    secret_ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    confirmed_at: Mapped[datetime | None]
    last_used_step: Mapped[int | None] = mapped_column(BigInteger)


class MfaRecoveryCode(Base, UUIDPrimaryKey, CreatedAt):
    __tablename__ = "mfa_recovery_codes"

    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    code_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    used_at: Mapped[datetime | None]
