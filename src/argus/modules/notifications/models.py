"""In-app notifications (tenant-scoped)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, ForeignKeyConstraint, Index, String, text
from sqlalchemy.orm import Mapped, mapped_column

from argus.core.events import EVENT_TYPES
from argus.infrastructure.db.base import Base, CreatedAt, UUIDPrimaryKey, sql_in


class Notification(Base, UUIDPrimaryKey, CreatedAt):
    """An in-app notification for one user. Plain text only."""

    __tablename__ = "notifications"

    organization_id: Mapped[UUID]
    user_id: Mapped[UUID]
    event: Mapped[str] = mapped_column(String(48))
    title: Mapped[str] = mapped_column(String(200))
    body: Mapped[str] = mapped_column(String(2000))
    link: Mapped[str | None] = mapped_column(String(300))
    read_at: Mapped[datetime | None]

    __table_args__ = (
        ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        CheckConstraint(f"event IN {sql_in(EVENT_TYPES)}", name="event"),
        Index("ix_notifications_user", "organization_id", "user_id", "created_at"),
        Index(
            "ix_notifications_unread",
            "organization_id",
            "user_id",
            postgresql_where=text("read_at IS NULL"),
        ),
    )
