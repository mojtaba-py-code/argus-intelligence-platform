"""Notifications: who hears about an event, and how - in-app and by e-mail.

``NotificationService`` is the platform's :class:`~argus.core.events.EventSink`. Emitting never
raises: a broken mail server must not fail a research job or a monitor run.

* Recipients are re-checked against the organisation's *current* members when the event fires.
* Notifications are plain text: a one-line sanitised title and a sanitised body. Links are
  application paths only, never external URLs, so a notification cannot carry a phishing link,
  whatever text a monitored page contained.
* E-mail is plain text and goes only to active users, only for events that ask for it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Final
from uuid import UUID

from sqlalchemy import func, select, text, update

from argus.core.clock import Clock
from argus.core.config import NotificationSettings
from argus.core.errors import NotFound
from argus.core.events import Event
from argus.core.logging import get_logger
from argus.core.pagination import Page, PageQuery, encode_cursor
from argus.core.scope import Actor, TenantScope
from argus.infrastructure.db import Database
from argus.infrastructure.email import EmailMessage, Mailer
from argus.modules.identity.models import User
from argus.modules.notifications.models import Notification
from argus.modules.notifications.schemas import NotificationResponse, UnreadCountResponse
from argus.modules.tenancy.authorization import OrgAccess
from argus.modules.tenancy.models import OrganizationMember
from argus.security.text import clean_line, sanitize_text

log = get_logger(__name__)
ADMIN_ROLES: Final = ("owner", "admin")


def safe_link(link: str | None) -> str | None:
    """Only application paths: never an external or protocol-relative URL."""
    if not link or not link.startswith("/") or link.startswith("//") or "\\" in link:
        return None
    return clean_line(link, 300)


@dataclass(frozen=True)
class NotificationDependencies:
    database: Database
    mailer: Mailer
    clock: Clock
    settings: NotificationSettings
    public_base_url: str


class NotificationService:
    def __init__(self, deps: NotificationDependencies) -> None:
        self._d = deps

    # ------------------------------------------------------------------- the event sink
    async def emit(self, event: Event) -> None:
        try:
            await self._emit(event)
        except Exception:  # a notification problem must never fail the producer
            log.exception("notifications.emit_failed", event_type=event.type)

    async def _emit(self, event: Event) -> None:
        if not event.recipients:
            return
        scope = TenantScope(event.organization_id, Actor.system())
        title = clean_line(event.title, 200) or event.type
        body = sanitize_text(event.body, max_chars=2000).text
        link = safe_link(event.link)
        async with self._d.database.tenant(scope) as session:
            members = set(
                (
                    await session.execute(
                        select(OrganizationMember.user_id).where(
                            OrganizationMember.organization_id == event.organization_id,
                            OrganizationMember.user_id.in_(event.recipients),
                        )
                    )
                ).scalars()
            )
            recipients = [user for user in dict.fromkeys(event.recipients) if user in members]
            session.add_all(
                Notification(
                    organization_id=event.organization_id,
                    user_id=user,
                    event=event.type,
                    title=title,
                    body=body,
                    link=link,
                )
                for user in recipients
            )
        if event.email and self._d.settings.email and recipients:
            await self._email(recipients, title, body, link)

    async def _email(self, recipients: list[UUID], title: str, body: str, link: str | None) -> None:
        async with self._d.database.session(read_only=True) as session:
            addresses = (
                (
                    await session.execute(
                        select(User.email).where(User.id.in_(recipients), User.status == "active")
                    )
                )
                .scalars()
                .all()
            )
        footer = f"\n\nOpen in Argus: {self._d.public_base_url.rstrip('/')}{link}" if link else ""
        for address in addresses:
            try:
                await self._d.mailer.send(
                    EmailMessage(
                        to=address,
                        subject=f"[Argus] {title}"[:150],
                        text=f"{body}{footer}\n",
                        category="notification",
                    )
                )
            except Exception:  # one bad address or a mail outage must not stop the others
                log.exception("notifications.email_failed")

    async def administrators(self, organization_id: UUID) -> tuple[UUID, ...]:
        """Owners and administrators: the people who decide approvals."""
        scope = TenantScope(organization_id, Actor.system())
        async with self._d.database.tenant(scope, read_only=True) as session:
            return tuple(
                (
                    await session.execute(
                        select(OrganizationMember.user_id).where(
                            OrganizationMember.organization_id == organization_id,
                            OrganizationMember.role.in_(ADMIN_ROLES),
                        )
                    )
                ).scalars()
            )

    # --------------------------------------------------------------------- reading them
    @staticmethod
    def _user(access: OrgAccess) -> UUID | None:
        # Service-account keys have no inbox; a user's API key reads that user's inbox.
        return access.principal.user_id if access.principal.service_account_id is None else None

    async def list_notifications(
        self, access: OrgAccess, page: PageQuery, *, unread: bool = False
    ) -> Page[NotificationResponse]:
        user = self._user(access)
        if user is None:
            return Page[NotificationResponse](items=[])
        cursor = page.decoded()
        stmt = select(Notification).where(
            Notification.organization_id == access.organization_id, Notification.user_id == user
        )
        if unread:
            stmt = stmt.where(Notification.read_at.is_(None))
        if cursor is not None:
            stmt = stmt.where(
                (Notification.created_at < cursor.created_at)
                | ((Notification.created_at == cursor.created_at) & (Notification.id < cursor.id))
            )
        stmt = stmt.order_by(Notification.created_at.desc(), Notification.id.desc()).limit(
            page.limit + 1
        )
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            rows = list((await session.execute(stmt)).scalars().all())
        next_cursor = None
        if len(rows) > page.limit:
            rows = rows[: page.limit]
            next_cursor = encode_cursor(rows[-1].created_at, rows[-1].id)
        return Page[NotificationResponse](
            items=[NotificationResponse.model_validate(row) for row in rows],
            next_cursor=next_cursor,
        )

    async def unread_count(self, access: OrgAccess) -> UnreadCountResponse:
        user = self._user(access)
        if user is None:
            return UnreadCountResponse(unread=0)
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            count = (
                await session.execute(
                    select(func.count())
                    .select_from(Notification)
                    .where(
                        Notification.organization_id == access.organization_id,
                        Notification.user_id == user,
                        Notification.read_at.is_(None),
                    )
                )
            ).scalar_one()
        return UnreadCountResponse(unread=int(count))

    async def mark_read(self, access: OrgAccess, notification_id: UUID) -> None:
        user = self._user(access)
        async with self._d.database.tenant(access.scope) as session:
            result = await session.execute(
                update(Notification)
                .where(
                    Notification.organization_id == access.organization_id,
                    Notification.id == notification_id,
                    Notification.user_id == user,
                )
                .values(read_at=func.coalesce(Notification.read_at, self._d.clock.now()))
                .returning(Notification.id)
            )
            if result.first() is None:
                raise NotFound  # someone else's notification looks exactly like a missing one

    async def mark_all_read(self, access: OrgAccess) -> int:
        user = self._user(access)
        if user is None:
            return 0
        async with self._d.database.tenant(access.scope) as session:
            result = await session.execute(
                update(Notification)
                .where(
                    Notification.organization_id == access.organization_id,
                    Notification.user_id == user,
                    Notification.read_at.is_(None),
                )
                .values(read_at=self._d.clock.now())
                .returning(Notification.id)
            )
            return len(result.all())

    # -------------------------------------------------------------------------- retention
    async def purge_read(self) -> int:
        """Delete read notifications past the retention period, in every organisation."""
        cutoff = self._d.clock.now() - timedelta(days=self._d.settings.retention_days)
        async with self._d.database.session() as session:
            deleted = (
                await session.execute(
                    text("SELECT argus_purge_read_notifications(:cutoff)"), {"cutoff": cutoff}
                )
            ).scalar_one()
        return int(deleted)
