"""Value objects that describe *who* acts and *inside which tenant*.

A :class:`TenantScope` is created by the authorisation layer after membership has been checked
and is the only way into tenant-scoped repositories and units of work. It is deliberately a plain
frozen value: it carries no database session and no permissions, so it can be passed into the
worker (serialised as ids) without dragging security state along.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID


class ActorType(StrEnum):
    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    API_KEY = "api_key"
    SYSTEM = "system"
    ANONYMOUS = "anonymous"


@dataclass(frozen=True, slots=True)
class Actor:
    type: ActorType
    id: UUID | None = None
    """User id, service-account id, API-key id; ``None`` for system/anonymous."""
    user_id: UUID | None = None
    """The human behind the action when there is one (API key owned by a user)."""

    @classmethod
    def system(cls) -> Actor:
        return cls(ActorType.SYSTEM)

    @classmethod
    def anonymous(cls) -> Actor:
        return cls(ActorType.ANONYMOUS)


@dataclass(frozen=True, slots=True)
class TenantScope:
    """An authorised position inside one organisation (and optionally one project)."""

    organization_id: UUID
    actor: Actor
    project_id: UUID | None = None

    def with_project(self, project_id: UUID) -> TenantScope:
        return TenantScope(self.organization_id, self.actor, project_id)
