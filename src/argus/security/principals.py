"""The authenticated caller, as established by the authentication layer."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from argus.core.scope import Actor, ActorType
from argus.security.permissions import Permission


@dataclass(frozen=True, slots=True)
class ClientInfo:
    """Request metadata recorded on sessions and audit events (never used for authorisation)."""

    ip_address: str | None = None
    user_agent: str | None = None
    request_id: str | None = None

    @classmethod
    def system(cls) -> ClientInfo:
        return cls()


@dataclass(frozen=True, slots=True)
class Principal:
    actor: Actor
    user_id: UUID | None = None
    session_id: UUID | None = None
    amr: tuple[str, ...] = ()
    is_platform_admin: bool = False
    api_key_id: UUID | None = None
    service_account_id: UUID | None = None
    key_organization_id: UUID | None = None
    """API keys and service accounts are bound to exactly one organisation."""
    scopes: frozenset[Permission] | None = None
    """API-key scopes; ``None`` means "whatever the role allows" (interactive users)."""

    @classmethod
    def user(
        cls,
        user_id: UUID,
        *,
        session_id: UUID | None = None,
        amr: tuple[str, ...] = (),
        is_platform_admin: bool = False,
    ) -> Principal:
        return cls(
            actor=Actor(ActorType.USER, user_id, user_id),
            user_id=user_id,
            session_id=session_id,
            amr=amr,
            is_platform_admin=is_platform_admin,
        )

    @property
    def is_interactive(self) -> bool:
        return self.session_id is not None

    @property
    def mfa_verified(self) -> bool:
        return "otp" in self.amr
