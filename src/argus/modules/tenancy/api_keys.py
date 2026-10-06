"""Service accounts and API keys.

Key format: ``argus_sk_<key id: 12 chars>_<secret: 40 base62 chars>`` (~238 bits of secret).
The key id is public (indexed, shown in listings); the secret is stored only as
``HMAC-SHA256(pepper, secret)``. Verification happens *inside PostgreSQL* through the
``argus_authenticate_api_key(key_id, hash)`` SECURITY DEFINER function: the runtime role cannot
read the ``api_keys`` table across tenants (RLS), and the stored hash never leaves the database.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import select, text, update
from sqlalchemy.exc import IntegrityError

from argus.core.clock import Clock
from argus.core.crypto import hmac_sha256, sha256
from argus.core.errors import Conflict, InvalidCredentials, NotFound, PermissionDenied, RateLimited
from argus.core.ids import random_base62, random_lower_alnum
from argus.core.scope import Actor, ActorType, TenantScope
from argus.infrastructure.db import Database
from argus.modules.audit.service import AuditCategory, AuditEvent, AuditOutcome, AuditService
from argus.modules.identity.models import User
from argus.modules.platform import quotas
from argus.modules.tenancy.authorization import OrgAccess
from argus.modules.tenancy.models import ApiKey, ServiceAccount
from argus.modules.tenancy.schemas import (
    ApiKeyResponse,
    CreateApiKeyRequest,
    CreatedApiKeyResponse,
    CreateServiceAccountRequest,
    ServiceAccountResponse,
)
from argus.security.permissions import (
    ORG_ROLE_PERMISSIONS,
    ROLE_RANK,
    OrgRole,
    Permission,
)
from argus.security.principals import ClientInfo, Principal
from argus.security.ratelimit import POLICIES, RateLimiter

KEY_PATTERN = re.compile(r"^argus_sk_([a-z0-9]{12})_([A-Za-z0-9]{40})$")
_TOUCH_INTERVAL = timedelta(minutes=1)


def _prefix(key_id: str) -> str:
    return f"argus_sk_{key_id}_..."


@dataclass(frozen=True)
class ApiKeyDependencies:
    database: Database
    audit: AuditService
    limiter: RateLimiter
    clock: Clock
    pepper: bytes


class ApiKeyService:
    def __init__(self, deps: ApiKeyDependencies) -> None:
        self._d = deps

    def _hash(self, secret: str) -> bytes:
        return hmac_sha256(self._d.pepper, "api-key", secret)

    def _event(self, action: str, scope: TenantScope, client: ClientInfo, **kw: Any) -> AuditEvent:
        return AuditEvent(
            action=action,
            category=kw.pop("category", AuditCategory.SECURITY),
            actor=scope.actor,
            organization_id=scope.organization_id,
            client=client,
            **kw,
        )

    # ------------------------------------------------------------- service accounts
    async def create_service_account(
        self, access: OrgAccess, request: CreateServiceAccountRequest, client: ClientInfo
    ) -> ServiceAccountResponse:
        access.require(Permission.SERVICE_ACCOUNTS_MANAGE)
        role = OrgRole(request.role)
        if ROLE_RANK[role] > ROLE_RANK[access.role]:
            raise PermissionDenied("A service account cannot have a higher role than yours.")
        try:
            async with self._d.database.tenant(access.scope) as session:
                account = ServiceAccount(
                    organization_id=access.organization_id,
                    name=request.name,
                    description=request.description,
                    role=role.value,
                    created_by=access.principal.user_id,
                )
                session.add(account)
                await session.flush()
                await self._d.audit.record(
                    session,
                    self._event(
                        "service_account.created",
                        access.scope,
                        client,
                        target_type="service_account",  # nosemgrep: detected-google-gcm-service-account
                        target_id=str(account.id),
                        details={"role": role.value},
                    ),
                )
                return ServiceAccountResponse.model_validate(account)
        except IntegrityError as exc:
            if "uq_service_accounts_organization_id_name" in str(exc.orig):
                raise Conflict("A service account with this name already exists.") from None
            raise

    async def list_service_accounts(self, access: OrgAccess) -> list[ServiceAccountResponse]:
        access.require(Permission.APIKEYS_READ)
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            rows = (
                (
                    await session.execute(
                        select(ServiceAccount)
                        .where(ServiceAccount.organization_id == access.organization_id)
                        .order_by(ServiceAccount.created_at)
                        .limit(1000)
                    )
                )
                .scalars()
                .all()
            )
        return [ServiceAccountResponse.model_validate(row) for row in rows]

    async def disable_service_account(
        self, access: OrgAccess, service_account_id: UUID, client: ClientInfo
    ) -> None:
        access.require(Permission.SERVICE_ACCOUNTS_MANAGE)
        now = self._d.clock.now()
        async with self._d.database.tenant(access.scope) as session:
            account = (
                await session.execute(
                    select(ServiceAccount)
                    .where(
                        ServiceAccount.organization_id == access.organization_id,
                        ServiceAccount.id == service_account_id,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if account is None or account.disabled_at is not None:
                raise NotFound
            account.disabled_at = now
            await session.execute(
                update(ApiKey)
                .where(
                    ApiKey.organization_id == access.organization_id,
                    ApiKey.service_account_id == service_account_id,
                    ApiKey.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            )
            await self._d.audit.record(
                session,
                self._event(
                    "service_account.disabled",
                    access.scope,
                    client,
                    target_type="service_account",  # nosemgrep: detected-google-gcm-service-account
                    target_id=str(service_account_id),
                ),
            )

    # ------------------------------------------------------------------------ keys
    async def create(
        self, access: OrgAccess, request: CreateApiKeyRequest, client: ClientInfo
    ) -> CreatedApiKeyResponse:
        access.require(Permission.APIKEYS_MANAGE)
        decision = await self._d.limiter.hit(
            POLICIES["apikeys.create.org"], str(access.organization_id)
        )
        if not decision.allowed:
            raise RateLimited(decision.retry_after_s)
        scopes = frozenset(request.scopes)
        now = self._d.clock.now()
        async with self._d.database.tenant(access.scope) as session:
            await quotas.enforce(session, access.organization_id, "api_keys", now=now)
            owner_user_id: UUID | None = None
            if request.service_account_id is not None:
                account = (
                    await session.execute(
                        select(ServiceAccount).where(
                            ServiceAccount.organization_id == access.organization_id,
                            ServiceAccount.id == request.service_account_id,
                        )
                    )
                ).scalar_one_or_none()
                if account is None or account.disabled_at is not None:
                    raise NotFound
                ceiling = ORG_ROLE_PERMISSIONS[OrgRole(account.role)]
            else:
                if access.principal.user_id is None or access.principal.session_id is None:
                    raise PermissionDenied("Personal API keys are created by signed-in users.")
                owner_user_id = access.principal.user_id
                ceiling = access.permissions
            excess = scopes - ceiling
            if excess:
                raise PermissionDenied(
                    "The key would exceed its owner's permissions: "
                    + ", ".join(sorted(p.value for p in excess))
                )
            key_id = random_lower_alnum(12)
            secret = random_base62(40)
            record = ApiKey(
                organization_id=access.organization_id,
                key_id=key_id,
                secret_hash=self._hash(secret),
                name=request.name,
                owner_user_id=owner_user_id,
                service_account_id=request.service_account_id,
                scopes=sorted(p.value for p in scopes),
                expires_at=now + timedelta(days=request.expires_in_days)
                if request.expires_in_days
                else None,
                created_by=access.principal.user_id,
            )
            session.add(record)
            await session.flush()
            await self._d.audit.record(
                session,
                self._event(
                    "api_key.created",
                    access.scope,
                    client,
                    target_type="api_key",
                    target_id=str(record.id),
                    details={
                        "scopes": record.scopes,
                        "prefix": _prefix(key_id),
                        "service_account_id": str(request.service_account_id)
                        if request.service_account_id
                        else None,
                    },
                ),
            )
            return CreatedApiKeyResponse(
                **ApiKeyResponse.model_validate(
                    {**_row_dict(record), "prefix": _prefix(key_id)}
                ).model_dump(),
                key=f"argus_sk_{key_id}_{secret}",
            )

    async def list_keys(self, access: OrgAccess) -> list[ApiKeyResponse]:
        access.require(Permission.APIKEYS_READ)
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            rows = (
                (
                    await session.execute(
                        select(ApiKey)
                        .where(ApiKey.organization_id == access.organization_id)
                        .order_by(ApiKey.created_at.desc())
                        .limit(1000)
                    )
                )
                .scalars()
                .all()
            )
        return [
            ApiKeyResponse.model_validate({**_row_dict(row), "prefix": _prefix(row.key_id)})
            for row in rows
        ]

    async def revoke(self, access: OrgAccess, api_key_id: UUID, client: ClientInfo) -> None:
        access.require(Permission.APIKEYS_MANAGE)
        async with self._d.database.tenant(access.scope) as session:
            result = await session.execute(
                update(ApiKey)
                .where(
                    ApiKey.organization_id == access.organization_id,
                    ApiKey.id == api_key_id,
                    ApiKey.revoked_at.is_(None),
                )
                .values(revoked_at=self._d.clock.now())
            )
            if result.rowcount == 0:  # type: ignore[attr-defined]
                raise NotFound
            await self._d.audit.record(
                session,
                self._event(
                    "api_key.revoked",
                    access.scope,
                    client,
                    target_type="api_key",
                    target_id=str(api_key_id),
                ),
            )

    async def authenticate(self, token: str, *, client: ClientInfo) -> Principal:
        invalid = InvalidCredentials("The API key is invalid, expired or revoked.")
        match = KEY_PATTERN.fullmatch(token)
        if match is None:
            raise invalid
        key_id, secret = match.groups()
        decision = await self._d.limiter.hit(POLICIES["api.principal"], f"key:{key_id}")
        if not decision.allowed:
            raise RateLimited(decision.retry_after_s)
        now = self._d.clock.now()
        async with self._d.database.session(read_only=True) as session:
            row = (
                await session.execute(
                    text("SELECT * FROM argus_authenticate_api_key(:key_id, :hash)"),
                    {"key_id": key_id, "hash": self._hash(secret)},
                )
            ).one_or_none()
            owner = (
                await session.get(User, row.owner_user_id)
                if row is not None and row.owner_user_id is not None
                else None
            )
        if (
            row is None
            or row.revoked_at is not None
            or (row.expires_at is not None and row.expires_at <= now)
            or row.org_status != "active"
            or (row.owner_user_id is not None and (owner is None or owner.status != "active"))
            or (row.service_account_id is not None and row.sa_disabled_at is not None)
        ):
            # A real key that is revoked, expired or disabled is still in use somewhere: that
            # is the owning organisation's security signal. Unknown keys and wrong secrets
            # belong to no tenant (anyone can send them) and go to the platform chain.
            await self._d.audit.record_detached(
                AuditEvent(
                    action="api_key.authentication_failed",
                    category=AuditCategory.AUTHENTICATION,
                    actor=Actor.anonymous(),
                    outcome=AuditOutcome.FAILURE,
                    organization_id=row.organization_id if row is not None else None,
                    target_type="api_key" if row is not None else None,
                    target_id=str(row.id) if row is not None else None,
                    client=client,
                    details={"key_fingerprint": sha256(key_id).hex()[:16]},
                )
            )
            raise invalid
        if row.last_used_at is None or now - row.last_used_at > _TOUCH_INTERVAL:
            scope = TenantScope(
                row.organization_id, Actor(ActorType.API_KEY, row.id, row.owner_user_id)
            )
            async with self._d.database.tenant(scope) as session:
                await session.execute(
                    update(ApiKey).where(ApiKey.id == row.id).values(last_used_at=now)
                )
        return key_principal(
            key_id=row.id,
            organization_id=row.organization_id,
            owner_user_id=row.owner_user_id,
            service_account_id=row.service_account_id,
            scopes=row.scopes,
        )


def key_principal(
    *,
    key_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID | None,
    service_account_id: UUID | None,
    scopes: Iterable[str],
) -> Principal:
    """The principal an API key acts as: its owner (user or service account), bound to one
    organisation and limited to the key's scopes. Used for requests *and* for background work
    started with the key, so a job can never do more than the key that created it."""
    return Principal(
        actor=Actor(ActorType.API_KEY, key_id, owner_user_id),
        user_id=owner_user_id,
        api_key_id=key_id,
        service_account_id=service_account_id,
        key_organization_id=organization_id,
        scopes=frozenset(
            Permission(scope) for scope in scopes if scope in Permission._value2member_map_
        ),
    )


def _row_dict(row: ApiKey) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "scopes": list(row.scopes),
        "service_account_id": row.service_account_id,
        "owner_user_id": row.owner_user_id,
        "created_at": row.created_at,
        "expires_at": row.expires_at,
        "last_used_at": row.last_used_at,
        "revoked_at": row.revoked_at,
    }
