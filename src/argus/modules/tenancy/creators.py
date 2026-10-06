"""Who background work acts for - re-resolved every time it acts.

Research jobs and monitors run long after a person or an API key created them, so permission
checked at creation is not enough. Before acting, background work re-authorises its creator
*now*, with the same rules as an API request:

* work created with an API key acts with that key's scopes (role ∩ scopes) - never with the
  owner's full role, or a narrowly scoped key could reach data through a job;
* a revoked or expired key, a disabled user, or a creator who has left the organisation (or the
  restricted project) means the work may not act any more.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select

from argus.core.errors import NotFound, PermissionDenied
from argus.core.scope import TenantScope
from argus.infrastructure.db import Database
from argus.modules.identity.models import User
from argus.modules.tenancy.api_keys import key_principal
from argus.modules.tenancy.authorization import Authorizer, ProjectAccess
from argus.modules.tenancy.models import ApiKey
from argus.security.principals import Principal


class CreatorRevoked(Exception):
    """The creator may no longer act in this organisation or project."""


async def creator_principal(
    database: Database,
    scope: TenantScope,
    *,
    user_id: UUID | None,
    api_key_id: UUID | None,
    now: datetime,
) -> Principal:
    key: ApiKey | None = None
    async with database.tenant(scope, read_only=True) as session:
        if api_key_id is not None:
            key = (
                await session.execute(
                    select(ApiKey).where(
                        ApiKey.organization_id == scope.organization_id, ApiKey.id == api_key_id
                    )
                )
            ).scalar_one_or_none()
            if (
                key is None
                or key.revoked_at is not None
                or (key.expires_at is not None and key.expires_at <= now)
            ):
                raise CreatorRevoked
            owner = key.owner_user_id
        else:
            owner = user_id
        if owner is not None:
            status = (
                await session.execute(select(User.status).where(User.id == owner))
            ).scalar_one_or_none()
            if status != "active":
                raise CreatorRevoked
    if key is not None:
        return key_principal(
            key_id=key.id,
            organization_id=key.organization_id,
            owner_user_id=key.owner_user_id,
            service_account_id=key.service_account_id,
            scopes=key.scopes,
        )
    if owner is None:
        raise CreatorRevoked
    return Principal.user(owner)


async def creator_access(
    database: Database,
    authorizer: Authorizer,
    scope: TenantScope,
    project_id: UUID,
    *,
    user_id: UUID | None,
    api_key_id: UUID | None,
    now: datetime,
) -> ProjectAccess:
    principal = await creator_principal(
        database, scope, user_id=user_id, api_key_id=api_key_id, now=now
    )
    try:
        return await authorizer.project(principal, scope.organization_id, project_id)
    except (NotFound, PermissionDenied):
        raise CreatorRevoked from None
