"""Who a research job acts for - re-resolved by every stage that reads or adds knowledge.

The rules live in :mod:`argus.modules.tenancy.creators` (shared with monitors): an API key's
scopes, never its owner's full role; a revoked key, a disabled user or a creator who left stops
the job with ``access_revoked`` before it spends anything.
"""

from __future__ import annotations

from argus.modules.research.pipeline import StageContext, StageFailed
from argus.modules.tenancy import creators
from argus.modules.tenancy.authorization import ProjectAccess


async def creator_access(ctx: StageContext) -> ProjectAccess:
    try:
        return await creators.creator_access(
            ctx.services.database,
            ctx.services.authorizer,
            ctx.scope,
            ctx.job.project_id,
            user_id=ctx.job.created_by_user_id,
            api_key_id=ctx.job.created_by_api_key_id,
            now=ctx.services.clock.now(),
        )
    except creators.CreatorRevoked:
        raise StageFailed(
            "access_revoked", "The person or key that started this job no longer has access."
        ) from None
