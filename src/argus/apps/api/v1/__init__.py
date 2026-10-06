"""Version 1 of the public API. Routers translate HTTP to service calls and nothing more."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from argus.apps.api.deps import reject_unknown_query_parameters
from argus.apps.api.v1 import (
    auth,
    documents,
    knowledge,
    monitors,
    notifications,
    orgs,
    platform,
    projects,
    research,
    security_center,
    sources,
)


def build_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1", dependencies=[Depends(reject_unknown_query_parameters)])
    router.include_router(auth.router)
    router.include_router(orgs.router)
    router.include_router(projects.router)
    router.include_router(research.router)
    router.include_router(sources.router)
    router.include_router(documents.router)
    router.include_router(knowledge.router)
    router.include_router(monitors.router)
    router.include_router(notifications.router)
    router.include_router(security_center.router)
    router.include_router(platform.router)
    return router
