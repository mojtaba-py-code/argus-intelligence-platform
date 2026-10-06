"""Public verification keys (JWKS) for services that validate Argus access tokens."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from argus.apps.api.security import ContainerDep

router = APIRouter(tags=["auth"])


@router.get("/.well-known/jwks.json")
async def jwks(container: ContainerDep) -> JSONResponse:
    return JSONResponse(container.tokens.jwks(), headers={"Cache-Control": "public, max-age=300"})
