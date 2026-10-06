"""Liveness and readiness probes.

* ``/health/live`` - the process is up. No dependencies, so a database outage never makes the
  orchestrator restart healthy API pods in a loop.
* ``/health/ready`` - dependencies reachable and the schema is at the expected migration head;
  failing readiness only removes the instance from load balancing.

Responses name components and states only - never host names, versions or error messages.
"""

from __future__ import annotations

import asyncio
import time
from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import text

from argus.apps.api.deps import get_container
from argus.apps.container import Container
from argus.core.logging import get_logger
from argus.infrastructure.db.migrations import schema_state

router = APIRouter(tags=["health"])
log = get_logger(__name__)

CheckState = Literal["ok", "fail", "pending", "disabled"]


class LiveResponse(BaseModel):
    status: Literal["ok"] = "ok"


class ReadyResponse(BaseModel):
    status: Literal["ready", "not_ready"]
    checks: dict[str, CheckState]


@router.get("/health/live", response_model=LiveResponse)
async def live() -> LiveResponse:
    return LiveResponse()


async def _check_database(container: Container) -> tuple[CheckState, CheckState]:
    started = time.perf_counter()
    try:
        async with asyncio.timeout(2.0), container.database.engine.connect() as conn:
            current = (await conn.execute(text("SELECT version_num FROM alembic_version"))).scalar()
    except Exception as exc:  # noqa: BLE001 - any failure means "not ready"; details go to logs
        log.warning("health.database_unavailable", error_type=type(exc).__name__)
        return "fail", "fail"
    finally:
        container.metrics.db_latency.labels("ping").observe(time.perf_counter() - started)
    return "ok", "ok" if schema_state(current) == "ok" else "pending"


async def _check_redis(container: Container) -> CheckState:
    if container.redis is None:
        return "disabled"
    try:
        async with asyncio.timeout(1.0):
            await container.redis.ping()
    except Exception as exc:  # noqa: BLE001
        log.warning("health.redis_unavailable", error_type=type(exc).__name__)
        return "fail"
    return "ok"


async def readiness_checks(container: Container) -> dict[str, CheckState]:
    (database, migrations), redis = await asyncio.gather(
        _check_database(container), _check_redis(container)
    )
    return {"database": database, "migrations": migrations, "redis": redis}


@router.get(
    "/health/ready",
    response_model=ReadyResponse,
    responses={503: {"model": ReadyResponse}},
)
async def ready(container: Annotated[Container, Depends(get_container)]) -> JSONResponse:
    checks = await readiness_checks(container)
    ok = all(state in {"ok", "disabled"} for state in checks.values())
    body = ReadyResponse(status="ready" if ok else "not_ready", checks=checks)
    return JSONResponse(body.model_dump(), status_code=200 if ok else 503)
