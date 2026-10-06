"""Prometheus scrape endpoint, protected by a bearer token outside development.

Metrics reveal traffic shapes, error rates and internal names; they are not public data.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST

from argus.apps.api.deps import get_container
from argus.apps.container import Container
from argus.core.crypto import constant_time_equals
from argus.core.errors import AuthenticationRequired, NotFound

router = APIRouter(tags=["operations"], include_in_schema=False)


@router.get("/metrics")
async def metrics(
    request: Request, container: Annotated[Container, Depends(get_container)]
) -> Response:
    settings = container.settings.observability
    if not settings.metrics_enabled:
        raise NotFound
    if settings.metrics_token is not None:
        supplied = request.headers.get("authorization", "")
        expected = f"Bearer {settings.metrics_token.get_secret_value()}"
        if not constant_time_equals(supplied, expected):
            raise AuthenticationRequired
    return Response(container.metrics.render(), media_type=CONTENT_TYPE_LATEST)
