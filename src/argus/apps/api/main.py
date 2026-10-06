"""FastAPI application factory.

``uvicorn --factory argus.apps.api.main:create_app`` (or ``argus serve``) builds the app from the
environment. Tests call :func:`create_app` with explicit settings and an optional prebuilt
container.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from argus import __version__
from argus.apps.api.access import audit_permission_denied
from argus.apps.api.middleware import (
    BodyLimitRule,
    BodySizeLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
    TimeoutMiddleware,
    TracingMiddleware,
)
from argus.apps.api.problems import install_exception_handlers
from argus.apps.api.routes import health, jwks, metrics
from argus.apps.api.v1 import build_router
from argus.apps.container import Container, build_container
from argus.apps.process import start_observability
from argus.apps.web import router as web
from argus.core.config import Settings, load_settings
from argus.core.logging import get_logger

log = get_logger(__name__)
DOCS_PATHS = ("/docs", "/openapi.json")
UPLOAD_PATH = re.compile(r"/api/v1/orgs/[^/]+/projects/[^/]+/documents")


def create_app(settings: Settings | None = None, *, container: Container | None = None) -> FastAPI:
    settings = settings or (container.settings if container else load_settings())
    provider = start_observability(settings, "api")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        owned = container is None
        app.state.container = container or build_container(settings, role="api")
        log.info("api.started", environment=settings.environment.value, version=__version__)
        try:
            yield
        finally:
            if owned:
                await app.state.container.aclose()
            if provider is not None:
                provider.shutdown()
            log.info("api.stopped")

    expose_docs = settings.http.expose_docs
    app = FastAPI(
        title="Argus API",
        version=__version__,
        summary="Enterprise AI intelligence & research platform",
        lifespan=lifespan,
        docs_url="/docs" if expose_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if expose_docs else None,
        swagger_ui_parameters={"persistAuthorization": False},
        # FastAPI's native OpenTelemetry would trust any incoming traceparent, export validation
        # errors with the submitted values (passwords included) and stack traces as logs, and
        # configure exporters from OTEL_* variables. Argus traces with its own allow-listed
        # middleware instead (argus.apps.api.middleware.TracingMiddleware).
        telemetry={
            "tracing": False,
            "metrics": False,
            "logs": False,
            "operation_spans": False,
            "auto_configure": False,
        },
    )
    install_exception_handlers(app, on_permission_denied=audit_permission_denied)

    app.include_router(health.router)
    app.include_router(metrics.router)
    app.include_router(jwks.router)
    app.include_router(build_router())
    if settings.http.web_dashboard:
        app.include_router(web.build_router())

    # Starlette wraps in reverse order of registration: the last added runs first (outermost).
    type_base = settings.http.problem_type_base
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.http.cors_origins),
        allow_credentials=False,  # bearer tokens, not cookies
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Request-ID"],
        expose_headers=["X-Request-ID", "RateLimit", "RateLimit-Policy", "Retry-After", "Location"],
        max_age=600,
    )
    app.add_middleware(
        BodySizeLimitMiddleware,
        default_limit=settings.http.max_body_bytes,
        rules=[BodyLimitRule("POST", UPLOAD_PATH, settings.http.max_upload_bytes)],
        problem_type_base=type_base,
    )
    app.add_middleware(
        TimeoutMiddleware,
        timeout_s=settings.http.request_timeout_s,
        exempt_prefixes=("/api/v1/stream",),
        problem_type_base=type_base,
    )
    app.add_middleware(
        SecurityHeadersMiddleware,
        hsts=settings.http.hsts or settings.environment.is_production_like,
        docs_paths=DOCS_PATHS if expose_docs else (),
        web_paths=(web.PREFIX,) if settings.http.web_dashboard else (),
    )
    app.add_middleware(
        RequestContextMiddleware,
        allowed_hosts=settings.http.allowed_hosts,
        trusted_proxies=settings.http.trusted_proxies,
        problem_type_base=type_base,
    )
    app.add_middleware(
        TracingMiddleware,
        trust_incoming=settings.observability.trust_incoming_trace_context,
        excluded_paths=("/health/live", "/health/ready", "/metrics"),
    )
    return app
