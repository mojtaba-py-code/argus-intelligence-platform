"""Phase 1 acceptance: the HTTP skeleton is secure by default."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from ipaddress import ip_network
from typing import Annotated

import httpx
import pytest
from asgi_lifespan import LifespanManager
from fastapi import APIRouter, FastAPI, Query, Request
from pydantic import BaseModel, ConfigDict

from argus.apps.api.deps import reject_unknown_query_parameters
from argus.apps.api.main import create_app
from argus.apps.api.middleware import resolve_client
from argus.apps.container import build_container
from argus.core.config import Settings
from tests.support import make_settings


class _Secretive(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str
    password: str
    age: int


def _test_router() -> APIRouter:
    from fastapi import Depends

    router = APIRouter(prefix="/__test", dependencies=[Depends(reject_unknown_query_parameters)])

    @router.post("/echo")
    async def echo(request: Request) -> dict[str, int]:
        return {"received": len(await request.body())}

    @router.post("/model")
    async def model(payload: _Secretive) -> dict[str, str]:
        return {"email": payload.email}

    @router.get("/slow")
    async def slow() -> dict[str, str]:
        await asyncio.sleep(5)
        return {"status": "late"}

    @router.get("/crash")
    async def crash() -> None:
        msg = "boom: postgresql://argus:hunter2@db/argus at C:\\secret\\path.py"
        raise RuntimeError(msg)

    @router.get("/items")
    async def items(limit: Annotated[int, Query(ge=1, le=10)] = 5) -> dict[str, int]:
        return {"limit": limit}

    return router


async def _client(settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    container = build_container(settings, role="api")
    app: FastAPI = create_app(settings, container=container)
    app.include_router(_test_router())
    # raise_app_exceptions=False: Starlette re-raises after sending the 500 so the *server* can
    # log it; the client must still observe the sanitised response.
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with (
        LifespanManager(app),
        httpx.AsyncClient(transport=transport, base_url="http://testserver") as client,
    ):
        yield client
    await container.aclose()


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    settings = make_settings(
        http={
            "request_timeout_s": 0.3,
            "max_body_bytes": 2048,
            "cors_origins": ["https://app.example.com"],
        },
        observability={"metrics_token": "scrape-me"},
    )
    async for c in _client(settings):
        yield c


async def test_liveness_and_security_headers(client: httpx.AsyncClient) -> None:
    response = await client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    headers = response.headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert "default-src 'none'" in headers["content-security-policy"]
    assert headers["cache-control"] == "no-store"
    assert "server" not in headers
    assert len(headers["x-request-id"]) >= 8


async def test_request_id_is_echoed_only_when_well_formed(client: httpx.AsyncClient) -> None:
    good = await client.get("/health/live", headers={"X-Request-ID": "trace-1234567"})
    assert good.headers["x-request-id"] == "trace-1234567"
    evil = await client.get("/health/live", headers={"X-Request-ID": "bad id\nInjected: yes"})
    assert evil.headers["x-request-id"] != "bad id\nInjected: yes"
    assert "\n" not in evil.headers["x-request-id"]


async def test_unknown_route_is_a_problem_document(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/nope")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert body["code"] == "not_found"
    assert body["status"] == 404
    assert body["type"] == "urn:argus:problem:not_found"
    assert body["request_id"] == response.headers["x-request-id"]


async def test_method_not_allowed_lists_allowed_methods(client: httpx.AsyncClient) -> None:
    response = await client.delete("/health/live")
    assert response.status_code == 405
    assert "GET" in response.headers["allow"]
    assert response.json()["code"] == "method_not_allowed"


@pytest.mark.parametrize("param", ["access_token", "api_key", "token", "PASSWORD"])
async def test_credentials_in_url_are_rejected(client: httpx.AsyncClient, param: str) -> None:
    response = await client.get(f"/health/live?{param}=secret-value")
    assert response.status_code == 400
    body = response.json()
    assert body["code"] == "credentials_in_url"
    assert "secret-value" not in response.text


async def test_disallowed_host_header(client: httpx.AsyncClient) -> None:
    response = await client.get("/health/live", headers={"Host": "evil.example.com"})
    assert response.status_code == 400
    assert response.json()["code"] == "invalid_host"


async def test_declared_oversized_body_is_rejected_before_reading(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post("/__test/echo", content=b"x" * 4096)
    assert response.status_code == 413
    assert response.json()["code"] == "payload_too_large"


async def test_chunked_oversized_body_is_rejected_while_streaming(
    client: httpx.AsyncClient,
) -> None:
    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(10):
            yield b"y" * 512

    response = await client.post("/__test/echo", content=chunks())
    assert response.status_code == 413


async def test_small_body_passes(client: httpx.AsyncClient) -> None:
    response = await client.post("/__test/echo", content=b"x" * 100)
    assert response.status_code == 200
    assert response.json() == {"received": 100}


async def test_slow_request_times_out_with_504(client: httpx.AsyncClient) -> None:
    response = await client.get("/__test/slow")
    assert response.status_code == 504
    assert response.json()["code"] == "timeout"


async def test_unhandled_errors_never_leak_internals(client: httpx.AsyncClient) -> None:
    response = await client.get("/__test/crash")
    assert response.status_code == 500
    text = response.text
    assert "hunter2" not in text
    assert "boom" not in text
    assert "secret" not in text
    assert "Traceback" not in text
    assert response.json()["code"] == "internal_error"


async def test_validation_errors_do_not_echo_input(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/__test/model",
        json={
            "email": "a@example.com",
            "password": "Sup3r-Secret-Pa55",
            "age": "not-a-number",
            "x": 1,
        },
    )
    assert response.status_code == 422
    assert "Sup3r-Secret-Pa55" not in response.text
    assert "not-a-number" not in response.text
    errors = response.json()["errors"]
    assert {tuple(e["loc"]) for e in errors} >= {("body", "age"), ("body", "x")}


async def test_unknown_query_parameters_are_rejected(client: httpx.AsyncClient) -> None:
    ok = await client.get("/__test/items?limit=3")
    assert ok.status_code == 200
    typo = await client.get("/__test/items?limt=3")
    assert typo.status_code == 422
    assert "limt" in typo.json()["detail"]


async def test_cors_only_for_configured_origins(client: httpx.AsyncClient) -> None:
    allowed = await client.options(
        "/health/live",
        headers={"Origin": "https://app.example.com", "Access-Control-Request-Method": "GET"},
    )
    assert allowed.headers.get("access-control-allow-origin") == "https://app.example.com"
    denied = await client.options(
        "/health/live",
        headers={"Origin": "https://evil.example.com", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in denied.headers


async def test_metrics_require_the_scrape_token(client: httpx.AsyncClient) -> None:
    await client.get("/health/live")
    assert (await client.get("/metrics")).status_code == 401
    wrong = await client.get("/metrics", headers={"Authorization": "Bearer wrong"})
    assert wrong.status_code == 401
    ok = await client.get("/metrics", headers={"Authorization": "Bearer scrape-me"})
    assert ok.status_code == 200
    assert "argus_http_requests_total" in ok.text
    assert 'route="/health/live"' in ok.text


async def test_readiness_reports_unavailable_database_without_details() -> None:
    settings = make_settings(
        database={"url": "postgresql+asyncpg://argus_app:pw@127.0.0.1:9/argus"}  # discard port
    )
    async for client in _client(settings):
        response = await client.get("/health/ready")
        assert response.status_code == 503
        assert response.json() == {
            "status": "not_ready",
            "checks": {"database": "fail", "migrations": "fail", "redis": "disabled"},
        }
        assert "127.0.0.1" not in response.text


async def test_docs_hidden_when_disabled() -> None:
    settings = make_settings(http={"expose_docs": False})
    async for client in _client(settings):
        assert (await client.get("/docs")).status_code == 404
        assert (await client.get("/openapi.json")).status_code == 404


# ------------------------------------------------------------------- client IP resolution
TRUSTED = (ip_network("10.0.0.0/8"),)


def test_forwarded_headers_ignored_from_untrusted_peers() -> None:
    assert resolve_client("203.0.113.5", "1.2.3.4", "https", TRUSTED, "http") == (
        "203.0.113.5",
        "http",
    )


def test_first_untrusted_hop_from_the_right_is_the_client() -> None:
    client, scheme = resolve_client(
        "10.0.0.2", "198.51.100.7, 203.0.113.9, 10.0.0.5", "https", TRUSTED, "http"
    )
    assert client == "203.0.113.9"  # 198.51.100.7 was client-supplied and cannot be trusted
    assert scheme == "https"


def test_malformed_chain_stops_the_walk() -> None:
    client, _ = resolve_client("10.0.0.2", "garbage, 10.0.0.9", None, TRUSTED, "http")
    assert client == "10.0.0.9"


def test_middleware_order_is_fixed(settings: Settings) -> None:
    """Outermost first: tracing must see every request (rejected hosts and oversized bodies
    too), the request id must exist before anything logs, and limits apply before routing."""
    app = create_app(settings)  # the container is built by the lifespan, which is not started
    assert [getattr(m.cls, "__name__", "?") for m in app.user_middleware] == [
        "TracingMiddleware",
        "RequestContextMiddleware",
        "SecurityHeadersMiddleware",
        "TimeoutMiddleware",
        "BodySizeLimitMiddleware",
        "CORSMiddleware",
    ]


def test_readiness_follows_the_schema_during_rolling_updates() -> None:
    """At or ahead of this build's head: ready (a newer release migrated; migrations stay
    backward compatible for one release, so old pods keep serving during the rollout). Behind:
    not ready (this build needs a migration that has not run)."""
    from argus.infrastructure.db.migrations import head_revision, known_revisions, schema_state

    head = head_revision()
    assert head is not None
    assert schema_state(head) == "ok"
    assert schema_state("9999_from_a_newer_release") == "ok"
    older = sorted(known_revisions() - {head})
    assert older
    assert all(schema_state(revision) == "pending" for revision in older)
    assert schema_state(None) == "pending"


UNDOCUMENTED: frozenset[tuple[str, str]] = frozenset(
    {
        # Interactive API docs (development only: production refuses ARGUS_HTTP__EXPOSE_DOCS).
        ("GET", "/openapi.json"),
        ("HEAD", "/openapi.json"),
        ("GET", "/docs"),
        ("HEAD", "/docs"),
        ("GET", "/docs/oauth2-redirect"),
        ("HEAD", "/docs/oauth2-redirect"),
        # Prometheus scrape endpoint, guarded by its own token.
        ("GET", "/metrics"),
        # The web dashboard's static files (argus.apps.web), and / pointing at it.
        ("GET", "/"),
        ("GET", "/app"),
        ("GET", "/app/"),
        ("GET", "/app/{name}"),
    }
)
"""Routes the OpenAPI document does not describe - so the OpenAPI-driven security suite does not
probe them. Reviewed: adding one is a security decision, like ``PUBLIC`` in that suite."""


def test_every_route_outside_the_openapi_document_is_reviewed(settings: Settings) -> None:
    from fastapi.routing import iter_route_contexts

    app = create_app(settings, container=build_container(settings, role="api"))
    documented = {
        (method.upper(), path)
        for path, methods in app.openapi()["paths"].items()
        for method in methods
    }
    served = {
        (method, context.path)
        for context in iter_route_contexts(app.routes)
        for method in context.methods or ()
        if context.path is not None
    }
    assert documented <= served
    assert served - documented == UNDOCUMENTED
