"""Helpers shared by tests (importable as ``tests.support``)."""

from __future__ import annotations

import base64
import json
import secrets
import tempfile
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from asgi_lifespan import LifespanManager
from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from sqlalchemy.engine import make_url

from argus.apps.api.main import create_app
from argus.apps.container import Container, build_container
from argus.core.config import Settings
from argus.infrastructure.email import MemoryMailer
from argus.infrastructure.observability.tracing import configure_tracing
from argus.security.passwords import fast_test_hasher
from argus.security.ratelimit import MemoryRateLimiter

TEST_OWNER_ROLE = "argus_test_owner"
TEST_APP_ROLE = "argus_test_app"
TEST_ROLE_PASSWORD = "argus-test-only-password"  # roles exist only in throwaway test clusters

# Deterministic, test-only key material (valid nowhere else).
TEST_JWT_KID = "test-kid"
TEST_JWT_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIKu0B9Wm0eZ2bm6E0nH8C0yo5d7l1ZQ3k6bUj0YfJx3T\n"
    "-----END PRIVATE KEY-----\n"
)
TEST_B64_32 = base64.b64encode(b"test-key-material-32-bytes-long!").decode()
TEST_ENC_KEYS = json.dumps({"t1": TEST_B64_32})


def make_settings(**overrides: Any) -> Settings:
    """Testing settings with deterministic secrets; nested sections are merged, not replaced."""
    base: dict[str, Any] = {
        "environment": "testing",
        "database": {"tls_mode": "disable", "pool_size": 5, "max_overflow": 5},
        "auth": {
            "jwt_signing_keys": json.dumps({TEST_JWT_KID: TEST_JWT_PEM}),
            "jwt_active_kid": TEST_JWT_KID,
            "api_key_pepper": TEST_B64_32,
        },
        "security": {
            "encryption_keys": TEST_ENC_KEYS,
            "active_encryption_key": "t1",
            "audit_hmac_key": TEST_B64_32,
            "signing_key": TEST_B64_32,
        },
        "email": {"backend": "memory"},
        "observability": {"log_format": "console", "log_level": "WARNING"},
        # Never the repository's var/ directory; document tests pass their own tmp_path store.
        "storage": {"local_root": str(Path(tempfile.gettempdir()) / "argus-test-storage")},
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = {**base[key], **value}
        else:
            base[key] = value
    return Settings(_env_file=None, **base)


class MutableClock:
    """A clock the test moves explicitly (expiry, lockout, rotation scenarios)."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime.now(UTC)
        self._mono = 1_000.0

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return self._mono

    def advance(self, seconds: float) -> None:
        self._now += timedelta(seconds=seconds)
        self._mono += seconds


@dataclass
class ApiHarness:
    client: httpx.AsyncClient
    container: Container
    mailer: MemoryMailer
    clock: MutableClock
    app: FastAPI | None = None


@asynccontextmanager
async def api_harness(settings: Settings, **overrides: Any) -> AsyncIterator[ApiHarness]:
    """A fully wired app with test doubles for e-mail, password hashing, clock and limits."""
    mailer = overrides.pop("mailer", MemoryMailer())
    clock = overrides.pop("clock", MutableClock())
    container = build_container(
        settings,
        role="api",
        mailer=mailer,
        clock=clock,
        hasher=overrides.pop("hasher", fast_test_hasher()),
        limiter=overrides.pop("limiter", MemoryRateLimiter()),
        **overrides,
    )
    app = create_app(settings, container=container)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    try:
        async with (
            LifespanManager(app),
            httpx.AsyncClient(transport=transport, base_url="http://testserver") as client,
        ):
            yield ApiHarness(client, container, mailer, clock, app)
    finally:
        await container.aclose()


class SpanSink(SpanExporter):
    """Collects finished spans while a test listens (the provider is process-wide)."""

    def __init__(self) -> None:
        self.spans: list[ReadableSpan] = []
        self.listening = False

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        if self.listening:
            self.spans.extend(spans)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        self.listening = False

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        del timeout_millis
        return True

    def finished(self) -> list[ReadableSpan]:
        flush = getattr(trace.get_tracer_provider(), "force_flush", None)
        if callable(flush):
            flush()
        return list(self.spans)


SPANS = SpanSink()


def capture_spans() -> SpanSink:
    """Install the test tracer provider once (through the production code path) and listen."""
    configure_tracing(
        make_settings(observability={"otel_sample_ratio": 1.0}).observability,
        service="argus-test",
        version="test",
        environment="testing",
        exporter=SPANS,
    )
    SPANS.finished()
    SPANS.spans.clear()
    SPANS.listening = True
    return SPANS


def unique_email(prefix: str = "user") -> str:
    return f"{prefix}.{secrets.token_hex(6)}@example.com"


STRONG_PASSWORD = "correct-Horse-battery-42"


def token_from_email(text: str) -> str:
    marker = "#token="
    start = text.index(marker) + len(marker)
    end = start
    while end < len(text) and (text[end].isalnum() or text[end] in "_-"):
        end += 1
    return text[start:end]


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def register_verified(h: ApiHarness, email: str | None = None) -> str:
    """Register and verify the e-mail address (no login yet)."""
    email = email or unique_email()
    response = await h.client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": STRONG_PASSWORD, "full_name": "Test User"},
    )
    assert response.status_code == 202, response.text
    token = token_from_email(h.mailer.last_to(email).text)
    verified = await h.client.post("/api/v1/auth/email/verify", json={"token": token})
    assert verified.status_code == 204, verified.text
    return email


async def register_and_login(h: ApiHarness, email: str | None = None) -> tuple[str, dict[str, Any]]:
    """Register, verify the e-mail and log in; returns (email, token response)."""
    email = await register_verified(h, email)
    login = await h.client.post(
        "/api/v1/auth/login", json={"email": email, "password": STRONG_PASSWORD}
    )
    assert login.status_code == 200, login.text
    return email, login.json()


async def create_org(h: ApiHarness, token: str, name: str = "Acme Research") -> dict[str, Any]:
    response = await h.client.post("/api/v1/orgs", json={"name": name}, headers=bearer(token))
    assert response.status_code == 201, response.text
    return dict(response.json())


async def create_project(
    h: ApiHarness, token: str, org_id: str, name: str = "Market"
) -> dict[str, Any]:
    response = await h.client.post(
        f"/api/v1/orgs/{org_id}/projects", json={"name": name}, headers=bearer(token)
    )
    assert response.status_code == 201, response.text
    return dict(response.json())


async def join_org(h: ApiHarness, owner_token: str, org_id: str, role: str) -> tuple[str, str]:
    """Invite a fresh user with ``role`` and have them accept; returns (email, access token)."""
    email = unique_email(role)
    invite = await h.client.post(
        f"/api/v1/orgs/{org_id}/invitations",
        json={"email": email, "role": role},
        headers=bearer(owner_token),
    )
    assert invite.status_code == 201, invite.text
    invitation_token = token_from_email(h.mailer.last_to(email).text)
    _, tokens = await register_and_login(h, email)
    accepted = await h.client.post(
        "/api/v1/invitations/accept",
        json={"token": invitation_token},
        headers=bearer(tokens["access_token"]),
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["role"] == role
    return email, tokens["access_token"]


@dataclass(frozen=True)
class DatabaseURLs:
    admin: str
    owner: str
    app: str
    name: str


def with_credentials(
    url: str, *, user: str, password: str | None, database: str, driver: str
) -> str:
    parsed = make_url(url).set(
        drivername=driver, username=user, password=password, database=database
    )
    return parsed.render_as_string(hide_password=False)
