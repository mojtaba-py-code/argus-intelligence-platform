"""Dynamic security tests over the whole API surface (phase 19, spec §46).

The operation list comes from the application's own OpenAPI document, so a route added later is
covered automatically - and a new route that forgets authentication or tenant checks fails here
before it ships. Four sweeps:

1. **Authentication**: every operation outside a short, reviewed public list answers 401 (with a
   ``WWW-Authenticate`` challenge) when no credentials are sent.
2. **Tenant isolation**: another organisation's owner - and that organisation's API key - get 404
   for every organisation-scoped operation, read or write, with the victim's real identifiers.
3. **Malformed input**: hostile path segments, query values and JSON bodies never produce a
   server error, and are rejected before reaching the database.
4. **Error hygiene**: every error is an RFC 9457 problem document without internals (stack
   traces, SQL, driver or file names), and carries the security headers.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import httpx
import pytest

from argus.core.config import Settings
from tests.support import (
    ApiHarness,
    api_harness,
    bearer,
    create_org,
    create_project,
    register_and_login,
)

pytestmark = pytest.mark.integration

PUBLIC: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/health/live"),
        ("GET", "/health/ready"),
        ("GET", "/.well-known/jwks.json"),
        ("POST", "/api/v1/auth/register"),
        ("POST", "/api/v1/auth/email/verify"),
        ("POST", "/api/v1/auth/email/resend"),
        ("POST", "/api/v1/auth/login"),
        ("POST", "/api/v1/auth/mfa/verify"),
        ("POST", "/api/v1/auth/refresh"),
        ("POST", "/api/v1/auth/password/forgot"),
        ("POST", "/api/v1/auth/password/reset"),
        # Authorised by the signed, expiring token in the path (not by a session).
        ("GET", "/api/v1/downloads/{token}"),
    }
)
"""Reviewed list of operations that do not take a bearer credential. Changing it is a security
decision: add an entry only with a reason next to it."""

LEAKS = re.compile(
    r"traceback|sqlalchemy|asyncpg|psycopg|pydantic_core|site-packages|"
    r"\bselect\s.+\bfrom\b|\binsert\s+into\b|syntax error|stack trace|"
    r"[a-z]:\\\\|/usr/lib/|\.py\b",
    re.IGNORECASE,
)
HOSTILE_SEGMENTS = (
    "not-a-uuid",
    "00000000-0000-0000-0000-00000000000g",
    "1 OR 1=1",
    "' OR '1'='1",
    "%27%3B%20DROP%20TABLE%20users%3B--",
    "..%2F..%2Fetc%2Fpasswd",
    "%00",
    "a" * 300,
    "{{7*7}}",
    "<script>alert(1)</script>",
)
HOSTILE_QUERIES = (
    {"limit": "-1"},
    {"limit": "100000000000000000000"},
    {"limit": "1e3"},
    {"cursor": "'; DROP TABLE users;--"},
    {"cursor": "A" * 5000},
    {"days": "NaN"},
    {"unknown_parameter": "1"},
)
HOSTILE_BODIES: tuple[Any, ...] = (
    [],
    "a string",
    12345,
    None,
    {"__proto__": {"is_admin": True}},
    {"name": 123, "role": ["owner"], "scopes": "all"},
    {"name": "x" * 100_000},
    {"nested": {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {}}}}}}}}}},
)


@dataclass(frozen=True)
class Operation:
    method: str
    path: str
    path_params: tuple[str, ...]
    query_params: tuple[str, ...]
    has_body: bool

    @property
    def org_scoped(self) -> bool:
        return self.path.startswith("/api/v1/orgs/{org_id}")


@dataclass
class Tenants:
    victim_token: str
    victim_org: str
    victim_project: str
    attacker_token: str
    attacker_org: str
    attacker_key: str


def operations(h: ApiHarness) -> list[Operation]:
    assert h.app is not None
    spec = h.app.openapi()
    found: list[Operation] = []
    for path, methods in spec["paths"].items():
        for method, operation in methods.items():
            params = operation.get("parameters", [])
            found.append(
                Operation(
                    method=method.upper(),
                    path=path,
                    path_params=tuple(p["name"] for p in params if p["in"] == "path"),
                    query_params=tuple(p["name"] for p in params if p["in"] == "query"),
                    has_body="requestBody" in operation,
                )
            )
    return found


def fill(operation: Operation, values: dict[str, str]) -> str:
    path = operation.path
    for name in operation.path_params:
        path = path.replace("{" + name + "}", values.get(name, str(uuid.uuid4())))
    return path


def assert_clean_error(response: httpx.Response, context: str) -> None:
    assert response.status_code < 500, f"{context}: {response.status_code} {response.text[:300]}"
    if response.status_code >= 400:
        assert response.headers["content-type"].startswith("application/problem+json"), context
        assert not LEAKS.search(response.text), f"{context}: leaks internals: {response.text[:300]}"
        problem = response.json()
        assert {"type", "title", "status", "code"} <= set(problem), context
        assert problem["status"] == response.status_code, context
    assert response.headers.get("x-content-type-options") == "nosniff", context


async def send(
    h: ApiHarness,
    operation: Operation,
    url: str,
    *,
    token: str | None = None,
    params: dict[str, str] | None = None,
    body: Any = ...,
) -> httpx.Response:
    headers = bearer(token) if token else {}
    kwargs: dict[str, Any] = {"headers": headers, "params": params}
    if body is not ...:
        kwargs["json"] = body
    return await h.client.request(operation.method, url, **kwargs)


@pytest.fixture
async def h(db_settings: Settings) -> AsyncIterator[ApiHarness]:
    async with api_harness(db_settings) as harness:
        yield harness


@pytest.fixture
async def tenants(h: ApiHarness) -> Tenants:
    _, victim = await register_and_login(h)
    victim_token = victim["access_token"]
    victim_org = (await create_org(h, victim_token, "Victim Corp"))["id"]
    victim_project = (await create_project(h, victim_token, victim_org))["id"]
    _, attacker = await register_and_login(h)
    attacker_token = attacker["access_token"]
    attacker_org = (await create_org(h, attacker_token, "Attacker Corp"))["id"]
    key = await h.client.post(
        f"/api/v1/orgs/{attacker_org}/api-keys",
        json={"name": "attacker automation", "scopes": sorted(_key_scopes())},
        headers=bearer(attacker_token),
    )
    assert key.status_code == 201, key.text
    return Tenants(
        victim_token=victim_token,
        victim_org=str(victim_org),
        victim_project=str(victim_project),
        attacker_token=attacker_token,
        attacker_org=str(attacker_org),
        attacker_key=key.json()["key"],
    )


def _key_scopes() -> set[str]:
    from argus.security.permissions import API_KEY_SCOPES

    return {scope.value for scope in API_KEY_SCOPES}


# ---------------------------------------------------------------------------- the sweeps
async def test_the_operation_inventory_is_complete(h: ApiHarness) -> None:
    ops = operations(h)
    assert len(ops) >= 90
    public = {(op.method, op.path) for op in ops} & PUBLIC
    assert public == PUBLIC, f"stale public entries: {sorted(PUBLIC - public)}"


async def test_every_non_public_operation_requires_authentication(h: ApiHarness) -> None:
    checked = 0
    for operation in operations(h):
        if (operation.method, operation.path) in PUBLIC:
            continue
        url = fill(operation, {})
        response = await send(h, operation, url)
        context = f"{operation.method} {operation.path}"
        assert response.status_code == 401, f"{context}: {response.status_code}"
        assert response.headers.get("www-authenticate", "").startswith("Bearer"), context
        assert_clean_error(response, context)
        # A malformed credential is the same 401, never a 500 or a hint.
        forged = await send(h, operation, url, token="argus_sk_" + "A" * 40)
        assert forged.status_code == 401, f"{context} (forged key): {forged.status_code}"
        checked += 1
    assert checked >= 80


async def test_no_operation_crosses_the_tenant_boundary(h: ApiHarness, tenants: Tenants) -> None:
    values = {"org_id": tenants.victim_org, "project_id": tenants.victim_project}
    checked = 0
    for operation in operations(h):
        if not operation.org_scoped:
            continue
        url = fill(operation, values)
        for label, token in (
            ("attacker owner", tenants.attacker_token),
            ("attacker API key", tenants.attacker_key),
        ):
            response = await send(h, operation, url, token=token, body={})
            context = f"{label}: {operation.method} {operation.path}"
            assert response.status_code == 404, f"{context}: {response.status_code}"
            assert_clean_error(response, context)
        checked += 1
    assert checked >= 60

    # The victim's data is untouched and nothing was written into its audit log.
    victim_log = await h.client.get(
        f"/api/v1/orgs/{tenants.victim_org}/audit-logs",
        params={"limit": 200},
        headers=bearer(tenants.victim_token),
    )
    assert victim_log.status_code == 200
    assert all(entry["action"] != "access.denied" for entry in victim_log.json()["items"])


async def test_hostile_path_segments_never_reach_the_database(
    h: ApiHarness, tenants: Tenants
) -> None:
    base = {"org_id": tenants.victim_org, "project_id": tenants.victim_project}
    checked = 0
    for operation in operations(h):
        if not operation.org_scoped or operation.method != "GET" or not operation.path_params:
            continue
        checked += 1
        for name in operation.path_params:
            for segment in HOSTILE_SEGMENTS:
                url = fill(operation, {**base, name: segment})
                response = await send(h, operation, url, token=tenants.victim_token)
                context = f"GET {operation.path} [{name}={segment[:20]!r}]"
                assert response.status_code in {400, 404, 405, 422}, (
                    f"{context}: {response.status_code}"
                )
                assert_clean_error(response, context)
    assert checked >= 25


async def test_hostile_query_values_are_rejected_cleanly(h: ApiHarness, tenants: Tenants) -> None:
    values = {"org_id": tenants.victim_org, "project_id": tenants.victim_project}
    checked = 0
    for operation in operations(h):
        if not operation.org_scoped or operation.method != "GET" or not operation.query_params:
            continue
        url = fill(operation, values)
        for params in HOSTILE_QUERIES:
            name = next(iter(params))
            if name not in operation.query_params and name != "unknown_parameter":
                continue
            response = await send(h, operation, url, token=tenants.victim_token, params=params)
            context = f"GET {operation.path} {params!r:.60}"
            assert response.status_code in {400, 404, 422}, f"{context}: {response.status_code}"
            assert_clean_error(response, context)
            checked += 1
    assert checked >= 20


async def test_hostile_json_bodies_are_rejected_cleanly(h: ApiHarness, tenants: Tenants) -> None:
    """Only operations that declare a JSON body, as the victim's owner (so the request passes
    authorisation and reaches validation). Operations without a body are never sent anything:
    they would act (log out, start a verification) instead of validating."""
    values = {"org_id": tenants.victim_org, "project_id": tenants.victim_project}
    checked = 0
    for operation in operations(h):
        if not operation.org_scoped or not operation.has_body:
            continue
        if operation.path.endswith("/documents") and operation.method == "POST":
            continue  # multipart upload: covered by the document security suite
        url = fill(operation, values)
        for body in HOSTILE_BODIES:
            response = await send(h, operation, url, token=tenants.victim_token, body=body)
            context = f"{operation.method} {operation.path} body={str(body)[:40]!r}"
            assert response.status_code in {400, 404, 409, 413, 415, 422}, (
                f"{context}: {response.status_code} {response.text[:200]}"
            )
            assert_clean_error(response, context)
            checked += 1
        # Not JSON at all.
        raw = await h.client.request(
            operation.method,
            url,
            content=b"{'single': quotes, trailing,}",
            headers={**bearer(tenants.victim_token), "content-type": "application/json"},
        )
        assert raw.status_code in {400, 404, 422}, f"{operation.path}: {raw.status_code}"
        assert_clean_error(raw, f"{operation.method} {operation.path} raw body")
    assert checked >= 100
