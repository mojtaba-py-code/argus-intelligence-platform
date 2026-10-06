"""Pure-ASGI middleware (no ``BaseHTTPMiddleware``: it buffers streaming bodies and breaks
cancellation semantics).

Order, outermost first (assembled in :func:`argus.apps.api.main.create_app`):

1. :class:`RequestContextMiddleware` - host allow-list, request id, client IP via trusted proxies,
   credentials-in-URL rejection, access log, HTTP metrics.
2. :class:`SecurityHeadersMiddleware` - response hardening headers.
3. :class:`TimeoutMiddleware` - per-request deadline (504 if no response started in time).
4. :class:`BodySizeLimitMiddleware` - byte caps that also hold for chunked bodies.
5. CORS, then routing.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address
from urllib.parse import parse_qsl

from opentelemetry.context import Context
from opentelemetry.trace import SpanKind, Status, StatusCode
from starlette.datastructures import Headers, MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from argus.apps.api.problems import send_problem
from argus.core import context
from argus.core.ids import uuid7
from argus.core.logging import get_logger
from argus.infrastructure.observability.metrics import Metrics
from argus.infrastructure.observability.tracing import (
    context_from_headers,
    set_attributes,
    span,
)

log = get_logger("argus.http")
# Paths whose last segment is a capability (signed download links): logged redacted.
_CAPABILITY_PATHS = ("/api/v1/downloads/",)


def loggable_path(path: str) -> str:
    for prefix in _CAPABILITY_PATHS:
        if path.startswith(prefix):
            return prefix + "[redacted]"
    return path


_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_CREDENTIAL_PARAMS = frozenset(
    {
        "access_token",
        "refresh_token",
        "id_token",
        "token",
        "api_key",
        "apikey",
        "key",
        "password",
        "secret",
        "jwt",
        "authorization",
        "session",
    }
)
type Network = IPv4Network | IPv6Network


# --------------------------------------------------------------------------------------------
# Client address resolution
# --------------------------------------------------------------------------------------------
def route_template(scope: Scope) -> str | None:
    """The matched route's full path template, e.g. ``/api/v1/orgs/{org_id}/api-keys``.

    FastAPI 0.142 records the route as declared on its own router, without the prefixes of the
    routers that include it. The prefix is recovered by removing the concrete route part (the
    template filled with the matched path parameters) from the request path, so the result is
    still a bounded template - never an id - and safe as a metric label or audit value.
    """
    template = getattr(scope.get("route"), "path", None)
    if not isinstance(template, str) or not template:
        return None
    params = {name: str(value) for name, value in (scope.get("path_params") or {}).items()}
    try:
        concrete = template.format(**params)
    except (KeyError, IndexError, ValueError):
        return template
    path = str(scope.get("path", ""))
    if concrete and path.endswith(concrete):
        return path[: len(path) - len(concrete)] + template
    return template


def _parse_ip(value: str) -> IPv4Address | IPv6Address | None:
    try:
        return ip_address(value.strip().strip("[]"))
    except ValueError:
        return None


def _is_trusted(address: IPv4Address | IPv6Address | None, trusted: Sequence[Network]) -> bool:
    return address is not None and any(address in network for network in trusted)


def resolve_client(
    peer: str | None,
    forwarded_for: str | None,
    forwarded_proto: str | None,
    trusted: Sequence[Network],
    default_scheme: str,
) -> tuple[str, str]:
    """Return ``(client_ip, scheme)``.

    ``X-Forwarded-*`` headers are only believed when the *direct* peer is a trusted proxy; the
    chain is then walked right-to-left and the first untrusted hop is the client. A malformed hop
    stops the walk (never trust a chain we cannot parse).
    """
    peer_ip = _parse_ip(peer) if peer else None
    if not _is_trusted(peer_ip, trusted):
        return (peer or "unknown", default_scheme)
    scheme = default_scheme
    if forwarded_proto:
        candidate = forwarded_proto.split(",")[0].strip().lower()
        if candidate in {"http", "https"}:
            scheme = candidate
    if not forwarded_for:
        return (peer or "unknown", scheme)
    client = peer or "unknown"
    for hop in reversed([h for h in forwarded_for.split(",") if h.strip()]):
        hop_ip = _parse_ip(hop)
        if hop_ip is None:
            break
        client = str(hop_ip)
        if not _is_trusted(hop_ip, trusted):
            break
    return (client, scheme)


def _host_allowed(host_header: str | None, allowed: Iterable[str]) -> bool:
    if not host_header:
        return False
    host = host_header.strip().lower()
    if host.startswith("["):  # IPv6 literal with optional port
        host = host.split("]")[0] + "]"
    elif host.count(":") == 1:
        host = host.split(":")[0]
    for pattern in allowed:
        pattern = pattern.lower()
        if pattern == "*" or host == pattern:
            return True
        if pattern.startswith("*.") and host.endswith(pattern[1:]):
            return True
    return False


class RequestContextMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        allowed_hosts: Sequence[str],
        trusted_proxies: Sequence[Network],
        problem_type_base: str,
    ) -> None:
        self.app = app
        self.allowed_hosts = tuple(allowed_hosts)
        self.trusted = tuple(trusted_proxies)
        self.type_base = problem_type_base

    @staticmethod
    def _metrics(scope: Scope) -> Metrics | None:
        """The container is created in the lifespan, after middleware construction."""
        app = scope.get("app")
        container = getattr(getattr(app, "state", None), "container", None)
        metrics = getattr(container, "metrics", None)
        return metrics if isinstance(metrics, Metrics) else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        inbound_id = headers.get("x-request-id", "")
        request_id = inbound_id if _REQUEST_ID.fullmatch(inbound_id) else uuid7().hex
        client = scope.get("client")
        client_ip, scheme = resolve_client(
            client[0] if client else None,
            headers.get("x-forwarded-for"),
            headers.get("x-forwarded-proto"),
            self.trusted,
            scope.get("scheme", "http"),
        )
        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        state["client_ip"] = client_ip
        state["scheme"] = scheme

        started = time.perf_counter()
        status_code = 500

        async def send_with_id(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                MutableHeaders(scope=message)["X-Request-ID"] = request_id
            await send(message)

        id_header = [(b"x-request-id", request_id.encode())]
        with context.bind(request_id=request_id, client_ip=client_ip):
            try:
                if not _host_allowed(headers.get("host"), self.allowed_hosts):
                    status_code = 400
                    await send_problem(
                        send,
                        status=400,
                        code="invalid_host",
                        title="Bad request",
                        detail="The Host header is not allowed.",
                        type_base=self.type_base,
                        headers=id_header,
                    )
                    return
                query = scope.get("query_string", b"").decode("latin-1")
                if query and any(
                    name.lower() in _CREDENTIAL_PARAMS
                    for name, _ in parse_qsl(query, keep_blank_values=True)
                ):
                    status_code = 400
                    await send_problem(
                        send,
                        status=400,
                        code="credentials_in_url",
                        title="Bad request",
                        detail="Credentials must be sent in the Authorization header, never in the URL.",
                        type_base=self.type_base,
                        headers=id_header,
                    )
                    return
                await self.app(scope, receive, send_with_id)
            finally:
                elapsed = time.perf_counter() - started
                route_label = route_template(scope) or "unmatched"
                method = scope.get("method", "?")
                metrics = self._metrics(scope)
                if metrics is not None:
                    metrics.http_requests.labels(method, route_label, str(status_code)).inc()
                    metrics.http_latency.labels(method, route_label).observe(elapsed)
                log.info(
                    "http.request",
                    method=method,
                    route=route_label,
                    path=loggable_path(scope.get("path", "")),
                    status=status_code,
                    duration_ms=round(elapsed * 1000, 2),
                )


# --------------------------------------------------------------------------------------------
# Tracing
# --------------------------------------------------------------------------------------------
class TracingMiddleware:
    """One server span per request, named ``METHOD /route/{template}`` once routing is known.

    The span records the method, route template, status and request id - never the concrete
    path (it contains ids), the query string (it could contain anything) or headers. A caller's
    ``traceparent`` is continued only when ``trust_incoming`` is set (behind a gateway that sets
    it); otherwise every request starts a new trace.
    """

    def __init__(
        self, app: ASGIApp, *, trust_incoming: bool, excluded_paths: Sequence[str] = ()
    ) -> None:
        self.app = app
        self.trust_incoming = trust_incoming
        self.excluded = frozenset(excluded_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") in self.excluded:
            await self.app(scope, receive, send)
            return
        method = str(scope.get("method", "GET"))
        parent = context_from_headers(Headers(scope=scope)) if self.trust_incoming else None
        status_code = 500

        async def send_with_status(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
            await send(message)

        with span(
            f"HTTP {method}",
            kind=SpanKind.SERVER,
            parent=parent if parent is not None else Context(),
            attributes={"http.request.method": method, "url.scheme": scope.get("scheme")},
        ) as current:
            try:
                await self.app(scope, receive, send_with_status)
            finally:
                route = route_template(scope)
                if route is not None:
                    current.update_name(f"{method} {route}")
                set_attributes(
                    current,
                    {
                        "http.route": route,
                        "http.response.status_code": status_code,
                        "argus.request_id": scope.get("state", {}).get("request_id"),
                    },
                )
                if status_code >= 500:
                    current.set_status(Status(StatusCode.ERROR))


# --------------------------------------------------------------------------------------------
# Security headers
# --------------------------------------------------------------------------------------------
_API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
# The web dashboard: its own same-origin files only, no inline code, API calls to this origin
# only, and Trusted Types - an HTML or script sink (innerHTML, eval...) throws instead of running.
WEB_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; "
    "object-src 'none'; require-trusted-types-for 'script'; trusted-types 'none'"
)
_DOCS_CSP = (
    "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "img-src 'self' data: https://fastapi.tiangolo.com; frame-ancestors 'none'; base-uri 'none'"
)
_STATIC_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    (
        "Permissions-Policy",
        (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), "
            "microphone=(), payment=(), usb=()"
        ),
    ),
)


class SecurityHeadersMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        hsts: bool,
        docs_paths: Sequence[str] = (),
        web_paths: Sequence[str] = (),
    ) -> None:
        self.app = app
        self.hsts = hsts
        self.docs_paths = tuple(docs_paths)
        self.web_paths = tuple(web_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope.get("path", "")
        is_docs = any(path == p or path.startswith(p + "/") for p in self.docs_paths)
        is_web = any(path == p or path.startswith(p + "/") for p in self.web_paths)
        policy = _DOCS_CSP if is_docs else WEB_CSP if is_web else _API_CSP
        https = scope.get("state", {}).get("scheme", scope.get("scheme")) == "https"

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in _STATIC_HEADERS:
                    headers.setdefault(name, value)
                headers.setdefault("Content-Security-Policy", policy)
                if not is_docs:
                    headers.setdefault("Cache-Control", "no-store")
                if self.hsts or https:
                    headers.setdefault(
                        "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
                    )
                if "server" in headers:
                    del headers["server"]
            await send(message)

        await self.app(scope, receive, send_with_headers)


# --------------------------------------------------------------------------------------------
# Timeouts
# --------------------------------------------------------------------------------------------
class TimeoutMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        timeout_s: float,
        exempt_prefixes: Sequence[str] = (),
        problem_type_base: str,
    ) -> None:
        self.app = app
        self.timeout_s = timeout_s
        self.exempt = tuple(exempt_prefixes)
        self.type_base = problem_type_base

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path", "").startswith(self.exempt):
            await self.app(scope, receive, send)
            return
        response_started = False

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            async with asyncio.timeout(self.timeout_s):
                await self.app(scope, receive, tracking_send)
        except TimeoutError:
            if response_started:
                raise
            log.warning("http.request_timeout", timeout_s=self.timeout_s)
            await send_problem(
                send,
                status=504,
                code="timeout",
                title="Timeout",
                detail="The request took too long to complete.",
                type_base=self.type_base,
            )


# --------------------------------------------------------------------------------------------
# Body size limits
# --------------------------------------------------------------------------------------------
class BodyTooLarge(StarletteHTTPException):
    """An ``HTTPException`` so FastAPI's body parsing re-raises it unchanged (it converts other
    exceptions raised while reading the body into a generic 400)."""

    def __init__(self) -> None:
        super().__init__(status_code=413, detail="The request body exceeds the allowed size.")


@dataclass(frozen=True, slots=True)
class BodyLimitRule:
    method: str
    path: re.Pattern[str]
    limit: int


class BodySizeLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        default_limit: int,
        rules: Sequence[BodyLimitRule] = (),
        problem_type_base: str,
    ) -> None:
        self.app = app
        self.default_limit = default_limit
        self.rules = tuple(rules)
        self.type_base = problem_type_base

    def limit_for(self, method: str, path: str) -> int:
        for rule in self.rules:
            if rule.method == method and rule.path.fullmatch(path):
                return rule.limit
        return self.default_limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.limit_for(scope.get("method", "GET"), scope.get("path", ""))
        declared = Headers(scope=scope).get("content-length")
        if declared is not None:
            if not declared.isdigit():
                await send_problem(
                    send,
                    status=400,
                    code="bad_request",
                    title="Bad request",
                    detail="Invalid Content-Length header.",
                    type_base=self.type_base,
                )
                return
            if int(declared) > limit:
                await send_problem(
                    send,
                    status=413,
                    code="payload_too_large",
                    title="Payload too large",
                    detail="The request body exceeds the allowed size.",
                    type_base=self.type_base,
                )
                return
        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise BodyTooLarge
            return message

        await self.app(scope, limited_receive, send)
