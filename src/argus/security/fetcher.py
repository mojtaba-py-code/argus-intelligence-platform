"""SafeFetcher: the only way the platform reads attacker-influenced URLs.

Built directly on httpcore (no environment proxies, no automatic redirects, no automatic
decompression) over :class:`GuardedNetworkBackend`. Per request:

* overall deadline across all redirect hops (slowloris-proof), plus connect/read timeouts;
* manual redirects: every ``Location`` is re-parsed and re-validated, loops and excess hops are
  refused, and HTTPS → HTTP downgrades are refused;
* an optional *gate* runs before every hop (robots.txt and per-domain politeness), so a redirect
  cannot jump to a path that robots.txt forbids;
* ``Content-Length`` is checked before reading; the body is streamed with a byte cap applied
  **after** decompression, and inflation per chunk is bounded (``max_length``) so a 10 KB gzip bomb
  never materialises as 10 GB in memory;
* the declared content type must be allowed *and* agree with the magic bytes.
"""

from __future__ import annotations

import asyncio
import ssl
import zlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final
from urllib.parse import urljoin, urlsplit

import certifi
import httpcore
from opentelemetry import trace
from opentelemetry.trace import SpanKind

from argus.core.logging import get_logger
from argus.infrastructure.observability.metrics import Metrics
from argus.infrastructure.observability.tracing import set_attributes, span
from argus.security.content import compatible, sniff
from argus.security.egress import GuardedNetworkBackend, Resolver, SystemResolver
from argus.security.ssrf import EgressBlocked, SafeURL, parse_url

log = get_logger(__name__)

TEXT_TYPES: Final = frozenset(
    {
        "text/html",
        "application/xhtml+xml",
        "text/plain",
        "text/markdown",
        "text/csv",
        "application/json",
        "application/ld+json",
        "application/xml",
        "text/xml",
        "application/rss+xml",
        "application/atom+xml",
    }
)
DOCUMENT_TYPES: Final = frozenset({"application/pdf"})
_REDIRECTS: Final = frozenset({301, 302, 303, 307, 308})
_KEPT_HEADERS: Final = ("content-type", "content-language", "last-modified", "etag", "date")


class FetchError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class FetchPolicy:
    user_agent: str
    connect_timeout_s: float = 5.0
    read_timeout_s: float = 15.0
    total_timeout_s: float = 30.0
    max_redirects: int = 5
    max_bytes: int = 10 * 1024 * 1024
    max_decompression_ratio: int = 100
    allowed_ports: tuple[int, ...] = (80, 443)
    allow_https_downgrade: bool = False


@dataclass
class FetchResult:
    url: str
    status: int
    media_type: str
    charset: str | None
    content: bytes
    headers: dict[str, str]
    redirects: list[str] = field(default_factory=list)
    server_ip: str | None = None
    fetched_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def text(self) -> str:
        for encoding in (self.charset, "utf-8"):
            if not encoding:
                continue
            try:
                return self.content.decode(encoding)
            except (LookupError, UnicodeDecodeError):
                continue
        return self.content.decode("utf-8", errors="replace")


Gate = Callable[[SafeURL], Awaitable[None]]


class _BoundedDecoder:
    """Incremental gzip/deflate decoding that never produces more than ``limit`` bytes."""

    def __init__(self, encoding: str, *, limit: int, max_ratio: int) -> None:
        if encoding not in {"identity", "gzip", "x-gzip", "deflate"}:
            raise FetchError("unsupported_encoding", encoding)
        self._identity = encoding == "identity"
        self._raw_deflate_fallback = encoding == "deflate"
        self._decoder = zlib.decompressobj(wbits=zlib.MAX_WBITS | 32)
        self._limit = limit
        self._max_ratio = max_ratio
        self._compressed = 0
        self._produced = 0
        self._started = False

    def feed(self, chunk: bytes) -> bytes:
        self._compressed += len(chunk)
        if self._identity:
            return self._account(chunk)
        output = bytearray()
        data = chunk
        while data:
            budget = self._limit - self._produced - len(output) + 1
            try:
                piece = self._decoder.decompress(data, budget)
            except zlib.error:
                if self._raw_deflate_fallback and not self._started:
                    self._decoder = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
                    self._raw_deflate_fallback = False
                    continue
                raise FetchError("corrupt_encoding") from None
            self._started = True
            output += piece
            if self._produced + len(output) > self._limit:
                raise FetchError("too_large", "decoded body exceeds the limit")
            data = self._decoder.unconsumed_tail
            if not piece and data:
                break  # pragma: no cover - decoder needs more input
        return self._account(bytes(output))

    def _account(self, data: bytes) -> bytes:
        self._produced += len(data)
        if self._produced > self._limit:
            raise FetchError("too_large", "body exceeds the limit")
        if self._produced > 1024 * 1024 and self._produced > self._max_ratio * max(
            1, self._compressed
        ):
            raise FetchError("decompression_bomb")
        return data


def _media_type(header: str | None) -> tuple[str, str | None]:
    if not header:
        return "", None
    media, _, params = header.partition(";")
    charset = None
    for param in params.split(";"):
        key, _, value = param.strip().partition("=")
        if key.lower() == "charset" and value:
            charset = value.strip("\"' ").lower()[:32]
    return media.strip().lower(), charset


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "invalid")[:253]
    except ValueError:
        return "invalid"


def default_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=certifi.where())
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class SafeFetcher:
    def __init__(
        self,
        policy: FetchPolicy,
        *,
        resolver: Resolver | None = None,
        inner_backend: httpcore.AsyncNetworkBackend | None = None,
        ssl_context: ssl.SSLContext | None = None,
        metrics: Metrics | None = None,
    ) -> None:
        self.policy = policy
        self._metrics = metrics
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context or default_ssl_context(),
            max_connections=32,
            max_keepalive_connections=8,
            keepalive_expiry=20.0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=GuardedNetworkBackend(
                resolver or SystemResolver(policy.connect_timeout_s),
                inner_backend,
                allowed_ports=policy.allowed_ports,
                metrics=metrics,
            ),
        )

    async def aclose(self) -> None:
        await self._pool.aclose()

    def _count(self, outcome: str) -> None:
        trace.get_current_span().set_attribute("argus.egress.outcome", outcome)
        if self._metrics is not None:
            self._metrics.fetches.labels(outcome).inc()

    async def fetch(
        self,
        url: str,
        *,
        accept: frozenset[str] = TEXT_TYPES,
        max_bytes: int | None = None,
        gate: Gate | None = None,
    ) -> FetchResult:
        limit = min(max_bytes or self.policy.max_bytes, self.policy.max_bytes)
        # Host only: paths and queries of fetched pages stay out of telemetry, and nothing is
        # propagated to the site (no traceparent header).
        with span("egress.fetch", kind=SpanKind.CLIENT, attributes={"server.address": _host(url)}):
            result = await self._fetch_counted(url, accept=accept, limit=limit, gate=gate)
            set_attributes(
                trace.get_current_span(),
                {
                    "http.response.status_code": result.status,
                    "argus.egress.redirects": len(result.redirects),
                    "argus.egress.bytes": len(result.content),
                },
            )
            return result

    async def _fetch_counted(
        self, url: str, *, accept: frozenset[str], limit: int, gate: Gate | None
    ) -> FetchResult:
        try:
            async with asyncio.timeout(self.policy.total_timeout_s):
                result = await self._fetch(url, accept=accept, limit=limit, gate=gate)
        except TimeoutError:
            self._count("timeout")
            raise FetchError("timeout", "the overall deadline was exceeded") from None
        except EgressBlocked as exc:
            self._count("blocked")
            raise FetchError("blocked", exc.reason) from None
        except FetchError as exc:
            self._count(exc.code)
            raise
        except httpcore.TimeoutException as exc:
            self._count("timeout")
            raise FetchError("timeout", type(exc).__name__) from None
        except (
            httpcore.NetworkError,
            httpcore.ProtocolError,
            httpcore.UnsupportedProtocol,
            OSError,
        ) as exc:
            self._count("network_error")
            raise FetchError("network_error", type(exc).__name__) from None
        self._count("ok")
        return result

    async def _fetch(
        self, url: str, *, accept: frozenset[str], limit: int, gate: Gate | None
    ) -> FetchResult:
        current = parse_url(url, allowed_ports=self.policy.allowed_ports)
        visited: list[str] = []
        timeouts = {
            "connect": self.policy.connect_timeout_s,
            "read": self.policy.read_timeout_s,
            "write": self.policy.read_timeout_s,
            "pool": self.policy.connect_timeout_s,
        }
        headers = [
            (b"User-Agent", self.policy.user_agent.encode()),
            (b"Accept", ", ".join(sorted(accept)).encode() + b";q=0.9, */*;q=0.1"),
            (b"Accept-Encoding", b"gzip, deflate"),
            (b"Accept-Language", b"en;q=0.9, *;q=0.5"),
        ]
        for _hop in range(self.policy.max_redirects + 1):
            target = str(current)
            if target in visited:
                raise FetchError("redirect_loop")
            visited.append(target)
            if gate is not None:
                await gate(current)
            async with self._pool.stream(
                b"GET", target.encode(), headers=headers, extensions={"timeout": timeouts}
            ) as response:
                response_headers = {
                    k.decode("latin-1").lower(): v.decode("latin-1") for k, v in response.headers
                }
                if response.status in _REDIRECTS:
                    location = response_headers.get("location")
                    if not location:
                        raise FetchError("bad_redirect", "redirect without Location")
                    nxt = parse_url(
                        urljoin(target, location.strip()), allowed_ports=self.policy.allowed_ports
                    )
                    if (
                        current.scheme == "https"
                        and nxt.scheme == "http"
                        and not self.policy.allow_https_downgrade
                    ):
                        raise FetchError("insecure_redirect", "https to http downgrade refused")
                    current = nxt
                    continue
                server_ip = None
                stream = response.extensions.get("network_stream")
                if stream is not None:
                    address = stream.get_extra_info("server_addr")
                    server_ip = str(address[0]) if address else None
                if response.status >= 400:
                    raise FetchError("http_error", str(response.status))
                media_type, charset = _media_type(response_headers.get("content-type"))
                if media_type and media_type not in accept:
                    raise FetchError("content_type", media_type)
                declared_length = response_headers.get("content-length", "")
                if declared_length.isdigit() and int(declared_length) > limit:
                    raise FetchError("too_large", "declared length exceeds the limit")
                decoder = _BoundedDecoder(
                    response_headers.get("content-encoding", "identity").strip().lower()
                    or "identity",
                    limit=limit,
                    max_ratio=self.policy.max_decompression_ratio,
                )
                body = bytearray()
                async for chunk in response.aiter_stream():
                    body += decoder.feed(chunk)
                content = bytes(body)
                sniffed = sniff(content)
                effective = media_type or sniffed
                if effective not in accept or not compatible(effective, sniffed):
                    raise FetchError(
                        "content_mismatch", f"declared {media_type or '-'} sniffed {sniffed}"
                    )
                return FetchResult(
                    url=target,
                    status=response.status,
                    media_type=effective,
                    charset=charset,
                    content=content,
                    headers={
                        k: response_headers[k][:512] for k in _KEPT_HEADERS if k in response_headers
                    },
                    redirects=visited[:-1],
                    server_ip=server_ip,
                )
        raise FetchError("too_many_redirects")
