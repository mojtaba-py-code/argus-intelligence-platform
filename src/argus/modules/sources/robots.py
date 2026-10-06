"""robots.txt (RFC 9309) with caching, and per-domain politeness.

RFC 9309 semantics: a robots.txt answering 4xx means "no restrictions"; 5xx or an unreachable
server means "assume complete disallow" (retried later, cached briefly). The file is fetched with
the same SafeFetcher (SSRF guard included) and a small size cap; Protego parses it, supporting
the ``*`` and ``$`` wildcards that ``urllib.robotparser`` ignores.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Final

from protego import Protego
from redis.asyncio import Redis
from redis.exceptions import RedisError

from argus.core.logging import get_logger
from argus.infrastructure.redis import RedisKeys
from argus.security.fetcher import FetchError, SafeFetcher
from argus.security.ratelimit import RateLimiter, RatePolicy
from argus.security.ssrf import SafeURL

log = get_logger(__name__)
_ALLOW_ALL: Final = "\x00allow-all"
_DISALLOW_ALL: Final = "\x00disallow-all"
_MAX_ROBOTS_BYTES: Final = 512 * 1024
_TTL_OK_S: Final = 6 * 3600
_TTL_UNREACHABLE_S: Final = 300
_MAX_CRAWL_DELAY_S: Final = 30.0


@dataclass(frozen=True)
class RobotsDecision:
    allowed: bool
    crawl_delay_s: float | None = None
    reason: str | None = None
    """``"disallowed"`` (the site's rules) or ``"unreachable"`` (RFC 9309: assume disallow)."""


class RobotsCache:
    def __init__(
        self,
        fetcher: SafeFetcher,
        *,
        user_agent: str,
        redis: Redis | None = None,
        keys: RedisKeys | None = None,
        max_memory_entries: int = 5_000,
    ) -> None:
        self._fetcher = fetcher
        self._agent = user_agent.split("/", 1)[0]
        self._redis = redis
        self._keys = keys
        self._memory: OrderedDict[str, tuple[float, str]] = OrderedDict()
        self._max = max_memory_entries
        self._locks: dict[str, asyncio.Lock] = {}

    async def _cached(self, origin: str) -> str | None:
        if self._redis is not None and self._keys is not None:
            try:
                raw = await self._redis.get(self._keys.key("robots", origin))
                if raw is not None:
                    return (
                        raw.decode("utf-8", errors="replace")
                        if isinstance(raw, bytes)
                        else str(raw)
                    )
            except RedisError:
                pass
        entry = self._memory.get(origin)
        if entry is not None and entry[0] > time.monotonic():
            return entry[1]
        return None

    async def _store(self, origin: str, body: str, ttl: int) -> None:
        self._memory[origin] = (time.monotonic() + ttl, body)
        self._memory.move_to_end(origin)
        while len(self._memory) > self._max:
            self._memory.popitem(last=False)
        if self._redis is not None and self._keys is not None:
            try:
                await self._redis.set(self._keys.key("robots", origin), body.encode(), ex=ttl)
            except RedisError:
                log.warning("robots.cache_write_failed")

    async def _robots_txt(self, url: SafeURL) -> str:
        origin = url.origin
        cached = await self._cached(origin)
        if cached is not None:
            return cached
        lock = self._locks.setdefault(origin, asyncio.Lock())
        async with lock:
            cached = await self._cached(origin)
            if cached is not None:
                return cached
            try:
                result = await self._fetcher.fetch(
                    f"{origin}/robots.txt",
                    accept=frozenset({"text/plain", "text/html"}),
                    max_bytes=_MAX_ROBOTS_BYTES,
                )
                body, ttl = result.text(), _TTL_OK_S
            except FetchError as exc:
                if exc.code == "blocked":
                    raise  # an SSRF-blocked host: report the real cause, never cache it
                if exc.code == "http_error" and exc.detail.startswith("4"):
                    body, ttl = _ALLOW_ALL, _TTL_OK_S
                elif exc.code in {"content_type", "content_mismatch", "too_large"}:
                    body, ttl = _ALLOW_ALL, _TTL_OK_S  # not a robots file: no restrictions
                else:
                    body, ttl = _DISALLOW_ALL, _TTL_UNREACHABLE_S
            await self._store(origin, body, ttl)
            return body

    async def check(self, url: SafeURL) -> RobotsDecision:
        body = await self._robots_txt(url)
        if body == _ALLOW_ALL:
            return RobotsDecision(True)
        if body == _DISALLOW_ALL:
            return RobotsDecision(False, reason="unreachable")
        parser = Protego.parse(body)
        allowed = bool(parser.can_fetch(str(url), self._agent))
        delay = parser.crawl_delay(self._agent)
        return RobotsDecision(
            allowed,
            min(float(delay), _MAX_CRAWL_DELAY_S) if delay else None,
            None if allowed else "disallowed",
        )


class Politeness:
    """At most one request per ``interval`` per host across every worker (GCRA in Redis)."""

    def __init__(self, limiter: RateLimiter, *, interval_s: float) -> None:
        self._limiter = limiter
        self._interval = interval_s

    async def wait(self, host: str, crawl_delay_s: float | None = None) -> None:
        interval = max(self._interval, crawl_delay_s or 0.0)
        if interval <= 0:
            return
        policy = RatePolicy("fetch.domain", 1, interval, burst=1)
        while True:
            decision = await self._limiter.hit(policy, host)
            if decision.allowed:
                return
            await asyncio.sleep(min(decision.retry_after_s, interval))
