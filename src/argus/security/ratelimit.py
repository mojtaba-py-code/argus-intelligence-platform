"""Rate limiting with GCRA (generic cell rate algorithm).

GCRA stores a single number per key - the *theoretical arrival time* (TAT) - and decides in O(1):

    T   = period / limit            (emission interval)
    tau = T * (burst - 1)           (how far ahead of schedule a client may run)
    allow  iff  now >= TAT - tau ;  on allow:  TAT = max(TAT, now) + T

The Redis implementation runs the check-and-update in one Lua script (atomic across API
replicas) using Redis' own clock (no skew between replicas). Keys are SHA-256 digests, so Redis
never stores raw e-mail addresses or IP addresses.

When Redis is unreachable the limiter **degrades to an in-process GCRA** (per-instance limits) and
reports it - limits get looser, they never disappear. The in-process limiter is bounded (LRU) so
a flood of distinct keys cannot exhaust memory.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Protocol

from redis.asyncio import Redis
from redis.exceptions import RedisError

from argus.core.logging import get_logger
from argus.infrastructure.observability.metrics import Metrics
from argus.infrastructure.redis import RedisKeys

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class RatePolicy:
    name: str
    limit: int
    period_s: float
    burst: int | None = None

    @property
    def emission_ms(self) -> float:
        return self.period_s * 1000.0 / self.limit

    @property
    def tolerance_ms(self) -> float:
        return self.emission_ms * ((self.burst or self.limit) - 1)

    def header(self) -> str:
        """IETF draft ``RateLimit-Policy`` value."""
        return f'"{self.name}";q={self.limit};w={int(self.period_s)}'


@dataclass(frozen=True, slots=True)
class RateDecision:
    allowed: bool
    retry_after_s: float
    remaining: int
    degraded: bool = False


POLICIES: Final[dict[str, RatePolicy]] = {
    p.name: p
    for p in (
        RatePolicy("global.ip", 300, 60),
        RatePolicy("auth.login.ip", 20, 60),
        # 5 attempts at once, then one every 3 minutes - applied to *any* e-mail string, known or
        # not, so lockout behaviour does not reveal which accounts exist.
        RatePolicy("auth.login.account", 5, 15 * 60, burst=5),
        RatePolicy("auth.register.ip", 10, 3600),
        RatePolicy("auth.password_reset.ip", 5, 3600),
        RatePolicy("auth.password_reset.account", 3, 3600),
        RatePolicy("auth.verification.account", 3, 3600),
        RatePolicy("auth.mfa", 10, 15 * 60),
        RatePolicy("auth.refresh.session", 30, 60),
        RatePolicy("api.principal", 600, 60),
        RatePolicy("apikeys.create.org", 20, 3600),
        RatePolicy("research.create.org", 60, 3600),
        RatePolicy("research.create.user", 20, 3600),
        RatePolicy("documents.upload.org", 200, 3600),
        RatePolicy("invitations.create.org", 50, 3600),
        RatePolicy("sources.add.org", 120, 3600),
        RatePolicy("knowledge.ask.user", 60, 3600),
        RatePolicy("reports.export.user", 60, 3600),
        RatePolicy("monitors.run.user", 20, 3600),
        RatePolicy("security.audit_verify.org", 6, 3600),
        RatePolicy("audit.denials.principal", 30, 600),
        RatePolicy("exports.create.org", 3, 86_400),
        RatePolicy("exports.download.user", 10, 3600),
        RatePolicy("fetch.domain", 1, 2, burst=1),
    )
}


class RateLimiter(Protocol):
    async def hit(self, policy: RatePolicy, key: str, *, cost: int = 1) -> RateDecision: ...


def _digest(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


class MemoryRateLimiter:
    """In-process GCRA. Used in development/tests and as the degraded fallback."""

    def __init__(
        self,
        *,
        max_keys: int = 100_000,
        clock: Callable[[], float] = time.monotonic,
        metrics: Metrics | None = None,
    ) -> None:
        self._tat: OrderedDict[str, float] = OrderedDict()
        self._max_keys = max_keys
        self._clock = clock
        self._lock = asyncio.Lock()
        self._metrics = metrics

    async def hit(self, policy: RatePolicy, key: str, *, cost: int = 1) -> RateDecision:
        now = self._clock() * 1000.0
        full_key = f"{policy.name}:{_digest(key)}"
        async with self._lock:
            tat = max(self._tat.get(full_key, now), now)
            new_tat = tat + policy.emission_ms * cost
            allow_at = new_tat - policy.tolerance_ms - policy.emission_ms
            if now < allow_at:
                if self._metrics is not None:
                    self._metrics.rate_limited.labels(policy.name).inc()
                return RateDecision(False, (allow_at - now) / 1000.0, 0)
            self._tat[full_key] = new_tat
            self._tat.move_to_end(full_key)
            while len(self._tat) > self._max_keys:
                self._tat.popitem(last=False)
            remaining = math.floor((now - allow_at) / policy.emission_ms)
            return RateDecision(True, 0.0, max(0, remaining))

    async def reset(self) -> None:
        async with self._lock:
            self._tat.clear()


_GCRA_LUA: Final = """
local key = KEYS[1]
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local emission = tonumber(ARGV[1])
local tolerance = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
local tat = tonumber(redis.call('GET', key) or now)
if tat < now then tat = now end
local new_tat = tat + emission * cost
local allow_at = new_tat - tolerance - emission
if now < allow_at then
  return {0, tostring(allow_at - now), 0}
end
redis.call('SET', key, tostring(new_tat), 'PX', math.max(1, math.ceil(new_tat - now)))
return {1, '0', math.floor((now - allow_at) / emission)}
"""


class RedisRateLimiter:
    def __init__(
        self,
        redis: Redis,
        keys: RedisKeys,
        *,
        fallback: MemoryRateLimiter | None = None,
        metrics: Metrics | None = None,
    ) -> None:
        self._redis = redis
        self._keys = keys
        self._fallback = fallback or MemoryRateLimiter(metrics=metrics)
        self._metrics = metrics
        self._script = redis.register_script(_GCRA_LUA)
        self._last_warning = 0.0

    async def hit(self, policy: RatePolicy, key: str, *, cost: int = 1) -> RateDecision:
        redis_key = self._keys.key("rl", policy.name, _digest(key))
        try:
            allowed, retry_ms, remaining = await self._script(
                keys=[redis_key],
                args=[policy.emission_ms, policy.tolerance_ms, cost],
            )
        except (RedisError, OSError, TimeoutError) as exc:
            if self._metrics is not None:
                self._metrics.ratelimit_degraded.inc()
            now = time.monotonic()
            if now - self._last_warning > 30:
                self._last_warning = now
                log.warning("ratelimit.degraded", error_type=type(exc).__name__)
            decision = await self._fallback.hit(policy, key, cost=cost)
            return RateDecision(decision.allowed, decision.retry_after_s, decision.remaining, True)
        decision = RateDecision(bool(int(allowed)), float(retry_ms) / 1000.0, int(remaining))
        if not decision.allowed and self._metrics is not None:
            self._metrics.rate_limited.labels(policy.name).inc()
        return decision
