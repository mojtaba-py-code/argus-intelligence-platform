"""Short-lived cache of session validity, so each API request does not query PostgreSQL.

Revocation is write-through: revoking a session writes ``revoked`` to the cache immediately, so a
revoked session stops working on every replica at once. Without Redis the cache is disabled and
every request checks PostgreSQL (correct, just slower).
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from redis.asyncio import Redis
from redis.exceptions import RedisError

from argus.core.logging import get_logger
from argus.infrastructure.redis import RedisKeys

log = get_logger(__name__)
_TTL_S = 60
_REVOKED_TTL_S = 900  # longer than an access token's lifetime


@dataclass(frozen=True, slots=True)
class SessionState:
    active: bool
    is_platform_admin: bool = False


class SessionCache:
    def __init__(self, redis: Redis | None, keys: RedisKeys) -> None:
        self._redis = redis
        self._keys = keys

    def _key(self, session_id: UUID) -> str:
        return self._keys.key("sess", session_id)

    async def get(self, session_id: UUID) -> SessionState | None:
        if self._redis is None:
            return None
        try:
            raw = await self._redis.get(self._key(session_id))
        except RedisError:
            return None
        if raw is None:
            return None
        value = raw.decode() if isinstance(raw, bytes) else str(raw)
        if value == "revoked":
            return SessionState(active=False)
        return SessionState(active=True, is_platform_admin=value == "active:admin")

    async def put(self, session_id: UUID, state: SessionState) -> None:
        if self._redis is None:
            return
        if not state.active:
            await self.revoke(session_id)
            return
        value = "active:admin" if state.is_platform_admin else "active"
        try:
            await self._redis.set(self._key(session_id), value, ex=_TTL_S)
        except RedisError:
            log.warning("session_cache.write_failed")

    async def revoke(self, session_id: UUID) -> None:
        if self._redis is None:
            return
        try:
            await self._redis.set(self._key(session_id), "revoked", ex=_REVOKED_TTL_S)
        except RedisError:
            # The database is authoritative; a cached "active" expires within _TTL_S seconds.
            log.warning("session_cache.revoke_failed")

    async def forget(self, session_id: UUID) -> None:
        if self._redis is None:
            return
        try:
            await self._redis.delete(self._key(session_id))
        except RedisError:
            log.warning("session_cache.delete_failed")
