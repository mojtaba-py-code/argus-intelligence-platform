"""Redis is a cache and coordination layer here, never a source of truth.

Every key lives under ``<prefix>:<environment>:`` so several deployments can share a Redis
instance without collisions, and tenant data under ``...:org:<organization_id>:`` so a tenant's
namespace can be flushed on deletion. Every write sets a TTL.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from redis.asyncio import Redis

from argus.core.config import Environment, RedisSettings


def create_redis(settings: RedisSettings) -> Redis | None:
    if settings.url is None:
        return None
    client: Redis = Redis.from_url(
        settings.url.get_secret_value(),
        socket_timeout=settings.socket_timeout_s,
        socket_connect_timeout=settings.socket_timeout_s,
        health_check_interval=30,
        decode_responses=False,
    )
    return client


class RedisKeys:
    def __init__(self, prefix: str, environment: Environment) -> None:
        self._base = f"{prefix}:{environment.value}"

    def key(self, *parts: Any) -> str:
        cleaned = [str(part).replace(":", "_") for part in parts]
        return ":".join([self._base, *cleaned])

    def org(self, organization_id: UUID, *parts: Any) -> str:
        return self.key("org", organization_id, *parts)

    def org_pattern(self, organization_id: UUID) -> str:
        return f"{self.key('org', organization_id)}:*"
