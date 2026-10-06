"""Active prompt versions per environment, and rendering through them.

Without a deployment row the latest version is active; deploying an older version is the
rollback. Lookups are cached in-process briefly (``ttl_s``) - deployments are rare and a short
lag is harmless, a database round trip per model call is not.
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import select, text

from argus.core.clock import Clock
from argus.core.scope import Actor
from argus.infrastructure.db import Database
from argus.modules.audit.service import AuditCategory, AuditEvent, AuditService
from argus.modules.llm.models import PromptDeployment
from argus.modules.llm.prompts import PromptError, PromptRegistry
from argus.modules.llm.types import RenderedPrompt


class PromptService:
    def __init__(
        self,
        registry: PromptRegistry,
        *,
        database: Database,
        audit: AuditService,
        environment: str,
        clock: Clock,
        ttl_s: float = 30.0,
    ) -> None:
        self.registry = registry
        self._db = database
        self._audit = audit
        self._environment = environment
        self._clock = clock
        self._ttl = ttl_s
        self._cache: dict[str, tuple[float, int]] = {}

    async def active_version(self, name: str) -> int:
        cached = self._cache.get(name)
        if cached is not None and cached[0] > time.monotonic():
            return cached[1]
        async with self._db.session(read_only=True) as session:
            version = (
                await session.execute(
                    select(PromptDeployment.version).where(
                        PromptDeployment.name == name,
                        PromptDeployment.environment == self._environment,
                    )
                )
            ).scalar_one_or_none()
        resolved = (
            version if version in self.registry.versions(name) else self.registry.latest(name)
        )
        self._cache[name] = (time.monotonic() + self._ttl, resolved)
        return resolved

    async def render(self, name: str, variables: dict[str, Any]) -> RenderedPrompt:
        return self.registry.render(name, variables, version=await self.active_version(name))

    async def deploy(self, name: str, version: int, *, deployed_by: str) -> None:
        if version not in self.registry.versions(name):
            msg = f"prompt {name} has no version {version}"
            raise PromptError(msg)
        now = self._clock.now()
        async with self._db.session() as session:
            await session.execute(
                text(
                    "INSERT INTO prompt_deployments (name, environment, version, deployed_by,"
                    " deployed_at) VALUES (:name, :env, :version, :by, :at) ON CONFLICT (name,"
                    " environment) DO UPDATE SET version = EXCLUDED.version,"
                    " deployed_by = EXCLUDED.deployed_by, deployed_at = EXCLUDED.deployed_at"
                ),
                {
                    "name": name,
                    "env": self._environment,
                    "version": version,
                    "by": deployed_by[:200],
                    "at": now,
                },
            )
            await self._audit.record(
                session,
                AuditEvent(
                    action="prompt.deployed",
                    category=AuditCategory.CONFIGURATION,
                    actor=Actor.system(),
                    target_type="prompt",
                    target_id=f"{name}@v{version}",
                    details={"environment": self._environment, "by": deployed_by[:200]},
                ),
            )
        self._cache.pop(name, None)

    async def deployments(self) -> dict[str, int]:
        async with self._db.session(read_only=True) as session:
            rows = await session.execute(
                select(PromptDeployment.name, PromptDeployment.version).where(
                    PromptDeployment.environment == self._environment
                )
            )
            return {row.name: row.version for row in rows}
