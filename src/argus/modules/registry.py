"""Imports every module's ORM models so ``Base.metadata`` is complete.

Used by Alembic (autogenerate / ``argus db check``) and by tests that inspect the schema.
Add new modules here when they gain tables.
"""

from __future__ import annotations

import importlib

MODEL_MODULES: tuple[str, ...] = (
    "argus.modules.identity.models",
    "argus.modules.audit.models",
    "argus.modules.tenancy.models",
    "argus.modules.research.models",
    "argus.modules.sources.models",
    "argus.modules.documents.models",
    "argus.modules.knowledge.models",
    "argus.modules.llm.models",
    "argus.modules.agents.models",
    "argus.modules.monitoring.models",
    "argus.modules.notifications.models",
    "argus.modules.security_center.models",
    "argus.modules.platform.models",
    "argus.infrastructure.queue.models",
    "argus.infrastructure.idempotency",
)


def import_all_models() -> None:
    for name in MODEL_MODULES:
        importlib.import_module(name)
