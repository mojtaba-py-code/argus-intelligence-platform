"""The plan catalogue - code, like the permission matrix, so a limit changes only by review.

``None`` means unlimited. ``enterprise`` is the self-hosted default: no quota applies, budgets are
whatever the organisation sets. A hosted service starts organisations on ``free``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

PlanName = Literal["free", "team", "business", "enterprise"]
Metric = Literal[
    "members",
    "projects",
    "monitors",
    "api_keys",
    "research_jobs_per_month",
    "storage_bytes",
]
METRICS: Final[tuple[Metric, ...]] = (
    "members",
    "projects",
    "monitors",
    "api_keys",
    "research_jobs_per_month",
    "storage_bytes",
)
GIB: Final = 1024**3


@dataclass(frozen=True)
class Plan:
    name: PlanName
    members: int | None
    """Members plus open invitations."""
    projects: int | None
    monitors: int | None
    api_keys: int | None
    """Active (not revoked, not expired) keys."""
    research_jobs_per_month: int | None
    storage_bytes: int | None
    """Uploaded and collected documents."""
    monthly_llm_usd: float | None
    """Ceiling for the organisation's own monthly model budget."""

    def limit(self, metric: Metric) -> int | None:
        value: int | None = getattr(self, metric)
        return value


PLANS: Final[dict[PlanName, Plan]] = {
    "free": Plan("free", 5, 3, 3, 5, 50, 1 * GIB, 25.0),
    "team": Plan("team", 25, 25, 25, 25, 1_000, 25 * GIB, 500.0),
    "business": Plan("business", 200, 200, 200, 100, 10_000, 250 * GIB, 5_000.0),
    "enterprise": Plan("enterprise", None, None, None, None, None, None, None),
}
PLAN_NAMES: Final = tuple(PLANS)


def plan(name: str) -> Plan:
    """An unknown plan name (an operator typo in the database) is treated as the most
    restrictive plan: quotas fail closed."""
    return next((p for key, p in PLANS.items() if key == name), PLANS["free"])
