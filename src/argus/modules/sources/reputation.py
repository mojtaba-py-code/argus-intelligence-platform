"""Domain reputation priors from ``configs/source_reputation.yaml`` plus organisation overrides."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from argus.core.resources import config_path

ListedTier = Literal["high", "medium", "low"]
Tier = Literal[ListedTier, "unknown"]


class _ReputationFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default: float = Field(0.5, ge=0, le=1)
    tiers: dict[ListedTier, float]
    domains: dict[ListedTier, list[str]]


@dataclass(frozen=True)
class Reputation:
    score: float
    tier: Tier


class ReputationModel:
    def __init__(self, data: _ReputationFile) -> None:
        self._default = data.default
        self._tiers = data.tiers
        self._suffixes: list[tuple[str, ListedTier]] = sorted(
            (
                (suffix.lower(), tier)
                for tier, suffixes in data.domains.items()
                for suffix in suffixes
            ),
            key=lambda item: -len(item[0]),
        )

    @classmethod
    def load(cls, path: Path | None = None) -> ReputationModel:
        raw = yaml.safe_load(
            (path or config_path("source_reputation.yaml")).read_text(encoding="utf-8")
        )
        return cls(_ReputationFile.model_validate(raw))

    def lookup(self, host: str, *, override: float | None = None) -> Reputation:
        host = host.lower().rstrip(".")
        if override is not None:
            return Reputation(override, _tier_for(override))
        for suffix, tier in self._suffixes:
            if suffix.startswith("."):
                if host.endswith(suffix):
                    return Reputation(self._tiers[tier], tier)
            elif host == suffix or host.endswith("." + suffix):
                return Reputation(self._tiers[tier], tier)
        return Reputation(self._default, "unknown")


def _tier_for(score: float) -> Tier:
    if score >= 0.85:
        return "high"
    if score >= 0.6:
        return "medium"
    if score <= 0.35:
        return "low"
    return "unknown"


@lru_cache(maxsize=1)
def default_reputation_model() -> ReputationModel:
    return ReputationModel.load()


def domain_matches(host: str, domain: str) -> bool:
    """Policy for ``example.com`` applies to ``example.com`` and its subdomains only."""
    host, domain = host.lower().rstrip("."), domain.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)
