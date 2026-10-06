"""Data classification levels, ordered so that ceilings are a simple comparison."""

from __future__ import annotations

from enum import IntEnum


class Classification(IntEnum):
    PUBLIC = 0
    """Published on the open web (collected pages)."""
    INTERNAL = 1
    """Organisation-internal, low sensitivity."""
    CONFIDENTIAL = 2
    """Default for uploaded documents and research outputs."""
    RESTRICTED = 3
    """Highest sensitivity: never leaves the deployment unless policy explicitly allows it."""

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str | int) -> Classification:
        if isinstance(value, int):
            return cls(value)
        return cls[value.strip().upper()]
