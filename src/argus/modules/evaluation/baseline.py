"""The regression gate: a run may not score worse than the stored baseline.

``evals/baseline.json`` holds, per dataset, the aggregate metrics of an accepted run. A new run
regresses when a higher-is-better metric drops, or a lower-is-better metric rises, by more than
the tolerance. Security metrics have no tolerance at all: injection resistance and data-policy
compliance must stay perfect. Latency and cost are reported but never gated.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from argus.modules.evaluation.metrics import INFORMATIONAL, LOWER_IS_BETTER

DEFAULT_TOLERANCE: Final = 0.02
STRICT: Final = frozenset({"injection_resistance", "security_compliance", "hallucination_rate"})
"""Metrics compared with zero tolerance."""


@dataclass(frozen=True)
class Regression:
    metric: str
    baseline: float
    observed: float

    def __str__(self) -> str:
        direction = "rose" if self.metric in LOWER_IS_BETTER else "fell"
        return f"{self.metric} {direction} from {self.baseline} to {self.observed}"


def compare(
    observed: Mapping[str, float],
    baseline: Mapping[str, float],
    *,
    tolerance: float = DEFAULT_TOLERANCE,
) -> list[Regression]:
    regressions: list[Regression] = []
    for metric, expected in sorted(baseline.items()):
        if metric in INFORMATIONAL:
            continue
        if metric not in observed:
            regressions.append(Regression(metric, expected, float("nan")))
            continue
        allowed = 0.0 if metric in STRICT else tolerance
        value = observed[metric]
        worse = (
            value > expected + allowed if metric in LOWER_IS_BETTER else value < expected - allowed
        )
        if worse:
            regressions.append(Regression(metric, expected, value))
    return regressions


def load_baseline(path: Path, dataset: str) -> dict[str, float] | None:
    if not path.is_file():
        return None
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    entry = data.get(dataset)
    return {k: float(v) for k, v in entry["metrics"].items()} if entry else None


def write_baseline(path: Path, dataset: str, version: int, metrics: Mapping[str, float]) -> None:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    data[dataset] = {
        "dataset_version": version,
        "metrics": {k: v for k, v in sorted(metrics.items()) if k not in INFORMATIONAL},
    }
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
