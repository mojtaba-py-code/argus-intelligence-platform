"""Routing table: which models may serve a task, in which order, at what price.

Loaded from ``configs/llm_routing.yaml`` (or ``llm.routing_file``) and validated at start-up: every
route must reference known, routable models and the table must have a ``default`` route. Task
names resolve exactly first, then by the longest matching ``prefix.*`` route, then ``default``.
"""

from __future__ import annotations

from decimal import Decimal
from functools import lru_cache
from pathlib import Path
from typing import Final, Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from argus.core.resources import config_path
from argus.modules.llm.governance import Locality
from argus.modules.llm.types import Effort

LOCAL_MODEL: Final = "local/extractive"
_MILLION: Final = Decimal(1_000_000)


class Price(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    input: Decimal = Field(ge=0)
    output: Decimal = Field(ge=0)
    cache_read: Decimal = Field(ge=0)
    cache_write: Decimal = Field(ge=0)

    def cost(
        self, *, input_tokens: int, output_tokens: int, cache_read: int = 0, cache_write: int = 0
    ) -> Decimal:
        total = (
            self.input * input_tokens
            + self.output * output_tokens
            + self.cache_read * cache_read
            + self.cache_write * cache_write
        )
        return (total / _MILLION).quantize(Decimal("0.000001"))


class ModelSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: Literal["anthropic", "openai", "local"]
    locality: Locality
    context_tokens: int = Field(gt=0)
    max_output_tokens: int = Field(gt=0)
    structured_output: bool
    effort: bool
    refusal_fallback: bool
    routable: bool = True
    price: Price


class TaskRoute(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    models: tuple[str, ...] = Field(min_length=1)
    effort: Effort | None = None
    max_output_tokens: int = Field(8000, gt=0, le=128_000)


class RoutingTable(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    models: dict[str, ModelSpec]
    tasks: dict[str, TaskRoute]

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if "default" not in self.tasks:
            msg = "the routing table needs a 'default' task"
            raise ValueError(msg)
        for task, route in self.tasks.items():
            for model in route.models:
                spec = self.models.get(model)
                if spec is None:
                    msg = f"task {task!r} references unknown model {model!r}"
                    raise ValueError(msg)
                if not spec.routable:
                    msg = f"task {task!r} references non-routable model {model!r}"
                    raise ValueError(msg)
        return self

    def route(self, task: str) -> TaskRoute:
        if task in self.tasks:
            return self.tasks[task]
        prefixes = [name[:-1] for name in self.tasks if name.endswith(".*")]
        matches = [prefix for prefix in prefixes if task.startswith(prefix)]
        if matches:
            return self.tasks[max(matches, key=len) + "*"]
        return self.tasks["default"]

    def with_model(self, name: str, spec: ModelSpec, *, before: str = LOCAL_MODEL) -> RoutingTable:
        """A copy with an operator-configured model (e.g. self-hosted) in every route."""
        tasks = {
            task: route.model_copy(
                update={
                    "models": tuple(
                        model
                        for existing in route.models
                        for model in ((name, existing) if existing == before else (existing,))
                    )
                }
            )
            for task, route in self.tasks.items()
        }
        return RoutingTable(models={**self.models, name: spec}, tasks=tasks)


def load_routing(path: Path | None = None) -> RoutingTable:
    raw = yaml.safe_load((path or config_path("llm_routing.yaml")).read_text(encoding="utf-8"))
    return RoutingTable.model_validate(raw)


@lru_cache(maxsize=1)
def default_routing() -> RoutingTable:
    return load_routing()
