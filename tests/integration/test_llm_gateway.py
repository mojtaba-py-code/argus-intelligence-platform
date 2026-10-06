"""Phase 11 acceptance: the LLM gateway against a scripted provider and the real ledger."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from pydantic import BaseModel
from sqlalchemy import text

from argus.core.circuit_breaker import BreakerRegistry
from argus.core.classification import Classification
from argus.core.config import Settings
from argus.core.errors import BudgetExceeded
from argus.modules.llm.deployments import PromptService
from argus.modules.llm.gateway import GatewayDependencies, LLMGateway
from argus.modules.llm.ledger import Ledger
from argus.modules.llm.prompts import PromptError, PromptRegistry
from argus.modules.llm.providers.local import LocalProvider
from argus.modules.llm.routing import RoutingTable, TaskRoute, default_routing
from argus.modules.llm.types import (
    CallContext,
    LLMRequest,
    LLMUnavailable,
    ProviderCall,
    ProviderError,
    ProviderRefused,
    ProviderResult,
    ProviderRetryable,
    RenderedPrompt,
    UntrustedData,
)
from tests.support import (
    ApiHarness,
    api_harness,
    bearer,
    create_org,
    create_project,
    register_and_login,
)

pytestmark = pytest.mark.integration
V1 = "/api/v1"


class Answer(BaseModel):
    answer: str


Step = ProviderResult | Exception | Callable[[ProviderCall], ProviderResult]


def ok(
    answer: str = "fine", *, model: str = "claude-opus-5-5", tokens: tuple[int, int] = (1000, 200)
) -> ProviderResult:
    return ProviderResult(
        text=json.dumps({"answer": answer}),
        served_model=model,
        input_tokens=tokens[0],
        output_tokens=tokens[1],
    )


@dataclass
class ScriptedProvider:
    name: str = "anthropic"
    script: list[Step] = field(default_factory=list)
    calls: list[ProviderCall] = field(default_factory=list)

    async def complete(self, call: ProviderCall) -> ProviderResult:
        self.calls.append(call)
        step = self.script.pop(0) if self.script else ok(model=call.model)
        if isinstance(step, Exception):
            raise step
        return step(call) if callable(step) else step

    async def aclose(self) -> None:
        return None


async def no_sleep(_: float) -> None:
    return None


def routing() -> RoutingTable:
    base = default_routing()
    tasks = {
        **base.tasks,
        "test.answer": TaskRoute(
            models=("claude-opus-5-5", "claude-sonnet-5-5", "local/extractive"),
            effort="medium",
            max_output_tokens=2000,
        ),
        "test.no_local": TaskRoute(models=("claude-opus-5-5",), max_output_tokens=2000),
    }
    return RoutingTable(models=base.models, tasks=tasks)


def prompt(task: str = "test.answer") -> RenderedPrompt:
    return RenderedPrompt(
        name=task,
        version=1,
        sha256="a" * 64,
        task=task,
        system="Answer from the evidence only.",
        user="Question: what happened?",
        output_schema=Answer,
    )


@dataclass
class World:
    h: ApiHarness
    provider: ScriptedProvider
    gateway: LLMGateway
    owner: str
    org_id: UUID
    project_id: str

    def context(self, **extra: Any) -> CallContext:
        return CallContext(organization_id=self.org_id, **extra)

    async def ledger_rows(self) -> list[dict[str, Any]]:
        async with self.h.container.database.session(organization_id=self.org_id) as session:
            rows = await session.execute(
                text(
                    "SELECT model, outcome, error_code, cost_usd FROM llm_requests ORDER BY created_at, id"
                )
            )
            return [dict(row._mapping) for row in rows]


def build_gateway(
    h: ApiHarness, provider: ScriptedProvider, *, retries: int = 2, threshold: int = 5
) -> LLMGateway:
    local = LocalProvider()
    local.register("test.answer", lambda _: Answer(answer="local").model_dump_json())
    settings = h.container.settings.llm.model_copy(update={"max_retries_per_model": retries})
    return LLMGateway(
        GatewayDependencies(
            routing=routing(),
            providers={"anthropic": provider, "local": local},
            local=local,
            ledger=Ledger(h.container.database, h.clock),
            breakers=BreakerRegistry(failure_threshold=threshold, reset_timeout_s=60),
            settings=settings,
            metrics=h.container.metrics,
            clock=h.clock,
            sleep=no_sleep,
        )
    )


async def _world(h: ApiHarness, **gateway_options: Any) -> World:
    _, tokens = await register_and_login(h)
    owner = tokens["access_token"]
    org = await create_org(h, owner, "Gateway Co")
    project = await create_project(h, owner, org["id"])
    provider = ScriptedProvider()
    return World(
        h,
        provider,
        build_gateway(h, provider, **gateway_options),
        owner,
        UUID(org["id"]),
        project["id"],
    )


@pytest.fixture
async def world(db_settings: Settings) -> AsyncIterator[World]:
    async with api_harness(db_settings) as h:
        yield await _world(h)


# ------------------------------------------------------------------------------ happy path
async def test_a_call_is_validated_priced_and_recorded(world: World) -> None:
    result = await world.gateway.generate(LLMRequest(prompt=prompt()), world.context())
    assert isinstance(result.parsed, Answer)
    assert (result.provider, result.model, result.cost_usd) == (
        "anthropic",
        "claude-opus-5-5",
        Decimal("0.008000"),
    )
    call = world.provider.calls[0]
    assert (call.model, call.effort, call.output_model, call.refusal_fallback) == (
        "claude-opus-5-5",
        "medium",
        Answer,
        True,
    )
    assert await world.ledger_rows() == [
        {
            "model": "claude-opus-5-5",
            "outcome": "ok",
            "error_code": None,
            "cost_usd": Decimal("0.008000"),
        }
    ]
    async with world.h.container.database.session(organization_id=world.org_id) as session:
        usage = (
            await session.execute(text("SELECT requests, cost_usd FROM llm_usage_daily"))
        ).one()
    assert (usage.requests, usage.cost_usd) == (1, Decimal("0.008000"))


async def test_transient_errors_are_retried_with_backoff(world: World) -> None:
    world.provider.script = [
        ProviderRetryable(code="http_529"),
        ProviderRetryable(code="timeout"),
        ok(),
    ]
    result = await world.gateway.generate(LLMRequest(prompt=prompt()), world.context())
    assert result.model == "claude-opus-5-5"
    assert [row["outcome"] for row in await world.ledger_rows()] == [
        "retryable_error",
        "retryable_error",
        "ok",
    ]


async def test_a_refusal_moves_to_the_next_candidate(world: World) -> None:
    world.provider.script = [ProviderRefused("cyber"), ok(model="claude-sonnet-5-5")]
    result = await world.gateway.generate(LLMRequest(prompt=prompt()), world.context())
    assert result.model == "claude-sonnet-5-5"
    rows = await world.ledger_rows()
    assert [(r["outcome"], r["error_code"]) for r in rows] == [("refused", "cyber"), ("ok", None)]


async def test_invalid_output_gets_exactly_one_repair_attempt(world: World) -> None:
    bad = ProviderResult(
        text='{"wrong": 1}', served_model="claude-opus-5-5", input_tokens=10, output_tokens=5
    )
    world.provider.script = [bad, ok("repaired")]
    result = await world.gateway.generate(LLMRequest(prompt=prompt()), world.context())
    assert result.parsed == Answer(answer="repaired")
    assert "did not match the required output schema" in world.provider.calls[1].user

    world.provider.calls.clear()
    world.provider.script = [bad, bad, ok("from sonnet", model="claude-sonnet-5-5")]
    result = await world.gateway.generate(LLMRequest(prompt=prompt()), world.context())
    assert (result.model, len(world.provider.calls)) == ("claude-sonnet-5-5", 3)


async def test_all_candidates_failing_is_an_explicit_error(world: World) -> None:
    world.provider.script = [ProviderError(code="http_400")]
    with pytest.raises(LLMUnavailable) as caught:
        await world.gateway.generate(LLMRequest(prompt=prompt("test.no_local")), world.context())
    assert [a.outcome for a in caught.value.attempts] == ["error"]


# --------------------------------------------------------------------------- governance
async def test_confidential_data_never_reaches_an_external_model(world: World) -> None:
    request = LLMRequest(
        prompt=prompt(),
        untrusted=(UntrustedData("Q3 board minutes.", "E1", Classification.CONFIDENTIAL),),
    )
    result = await world.gateway.generate(request, world.context())
    assert result.provider == "local"
    assert world.provider.calls == []
    outcomes = [(r["model"], r["outcome"]) for r in await world.ledger_rows()]
    assert outcomes[:2] == [
        ("claude-opus-5-5", "blocked_policy"),
        ("claude-sonnet-5-5", "blocked_policy"),
    ]

    # The policy's "approval" escape hatch: an approved job may send it.
    approved = await world.gateway.generate(request, world.context(approved_external=True))
    assert approved.provider == "anthropic"


async def test_credentials_are_redacted_before_leaving_the_process(world: World) -> None:
    secret = "sk-ant-api03-" + "Q" * 40
    request = LLMRequest(
        prompt=prompt(),
        untrusted=(UntrustedData(f"Leaked config: key={secret}", "E1", Classification.PUBLIC),),
    )
    await world.gateway.generate(request, world.context())
    sent = world.provider.calls[0].user
    assert secret not in sent
    assert "[REDACTED]" in sent


# ------------------------------------------------------------------------------ budgets
async def test_budgets_skip_expensive_models_and_stop_when_nothing_is_affordable(
    world: World,
) -> None:
    response = await world.h.client.patch(
        f"{V1}/orgs/{world.org_id}",
        json={
            "budgets": {
                "monthly_llm_usd": 0.0001,
                "job_default_usd": 1,
                "approval_threshold_usd": 20,
            }
        },
        headers=bearer(world.owner),
    )
    assert response.status_code == 200, response.text
    result = await world.gateway.generate(LLMRequest(prompt=prompt()), world.context())
    assert result.provider == "local"  # free, so still affordable
    assert world.provider.calls == []
    with pytest.raises(BudgetExceeded):
        await world.gateway.generate(LLMRequest(prompt=prompt("test.no_local")), world.context())


async def test_job_spend_is_charged_to_the_job(world: World) -> None:
    job = await world.h.client.post(
        f"{V1}/orgs/{world.org_id}/projects/{world.project_id}/research-jobs",
        json={"objective": "Assess the market for AI customer support tools."},
        headers=bearer(world.owner),
    )
    assert job.status_code == 202, job.text
    job_id = UUID(job.json()["id"])
    result = await world.gateway.generate(LLMRequest(prompt=prompt()), world.context(job_id=job_id))
    async with world.h.container.database.session(organization_id=world.org_id) as session:
        spent = (
            await session.execute(
                text(
                    "SELECT spent_usd, input_tokens, output_tokens FROM research_jobs WHERE id = :id"
                ),
                {"id": job_id},
            )
        ).one()
    assert (Decimal(spent.spent_usd), spent.input_tokens, spent.output_tokens) == (
        result.cost_usd,
        1000,
        200,
    )


# ---------------------------------------------------------------------- circuit breaker
async def test_a_failing_model_is_skipped_once_its_circuit_opens(db_settings: Settings) -> None:
    async with api_harness(db_settings) as h:
        world = await _world(h, retries=1, threshold=2)
        world.provider.script = [
            ProviderRetryable(code="http_503"),
            ProviderRetryable(code="http_503"),
        ]
        with pytest.raises(LLMUnavailable):
            await world.gateway.generate(
                LLMRequest(prompt=prompt("test.no_local")), world.context()
            )
        calls_before = len(world.provider.calls)
        with pytest.raises(LLMUnavailable) as caught:
            await world.gateway.generate(
                LLMRequest(prompt=prompt("test.no_local")), world.context()
            )
        assert len(world.provider.calls) == calls_before  # not even attempted
        assert caught.value.attempts[0].outcome == "circuit_open"


# -------------------------------------------------------------------- prompt deployments
async def test_prompt_versions_can_be_deployed_and_rolled_back(
    world: World, tmp_path: Path
) -> None:
    folder = tmp_path / "rollback.demo"
    folder.mkdir()
    for version, user in ((1, "First: {{ q }}"), (2, "Second: {{ q }}")):
        (folder / f"v{version}.yaml").write_text(
            json.dumps(
                {
                    "name": "rollback.demo",
                    "version": version,
                    "task": "rollback.demo",
                    "purpose": "Exercise deployments and rollbacks.",
                    "input_schema": {"q": "str"},
                    "system": "Static system prompt for the rollback test.",
                    "user": user,
                }
            ),
            encoding="utf-8",
        )
    service = PromptService(
        PromptRegistry.load(tmp_path),
        database=world.h.container.database,
        audit=world.h.container.audit,
        environment="testing",
        clock=world.h.clock,
        ttl_s=0,
    )
    assert await service.active_version("rollback.demo") == 2  # latest unless deployed otherwise
    await service.deploy("rollback.demo", 1, deployed_by="release-manager")
    assert (await service.render("rollback.demo", {"q": "x"})).user == "First: x"
    with pytest.raises(PromptError):
        await service.deploy("rollback.demo", 7, deployed_by="release-manager")
