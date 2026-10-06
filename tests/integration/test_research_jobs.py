"""Phase 4 acceptance: research jobs through the API, the queue and the pipeline engine."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

import pytest
from sqlalchemy import text

from argus.apps.container import Container
from argus.apps.worker.main import build_worker
from argus.core.config import Settings
from argus.modules.research.pipeline import ApprovalRequired, Stage, StageContext, StageFailed
from tests.support import (
    ApiHarness,
    api_harness,
    bearer,
    register_and_login,
    token_from_email,
    unique_email,
)

pytestmark = pytest.mark.integration
V1 = "/api/v1"


@dataclass
class Recorder:
    calls: list[str] = field(default_factory=list)
    fail_times: dict[str, int] = field(default_factory=dict)
    behaviours: dict[str, Callable[[StageContext], Any]] = field(default_factory=dict)


@dataclass
class ScriptedStage:
    key: str
    recorder: Recorder
    weight: int = 1

    async def run(self, ctx: StageContext) -> dict[str, Any] | None:
        self.recorder.calls.append(self.key)
        if self.recorder.fail_times.get(self.key, 0) > 0:
            self.recorder.fail_times[self.key] -= 1
            raise RuntimeError(f"{self.key} transient failure")
        behaviour = self.recorder.behaviours.get(self.key)
        if behaviour is not None:
            result = behaviour(ctx)
            if hasattr(result, "__await__"):
                result = await result
            return result  # type: ignore[no-any-return]
        return {"stage": self.key, "seen": sorted(ctx.outputs)}


@dataclass
class World:
    h: ApiHarness
    recorder: Recorder
    owner: str
    org_id: str
    project_id: str

    @property
    def jobs_url(self) -> str:
        return f"{V1}/orgs/{self.org_id}/projects/{self.project_id}/research-jobs"


@pytest.fixture
async def world(db_settings: Settings) -> AsyncIterator[World]:
    recorder = Recorder()

    def stages(_: Container) -> Sequence[Stage]:
        return [
            ScriptedStage("plan", recorder),
            ScriptedStage("collect", recorder, 2),
            ScriptedStage("report", recorder),
        ]

    async with api_harness(db_settings, stages=stages) as h:
        async with h.container.database.session() as session:
            await session.execute(text("DELETE FROM jobs"))
        _, tokens = await register_and_login(h)
        owner = tokens["access_token"]
        org = (
            await h.client.post(f"{V1}/orgs", json={"name": "Research Co"}, headers=bearer(owner))
        ).json()
        project = (
            await h.client.post(
                f"{V1}/orgs/{org['id']}/projects", json={"name": "Markets"}, headers=bearer(owner)
            )
        ).json()
        yield World(h, recorder, owner, org["id"], project["id"])


async def _run_worker(world: World) -> int:
    worker = build_worker(world.h.container, queues=("research",))
    return await worker.run_until_idle()


async def _create(world: World, **body: Any) -> dict[str, Any]:
    payload = {"objective": "Analyse the AI customer-support market and its leaders.", **body}
    response = await world.h.client.post(world.jobs_url, json=payload, headers=bearer(world.owner))
    assert response.status_code == 202, response.text
    return dict(response.json())


async def test_create_run_and_inspect_a_research_job(world: World) -> None:
    response = await world.h.client.post(
        world.jobs_url,
        json={
            "objective": "Analyse the AI customer-support market and its leaders.",
            "budget_usd": 2.5,
        },
        headers=bearer(world.owner),
    )
    assert response.status_code == 202
    job = response.json()
    assert response.headers["location"].endswith(job["id"])
    assert job["status"] == "queued"
    assert job["budget_usd"] == 2.5

    assert await _run_worker(world) == 1
    finished = (
        await world.h.client.get(f"{world.jobs_url}/{job['id']}", headers=bearer(world.owner))
    ).json()
    assert finished["status"] == "completed"
    assert finished["progress"] == 100
    assert world.recorder.calls == ["plan", "collect", "report"]
    steps = (
        await world.h.client.get(f"{world.jobs_url}/{job['id']}/steps", headers=bearer(world.owner))
    ).json()
    assert [(s["key"], s["status"]) for s in steps] == [
        ("plan", "succeeded"),
        ("collect", "succeeded"),
        ("report", "succeeded"),
    ]
    assert steps[2]["output"]["seen"] == [
        "collect",
        "plan",
    ]  # later stages read earlier checkpoints
    listing = (
        await world.h.client.get(f"{world.jobs_url}?status=completed", headers=bearer(world.owner))
    ).json()
    assert [j["id"] for j in listing["items"]] == [job["id"]]


async def test_idempotency_key_prevents_duplicate_jobs(world: World) -> None:
    body = {"objective": "Monitor competitor pricing for analytics tools."}
    headers = {**bearer(world.owner), "Idempotency-Key": "create-job-0001"}
    first = await world.h.client.post(world.jobs_url, json=body, headers=headers)
    second = await world.h.client.post(world.jobs_url, json=body, headers=headers)
    assert first.status_code == second.status_code == 202
    assert first.json()["id"] == second.json()["id"]
    assert second.headers["idempotent-replayed"] == "true"
    changed = await world.h.client.post(
        world.jobs_url, json={**body, "mode": "web"}, headers=headers
    )
    assert changed.status_code == 422  # same key, different request
    other = await world.h.client.post(
        world.jobs_url,
        json=body,
        headers={**bearer(world.owner), "Idempotency-Key": "create-job-0002"},
    )
    assert other.json()["id"] != first.json()["id"]
    bad = await world.h.client.post(
        world.jobs_url, json=body, headers={**bearer(world.owner), "Idempotency-Key": "x"}
    )
    assert bad.status_code == 422
    async with world.h.container.database.session() as session:
        count = (
            await session.execute(text("SELECT count(*) FROM jobs WHERE task = 'research.run'"))
        ).scalar()
    assert count == 2


async def test_transient_failures_resume_from_the_checkpoint(world: World) -> None:
    world.recorder.fail_times["collect"] = 1
    job = await _create(world)
    await _run_worker(world)
    async with world.h.container.database.session() as session:
        await session.execute(text("UPDATE jobs SET run_at = now() WHERE status = 'queued'"))
    await _run_worker(world)
    finished = (
        await world.h.client.get(f"{world.jobs_url}/{job['id']}", headers=bearer(world.owner))
    ).json()
    assert finished["status"] == "completed"
    assert world.recorder.calls == ["plan", "collect", "collect", "report"]  # plan not re-run
    steps = (
        await world.h.client.get(f"{world.jobs_url}/{job['id']}/steps", headers=bearer(world.owner))
    ).json()
    assert {s["key"]: s["attempts"] for s in steps} == {"plan": 1, "collect": 2, "report": 1}


async def test_permanent_stage_failure_fails_the_job_without_retry(world: World) -> None:
    def refuse(ctx: StageContext) -> None:
        raise StageFailed("no_sources", "No usable sources were found.")

    world.recorder.behaviours["collect"] = refuse
    job = await _create(world)
    await _run_worker(world)
    finished = (
        await world.h.client.get(f"{world.jobs_url}/{job['id']}", headers=bearer(world.owner))
    ).json()
    assert finished["status"] == "failed"
    assert finished["error_code"] == "no_sources"
    assert world.recorder.calls == ["plan", "collect"]


async def test_budget_is_enforced(world: World) -> None:
    async def spend(ctx: StageContext) -> dict[str, Any]:
        await ctx.charge(cost_usd=0.4, input_tokens=1000, output_tokens=200)
        await ctx.charge(cost_usd=0.4)
        return {}

    world.recorder.behaviours["collect"] = spend
    job = await _create(world, budget_usd=0.5)
    await _run_worker(world)
    finished = (
        await world.h.client.get(f"{world.jobs_url}/{job['id']}", headers=bearer(world.owner))
    ).json()
    assert finished["status"] == "failed"
    assert finished["error_code"] == "budget_exceeded"
    assert finished["spent_usd"] == pytest.approx(0.8)
    assert finished["input_tokens"] == 1000


async def test_cancelling_a_queued_job_is_immediate(world: World) -> None:
    job = await _create(world)
    response = await world.h.client.post(
        f"{world.jobs_url}/{job['id']}/cancel", headers=bearer(world.owner)
    )
    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"
    assert await _run_worker(world) == 0  # the queue entry was cancelled too
    again = await world.h.client.post(
        f"{world.jobs_url}/{job['id']}/cancel", headers=bearer(world.owner)
    )
    assert again.status_code == 409


async def test_cancelling_a_running_job_is_cooperative(world: World) -> None:
    async def request_cancel(ctx: StageContext) -> dict[str, Any]:
        await world.h.client.post(
            f"{world.jobs_url}/{ctx.job.id}/cancel", headers=bearer(world.owner)
        )
        return {}

    world.recorder.behaviours["plan"] = request_cancel
    job = await _create(world)
    await _run_worker(world)
    finished = (
        await world.h.client.get(f"{world.jobs_url}/{job['id']}", headers=bearer(world.owner))
    ).json()
    assert finished["status"] == "cancelled"
    assert world.recorder.calls == ["plan"]  # the next stage never started


async def test_human_approval_gate(world: World) -> None:
    def gate(ctx: StageContext) -> dict[str, Any]:
        if "cost_threshold" not in ctx.approvals:
            raise ApprovalRequired(
                "cost_threshold",
                "Estimated cost exceeds the approval threshold.",
                {"estimate_usd": 42},
            )
        return {"approved": True}

    world.recorder.behaviours["collect"] = gate
    job = await _create(world)
    await _run_worker(world)
    parked = (
        await world.h.client.get(f"{world.jobs_url}/{job['id']}", headers=bearer(world.owner))
    ).json()
    assert parked["status"] == "awaiting_approval"

    # a viewer may not decide
    viewer_email = unique_email("viewer")
    await world.h.client.post(
        f"{V1}/orgs/{world.org_id}/invitations",
        json={"email": viewer_email, "role": "viewer"},
        headers=bearer(world.owner),
    )
    invitation = token_from_email(world.h.mailer.last_to(viewer_email).text)
    _, viewer_tokens = await register_and_login(world.h, viewer_email)
    viewer = viewer_tokens["access_token"]
    await world.h.client.post(
        f"{V1}/invitations/accept", json={"token": invitation}, headers=bearer(viewer)
    )
    approvals = (
        await world.h.client.get(
            f"{V1}/orgs/{world.org_id}/approvals?status=pending", headers=bearer(world.owner)
        )
    ).json()
    assert [a["kind"] for a in approvals] == ["cost_threshold"]
    approval_id = approvals[0]["id"]
    denied = await world.h.client.post(
        f"{V1}/orgs/{world.org_id}/approvals/{approval_id}/decision",
        json={"approve": True},
        headers=bearer(viewer),
    )
    assert denied.status_code == 403
    lax_boolean = await world.h.client.post(
        f"{V1}/orgs/{world.org_id}/approvals/{approval_id}/decision",
        json={"approve": 1},
        headers=bearer(world.owner),
    )
    assert lax_boolean.status_code == 422  # strict booleans: 1 is not "true"

    approved = await world.h.client.post(
        f"{V1}/orgs/{world.org_id}/approvals/{approval_id}/decision",
        json={"approve": True, "note": "Within quarterly budget."},
        headers=bearer(world.owner),
    )
    assert approved.status_code == 200
    await _run_worker(world)
    finished = (
        await world.h.client.get(f"{world.jobs_url}/{job['id']}", headers=bearer(world.owner))
    ).json()
    assert finished["status"] == "completed"
    assert world.recorder.calls.count("plan") == 1  # resumed at the gated stage


async def test_rejected_approval_cancels_the_job(world: World) -> None:
    def gate(ctx: StageContext) -> None:
        raise ApprovalRequired("data_governance", "Confidential data would leave the deployment.")

    world.recorder.behaviours["plan"] = gate
    job = await _create(world)
    await _run_worker(world)
    approval = (
        await world.h.client.get(
            f"{V1}/orgs/{world.org_id}/approvals?status=pending", headers=bearer(world.owner)
        )
    ).json()[0]
    await world.h.client.post(
        f"{V1}/orgs/{world.org_id}/approvals/{approval['id']}/decision",
        json={"approve": False},
        headers=bearer(world.owner),
    )
    finished = (
        await world.h.client.get(f"{world.jobs_url}/{job['id']}", headers=bearer(world.owner))
    ).json()
    assert finished["status"] == "cancelled"
    assert finished["error_code"] == "approval_rejected"


async def test_research_jobs_are_tenant_isolated(world: World) -> None:
    job = await _create(world)
    _, stranger = await register_and_login(world.h)
    response = await world.h.client.get(
        f"{world.jobs_url}/{job['id']}", headers=bearer(stranger["access_token"])
    )
    assert response.status_code == 404


@pytest.mark.parametrize(
    "body",
    [
        {"objective": "short"},
        {"objective": "x" * 4001},
        {"objective": "Valid objective text here", "budget_usd": 0},
        {"objective": "Valid objective text here", "budget_usd": "5"},
        {"objective": "Valid objective text here", "mode": "everything"},
        {"objective": "Valid objective text here", "unexpected": True},
        {"objective": "Valid objective text \x00 with NUL"},
    ],
)
async def test_invalid_requests_are_rejected(world: World, body: dict[str, Any]) -> None:
    response = await world.h.client.post(world.jobs_url, json=body, headers=bearer(world.owner))
    assert response.status_code == 422
