"""Phases 13-14 acceptance: research jobs end to end - plan, collect, analyse - offline.

No external model is configured, so the gateway routes every task to the deterministic local
handlers; search is a fixed fake and the web is :class:`FakeInternet`. Everything else is real:
the queue, the pipeline, the SSRF-safe fetcher, indexing, retrieval, the agent runtime, row-level
security and the read API with its per-viewer filtering.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from uuid import UUID

import pytest

from argus.core.config import Settings
from tests.fake_network import PUBLIC_B
from tests.research_world import OBJECTIVE, V1, ExternalModel, World, open_world
from tests.support import bearer, create_project, join_org

pytestmark = pytest.mark.integration


@pytest.fixture
async def world(db_settings: Settings, tmp_path: Path) -> AsyncIterator[World]:
    async with open_world(db_settings, tmp_path) as opened:
        yield opened


# ------------------------------------------------------------------------- end to end
async def test_hybrid_research_produces_a_plan_sources_and_verified_findings(world: World) -> None:
    doc_id = await world.upload(
        "notes.md",
        b"# Market notes\n\nOur win rate against the leading vendors is 35 percent this year.",
    )
    job = await world.create_job(mode="hybrid")
    await world.run_jobs()
    finished = await world.job(job["id"])
    assert finished["status"] == "completed", finished
    steps = await world.get(f"/research-jobs/{job['id']}/steps")
    assert [(s["key"], s["status"]) for s in steps] == [
        ("plan", "succeeded"),
        ("collect", "succeeded"),
        ("analyze", "succeeded"),
        ("verify", "succeeded"),
        ("contradictions", "succeeded"),
        ("report", "succeeded"),
    ]
    assert steps[1]["output"]["fetched"] == 1

    plan = await world.get(f"/research-jobs/{job['id']}/plan")
    assert (plan["version"], plan["model"], plan["prompt_version"]) == (
        1,
        "local/extractive",
        "research.plan@v1",
    )
    assert [q["question"] for q in plan["questions"]] == [
        "AI customer-support market?",
        "Its leading vendors?",
    ]
    assert world.search.queries  # the plan's queries drove the search, not a model

    findings = await world.get(f"/research-jobs/{job['id']}/findings")
    assert findings["withheld"] == 0
    verified = [f for f in findings["findings"] if f["verified"]]
    assert verified
    for finding in verified:
        assert finding["kind"] == "fact"
        assert finding["statement"]
        assert all(c["verified"] for c in finding["citations"])
    origins = {c["origin"] for f in verified for c in f["citations"]}
    assert origins == {"document", "web"}
    web = next(c for f in verified for c in f["citations"] if c["origin"] == "web")
    assert web["url"] == "https://news.example.com/market"
    document = next(c for f in verified for c in f["citations"] if c["origin"] == "document")
    assert document["filename"] == "notes.md"

    runs = await world.get(f"/research-jobs/{job['id']}/agent-runs")
    assert [r["agent"] for r in runs][:3] == ["planner", "analyst", "analyst"]
    assert {"verifier", "reporter", "critic"} <= {r["agent"] for r in runs}
    assert {r["status"] for r in runs} == {"completed"}
    assert all(r["models"] == ["local/extractive"] * r["iterations"] for r in runs)
    assert runs[0]["prompts"] == ["research.plan@v1"]

    ledger = await world.rows(
        "SELECT DISTINCT provider, outcome FROM llm_requests WHERE job_id = :job",
        job=UUID(job["id"]),
    )
    # Unconfigured providers are a deployment fact, not ledger noise: only the local calls.
    assert ledger == [{"provider": "local", "outcome": "ok"}]

    # Deleting a document deletes the citations that rested on it; nothing stays "verified"
    # because of evidence that no longer exists.
    deleted = await world.h.client.delete(
        f"{world.base}/documents/{doc_id}", headers=bearer(world.owner)
    )
    assert deleted.status_code == 204
    after = await world.get(f"/research-jobs/{job['id']}/findings")
    assert all(c["origin"] == "web" for f in after["findings"] for c in f["citations"])
    for finding in after["findings"]:
        if not finding["citations"] and not finding["hidden_citations"]:
            assert finding["verified"] is False


async def test_restricted_evidence_is_withheld_from_viewers_below_its_level(world: World) -> None:
    await world.upload(
        "board.md",
        b"# Board\n\nThe leading vendors acquisition budget is 90 million dollars.",
        "restricted",
    )
    job = await world.create_job(mode="documents")
    await world.run_jobs()
    assert (await world.job(job["id"]))["status"] == "completed"

    own = await world.get(f"/research-jobs/{job['id']}/findings")
    assert own["withheld"] == 0
    assert any("90 million" in (f["statement"] or "") for f in own["findings"])

    _, viewer = await join_org(world.h, world.owner, world.org_id, "viewer")
    seen = await world.get(f"/research-jobs/{job['id']}/findings", viewer)
    assert seen["findings"]
    assert seen["withheld"] == len(seen["findings"])
    for finding in seen["findings"]:
        assert (finding["withheld"], finding["statement"], finding["citations"]) == (True, None, [])
    assert "90 million" not in str(seen)

    runs = await world.get(f"/research-jobs/{job['id']}/agent-runs", viewer)
    analysts = [r for r in runs if r["agent"] == "analyst"]
    assert analysts
    assert all(r["redacted"] for r in analysts)
    assert all(c["arguments"] is None for r in analysts for c in r["calls"])
    planner = next(r for r in runs if r["agent"] == "planner")
    assert planner["redacted"] is False  # the planner read nothing but the objective


async def test_web_research_pauses_for_domains_that_need_approval(world: World) -> None:
    await world.put_policy("research.example.org", "require_approval")
    world.search.urls.append("https://research.example.org/vendors")
    job = await world.create_job(mode="web")
    await world.run_jobs()
    paused = await world.job(job["id"])
    assert paused["status"] == "awaiting_approval"
    assert not world.net.contacted(PUBLIC_B)  # not even robots.txt before a human decided

    approvals = (
        await world.h.client.get(
            f"{V1}/orgs/{world.org_id}/approvals?status=pending", headers=bearer(world.owner)
        )
    ).json()
    assert [(a["kind"], a["details"]["domains"]) for a in approvals] == [
        ("crawl_scope", ["research.example.org"])
    ]
    decided = await world.h.client.post(
        f"{V1}/orgs/{world.org_id}/approvals/{approvals[0]['id']}/decision",
        json={"approve": True, "note": "reviewed"},
        headers=bearer(world.owner),
    )
    assert decided.status_code == 200, decided.text
    await world.run_jobs()
    assert (await world.job(job["id"]))["status"] == "completed"
    assert world.net.contacted(PUBLIC_B)
    statuses = await world.rows("SELECT url, status FROM sources ORDER BY url")
    assert statuses == [
        {"url": "https://news.example.com/market", "status": "fetched"},
        {"url": "https://research.example.org/vendors", "status": "fetched"},
    ]


# -------------------------------------------------------------------- authority and control
async def test_a_kill_switch_fails_the_job_before_any_model_call(world: World) -> None:
    await world.h.container.kill_switches.engage(
        kind="agent",
        target="planner",
        reason="planner incident",
        created_by="oncall",
        organization_id=UUID(world.org_id),
    )
    job = await world.create_job(mode="documents")
    await world.run_jobs()
    failed = await world.job(job["id"])
    assert (failed["status"], failed["error_code"]) == ("failed", "agent_disabled")
    assert await world.rows("SELECT id FROM llm_requests") == []


async def test_a_creator_who_lost_access_cannot_keep_researching(world: World) -> None:
    email, analyst = await join_org(world.h, world.owner, world.org_id, "analyst")
    job = await world.create_job(analyst, mode="documents")
    removed = await world.h.client.delete(
        f"{V1}/orgs/{world.org_id}/members/{await world.member_id(email)}",
        headers=bearer(world.owner),
    )
    assert removed.status_code == 204
    await world.run_jobs()
    failed = await world.job(job["id"])
    assert (failed["status"], failed["error_code"]) == ("failed", "access_revoked")
    assert await world.rows("SELECT id FROM agent_runs") == []  # no budget was spent


async def test_jobs_started_with_api_keys_act_with_the_keys_scopes(world: World) -> None:
    await world.upload("notes.md", b"# Notes\n\nThe leading vendors raised prices in 2026.")
    key = await world.api_key(["research:create", "research:read", "documents:read"])
    hybrid = await world.h.client.post(
        f"{world.base}/research-jobs",
        json={"objective": OBJECTIVE, "mode": "hybrid"},
        headers=bearer(key["key"]),
    )
    assert hybrid.status_code == 403
    assert "sources:read" in hybrid.text
    assert "sources:manage" in hybrid.text

    job = await world.create_job(key["key"], mode="documents")
    await world.run_jobs()
    assert (await world.job(job["id"]))["status"] == "completed"
    findings = await world.get(f"/research-jobs/{job['id']}/findings", key["key"])
    assert findings["findings"]

    revoked_job = await world.create_job(key["key"], mode="documents")
    revoked = await world.h.client.delete(
        f"{V1}/orgs/{world.org_id}/api-keys/{key['id']}", headers=bearer(world.owner)
    )
    assert revoked.status_code == 204
    await world.run_jobs()
    failed = await world.job(revoked_job["id"])
    assert (failed["status"], failed["error_code"]) == ("failed", "access_revoked")


async def test_results_need_read_access_to_the_jobs_origins(world: World) -> None:
    job = await world.create_job(mode="documents")
    await world.run_jobs()
    narrow = await world.api_key(["research:read"])
    await world.get(f"/research-jobs/{job['id']}/plan", narrow["key"])  # the plan is just the ask
    await world.get(f"/research-jobs/{job['id']}/findings", narrow["key"], expect=403)
    await world.get(f"/research-jobs/{job['id']}/agent-runs", narrow["key"], expect=403)
    other = await create_project(world.h, world.owner, world.org_id, "Elsewhere")
    response = await world.h.client.get(
        f"{V1}/orgs/{world.org_id}/projects/{other['id']}/research-jobs/{job['id']}/findings",
        headers=bearer(world.owner),
    )
    assert response.status_code == 404  # a job is only visible through its own project


# --------------------------------------------------------------------------- approvals
async def test_jobs_above_the_cost_threshold_wait_for_a_human(world: World) -> None:
    job = await world.create_job(mode="documents", budget_usd=50)
    await world.run_jobs()
    assert (await world.job(job["id"]))["status"] == "awaiting_approval"
    assert await world.rows("SELECT id FROM agent_runs") == []  # nothing spent before approval
    approvals = await world.pending_approvals()
    assert [a["kind"] for a in approvals] == ["cost_threshold"]
    assert "$50.00" in approvals[0]["reason"]
    await world.approve(approvals[0]["id"])
    await world.run_jobs()
    assert (await world.job(job["id"]))["status"] == "completed"


async def test_confidential_evidence_reaches_an_external_model_only_after_approval(
    db_settings: Settings, tmp_path: Path
) -> None:
    model = ExternalModel()
    async with open_world(db_settings, tmp_path, llm_providers={"anthropic": model}) as world:
        await world.upload("notes.md", b"# Notes\n\nThe leading vendors raised prices in 2026.")
        job = await world.create_job(mode="documents")
        await world.run_jobs()
        assert (await world.job(job["id"]))["status"] == "awaiting_approval"
        # The planner saw only the (internal) objective; no evidence has left the platform.
        assert [call.task for call in model.calls] == ["research.plan"]
        assert all(not call.untrusted for call in model.calls)
        approvals = await world.pending_approvals()
        assert [(a["kind"], a["details"]["classification"]) for a in approvals] == [
            ("data_policy", "confidential")
        ]
        await world.approve(approvals[0]["id"])
        await world.run_jobs()
        assert (await world.job(job["id"]))["status"] == "completed"
        analysis = [call for call in model.calls if call.task == "analysis.findings"]
        assert analysis
        assert any("leading vendors" in part.text for part in analysis[0].untrusted)
        runs = await world.get(f"/research-jobs/{job['id']}/agent-runs")
        analyst = next(r for r in runs if r["agent"] == "analyst")
        assert analyst["models"][0] == "claude-opus-5-5"


async def test_a_never_policy_keeps_analysis_local_without_asking(
    db_settings: Settings, tmp_path: Path
) -> None:
    model = ExternalModel()
    async with open_world(db_settings, tmp_path, llm_providers={"anthropic": model}) as world:
        patched = await world.h.client.patch(
            f"{V1}/orgs/{world.org_id}",
            json={"data_policy": {"external_above_ceiling": "never"}},
            headers=bearer(world.owner),
        )
        assert patched.status_code == 200, patched.text
        await world.upload("notes.md", b"# Notes\n\nThe leading vendors raised prices in 2026.")
        job = await world.create_job(mode="documents")
        await world.run_jobs()
        assert (await world.job(job["id"]))["status"] == "completed"
        assert await world.pending_approvals() == []
        assert [call.task for call in model.calls] == ["research.plan"]
        runs = await world.get(f"/research-jobs/{job['id']}/agent-runs")
        analyst = next(r for r in runs if r["agent"] == "analyst")
        assert set(analyst["models"]) == {"local/extractive"}
