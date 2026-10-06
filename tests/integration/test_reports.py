"""Phase 15 acceptance: verification, contradictions, the report and its exports - end to end.

Jobs run through the real pipeline offline (local handlers), or with :class:`ExternalModel`
standing in for Claude where a test needs a model that misbehaves: one that invents a figure,
writes ungrounded prose, or reviews harshly.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from argus.core.config import Settings
from argus.modules.llm.types import ProviderCall
from argus.modules.research.analysis import Finding, FindingsOutput, local_analyst
from argus.modules.research.reporting import CriticOutput, CriticScores, ReportDraft, local_report
from tests.fake_network import PUBLIC_A, PUBLIC_B, FakeInternet, html_page
from tests.research_world import MARKET_PAGE, ExternalModel, World, open_world
from tests.support import bearer, join_org

pytestmark = pytest.mark.integration

OLD_SHARE = html_page(
    "Vendor A market share report",
    "<article><p>Vendor A market share was 40 percent in 2026.</p></article>",
    head="<meta property='article:published_time' content='2026-01-10T08:00:00Z'>",
)
NEW_SHARE = html_page(
    "Vendor A market share update",
    "<article><p>Vendor A market share was 25 percent in 2026.</p></article>",
    head="<meta property='article:published_time' content='2026-09-01T08:00:00Z'>",
)
RISKY_PAGE = html_page(
    "Vendor review <img src=x onerror=alert(1)>",
    '<article><p>=HYPERLINK("https://evil.example/x") The leading vendors are Vendor A and '
    "Vendor B.</p><p>See https://evil.example/collect?q=secret for the leading vendors list."
    "</p></article>",
)


@pytest.fixture
async def world(db_settings: Settings, tmp_path: Path) -> AsyncIterator[World]:
    async with open_world(db_settings, tmp_path) as opened:
        yield opened


async def _completed(world: World, **body: Any) -> dict[str, Any]:
    job = await world.create_job(**body)
    await world.run_jobs()
    finished = await world.job(job["id"])
    assert finished["status"] == "completed", finished
    return finished


# ------------------------------------------------------------------------- end to end
async def test_a_report_is_composed_from_verified_findings_with_provenance(world: World) -> None:
    await world.upload(
        "notes.md", b"# Notes\n\nOur win rate against the leading vendors is 35 percent this year."
    )
    job = await _completed(
        world,
        mode="hybrid",
        objective="Analyse the AI customer-support market and its regulatory penalties.",
    )
    report = await world.get(f"/research-jobs/{job['id']}/report")
    assert report["schema_version"] == "argus.report/1"
    assert report["title"]
    statuses = {s["question_id"]: s["status"] for s in report["sections"]}
    assert statuses == {"q1": "answered", "q2": "insufficient_evidence"}
    unknown = next(s for s in report["sections"] if s["status"] == "insufficient_evidence")
    assert unknown["narrative"] == "Insufficient evidence."
    assert any(r["basis"] == "gap" for r in report["recommendations"])
    assert report["executive_summary"]
    assert {f["support"] for f in report["findings"]} <= {"supported", "partial"}
    assert all(f["citations"] for f in report["findings"])

    web = next(s for s in report["sources"] if s["origin"] == "web")
    assert web["url"] == "https://news.example.com/market"
    assert web["retrieved_at"]
    assert re.fullmatch(r"[0-9a-f]{64}", web["content_hash"])
    assert web["extraction_method"] == "html-extraction"
    assert web["reliability"] is not None

    methodology = report["methodology"]
    assert (methodology["questions"], methodology["answered"]) == (2, 1)
    assert methodology["findings_included"] == len(report["findings"])
    assert "report.compose@v1" in methodology["prompts"]
    assert "local/extractive" in methodology["models"]
    quality = report["quality"]
    assert quality["grounding"] == 1.0
    assert quality["references"] == 1.0
    assert 0 < quality["overall"] <= 1

    findings = await world.get(f"/research-jobs/{job['id']}/findings")
    assert {f["support"] for f in findings["findings"]} <= {"supported", "partial"}
    steps = {s["key"]: s["output"] for s in await world.get(f"/research-jobs/{job['id']}/steps")}
    assert steps["report"]["version"] == 1
    assert steps["verify"]["findings"] == len(findings["findings"])


async def test_disagreeing_sources_are_reported_with_an_explained_preference(
    db_settings: Settings, tmp_path: Path
) -> None:
    net = FakeInternet()
    net.site("old.example.com", PUBLIC_A, {"/share": OLD_SHARE})
    net.site("new.example.org", PUBLIC_B, {"/share": NEW_SHARE})
    urls = ["https://old.example.com/share", "https://new.example.org/share"]
    async with open_world(db_settings, tmp_path, net=net, search_urls=urls) as world:
        job = await _completed(
            world, mode="web", objective="Analyse Vendor A market share and its growth drivers."
        )
        listed = await world.get(f"/research-jobs/{job['id']}/contradictions")
        assert listed["withheld"] == 0
        assert len(listed["contradictions"]) == 1
        conflict = listed["contradictions"][0]
        assert conflict["explanation"] == "different_time_periods"
        findings = {
            f["id"]: f
            for f in (await world.get(f"/research-jobs/{job['id']}/findings"))["findings"]
        }
        preferred_id = conflict["finding_a_id" if conflict["preferred"] == "a" else "finding_b_id"]
        assert "25 percent" in findings[preferred_id]["statement"]  # the newer source
        assert findings[conflict["finding_a_id"]]["contested"] is True

        report = await world.get(f"/research-jobs/{job['id']}/report")
        assert len(report["contradictions"]) == 1
        assert "more recent" in report["contradictions"][0]["uncertainty"]
        assert all(f["contested"] for f in report["findings"])
        assert report["quality"]["balance"] == 1.0
        markdown = (
            await world.h.client.get(
                f"{world.base}/research-jobs/{job['id']}/report/export",
                params={"format": "markdown"},
                headers=bearer(world.owner),
            )
        ).text
        assert "## Contradictions" in markdown
        assert "40 percent" in markdown
        assert "25 percent" in markdown  # both values are reported, never silently dropped


async def test_invented_figures_and_ungrounded_prose_never_reach_the_report(
    db_settings: Settings, tmp_path: Path
) -> None:
    def fabricating_analyst(call: ProviderCall) -> str:
        output = FindingsOutput.model_validate_json(local_analyst(call))
        if not call.untrusted:
            return output.model_dump_json()
        first = call.untrusted[0]
        quote = first.text.split("\n\n", 1)[-1].split(".")[0] + "."
        invented = Finding(
            statement="Vendor A holds 99 percent of the market.",
            kind="fact",
            confidence=0.95,
            evidence=[first.label],
            quote=quote,
        )
        return output.model_copy(
            update={"findings": [invented, *output.findings]}
        ).model_dump_json()

    def careless_writer(call: ProviderCall) -> str:
        draft = ReportDraft.model_validate_json(local_report(call))
        if call.variables.get("revision"):
            return draft.model_dump_json()
        sloppy = (
            f"{draft.executive_summary} Revenue reached 77 billion dollars. "
            "Vendor A holds 99 percent of the market (F1)."
        )
        return draft.model_copy(update={"executive_summary": sloppy}).model_dump_json()

    def strict_critic(_: ProviderCall) -> str:
        return CriticOutput(
            scores=CriticScores(coverage=0.9, support=0.3, balance=1.0, clarity=0.9),
            issues=["The summary states figures that no finding supports."],
        ).model_dump_json()

    model = ExternalModel(
        overrides={
            "analysis.findings": fabricating_analyst,
            "report.compose": careless_writer,
            "report.critic": strict_critic,
        }
    )
    async with open_world(db_settings, tmp_path, llm_providers={"anthropic": model}) as world:
        job = await _completed(world, mode="web")
        findings = (await world.get(f"/research-jobs/{job['id']}/findings"))["findings"]
        invented = [f for f in findings if "99 percent" in (f["statement"] or "")]
        assert invented
        for finding in invented:
            assert (finding["support"], finding["kind"]) == ("unsupported", "hypothesis")
            assert finding["confidence"] <= 0.3
            assert "99" in finding["support_rationale"]

        report = await world.get(f"/research-jobs/{job['id']}/report")
        text = json.dumps(report)
        assert "99 percent" not in text
        assert "77 billion" not in text
        assert report["methodology"]["findings_rejected"] >= 1
        assert any("rejected" in item for item in report["limitations"])
        assert report["quality"]["revised"] is True
        assert "The summary states figures that no finding supports." in report["quality"]["issues"]
        tasks = model.tasks()
        assert tasks.count("report.compose") == 2  # one revision after the critic's review
        assert "verification.entailment" in tasks


# ------------------------------------------------------------------- exports and access
async def test_exports_are_inert_audited_and_need_the_export_permission(
    db_settings: Settings, tmp_path: Path
) -> None:
    net = FakeInternet()
    net.site("news.example.com", PUBLIC_A, {"/market": MARKET_PAGE})
    net.site("review.example.org", PUBLIC_B, {"/vendors": RISKY_PAGE})
    urls = ["https://review.example.org/vendors", "https://news.example.com/market"]
    async with open_world(db_settings, tmp_path, net=net, search_urls=urls) as world:
        job = await _completed(world, mode="web")
        export = f"{world.base}/research-jobs/{job['id']}/report/export"

        async def download(fmt: str, token: str | None = None) -> Any:
            return await world.h.client.get(
                export, params={"format": fmt}, headers=bearer(token or world.owner)
            )

        markdown = await download("markdown")
        assert markdown.status_code == 200
        assert markdown.headers["content-type"].startswith("text/markdown")
        assert markdown.headers["content-disposition"].startswith("attachment;")
        assert markdown.headers["cache-control"] == "no-store"
        body = markdown.text
        assert "https://evil.example" not in body
        assert "hxxps\\://evil\\.example" in body  # defanged, then Markdown-escaped
        assert re.search(r"(?<!\\)<img", body) is None
        assert "![" not in body

        rows = list(csv.reader(io.StringIO((await download("csv")).content.decode("utf-8-sig"))))
        statements = [row[rows[0].index("statement")] for row in rows[1:]]
        assert any(s.startswith("'=HYPERLINK") for s in statements)
        assert not any(s.startswith("=") for s in statements)

        pdf = await download("pdf")
        assert pdf.headers["content-type"] == "application/pdf"
        assert pdf.content.startswith(b"%PDF-")
        document = (await download("json")).json()
        assert document["schema_version"] == "argus.report/1"

        _, viewer = await join_org(world.h, world.owner, world.org_id, "viewer")
        await world.get(f"/research-jobs/{job['id']}/report", viewer)  # reading is allowed
        assert (await download("pdf", viewer)).status_code == 403  # exporting is not

        audit = await world.rows(
            "SELECT details FROM audit_logs WHERE action = 'report.exported' ORDER BY chain_seq"
        )
        assert [row["details"]["format"] for row in audit] == ["markdown", "csv", "pdf", "json"]


async def test_a_report_resting_on_restricted_evidence_is_closed_to_lower_clearance(
    world: World,
) -> None:
    await world.upload(
        "board.md",
        b"# Board\n\nThe leading vendors acquisition budget is 90 million dollars.",
        "restricted",
    )
    job = await _completed(world, mode="documents")
    own = await world.get(f"/research-jobs/{job['id']}/report")
    assert "90 million" in json.dumps(own)
    _, viewer = await join_org(world.h, world.owner, world.org_id, "viewer")
    denied = await world.h.client.get(
        f"{world.base}/research-jobs/{job['id']}/report", headers=bearer(viewer)
    )
    assert denied.status_code == 403
    assert "90 million" not in denied.text
    contradictions = await world.get(f"/research-jobs/{job['id']}/contradictions", viewer)
    assert contradictions["contradictions"] == []


async def test_no_report_before_the_report_stage(world: World) -> None:
    job = await world.create_job(mode="documents")
    missing = await world.h.client.get(
        f"{world.base}/research-jobs/{job['id']}/report", headers=bearer(world.owner)
    )
    assert missing.status_code == 404
