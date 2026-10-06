"""Phase 21: every statement the platform really issues on a growing table can use an index.

Instead of a hand-written list of "hot queries" that drifts from the code, this test records the
SQL the application sends while it does real work - a research job end to end, document upload
and search, the results, monitoring, notification and security APIs - and then asks PostgreSQL
to plan each statement with sequential scans disabled. A plan that still contains a ``Seq Scan``
on one of the growing tables means no index can serve that statement: on a large tenant it would
read the whole table.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import asyncpg
import pytest
from sqlalchemy import event

from argus.apps.worker.main import build_worker
from argus.core.config import Settings
from tests.research_world import V1, World, open_world
from tests.support import DatabaseURLs, bearer

pytestmark = pytest.mark.integration

GROWING = frozenset(
    {
        "jobs",
        "research_jobs",
        "research_steps",
        "research_plans",
        "research_findings",
        "research_citations",
        "research_contradictions",
        "research_reports",
        "approval_requests",
        "sources",
        "source_snapshots",
        "documents",
        "document_chunks",
        "agent_runs",
        "tool_calls",
        "llm_requests",
        "llm_usage_daily",
        "notifications",
        "monitors",
        "monitor_targets",
        "monitor_changes",
        "audit_logs",
        "audit_verifications",
        "api_keys",
        "organization_members",
        "invitations",
        "projects",
        "project_members",
    }
)
TABLE_REFERENCE = re.compile(r"\b(?:FROM|JOIN|UPDATE)\s+(?:public\.)?([a-z_]+)", re.IGNORECASE)


@pytest.fixture
async def world(db_settings: Settings, tmp_path: Path) -> AsyncIterator[World]:
    async with open_world(db_settings, tmp_path) as opened:
        yield opened


def seq_scans(plan: Any) -> list[str]:
    found: list[str] = []
    stack = [plan]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if node.get("Node Type") == "Seq Scan" and node.get("Relation Name") in GROWING:
                found.append(str(node["Relation Name"]))
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return found


async def exercise(world: World) -> None:
    """Real work through the public API and the worker."""
    h = world.h
    job = await world.create_job()
    await world.run_jobs()
    for path in (
        "",
        "/steps",
        "/plan",
        "/findings",
        "/agent-runs",
        "/contradictions",
        "/report",
    ):
        await world.get(f"/research-jobs/{job['id']}{path}")
    await world.get("/research-jobs")
    sources = await world.get("/sources")
    if sources["items"]:
        source_id = sources["items"][0]["id"]
        await world.get(f"/sources/{source_id}")
        await world.get(f"/sources/{source_id}/snapshots")
    await world.upload("notes.txt", b"Vendor A leads the AI support market in 2026. " * 20)
    await world.get("/documents")
    search = await h.client.post(
        f"{world.base}/search",
        json={"query": "support market vendors"},
        headers=bearer(world.owner),
    )
    assert search.status_code == 200, search.text
    monitor = await h.client.post(
        f"{world.base}/monitors",
        json={
            "name": "Market",
            "kind": "urls",
            "urls": ["https://news.example.com/market"],
            "topics": ["pricing"],
            "interval_minutes": 60,
        },
        headers=bearer(world.owner),
    )
    assert monitor.status_code == 201, monitor.text
    monitor_id = monitor.json()["id"]
    await h.client.post(f"{world.base}/monitors/{monitor_id}/run", headers=bearer(world.owner))
    await build_worker(h.container, queues=("monitoring",)).run_until_idle()
    await world.get(f"/monitors/{monitor_id}/changes")
    await world.get("/monitors")
    org = f"{V1}/orgs/{world.org_id}"
    for path in (
        "/notifications",
        "/notifications/unread-count",
        "/audit-logs",
        "/approvals",
        "/api-keys",
        "/members",
        "/security/summary",
        "/security/events",
        "/security/kill-switches",
        "/security/audit-verifications",
    ):
        response = await h.client.get(f"{org}{path}", headers=bearer(world.owner))
        assert response.status_code == 200, (path, response.text)
    await h.client.post(f"{org}/security/audit-verifications", headers=bearer(world.owner))
    await h.container.integrity.verify_due()
    await h.container.queue.reap_expired()
    await h.container.queue.depth()
    await h.container.monitors.dispatch_due()


async def test_every_statement_on_a_growing_table_can_use_an_index(
    world: World, database_urls: DatabaseURLs
) -> None:
    captured: dict[str, tuple[Any, ...]] = {}

    def record(
        conn: Any, cursor: Any, statement: str, parameters: Any, context: Any, executemany: bool
    ) -> None:
        del conn, cursor, context
        head = statement.lstrip().split(None, 1)[0].upper() if statement.strip() else ""
        if executemany or head not in {"SELECT", "WITH", "UPDATE", "DELETE"}:
            return
        tables = {name.lower() for name in TABLE_REFERENCE.findall(statement)}
        if tables & GROWING:
            captured.setdefault(statement, tuple(parameters or ()))

    engine = world.h.container.database.engine.sync_engine
    event.listen(engine, "before_cursor_execute", record)
    try:
        await exercise(world)
    finally:
        event.remove(engine, "before_cursor_execute", record)
    assert len(captured) >= 40, f"too few statements captured ({len(captured)})"

    problems: list[str] = []
    conn = await asyncpg.connect(database_urls.admin)
    try:
        for statement, parameters in captured.items():
            async with conn.transaction():
                await conn.execute("SET LOCAL enable_seqscan = off")
                raw = await conn.fetchval(f"EXPLAIN (FORMAT JSON) {statement}", *parameters)
            plan = json.loads(raw) if isinstance(raw, str) else raw
            if scans := seq_scans(plan):
                problems.append(f"{sorted(set(scans))}: {' '.join(statement.split())[:300]}")
    finally:
        await conn.close()
    assert not problems, "statements without a usable index:\n" + "\n".join(problems)
