"""A research test world: fake web and search, a real app, and an optional stand-in model.

Shared by the research-agent and report suites. Everything except the network edge is real -
queue, pipeline, SSRF-safe fetcher, indexing, retrieval, agents, row-level security and the API.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import text

from argus.apps.worker.main import build_worker
from argus.core.config import Settings
from argus.infrastructure.storage import LocalObjectStore
from argus.modules.llm.types import ProviderCall, ProviderResult
from argus.modules.research.analysis import local_analyst
from argus.modules.research.contradictions import local_contradiction_judge
from argus.modules.research.planning import local_plan
from argus.modules.research.reporting import local_critic, local_report
from argus.modules.research.verification import local_verifier
from argus.modules.sources.search import SearchResult
from tests.fake_network import PUBLIC_A, PUBLIC_B, FakeInternet, html_page
from tests.support import (
    ApiHarness,
    api_harness,
    bearer,
    create_org,
    create_project,
    register_and_login,
)

V1 = "/api/v1"
OBJECTIVE = "Analyse the AI customer-support market and its leading vendors."
MARKET_PAGE = html_page(
    "AI customer support in 2026",
    "<article><p>The AI customer-support market grew 40 percent in 2026.</p>"
    "<p>The leading vendors are Vendor A and Vendor B, according to analysts.</p></article>",
)
VENDOR_PAGE = html_page(
    "Vendor landscape",
    "<article><p>Independent reviewers rank the leading vendors on accuracy.</p></article>",
)
LOCAL_HANDLERS: dict[str, Callable[[ProviderCall], str]] = {
    "research.plan": local_plan,
    "analysis.findings": local_analyst,
    "verification.entailment": local_verifier,
    "verification.contradictions": local_contradiction_judge,
    "report.compose": local_report,
    "report.critic": local_critic,
}


@dataclass
class FakeSearch:
    urls: list[str]
    name: str = "fake"
    queries: list[str] = field(default_factory=list)

    async def search(self, query: str, *, limit: int) -> list[SearchResult]:
        self.queries.append(query)
        return [
            SearchResult(url=url, title="result", snippet="", rank=rank, provider=self.name)
            for rank, url in enumerate(self.urls[:limit], start=1)
        ]

    async def aclose(self) -> None:
        return None


@dataclass
class ExternalModel:
    """Stands in for Claude: answers like the local handlers (or a test's override per task)
    and records every call, so tests can see exactly what left the platform."""

    name: str = "anthropic"
    overrides: dict[str, Callable[[ProviderCall], str]] = field(default_factory=dict)
    calls: list[ProviderCall] = field(default_factory=list)

    async def complete(self, call: ProviderCall) -> ProviderResult:
        self.calls.append(call)
        handler = self.overrides.get(call.task) or LOCAL_HANDLERS[call.task]
        return ProviderResult(
            text=handler(call), served_model=call.model, input_tokens=800, output_tokens=200
        )

    async def aclose(self) -> None:
        return None

    def tasks(self) -> list[str]:
        return [call.task for call in self.calls]


@dataclass
class World:
    h: ApiHarness
    net: FakeInternet
    search: FakeSearch
    owner: str
    org_id: str
    project_id: str

    @property
    def base(self) -> str:
        return f"{V1}/orgs/{self.org_id}/projects/{self.project_id}"

    async def upload(self, name: str, body: bytes, classification: str | None = None) -> str:
        response = await self.h.client.post(
            f"{self.base}/documents",
            files={"file": (name, body, "application/octet-stream")},
            data={"classification": classification} if classification else {},
            headers=bearer(self.owner),
        )
        assert response.status_code == 202, response.text
        await build_worker(self.h.container, queues=("documents", "default")).run_until_idle()
        return str(response.json()["id"])

    async def create_job(self, token: str | None = None, **body: Any) -> dict[str, Any]:
        response = await self.h.client.post(
            f"{self.base}/research-jobs",
            json={"objective": OBJECTIVE, **body},
            headers=bearer(token or self.owner),
        )
        assert response.status_code == 202, response.text
        return dict(response.json())

    async def run_jobs(self) -> None:
        await build_worker(self.h.container, queues=("research",)).run_until_idle()

    async def get(self, path: str, token: str | None = None, expect: int = 200) -> Any:
        response = await self.h.client.get(
            f"{self.base}{path}", headers=bearer(token or self.owner)
        )
        assert response.status_code == expect, response.text
        return response.json()

    async def job(self, job_id: str) -> dict[str, Any]:
        return dict(await self.get(f"/research-jobs/{job_id}"))

    async def pending_approvals(self) -> list[dict[str, Any]]:
        response = await self.h.client.get(
            f"{V1}/orgs/{self.org_id}/approvals?status=pending", headers=bearer(self.owner)
        )
        assert response.status_code == 200, response.text
        return list(response.json())

    async def approve(self, approval_id: str) -> None:
        response = await self.h.client.post(
            f"{V1}/orgs/{self.org_id}/approvals/{approval_id}/decision",
            json={"approve": True, "note": "reviewed"},
            headers=bearer(self.owner),
        )
        assert response.status_code == 200, response.text

    async def put_policy(self, domain: str, policy: str) -> None:
        response = await self.h.client.put(
            f"{V1}/orgs/{self.org_id}/domain-policies/{domain}",
            json={"policy": policy},
            headers=bearer(self.owner),
        )
        assert response.status_code == 200, response.text

    async def member_id(self, email: str) -> str:
        members = (
            await self.h.client.get(f"{V1}/orgs/{self.org_id}/members", headers=bearer(self.owner))
        ).json()
        return next(str(m["user_id"]) for m in members if m["email"] == email)

    async def api_key(self, scopes: list[str]) -> dict[str, Any]:
        response = await self.h.client.post(
            f"{V1}/orgs/{self.org_id}/api-keys",
            json={"name": "automation", "scopes": scopes},
            headers=bearer(self.owner),
        )
        assert response.status_code == 201, response.text
        return dict(response.json())

    async def rows(self, sql: str, **params: Any) -> list[dict[str, Any]]:
        async with self.h.container.database.session(organization_id=UUID(self.org_id)) as session:
            return [dict(row._mapping) for row in await session.execute(text(sql), params)]


def _settings(settings: Settings) -> Settings:
    egress = settings.egress.model_copy(update={"per_domain_interval_s": 0.0})
    return settings.model_copy(update={"egress": egress})


@asynccontextmanager
async def open_world(
    db_settings: Settings,
    tmp_path: Path,
    *,
    net: FakeInternet | None = None,
    search_urls: list[str] | None = None,
    **overrides: Any,
) -> AsyncIterator[World]:
    if net is None:
        net = FakeInternet()
        net.site("news.example.com", PUBLIC_A, {"/market": MARKET_PAGE})
        net.site("research.example.org", PUBLIC_B, {"/vendors": VENDOR_PAGE})
    search = FakeSearch(search_urls or ["https://news.example.com/market"])
    async with api_harness(
        _settings(db_settings),
        fetcher=net.fetcher(),
        search=search,
        storage=LocalObjectStore(tmp_path),
        **overrides,
    ) as h:
        async with h.container.database.session() as session:
            await session.execute(text("DELETE FROM jobs"))
        _, tokens = await register_and_login(h)
        owner = tokens["access_token"]
        org = await create_org(h, owner, "Research Agents Co")
        project = await create_project(h, owner, org["id"])
        yield World(h, net, search, owner, org["id"], project["id"])
