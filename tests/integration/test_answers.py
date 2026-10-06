"""Cited answers (RAG generation) end to end: retrieval scope, gateway routing, citation checks."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import text

from argus.apps.worker.main import build_worker
from argus.core.config import Settings
from argus.infrastructure.storage import LocalObjectStore
from argus.modules.knowledge.answer import INSUFFICIENT
from argus.modules.llm.types import ProviderCall, ProviderResult
from tests.document_fixtures import make_pdf
from tests.support import (
    ApiHarness,
    api_harness,
    bearer,
    create_org,
    create_project,
    join_org,
    register_and_login,
)

pytestmark = pytest.mark.integration
V1 = "/api/v1"


@dataclass
class FakeClaude:
    """Answers like a model would - citing the first evidence block - or fabricates a quote."""

    name: str = "anthropic"
    fabricate: bool = False
    calls: list[ProviderCall] = field(default_factory=list)

    async def complete(self, call: ProviderCall) -> ProviderResult:
        self.calls.append(call)
        first = call.untrusted[0]
        body = first.text.split("\n\n", 1)[-1]
        quote = (
            "Revenue tripled overnight in every market."
            if self.fabricate
            else body.split(".")[0] + "."
        )
        output = {
            "answer": f"{quote} [{first.label}]",
            "claims": [{"statement": quote, "evidence": [first.label], "quote": quote}],
            "insufficient_evidence": False,
        }
        return ProviderResult(
            text=json.dumps(output), served_model=call.model, input_tokens=900, output_tokens=120
        )

    async def aclose(self) -> None:
        return None


@dataclass
class World:
    h: ApiHarness
    fake: FakeClaude
    owner: str
    org_id: str
    project_id: str

    @property
    def base(self) -> str:
        return f"{V1}/orgs/{self.org_id}/projects/{self.project_id}"

    async def upload(self, filename: str, data: bytes, classification: str | None = None) -> str:
        response = await self.h.client.post(
            f"{self.base}/documents",
            files={"file": (filename, data, "application/octet-stream")},
            data={"classification": classification} if classification else {},
            headers=bearer(self.owner),
        )
        assert response.status_code == 202, response.text
        return str(response.json()["id"])

    async def process(self) -> None:
        await build_worker(self.h.container, queues=("documents", "default")).run_until_idle()

    async def ask(
        self, question: str, token: str | None = None, expect: int = 200
    ) -> dict[str, Any]:
        response = await self.h.client.post(
            f"{self.base}/ask", json={"question": question}, headers=bearer(token or self.owner)
        )
        assert response.status_code == expect, response.text
        return dict(response.json())


@pytest.fixture
async def world(db_settings: Settings, tmp_path: Path) -> AsyncIterator[World]:
    fake = FakeClaude()
    async with api_harness(
        db_settings, storage=LocalObjectStore(tmp_path), llm_providers={"anthropic": fake}
    ) as h:
        async with h.container.database.session() as session:
            await session.execute(text("DELETE FROM jobs"))
        _, tokens = await register_and_login(h)
        owner = tokens["access_token"]
        org = await create_org(h, owner, "Answers Co")
        project = await create_project(h, owner, org["id"])
        yield World(h, fake, owner, org["id"], project["id"])


async def test_confidential_evidence_is_answered_locally_with_verified_citations(
    world: World,
) -> None:
    await world.upload(
        "handbook.pdf",
        make_pdf(
            ["Argon2id is the password hashing function we use.", "Sessions expire after 30 days."]
        ),
    )
    await world.process()
    answer = await world.ask("Which password hashing function do we use?")
    assert world.fake.calls == []  # confidential (the default) never goes to the external model
    assert answer["provider"] == "local"
    assert answer["insufficient_evidence"] is False
    claim = answer["claims"][0]
    assert claim["verified"] is True
    assert "Argon2id" in claim["quote"]
    citation = claim["citations"][0]
    assert (citation["filename"], citation["page_start"]) == ("handbook.pdf", 1)
    assert answer["cost_usd"] == "0.000000"


async def test_internal_evidence_may_use_the_external_model_and_is_checked(world: World) -> None:
    await world.upload(
        "wiki.md", b"# Laptops\n\nLaptops are requested through the IT portal.", "internal"
    )
    await world.process()
    answer = await world.ask("How are laptops requested?")
    assert len(world.fake.calls) == 1
    assert answer["provider"] == "anthropic"
    assert answer["claims"][0]["verified"] is True
    assert answer["insufficient_evidence"] is False
    call = world.fake.calls[0]
    assert call.output_model is not None
    assert call.untrusted[0].label == "E1"
    async with world.h.container.database.session(organization_id=UUID(world.org_id)) as session:
        outcomes = (await session.execute(text("SELECT outcome FROM llm_requests"))).scalars().all()
    assert outcomes == ["ok"]


async def test_fabricated_quotes_are_never_presented_as_supported(world: World) -> None:
    world.fake.fabricate = True
    await world.upload("wiki.md", b"# Revenue\n\nRevenue grew 5 percent in Europe.", "internal")
    await world.process()
    answer = await world.ask("How did revenue change?")
    assert answer["claims"][0]["verified"] is False
    assert answer["insufficient_evidence"] is True
    assert answer["answer"] == INSUFFICIENT


async def test_no_evidence_means_no_model_call(world: World) -> None:
    answer = await world.ask("What is the airspeed of an unladen swallow?")
    assert (answer["insufficient_evidence"], answer["provider"], answer["evidence_count"]) == (
        True,
        None,
        0,
    )
    assert world.fake.calls == []


async def test_asking_requires_research_permission(world: World) -> None:
    _, viewer = await join_org(world.h, world.owner, world.org_id, "viewer")
    await world.ask("Anything?", viewer, expect=403)
    bad = await world.h.client.post(
        f"{world.base}/ask", json={"question": "x"}, headers=bearer(world.owner)
    )
    assert bad.status_code == 422
