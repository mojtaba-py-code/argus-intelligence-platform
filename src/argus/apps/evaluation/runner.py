"""The evaluation runner: every dataset case as a real research job, through the public API.

For each run the runner builds its own container around an in-memory corpus web and a corpus
search, signs in an evaluation user, and drives cases through the HTTP API in-process - the same
authentication, authorisation, pipeline, agents, gateway and renderers as production. Only the
models vary: the deterministic local handlers by default, or the configured providers with
``live=True``. Everything sent to an external provider is recorded, so a canary that leaks into a
prompt is caught.

Run it against a disposable database: it creates organisations and processes the job queue.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
from sqlalchemy import text

from argus.apps.api.main import create_app
from argus.apps.container import Container, build_container, create_providers, fetch_policy
from argus.apps.worker.main import build_worker
from argus.core.config import Settings
from argus.infrastructure.email import MemoryMailer
from argus.infrastructure.storage import LocalObjectStore
from argus.modules.evaluation.corpus import CorpusNetwork, CorpusSearch
from argus.modules.evaluation.dataset import EvalCase, EvalDataset
from argus.modules.evaluation.metrics import (
    CaseObservation,
    CaseResult,
    aggregate,
    consistency,
    evaluate,
)
from argus.modules.llm.providers.base import Provider
from argus.modules.llm.types import ProviderCall, ProviderResult
from argus.security.ratelimit import MemoryRateLimiter

V1 = "/api/v1"


class RecordingProvider:
    """Passes calls through and keeps the text that left for the provider."""

    def __init__(self, inner: Provider, sink: list[str]) -> None:
        self._inner = inner
        self._sink = sink
        self.name = inner.name

    async def complete(self, call: ProviderCall) -> ProviderResult:
        self._sink.append(f"{call.system}\n{call.user}")
        return await self._inner.complete(call)

    async def aclose(self) -> None:
        await self._inner.aclose()


@dataclass
class RunSummary:
    dataset: str
    version: int
    live: bool
    results: list[CaseResult]
    metrics: dict[str, float]
    consistency: float | None = None
    regressions: list[str] = field(default_factory=list)

    @property
    def failures(self) -> dict[str, list[str]]:
        return {r.case_id: r.failures for r in self.results if r.failures}

    def to_json(self) -> dict[str, Any]:
        return {
            "dataset": self.dataset,
            "version": self.version,
            "live": self.live,
            "metrics": self.metrics,
            "consistency": self.consistency,
            "regressions": self.regressions,
            "cases": [r.to_json() for r in self.results],
        }


@dataclass
class _Session:
    client: httpx.AsyncClient
    container: Container
    network: CorpusNetwork
    search: CorpusSearch
    outbound: list[str]
    token: str

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}


async def run_evaluation(
    settings: Settings,
    dataset: EvalDataset,
    *,
    storage_root: Path,
    tags: set[str] | None = None,
    repeat: int = 1,
    live: bool = False,
    providers: Mapping[str, Provider] | None = None,
) -> RunSummary:
    """Run the selected cases ``repeat`` times; ``providers`` overrides the model providers."""
    network, search = CorpusNetwork(), CorpusSearch()
    outbound: list[str] = []
    limiter = MemoryRateLimiter()  # private to this run: reset between cases
    egress = settings.egress.model_copy(update={"per_domain_interval_s": 0.0})
    settings = settings.model_copy(update={"egress": egress})
    if providers is None:
        providers = create_providers(settings.llm) if live else {}
    container = build_container(
        settings,
        role="cli",
        mailer=MemoryMailer(),
        limiter=limiter,
        fetcher=network.fetcher(fetch_policy(settings.egress)),
        search=search,
        storage=LocalObjectStore(storage_root),
        llm_providers={name: RecordingProvider(p, outbound) for name, p in providers.items()},
    )
    app = create_app(settings, container=container)
    base = f"http://{settings.http.allowed_hosts[0]}"
    results: list[CaseResult] = []
    statements: dict[str, list[list[str]]] = {}
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=base) as client,
    ):
        session = _Session(client, container, network, search, outbound, "")
        session.token = await _sign_in(session)
        for case in dataset.select(tags):
            network.load(case)
            for _ in range(repeat):
                await limiter.reset()
                result, included = await _run_case(session, case)
                results.append(result)
                statements.setdefault(case.id, []).append(included)
    await container.aclose()
    pairs = [runs[:2] for runs in statements.values() if len(runs) >= 2]
    summary = RunSummary(
        dataset=dataset.name,
        version=dataset.version,
        live=live,
        results=results,
        metrics=aggregate(results),
        consistency=round(sum(consistency(a, b) for a, b in pairs) / len(pairs), 4)
        if pairs
        else None,
    )
    if summary.consistency is not None:
        summary.metrics["consistency"] = summary.consistency
    return summary


async def _sign_in(session: _Session) -> str:
    email = f"eval-{secrets.token_hex(6)}@example.com"
    password = secrets.token_urlsafe(24)
    await session.container.auth.create_user(
        email=email, password=password, full_name="Evaluation runner", verified=True
    )
    response = await session.client.post(
        f"{V1}/auth/login", json={"email": email, "password": password}
    )
    response.raise_for_status()
    return str(response.json()["access_token"])


async def _call(session: _Session, method: str, path: str, **kwargs: Any) -> Any:
    response = await session.client.request(method, path, headers=session.headers(), **kwargs)
    if response.status_code >= 400:
        msg = f"{method} {path} -> {response.status_code}: {response.text[:300]}"
        raise RuntimeError(msg)
    return response.json() if response.content else None


async def _run_case(session: _Session, case: EvalCase) -> tuple[CaseResult, list[str]]:
    org = await _call(session, "POST", f"{V1}/orgs", json={"name": f"Eval {case.id}"})
    project = await _call(
        session, "POST", f"{V1}/orgs/{org['id']}/projects", json={"name": case.id}
    )
    base = f"{V1}/orgs/{org['id']}/projects/{project['id']}"
    for document in case.documents:
        await _call(
            session,
            "POST",
            f"{base}/documents",
            files={
                "file": (document.name, document.text.encode("utf-8"), "application/octet-stream")
            },
            data={"classification": document.classification},
        )
    if case.documents:
        await build_worker(session.container, queues=("documents", "default")).run_until_idle()
    session.search.results = list(case.search_results)
    outbound_before = len(session.outbound)
    started = time.perf_counter()
    job = await _call(
        session,
        "POST",
        f"{base}/research-jobs",
        json={"objective": case.objective, "mode": case.mode},
    )
    await build_worker(session.container, queues=("research",)).run_until_idle()
    latency = time.perf_counter() - started
    job_path = f"{base}/research-jobs/{job['id']}"
    job = await _call(session, "GET", job_path)
    report = None
    if job["status"] == "completed":
        report = await _call(session, "GET", f"{job_path}/report")
    findings = (await _call(session, "GET", f"{job_path}/findings"))["findings"]
    runs = await _call(session, "GET", f"{job_path}/agent-runs")
    ledger, approvals, ceiling = await _ledger(session.container, UUID(org["id"]), UUID(job["id"]))
    observation = CaseObservation(
        case=case,
        job=job,
        report=report,
        findings=findings,
        agent_runs=runs,
        ledger=ledger,
        outbound=session.outbound[outbound_before:],
        touched_hosts=frozenset(
            h for h in case.expect.never_contacted if session.network.touched(h)
        ),
        external_ceiling=ceiling,
        approvals=approvals,
        latency_s=latency,
    )
    included = [str(f["statement"]) for f in (report or {}).get("findings", [])]
    return evaluate(observation), included


async def _ledger(
    container: Container, organization_id: UUID, job_id: UUID
) -> tuple[Sequence[dict[str, Any]], frozenset[str], int]:
    async with container.database.session(organization_id=organization_id) as session:
        rows = [
            dict(row._mapping)
            for row in await session.execute(
                text(
                    "SELECT provider, model, locality, classification, outcome, error_code "
                    "FROM llm_requests WHERE job_id = :job"
                ),
                {"job": job_id},
            )
        ]
        approvals = frozenset(
            (
                await session.execute(
                    text(
                        "SELECT kind FROM approval_requests WHERE job_id = :job "
                        "AND status = 'approved'"
                    ),
                    {"job": job_id},
                )
            ).scalars()
        )
        settings = (
            await session.execute(
                text("SELECT settings FROM organizations WHERE id = :org"),
                {"org": organization_id},
            )
        ).scalar_one()
    external = int(((settings or {}).get("data_policy") or {}).get("external", 1))
    return rows, approvals, external
