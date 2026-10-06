"""Phase 13 - search and collection, as deterministic code over the plan.

No model chooses what to fetch: the plan's queries (written by the planner from the user's own
objective) go to the search provider, and the results go through ``SourceService.collect`` - the
same SSRF-guarded, robots-respecting, injection-assessing path as every other page. Domains that an
organisation marked ``require_approval`` pause the job for a human decision (``crawl_scope``); once
approved, those domains - and only those - are read for this job.

Searches and fetches run concurrently, bounded per job (``search.concurrency``,
``egress.max_concurrent_fetches``): a job's wall-clock time is no longer the sum of every page's
latency. Per-host politeness still serialises requests to the same site across all workers, and
cancellation is checked before every request.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from typing import Any, Final

from sqlalchemy import select

from argus.core.logging import get_logger
from argus.modules.research.creator import creator_access
from argus.modules.research.models import ApprovalRequest
from argus.modules.research.pipeline import (
    ApprovalRequired,
    JobCancelled,
    StageContext,
    StageFailed,
)
from argus.modules.sources.search import SearchResult
from argus.security.permissions import Permission
from argus.security.ssrf import EgressBlocked, parse_url

log = get_logger(__name__)
_CANDIDATE_FACTOR: Final = 2  # candidates gathered per allowed source, before deduplication


class CollectStage:
    key = "collect"
    weight = 3

    async def run(self, ctx: StageContext) -> dict[str, Any]:
        if ctx.job.mode == "documents":
            return {"skipped": "documents-only research"}
        access = await creator_access(ctx)
        if not access.can(Permission.SOURCES_MANAGE):
            raise StageFailed(
                "access_revoked", "The job's creator can no longer add web sources to this project."
            )
        services = ctx.services
        plan = ctx.outputs.get("plan", {})
        queries = [
            (question["id"], query)
            for question in plan.get("questions", [])
            for query in question.get("search_queries", [])
        ]
        per_query = services.settings.search.max_results_per_query
        searches = asyncio.Semaphore(services.settings.search.concurrency)

        async def search(query: str) -> list[SearchResult] | None:
            async with searches:
                if await _cancelled(ctx):
                    return None
                try:
                    return list(await services.search.search(query, limit=per_query))
                except Exception as exc:  # noqa: BLE001 - an outage costs coverage, not the job
                    log.warning("research.search_failed", error=type(exc).__name__)
                    return None

        # Results are merged in plan order, so the chosen sources do not depend on timing.
        found = await asyncio.gather(*(search(query) for _, query in queries))
        await ctx.check_cancelled()
        candidates: dict[str, str] = {}
        failed_queries = sum(1 for results in found if results is None)
        for (_, query), results in zip(queries, found, strict=True):
            for result in results or []:
                candidates.setdefault(result.url, query)
        limit = min(len(candidates), ctx.job.max_sources)

        approved = await self._approved_domains(ctx)
        policies = await services.sources.domain_policies(ctx.scope)
        outcomes: Counter[str] = Counter()
        waiting: set[str] = set()
        fetches = asyncio.Semaphore(services.settings.egress.max_concurrent_fetches)

        async def collect(url: str, query: str) -> None:
            async with fetches:
                if await _cancelled(ctx):
                    return
                try:
                    outcome = await services.sources.collect(
                        ctx.scope,
                        url,
                        discovered_via="search",
                        job_id=ctx.job.id,
                        search_query=query,
                        policies=policies,
                        approved_domains=approved,
                    )
                except EgressBlocked:
                    outcomes["blocked"] += 1
                    return
            outcomes[outcome.status] += 1
            if outcome.status == "needs_approval":
                waiting.add(parse_url(url).host)

        await asyncio.gather(
            *(collect(url, query) for url, query in list(candidates.items())[:limit])
        )
        await ctx.check_cancelled()

        if waiting and "crawl_scope" not in ctx.approvals:
            raise ApprovalRequired(
                "crawl_scope",
                f"{len(waiting)} domain(s) require approval before this job may read them.",
                {"domains": sorted(waiting)},
            )
        return {
            "queries": len(queries),
            "failed_queries": failed_queries,
            "candidates": len(candidates),
            "fetched": outcomes["fetched"],
            "blocked": outcomes["blocked"],
            "failed": outcomes["failed"],
            "awaiting_approval": sorted(waiting),
        }

    @staticmethod
    async def _approved_domains(ctx: StageContext) -> frozenset[str]:
        if "crawl_scope" not in ctx.approvals:
            return frozenset()
        async with ctx.services.database.tenant(ctx.scope, read_only=True) as session:
            rows = (
                await session.execute(
                    select(ApprovalRequest.details).where(
                        ApprovalRequest.job_id == ctx.job.id,
                        ApprovalRequest.kind == "crawl_scope",
                        ApprovalRequest.status == "approved",
                    )
                )
            ).scalars()
            return frozenset(
                str(domain)
                for details in rows
                for domain in (details or {}).get("domains", [])
                if isinstance(domain, str)
            )


async def _cancelled(ctx: StageContext) -> bool:
    """Whether the job was cancelled; concurrent requests stop starting, and the stage raises
    once they have all returned (no exception groups, no half-cancelled siblings)."""
    try:
        await ctx.check_cancelled()
    except JobCancelled:
        return True
    return False
