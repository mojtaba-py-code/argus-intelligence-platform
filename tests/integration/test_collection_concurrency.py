"""Phase 21: a research job fetches its sources concurrently, within the configured bound.

Four sites on four hosts, each answering slowly. The fake network counts how many responses are
awaited at the same moment: one at a time with ``max_concurrent_fetches=1``, several (never more
than the bound) with four. Counting instead of timing keeps the test exact on a loaded machine.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.core.config import Settings
from tests.fake_network import PUBLIC_A, PUBLIC_B, PUBLIC_C, PUBLIC_D, FakeInternet, html_page
from tests.research_world import open_world

pytestmark = pytest.mark.integration
SITES = {
    "alpha.example.com": PUBLIC_A,
    "beta.example.com": PUBLIC_B,
    "gamma.example.com": PUBLIC_C,
    "delta.example.com": PUBLIC_D,
}


def network() -> FakeInternet:
    net = FakeInternet()
    for host, ip in SITES.items():
        net.site(
            host,
            ip,
            {
                "/report": html_page(
                    f"{host} market report",
                    "<p>The AI customer-support market grew 40 percent in 2026.</p>",
                )
            },
        )
    net.latency_s = 0.15
    return net


async def peak_in_flight(db_settings: Settings, tmp_path: Path, fetches: int) -> int:
    settings = db_settings.model_copy(
        update={"egress": db_settings.egress.model_copy(update={"max_concurrent_fetches": fetches})}
    )
    net = network()
    urls = [f"https://{host}/report" for host in SITES]
    async with open_world(settings, tmp_path / str(fetches), net=net, search_urls=urls) as world:
        job = await world.create_job(max_sources=4)
        await world.run_jobs()
        assert (await world.job(job["id"]))["status"] == "completed"
        fetched = {r.host for r in net.requests if r.path == "/report"}
        assert fetched == set(SITES)
        return net.peak_waiting


async def test_sources_are_fetched_concurrently_within_the_bound(
    db_settings: Settings, tmp_path: Path
) -> None:
    assert await peak_in_flight(db_settings, tmp_path, fetches=1) == 1
    assert 2 <= await peak_in_flight(db_settings, tmp_path, fetches=4) <= 4
