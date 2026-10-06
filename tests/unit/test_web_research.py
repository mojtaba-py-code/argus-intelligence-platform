"""Phases 5-6 building blocks: robots.txt, politeness, search providers and reputation."""

from __future__ import annotations

import json
import time
from pathlib import Path

import httpx
import pytest
from fakeredis import FakeAsyncRedis
from pydantic import SecretStr, ValidationError

from argus.core.config import Environment, SearchSettings
from argus.infrastructure.redis import RedisKeys
from argus.modules.sources.reputation import (
    ReputationModel,
    default_reputation_model,
    domain_matches,
)
from argus.modules.sources.robots import Politeness, RobotsCache
from argus.modules.sources.search import (
    BraveSearch,
    NoSearch,
    SearxngSearch,
    StaticSearch,
    clean_results,
    create_search_provider,
)
from argus.security.fetcher import FetchError
from argus.security.ratelimit import MemoryRateLimiter
from argus.security.ssrf import parse_url
from tests.fake_network import PUBLIC_A, PUBLIC_B, FakeInternet, http_response

AGENT = "ArgusResearchBot/0.1 (+https://example.com/bot)"


def robots_site(body: str | list[bytes] | None) -> FakeInternet:
    net = FakeInternet()
    net.site("site.example.com", PUBLIC_A, {}, robots=body)
    return net


async def decide(
    net: FakeInternet, path: str, cache: RobotsCache | None = None
) -> tuple[bool, float | None, str | None]:
    cache = cache or RobotsCache(net.fetcher(), user_agent=AGENT)
    decision = await cache.check(parse_url(f"https://site.example.com{path}"))
    return decision.allowed, decision.crawl_delay_s, decision.reason


# --------------------------------------------------------------------------- robots.txt
@pytest.mark.parametrize(
    ("robots", "path", "allowed"),
    [
        ("User-agent: *\nDisallow: /private\n", "/private/x", False),
        ("User-agent: *\nDisallow: /private\n", "/public", True),
        ("User-agent: *\nDisallow: /*.pdf$\n", "/report.pdf", False),  # wildcards (RFC 9309)
        ("User-agent: *\nDisallow: /*.pdf$\n", "/report.pdf.html", True),
        ("User-agent: *\nDisallow: /\nAllow: /open\n", "/open/page", True),  # longest match wins
        ("User-agent: ArgusResearchBot\nDisallow: /\n\nUser-agent: *\nAllow: /\n", "/x", False),
        ("User-agent: OtherBot\nDisallow: /\n", "/x", True),
        ("", "/anything", True),
    ],
)
async def test_robots_rules(robots: str, path: str, allowed: bool) -> None:
    assert (await decide(robots_site(robots), path))[0] is allowed


async def test_disallowed_reason_and_crawl_delay_cap() -> None:
    net = robots_site("User-agent: *\nCrawl-delay: 120\nDisallow: /no\n")
    assert await decide(net, "/no") == (False, 30.0, "disallowed")  # delay capped at 30 s
    assert await decide(net, "/yes") == (True, 30.0, None)


async def test_status_codes_follow_rfc_9309() -> None:
    missing = robots_site(None)  # 404 -> no restrictions
    assert await decide(missing, "/x") == (True, None, None)
    for status in (500, 503):
        failing = robots_site(http_response("down", status=status, content_type="text/plain"))
        assert await decide(failing, "/x") == (False, None, "unreachable")
    gone = robots_site(http_response("gone", status=410, content_type="text/plain"))
    assert (await decide(gone, "/x"))[0] is True


async def test_unreachable_host_is_assumed_disallowed() -> None:
    net = FakeInternet()
    net.host("site.example.com", PUBLIC_A)  # resolves, but nothing listens
    assert await decide(net, "/x") == (False, None, "unreachable")


async def test_robots_for_a_blocked_host_reports_the_real_cause() -> None:
    net = FakeInternet()
    net.host("site.example.com", "10.1.2.3")
    with pytest.raises(FetchError) as caught:
        await decide(net, "/x")
    assert caught.value.code == "blocked"
    assert net.connections == []


async def test_robots_txt_is_fetched_once_and_shared_through_redis() -> None:
    net = robots_site("User-agent: *\nDisallow: /private\n")
    redis = FakeAsyncRedis()
    keys = RedisKeys("argus", Environment.TESTING)
    first = RobotsCache(net.fetcher(), user_agent=AGENT, redis=redis, keys=keys)
    second = RobotsCache(net.fetcher(), user_agent=AGENT, redis=redis, keys=keys)  # another worker
    assert (await decide(net, "/private/a", first))[0] is False
    assert (await decide(net, "/public", first))[0] is True
    assert (await decide(net, "/private/b", second))[0] is False
    assert net.paths() == ["/robots.txt"]
    await redis.aclose()


async def test_oversized_robots_txt_is_ignored_as_no_restrictions() -> None:
    huge = "User-agent: *\n" + "Disallow: /x\n" * 60_000  # > 512 KiB
    assert (await decide(robots_site(huge), "/x"))[0] is True


# -------------------------------------------------------------------------- politeness
async def test_politeness_spaces_requests_per_host() -> None:
    politeness = Politeness(MemoryRateLimiter(), interval_s=0.2)
    started = time.perf_counter()
    await politeness.wait("a.example.com")
    await politeness.wait("b.example.com")  # other host: no wait
    assert time.perf_counter() - started < 0.1
    await politeness.wait("a.example.com")
    assert time.perf_counter() - started >= 0.15


async def test_crawl_delay_extends_the_interval() -> None:
    politeness = Politeness(MemoryRateLimiter(), interval_s=0.0)
    started = time.perf_counter()
    await politeness.wait("a.example.com")  # interval 0 and no crawl delay: never waits
    await politeness.wait("a.example.com")
    assert time.perf_counter() - started < 0.1
    await politeness.wait("c.example.com", 0.2)
    await politeness.wait("c.example.com", 0.2)
    assert time.perf_counter() - started >= 0.15


# ------------------------------------------------------------------------------ search
def test_search_results_are_validated_deduplicated_and_sanitised() -> None:
    raw = [
        ("https://example.com/a", "Good ‮title", "snippet​ one"),
        ("https://example.com/a#dup", "duplicate", ""),
        ("http://127.0.0.1/admin", "internal", ""),
        ("http://169.254.169.254/latest", "metadata", ""),
        ("javascript:alert(1)", "xss", ""),
        ("https://user:pw@example.com/", "credentials", ""),
        ("https://example.org/b", "second", "s"),
        ("https://example.net/c", "third", "s"),
    ]
    results = clean_results(raw, "test", limit=2)
    assert [r.url for r in results] == ["https://example.com/a", "https://example.org/b"]
    assert [r.rank for r in results] == [1, 2]
    assert "‮" not in results[0].title  # bidi override removed


async def test_static_search_ranks_by_term_overlap(tmp_path: Path) -> None:
    file = tmp_path / "results.json"
    file.write_text(
        json.dumps(
            [
                {"url": "https://a.example.com/", "title": "Cloud security", "snippet": "posture"},
                {
                    "url": "https://b.example.com/",
                    "title": "AI support market",
                    "keywords": "chatbots",
                },
                {
                    "url": "https://c.example.com/",
                    "title": "AI market",
                    "snippet": "support chatbots",
                },
                {"url": "http://10.0.0.1/", "title": "AI support market chatbots"},
            ]
        ),
        encoding="utf-8",
    )
    provider = StaticSearch.from_file(file)
    results = await provider.search("AI support chatbots market", limit=5)
    assert [r.url for r in results] == ["https://b.example.com/", "https://c.example.com/"]
    assert await provider.search("unrelated words", limit=5) == []


async def test_brave_provider_request_and_parsing() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "web": {
                    "results": [
                        {"url": "https://example.com/r1", "title": "R1", "description": "first"},
                        {"url": "http://localhost/", "title": "bad", "description": ""},
                        "not-a-dict",
                    ]
                }
            },
        )

    provider = BraveSearch(
        "brave-test-key", httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    results = await provider.search("ai market " * 100, limit=50)
    await provider.aclose()
    assert [r.url for r in results] == ["https://example.com/r1"]
    request = seen[0]
    assert request.headers["X-Subscription-Token"] == "brave-test-key"
    assert request.url.params["count"] == "20"  # provider maximum
    assert len(request.url.params["q"]) == 400  # query length bounded


async def test_searxng_provider_errors_surface() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/search"
        assert request.url.params["format"] == "json"
        return httpx.Response(503)

    provider = SearxngSearch(
        "http://searxng:8080/", httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    with pytest.raises(httpx.HTTPStatusError):
        await provider.search("anything", limit=3)
    await provider.aclose()


async def test_provider_factory_and_fail_fast_settings(tmp_path: Path) -> None:
    assert isinstance(create_search_provider(SearchSettings(), user_agent=AGENT), NoSearch)
    file = tmp_path / "r.json"
    file.write_text("[]", encoding="utf-8")
    static = create_search_provider(
        SearchSettings(provider="static", static_results_file=file), user_agent=AGENT
    )
    assert isinstance(static, StaticSearch)
    brave = create_search_provider(
        SearchSettings(provider="brave", brave_api_key=SecretStr("k")), user_agent=AGENT
    )
    assert isinstance(brave, BraveSearch)
    await brave.aclose()
    for provider in ("brave", "searxng", "static"):
        with pytest.raises(ValidationError, match="requires search"):
            SearchSettings(provider=provider)


# -------------------------------------------------------------------------- reputation
@pytest.mark.parametrize(
    ("host", "score", "tier"),
    [
        ("www.nist.gov", 0.9, "high"),
        ("data.census.gov", 0.9, "high"),
        ("en.wikipedia.org", 0.7, "medium"),
        ("someone.medium.com", 0.3, "low"),
        ("notmedium.com", 0.5, "unknown"),  # label boundary: not a subdomain of medium.com
        ("example.com", 0.5, "unknown"),
        ("ARXIV.ORG.", 0.9, "high"),
    ],
)
def test_reputation_priors(host: str, score: float, tier: str) -> None:
    reputation = default_reputation_model().lookup(host)
    assert (reputation.score, reputation.tier) == (score, tier)


def test_reputation_override_and_custom_file(tmp_path: Path) -> None:
    model = default_reputation_model()
    assert model.lookup("medium.com", override=0.2).tier == "low"
    assert model.lookup("medium.com", override=0.6).tier == "medium"
    custom = tmp_path / "rep.yaml"
    custom.write_text(
        "default: 0.4\ntiers: {high: 0.95, medium: 0.6, low: 0.2}\n"
        "domains: {high: [corp.example], medium: [], low: [.biz]}\n",
        encoding="utf-8",
    )
    loaded = ReputationModel.load(custom)
    assert loaded.lookup("docs.corp.example").score == 0.95
    assert loaded.lookup("deals.biz").tier == "low"
    assert loaded.lookup("other.example").score == 0.4


def test_domain_policy_matching_respects_label_boundaries() -> None:
    assert domain_matches("example.com", "example.com")
    assert domain_matches("a.b.example.com", "example.com")
    assert not domain_matches("badexample.com", "example.com")
    assert not domain_matches("example.com.evil.net", "example.com")
    assert domain_matches(PUBLIC_B, PUBLIC_B)
