"""Web search providers.

Provider endpoints are fixed, operator-configured hosts, so a plain httpx client is appropriate
here (with ``trust_env=False`` and no redirects). What comes *back* is untrusted: every result URL
is re-validated by the SSRF parser and every title/snippet is sanitised before use, and results
are only ever *candidates* - the collector fetches them through SafeFetcher.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx

from argus.core.config import SearchSettings
from argus.security.ssrf import EgressBlocked, parse_url
from argus.security.text import sanitize_text


@dataclass(frozen=True)
class SearchResult:
    url: str
    title: str
    snippet: str
    rank: int
    provider: str


class SearchProvider(Protocol):
    name: str

    async def search(self, query: str, *, limit: int) -> list[SearchResult]: ...

    async def aclose(self) -> None: ...


def clean_results(raw: list[tuple[str, str, str]], provider: str, limit: int) -> list[SearchResult]:
    results: list[SearchResult] = []
    seen: set[str] = set()
    for url, title, snippet in raw:
        try:
            safe = str(parse_url(url))
        except EgressBlocked:
            continue
        if safe in seen:
            continue
        seen.add(safe)
        results.append(
            SearchResult(
                url=safe,
                title=sanitize_text(title or "", max_chars=300).text,
                snippet=sanitize_text(snippet or "", max_chars=1000).text,
                rank=len(results) + 1,
                provider=provider,
            )
        )
        if len(results) >= limit:
            break
    return results


class NoSearch:
    name = "none"

    async def search(self, query: str, *, limit: int) -> list[SearchResult]:
        del query, limit
        return []

    async def aclose(self) -> None:
        return None


class _HttpProvider:
    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def aclose(self) -> None:
        await self._client.aclose()


class BraveSearch(_HttpProvider):
    name = "brave"
    endpoint = "https://api.search.brave.com/res/v1/web/search"

    def __init__(self, api_key: str, client: httpx.AsyncClient) -> None:
        super().__init__(client)
        self._key = api_key

    async def search(self, query: str, *, limit: int) -> list[SearchResult]:
        response = await self._client.get(
            self.endpoint,
            params={"q": query[:400], "count": min(limit, 20), "safesearch": "moderate"},
            headers={"Accept": "application/json", "X-Subscription-Token": self._key},
        )
        response.raise_for_status()
        data = response.json()
        items = data.get("web", {}).get("results", []) if isinstance(data, dict) else []
        raw = [
            (str(i.get("url", "")), str(i.get("title", "")), str(i.get("description", "")))
            for i in items
            if isinstance(i, dict)
        ]
        return clean_results(raw, self.name, limit)


class SearxngSearch(_HttpProvider):
    name = "searxng"

    def __init__(self, base_url: str, client: httpx.AsyncClient) -> None:
        super().__init__(client)
        self._base = base_url.rstrip("/")

    async def search(self, query: str, *, limit: int) -> list[SearchResult]:
        response = await self._client.get(
            f"{self._base}/search", params={"q": query[:400], "format": "json", "safesearch": 1}
        )
        response.raise_for_status()
        data = response.json()
        items = data.get("results", []) if isinstance(data, dict) else []
        raw = [
            (str(i.get("url", "")), str(i.get("title", "")), str(i.get("content", "")))
            for i in items
            if isinstance(i, dict)
        ]
        return clean_results(raw, self.name, limit)


_WORD = re.compile(r"[\w-]+", re.UNICODE)


class StaticSearch:
    """Offline provider over a curated JSON list - deterministic demos, evaluations and tests."""

    name = "static"

    def __init__(self, entries: list[dict[str, Any]]) -> None:
        self._entries = entries

    @classmethod
    def from_file(cls, path: Path) -> StaticSearch:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            msg = "static search file must contain a JSON list"
            raise ValueError(msg)
        return cls([entry for entry in data if isinstance(entry, dict)])

    async def search(self, query: str, *, limit: int) -> list[SearchResult]:
        terms = {term.lower() for term in _WORD.findall(query) if len(term) > 2}
        scored: list[tuple[int, int, dict[str, Any]]] = []
        for position, entry in enumerate(self._entries):
            haystack = " ".join(
                str(entry.get(field, "")) for field in ("title", "snippet", "keywords")
            ).lower()
            score = sum(1 for term in terms if term in haystack)
            if score:
                scored.append((-score, position, entry))
        scored.sort()
        raw = [
            (str(e.get("url", "")), str(e.get("title", "")), str(e.get("snippet", "")))
            for _, _, e in scored
        ]
        return clean_results(raw, self.name, limit)

    async def aclose(self) -> None:
        return None


def _client(user_agent: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(10.0, connect=5.0),
        trust_env=False,  # never pick up proxy or credential settings from the environment
        follow_redirects=False,
        headers={"User-Agent": user_agent},
        limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
    )


def create_search_provider(settings: SearchSettings, *, user_agent: str) -> SearchProvider:
    """Settings validation guarantees each provider's requirement is present."""
    if settings.provider == "static" and settings.static_results_file is not None:
        return StaticSearch.from_file(settings.static_results_file)
    if settings.provider == "brave" and settings.brave_api_key is not None:
        return BraveSearch(settings.brave_api_key.get_secret_value(), _client(user_agent))
    if settings.provider == "searxng" and settings.searxng_url is not None:
        return SearxngSearch(str(settings.searxng_url), _client(user_agent))
    return NoSearch()
