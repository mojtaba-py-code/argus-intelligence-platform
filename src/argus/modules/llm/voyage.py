"""Voyage AI HTTP client (embeddings and reranking).

No SDK: two JSON endpoints over a hardened httpx client (no environment proxies, no redirects,
timeouts). Transient failures (429, 5xx, network) are retried with full-jitter backoff honouring
``Retry-After``; responses are validated before use - a provider is a dependency, not a trusted
party. The API key travels only in the ``Authorization`` header and is never logged.
"""

from __future__ import annotations

import math
from functools import partial
from typing import Any, Final, Literal

import httpx

from argus.core.retry import RetryableError, RetryPolicy, retry_async

API: Final = "https://api.voyageai.com/v1"
EMBEDDING_DIMENSIONS: Final = 1024


class ProviderError(Exception):
    """The provider failed permanently for this request (bad key, bad input, bad response)."""


class ProviderUnavailable(Exception):
    """The provider is temporarily unavailable; the caller's job should retry later."""


def hardened_client(*, timeout_s: float, user_agent: str = "argus") -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout_s, connect=10.0),
        trust_env=False,
        follow_redirects=False,
        headers={"User-Agent": user_agent},
        limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
    )


def _retry_after(response: httpx.Response) -> float | None:
    value = response.headers.get("retry-after", "")
    return float(value) if value.replace(".", "", 1).isdigit() else None


class VoyageClient:
    def __init__(
        self,
        api_key: str,
        *,
        client: httpx.AsyncClient,
        retry: RetryPolicy | None = None,
        base_url: str = API,
    ) -> None:
        self._key = api_key
        self._client = client
        self._retry = retry or RetryPolicy(max_attempts=4, base_delay_s=1.0, max_delay_s=20.0)
        self._base = base_url.rstrip("/")

    async def _post_once(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            response = await self._client.post(
                f"{self._base}{path}", json=body, headers={"Authorization": f"Bearer {self._key}"}
            )
        except httpx.TransportError as exc:
            raise RetryableError(f"voyage transport error: {type(exc).__name__}") from exc
        if response.status_code == 429 or response.status_code >= 500:
            raise RetryableError(
                f"voyage HTTP {response.status_code}", retry_after_s=_retry_after(response)
            )
        if response.status_code >= 400:
            raise ProviderError(f"voyage rejected the request (HTTP {response.status_code})")
        try:
            payload = response.json()
        except ValueError:
            raise ProviderError("voyage returned invalid JSON") from None
        if not isinstance(payload, dict):
            raise ProviderError("voyage returned an unexpected payload")
        return payload

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            return await retry_async(partial(self._post_once, path, body), policy=self._retry)
        except RetryableError as exc:
            raise ProviderUnavailable(str(exc)) from exc

    async def embed(
        self, texts: list[str], *, model: str, kind: Literal["document", "query"]
    ) -> list[list[float]]:
        payload = await self._post(
            "/embeddings",
            {
                "input": texts,
                "model": model,
                "input_type": kind,
                "output_dimension": EMBEDDING_DIMENSIONS,
                "truncation": True,
            },
        )
        items = payload.get("data")
        if not isinstance(items, list) or len(items) != len(texts):
            raise ProviderError("voyage returned the wrong number of embeddings")
        vectors: list[list[float] | None] = [None] * len(texts)
        for item in items:
            index = item.get("index") if isinstance(item, dict) else None
            vector = item.get("embedding") if isinstance(item, dict) else None
            if (
                not isinstance(index, int)
                or not 0 <= index < len(texts)
                or not isinstance(vector, list)
                or len(vector) != EMBEDDING_DIMENSIONS
                or not all(isinstance(v, int | float) and math.isfinite(v) for v in vector)
            ):
                raise ProviderError("voyage returned a malformed embedding")
            vectors[index] = [float(v) for v in vector]
        if any(vector is None for vector in vectors):
            raise ProviderError("voyage returned duplicate embedding indexes")
        return [vector for vector in vectors if vector is not None]

    async def rerank(self, query: str, documents: list[str], *, model: str) -> list[float]:
        """Relevance score per document, in input order."""
        payload = await self._post(
            "/rerank",
            {"query": query, "documents": documents, "model": model, "truncation": True},
        )
        items = payload.get("data")
        if not isinstance(items, list):
            raise ProviderError("voyage returned no rerank results")
        scores = [0.0] * len(documents)
        for item in items:
            index = item.get("index") if isinstance(item, dict) else None
            score = item.get("relevance_score") if isinstance(item, dict) else None
            if (
                not isinstance(index, int)
                or not 0 <= index < len(documents)
                or not isinstance(score, int | float)
                or not math.isfinite(score)
            ):
                raise ProviderError("voyage returned a malformed rerank result")
            scores[index] = float(score)
        return scores

    async def aclose(self) -> None:
        await self._client.aclose()
