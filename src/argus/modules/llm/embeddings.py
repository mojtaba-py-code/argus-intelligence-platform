"""Embedding providers behind one interface.

* :class:`HashingEmbedder` (``argus-hash-v1``, local) - feature hashing of words, word bigrams and
  character trigrams into 1,024 signed buckets. Deterministic across machines (CRC-32, not
  Python's randomised ``hash``), offline and free. It captures lexical similarity, including
  morphology and typos through the trigrams - not meaning. It is the default so the platform
  works without any external service, and the evaluation suite measures exactly what it buys.
* :class:`VoyageEmbedder` (external) - semantic embeddings via Voyage AI.

Callers decide *whether* text may be embedded by a provider (``governance.may_send``); providers
only embed what they are given.
"""

from __future__ import annotations

import asyncio
import math
import re
import unicodedata
import zlib
from collections import Counter
from collections.abc import Sequence
from itertools import batched
from typing import Final, Literal, Protocol

from argus.core.config import EmbeddingSettings
from argus.modules.llm.governance import Locality
from argus.modules.llm.voyage import EMBEDDING_DIMENSIONS, VoyageClient, hardened_client

EmbeddingKind = Literal["document", "query"]
_WORD: Final = re.compile(r"\w+", re.UNICODE)
_STOPWORDS: Final = frozenset(
    [
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "for",
        "from",
        "has",
        "have",
        "in",
        "is",
        "it",
        "its",
        "of",
        "on",
        "or",
        "that",
        "the",
        "this",
        "to",
        "was",
        "were",
        "will",
        "with",
        "و",
        "در",
        "به",
        "از",
        "که",
        "را",
        "این",
        "با",
        "برای",
        "است",
    ]
)
DEFAULT_MODELS: Final = {"local": "argus-hash-v1", "voyage": "voyage-4"}


class Embedder(Protocol):
    provider: str
    model: str
    locality: Locality

    async def embed(self, texts: Sequence[str], *, kind: EmbeddingKind) -> list[list[float]]: ...

    async def aclose(self) -> None: ...


def _features(text: str) -> Counter[str]:
    words = [
        word
        for word in _WORD.findall(unicodedata.normalize("NFKC", text).casefold())
        if word not in _STOPWORDS
    ]
    features: Counter[str] = Counter()
    for index, word in enumerate(words):
        features["w:" + word] += 2
        if index:
            features[f"b:{words[index - 1]} {word}"] += 1
        padded = f"#{word}#"
        for start in range(len(padded) - 2):
            features["t:" + padded[start : start + 3]] += 1
    return features


def hash_embed(text: str, dimensions: int = EMBEDDING_DIMENSIONS) -> list[float]:
    vector = [0.0] * dimensions
    for feature, count in _features(text).items():
        digest = zlib.crc32(feature.encode("utf-8"))
        sign = 1.0 if (digest >> 31) & 1 else -1.0
        vector[digest % dimensions] += sign * (1.0 + math.log(count))
    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0.0:  # empty text: a fixed unit vector keeps cosine distance defined
        vector[0] = 1.0
        return vector
    return [value / norm for value in vector]


class HashingEmbedder:
    provider = "local"
    model = DEFAULT_MODELS["local"]
    locality: Locality = "local"

    async def embed(self, texts: Sequence[str], *, kind: EmbeddingKind) -> list[list[float]]:
        del kind  # symmetric: queries and documents are embedded the same way
        return await asyncio.to_thread(lambda: [hash_embed(text) for text in texts])

    async def aclose(self) -> None:
        return None


class VoyageEmbedder:
    provider = "voyage"
    locality: Locality = "external"

    def __init__(self, client: VoyageClient, *, model: str, batch_size: int = 64) -> None:
        self._client = client
        self.model = model
        self._batch = batch_size

    async def embed(self, texts: Sequence[str], *, kind: EmbeddingKind) -> list[list[float]]:
        vectors: list[list[float]] = []
        for batch in batched(texts, self._batch):
            vectors.extend(await self._client.embed(list(batch), model=self.model, kind=kind))
        return vectors

    async def aclose(self) -> None:
        await self._client.aclose()


def create_embedder(settings: EmbeddingSettings, *, user_agent: str = "argus") -> Embedder:
    if settings.provider == "voyage" and settings.voyage_api_key is not None:
        client = VoyageClient(
            settings.voyage_api_key.get_secret_value(),
            client=hardened_client(timeout_s=settings.request_timeout_s, user_agent=user_agent),
        )
        return VoyageEmbedder(
            client, model=settings.model or DEFAULT_MODELS["voyage"], batch_size=settings.batch_size
        )
    return HashingEmbedder()  # one fixed algorithm: the model name is not configurable
