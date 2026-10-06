"""The adapter interface every model provider implements."""

from __future__ import annotations

from typing import Protocol

from argus.modules.llm.types import ProviderCall, ProviderResult


class Provider(Protocol):
    name: str

    async def complete(self, call: ProviderCall) -> ProviderResult:
        """Run one attempt. Raise ``ProviderRetryable`` for transient failures (the gateway owns
        retries, so SDK-level retries are disabled), ``ProviderRefused`` for refusals,
        ``ProviderTruncated`` when the output was cut off, ``ProviderError`` for anything else."""
        ...

    async def aclose(self) -> None: ...
