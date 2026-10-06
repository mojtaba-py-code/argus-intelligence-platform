"""The local extractive provider: deterministic, offline, no network.

It does not imitate a language model. Each task registers a *handler* - plain code that produces
the task's output from the same inputs (template variables and untrusted parts) - typically by
extracting and ranking sentences from the evidence. It serves tests and offline demos, keeps
research working when the data policy allows no remote model, and is the floor every route
degrades to. A task without a handler is simply not served locally.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from argus.modules.llm.types import ProviderCall, ProviderResult, ProviderUnsupported

LocalHandler = Callable[[ProviderCall], str]


class LocalProvider:
    name = "local"

    def __init__(self) -> None:
        self._handlers: dict[str, LocalHandler] = {}

    def register(self, task: str, handler: LocalHandler) -> None:
        if task in self._handlers:
            msg = f"a local handler for {task!r} is already registered"
            raise ValueError(msg)
        self._handlers[task] = handler

    def supports(self, task: str) -> bool:
        return task in self._handlers

    async def complete(self, call: ProviderCall) -> ProviderResult:
        handler = self._handlers.get(call.task)
        if handler is None:
            raise ProviderUnsupported(f"no local implementation of {call.task!r}")
        text = await asyncio.to_thread(handler, call)  # handlers are CPU-bound pure functions
        consumed = len(call.system) + len(call.user)
        return ProviderResult(
            text=text,
            served_model="local/extractive",
            input_tokens=consumed // 4 + 1,
            output_tokens=len(text) // 4 + 1,
        )

    async def aclose(self) -> None:
        return None
