"""The tool catalogue: every tool an agent can be given, and whether it has side effects.

This is the review surface for agent capabilities (ADR 0007). Adding a tool means declaring it
here; the runtime refuses any tool that is not declared, or whose implementation claims a
different side-effect class than its declaration. A unit test checks every agent spec in the code
base against this catalogue under the taint rule.

A tool has **side effects** if it changes state outside the running job (writes, deletes,
approvals, notifications) or sends data out of the platform (network calls, e-mail, webhooks).
Reading the project's own knowledge within the job's authorised scope has none.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final


@dataclass(frozen=True)
class ToolDeclaration:
    name: str
    side_effects: bool
    description: str


TOOLS: Final[Mapping[str, ToolDeclaration]] = MappingProxyType(
    {
        declaration.name: declaration
        for declaration in (
            ToolDeclaration(
                "search_documents",
                side_effects=False,
                description=(
                    "Search this project's knowledge (documents and collected pages) within the "
                    "job's authorised scope. Read-only; no network access."
                ),
            ),
        )
    }
)
