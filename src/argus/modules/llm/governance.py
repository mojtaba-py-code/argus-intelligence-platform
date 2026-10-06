"""Data governance for model providers (ADR 0006): which data may go to which kind of provider.

Every provider declares a *locality*. An organisation's data policy sets the highest
classification each locality may receive. The rule is applied before any text leaves the
process - for generation, embeddings and reranking alike - and never by asking a model.
"""

from __future__ import annotations

from typing import Literal

from argus.core.classification import Classification
from argus.modules.tenancy.schemas import DataPolicy

Locality = Literal["local", "self_hosted", "external"]


def ceiling_for(policy: DataPolicy, locality: Locality) -> Classification:
    if locality == "local":
        return policy.local
    if locality == "self_hosted":
        return policy.self_hosted
    return policy.external


def may_send(classification: Classification | int, locality: Locality, policy: DataPolicy) -> bool:
    return Classification(classification) <= ceiling_for(policy, locality)
