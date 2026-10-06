"""The default research pipeline: plan → collect → analyse → verify → contradictions → report.

Each stage is checkpointed by the pipeline engine (phase 4), so a job resumes at the first
unfinished stage after a crash, a cancellation check, a budget stop or a human approval.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from argus.modules.research.analysis import AnalyzeStage
from argus.modules.research.collection import CollectStage
from argus.modules.research.contradictions import ContradictionStage
from argus.modules.research.pipeline import Stage
from argus.modules.research.planning import PlanStage
from argus.modules.research.reporting import ReportStage
from argus.modules.research.verification import VerifyStage


def research_stages(_: Any) -> Sequence[Stage]:
    return [
        PlanStage(),
        CollectStage(),
        AnalyzeStage(),
        VerifyStage(),
        ContradictionStage(),
        ReportStage(),
    ]
