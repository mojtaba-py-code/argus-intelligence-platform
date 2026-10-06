"""/api/v1 knowledge search (hybrid retrieval over a project's documents and web sources)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from argus.apps.api.access import project_access
from argus.apps.api.security import ContainerDep
from argus.modules.knowledge.answer import AskRequest, AskResponse
from argus.modules.knowledge.schemas import SearchRequest, SearchResponse
from argus.modules.tenancy.authorization import ProjectAccess
from argus.security.permissions import Permission

router = APIRouter(tags=["knowledge"])


@router.post("/orgs/{org_id}/projects/{project_id}/search", response_model=SearchResponse)
async def search_knowledge(
    body: SearchRequest,
    access: Annotated[ProjectAccess, Depends(project_access())],
    container: ContainerDep,
) -> SearchResponse:
    """Results are limited to what the caller may read: origins, classification and project are
    part of the database query, not filters applied afterwards."""
    return await container.knowledge.search(access, body)


@router.post("/orgs/{org_id}/projects/{project_id}/ask", response_model=AskResponse)
async def ask_knowledge(
    body: AskRequest,
    access: Annotated[ProjectAccess, Depends(project_access(Permission.RESEARCH_CREATE))],
    container: ContainerDep,
) -> AskResponse:
    """A cited answer from the project's knowledge. Every citation is checked against the cited
    text; claims that fail the check are returned flagged ``verified: false``."""
    return await container.answers.ask(access, body)
