"""Knowledge use cases: the authorised search scope, and search for API callers and agents."""

from __future__ import annotations

from datetime import datetime

from argus.core.config import RetrievalSettings
from argus.core.errors import PermissionDenied
from argus.modules.knowledge.retrieval import Hit, Retriever, SearchScope
from argus.modules.knowledge.schemas import SearchHit, SearchRequest, SearchResponse
from argus.modules.tenancy.authorization import ProjectAccess
from argus.security.permissions import Permission


class KnowledgeService:
    def __init__(self, retriever: Retriever, settings: RetrievalSettings) -> None:
        self.retriever = retriever
        self._settings = settings

    def scope_for(
        self,
        access: ProjectAccess,
        *,
        origins: list[str] | None = None,
        published_after: datetime | None = None,
    ) -> SearchScope:
        """Everything the caller may search - computed *before* retrieval, from permissions."""
        allowed: set[str] = set()
        if access.can(Permission.DOCUMENTS_READ):
            allowed.add("document")
        if access.can(Permission.SOURCES_READ):
            allowed.add("web")
        effective = (set(origins) if origins else allowed) & allowed
        if not effective:
            raise PermissionDenied("You cannot search this project's knowledge.")
        return SearchScope(
            organization_id=access.org.organization_id,
            project_ids=(access.project_id,),
            max_classification=access.classification_ceiling,
            origins=frozenset(effective),
            exclude_injection=frozenset(self._settings.exclude_injection_levels),
            published_after=published_after,
        )

    async def search(self, access: ProjectAccess, request: SearchRequest) -> SearchResponse:
        scope = self.scope_for(
            access, origins=list(request.origins or []), published_after=request.published_after
        )
        hits = await self.retriever.search(
            scope,
            request.query,
            policy=access.org.settings.data_policy,
            limit=request.limit,
            mode=request.mode,
        )
        return SearchResponse(
            query=request.query, mode=request.mode, hits=[_hit(hit) for hit in hits]
        )


def _hit(hit: Hit) -> SearchHit:
    return SearchHit.model_validate(hit, from_attributes=True)
