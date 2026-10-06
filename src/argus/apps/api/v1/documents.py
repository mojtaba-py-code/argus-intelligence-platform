"""/api/v1 documents: upload, list, inspect, download, delete - and signed download links."""

from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Query, Request, Response, status
from fastapi.responses import JSONResponse
from starlette.datastructures import UploadFile

from argus.apps.api.access import project_access
from argus.apps.api.deps import PageDep
from argus.apps.api.security import ClientDep, ContainerDep
from argus.core.classification import Classification
from argus.core.errors import (
    InvalidCredentials,
    NotFound,
    PayloadTooLarge,
    PermissionDenied,
    UnsupportedMediaType,
    ValidationFailed,
)
from argus.core.pagination import Page
from argus.modules.documents.schemas import DocumentDetail, DocumentResponse, DownloadLinkResponse
from argus.modules.documents.service import DownloadableFile
from argus.modules.documents.validation import content_disposition
from argus.modules.tenancy.authorization import ProjectAccess
from argus.security.links import MAX_LINK_CHARS, InvalidLink
from argus.security.permissions import Permission

router = APIRouter(tags=["documents"])
P = Permission
BASE = "/orgs/{org_id}/projects/{project_id}/documents"
DocumentStatus = Literal["pending_scan", "processing", "ready", "failed", "quarantined"]
_FORM_FIELDS = frozenset({"file", "classification"})
_UPLOAD_BODY: dict[str, Any] = {
    "requestBody": {
        "required": True,
        "content": {
            "multipart/form-data": {
                "schema": {
                    "type": "object",
                    "required": ["file"],
                    "properties": {
                        "file": {"type": "string", "format": "binary"},
                        "classification": {
                            "type": "string",
                            "enum": [level.label for level in Classification],
                        },
                    },
                }
            }
        },
    }
}


class InvalidDownloadLink(PermissionDenied):
    code = "invalid_download_link"
    default_detail = "This download link is invalid or has expired. Request a new one."


def _file_response(file: DownloadableFile) -> Response:
    return Response(
        content=file.content,
        media_type=file.media_type,
        headers={
            "Content-Disposition": content_disposition(file.filename),
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
        },
    )


def _classification(value: object) -> Classification | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValidationFailed("classification must be a text field.")
    try:
        return Classification.parse(value)
    except KeyError:
        labels = ", ".join(level.label for level in Classification)
        raise ValidationFailed(f"classification must be one of: {labels}.") from None


@router.post(
    BASE,
    status_code=status.HTTP_202_ACCEPTED,
    response_model=DocumentResponse,
    openapi_extra=_UPLOAD_BODY,
    responses={200: {"description": "The same content already exists; the existing document."}},
)
async def upload_document(
    request: Request,
    access: Annotated[ProjectAccess, Depends(project_access(P.DOCUMENTS_UPLOAD))],
    container: ContainerDep,
    client: ClientDep,
) -> JSONResponse:
    if not request.headers.get("content-type", "").lower().startswith("multipart/form-data"):
        raise UnsupportedMediaType("Send the document as multipart/form-data with a 'file' part.")
    limit = container.settings.http.max_upload_bytes
    # One file, a handful of small fields: the multipart parser refuses anything else.
    async with request.form(max_files=1, max_fields=4, max_part_size=1024) as form:
        unknown = set(form.keys()) - _FORM_FIELDS
        if unknown:
            raise ValidationFailed("Unknown form fields: " + ", ".join(sorted(unknown)[:5]))
        upload = form.get("file")
        if not isinstance(upload, UploadFile):
            raise ValidationFailed("A 'file' part is required.")
        classification = _classification(form.get("classification"))
        data = await upload.read(limit + 1)
        if len(data) > limit:
            raise PayloadTooLarge
        filename, declared = upload.filename, upload.content_type
    document, created = await container.documents.upload(
        access,
        filename=filename,
        declared_type=declared,
        data=data,
        classification=classification,
        client=client,
    )
    return JSONResponse(
        document.model_dump(mode="json"),
        status_code=status.HTTP_202_ACCEPTED if created else status.HTTP_200_OK,
        headers={"Location": f"{request.url.path}/{document.id}"},
    )


@router.get(BASE, response_model=Page[DocumentResponse])
async def list_documents(
    access: Annotated[ProjectAccess, Depends(project_access(P.DOCUMENTS_READ))],
    container: ContainerDep,
    page: PageDep,
    status_filter: Annotated[DocumentStatus | None, Query(alias="status")] = None,
) -> Page[DocumentResponse]:
    return await container.documents.list_documents(access, page, status=status_filter)


@router.get(BASE + "/{document_id}", response_model=DocumentDetail)
async def get_document(
    document_id: UUID,
    access: Annotated[ProjectAccess, Depends(project_access(P.DOCUMENTS_READ))],
    container: ContainerDep,
) -> DocumentDetail:
    return await container.documents.get(access, document_id)


@router.get(BASE + "/{document_id}/content", response_class=Response)
async def download_document(
    document_id: UUID,
    access: Annotated[ProjectAccess, Depends(project_access(P.DOCUMENTS_READ))],
    container: ContainerDep,
    client: ClientDep,
) -> Response:
    """Direct download for API clients (the Authorization header authenticates)."""
    return _file_response(await container.documents.content(access, document_id, client))


@router.post(
    BASE + "/{document_id}/download-link",
    status_code=status.HTTP_201_CREATED,
    response_model=DownloadLinkResponse,
)
async def create_download_link(
    document_id: UUID,
    access: Annotated[ProjectAccess, Depends(project_access(P.DOCUMENTS_READ))],
    container: ContainerDep,
    client: ClientDep,
) -> DownloadLinkResponse:
    """A short-lived link for browsers; it stops working when your session ends."""
    return await container.documents.create_download_link(access, document_id, client)


@router.delete(BASE + "/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_document(
    document_id: UUID,
    access: Annotated[ProjectAccess, Depends(project_access(P.DOCUMENTS_DELETE))],
    container: ContainerDep,
    client: ClientDep,
) -> Response:
    await container.documents.delete(access, document_id, client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/downloads/{token}", response_class=Response)
async def download_with_link(
    token: Annotated[
        str, Path(max_length=MAX_LINK_CHARS, pattern=r"^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$")
    ],
    container: ContainerDep,
    client: ClientDep,
) -> Response:
    """Signed-link download. The link's creator is re-authorised now, not when it was issued."""
    try:
        claims = container.documents.verify_link(token)
        principal = await container.auth.principal_for_session(
            claims.user_id, claims.session_id, claims.amr
        )
        access = await container.authorizer.project(
            principal, claims.organization_id, claims.project_id, P.DOCUMENTS_READ
        )
    except (InvalidLink, InvalidCredentials, NotFound, PermissionDenied):
        raise InvalidDownloadLink from None
    return _file_response(
        await container.documents.content(access, claims.document_id, client, via_link=True)
    )
