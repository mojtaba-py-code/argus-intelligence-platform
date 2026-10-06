"""Authentication dependencies: turn the ``Authorization`` header into a :class:`Principal`."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request

from argus.apps.api.deps import get_container
from argus.apps.container import Container
from argus.core import context
from argus.core.errors import AuthenticationRequired
from argus.security.principals import ClientInfo, Principal

API_KEY_PREFIX = "argus_sk_"


def client_info(request: Request) -> ClientInfo:
    state = request.scope.get("state", {})
    user_agent = request.headers.get("user-agent")
    return ClientInfo(
        ip_address=state.get("client_ip"),
        user_agent=user_agent[:256] if user_agent else None,
        request_id=state.get("request_id"),
    )


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization")
    if not header:
        return None
    scheme, _, credentials = header.partition(" ")
    if scheme.lower() != "bearer" or not credentials.strip():
        raise AuthenticationRequired("Use the Bearer authentication scheme.")
    return credentials.strip()


async def current_principal(
    request: Request, container: Annotated[Container, Depends(get_container)]
) -> Principal:
    token = _bearer(request)
    if token is None:
        raise AuthenticationRequired
    if token.startswith(API_KEY_PREFIX):
        principal = await container.api_keys.authenticate(token, client=client_info(request))
    else:
        principal = await container.auth.authenticate(token)
    context.set_value("user_id", principal.user_id)
    return principal


async def current_user(principal: Annotated[Principal, Depends(current_principal)]) -> Principal:
    """Interactive user sessions only (not API keys) - for account-management endpoints."""
    if principal.session_id is None:
        raise AuthenticationRequired("This endpoint requires a user session, not an API key.")
    return principal


ClientDep = Annotated[ClientInfo, Depends(client_info)]
PrincipalDep = Annotated[Principal, Depends(current_principal)]
UserDep = Annotated[Principal, Depends(current_user)]
ContainerDep = Annotated[Container, Depends(get_container)]
