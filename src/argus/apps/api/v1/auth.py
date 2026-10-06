"""/api/v1/auth - registration, sign-in, sessions, passwords and MFA."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Response, status

from argus.apps.api.security import ClientDep, ContainerDep, UserDep
from argus.modules.identity.schemas import (
    AcceptedResponse,
    ChangePasswordRequest,
    DisableMfaRequest,
    EmailRequest,
    LoginRequest,
    MeResponse,
    MfaChallengeResponse,
    MfaVerifyRequest,
    RecoveryCodesResponse,
    RefreshRequest,
    RegisterRequest,
    ResetPasswordRequest,
    SessionInfo,
    TokenRequest,
    TokenResponse,
    TotpCodeRequest,
    TotpEnrollResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])

_REGISTERED = "If the address can be used, a verification e-mail is on its way."
_RESET = "If an account exists for this address, a reset link is on its way."


@router.post("/register", status_code=status.HTTP_202_ACCEPTED, response_model=AcceptedResponse)
async def register(
    body: RegisterRequest, container: ContainerDep, client: ClientDep
) -> AcceptedResponse:
    await container.auth.register(
        email=body.email, password=body.password, full_name=body.full_name, client=client
    )
    return AcceptedResponse(detail=_REGISTERED)


@router.post("/email/verify", status_code=status.HTTP_204_NO_CONTENT)
async def verify_email(body: TokenRequest, container: ContainerDep, client: ClientDep) -> Response:
    await container.auth.verify_email(token=body.token, client=client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/email/resend", status_code=status.HTTP_202_ACCEPTED, response_model=AcceptedResponse)
async def resend_verification(
    body: EmailRequest, container: ContainerDep, client: ClientDep
) -> AcceptedResponse:
    await container.auth.resend_verification(email=body.email, client=client)
    return AcceptedResponse(detail=_REGISTERED)


@router.post("/login", response_model=TokenResponse | MfaChallengeResponse)
async def login(
    body: LoginRequest, container: ContainerDep, client: ClientDep
) -> TokenResponse | MfaChallengeResponse:
    return await container.auth.login(email=body.email, password=body.password, client=client)


@router.post("/mfa/verify", response_model=TokenResponse)
async def verify_mfa(
    body: MfaVerifyRequest, container: ContainerDep, client: ClientDep
) -> TokenResponse:
    return await container.auth.verify_mfa(mfa_token=body.mfa_token, code=body.code, client=client)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    body: RefreshRequest, container: ContainerDep, client: ClientDep
) -> TokenResponse:
    return await container.auth.refresh(refresh_token=body.refresh_token, client=client)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(principal: UserDep, container: ContainerDep, client: ClientDep) -> Response:
    await container.auth.logout(principal, client=client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(principal: UserDep, container: ContainerDep, client: ClientDep) -> Response:
    await container.auth.logout_all(principal, client=client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/sessions", response_model=list[SessionInfo])
async def list_sessions(principal: UserDep, container: ContainerDep) -> list[SessionInfo]:
    return await container.auth.list_sessions(principal)


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(
    session_id: UUID, principal: UserDep, container: ContainerDep, client: ClientDep
) -> Response:
    await container.auth.revoke_session(principal, session_id, client=client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=MeResponse)
async def me(principal: UserDep, container: ContainerDep) -> MeResponse:
    return await container.auth.me(principal)


@router.post("/password/change", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    body: ChangePasswordRequest, principal: UserDep, container: ContainerDep, client: ClientDep
) -> Response:
    await container.auth.change_password(
        principal,
        current_password=body.current_password,
        new_password=body.new_password,
        client=client,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/password/forgot", status_code=status.HTTP_202_ACCEPTED, response_model=AcceptedResponse
)
async def forgot_password(
    body: EmailRequest, container: ContainerDep, client: ClientDep
) -> AcceptedResponse:
    await container.auth.forgot_password(email=body.email, client=client)
    return AcceptedResponse(detail=_RESET)


@router.post("/password/reset", status_code=status.HTTP_204_NO_CONTENT)
async def reset_password(
    body: ResetPasswordRequest, container: ContainerDep, client: ClientDep
) -> Response:
    await container.auth.reset_password(
        token=body.token, new_password=body.new_password, client=client
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/mfa/totp/enroll", response_model=TotpEnrollResponse)
async def enroll_totp(principal: UserDep, container: ContainerDep) -> TotpEnrollResponse:
    return await container.auth.enroll_totp(principal)


@router.post("/mfa/totp/confirm", response_model=RecoveryCodesResponse)
async def confirm_totp(
    body: TotpCodeRequest, principal: UserDep, container: ContainerDep, client: ClientDep
) -> RecoveryCodesResponse:
    codes = await container.auth.confirm_totp(principal, code=body.code, client=client)
    return RecoveryCodesResponse(recovery_codes=codes)


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
async def disable_mfa(
    body: DisableMfaRequest, principal: UserDep, container: ContainerDep, client: ClientDep
) -> Response:
    await container.auth.disable_mfa(
        principal, password=body.password, code=body.code, client=client
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/mfa/recovery-codes", response_model=RecoveryCodesResponse)
async def regenerate_recovery_codes(
    body: TotpCodeRequest, principal: UserDep, container: ContainerDep, client: ClientDep
) -> RecoveryCodesResponse:
    codes = await container.auth.regenerate_recovery_codes(principal, code=body.code, client=client)
    return RecoveryCodesResponse(recovery_codes=codes)
