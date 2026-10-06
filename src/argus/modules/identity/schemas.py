"""Identity request and response models."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AfterValidator, EmailStr, Field

from argus.core.schemas import Name, RequestModel, ResponseModel, Secret, Token


def _normalise_email(value: str) -> str:
    return value.strip().lower()


Email = Annotated[EmailStr, Field(max_length=320), AfterValidator(_normalise_email)]
TotpOrRecoveryCode = Annotated[str, Field(min_length=6, max_length=32)]


class RegisterRequest(RequestModel):
    email: Email
    password: Secret
    full_name: Name


class EmailRequest(RequestModel):
    email: Email


class TokenRequest(RequestModel):
    token: Token


class LoginRequest(RequestModel):
    email: Email
    password: Secret


class MfaVerifyRequest(RequestModel):
    mfa_token: Token
    code: TotpOrRecoveryCode


class RefreshRequest(RequestModel):
    refresh_token: Token


class ChangePasswordRequest(RequestModel):
    current_password: Secret
    new_password: Secret


class ResetPasswordRequest(RequestModel):
    token: Token
    new_password: Secret


class TotpCodeRequest(RequestModel):
    code: TotpOrRecoveryCode


class DisableMfaRequest(RequestModel):
    password: Secret
    code: TotpOrRecoveryCode


class AcceptedResponse(ResponseModel):
    status: Literal["accepted"] = "accepted"
    detail: str


class TokenResponse(ResponseModel):
    status: Literal["authenticated"] = "authenticated"
    access_token: str
    token_type: Literal["Bearer"] = "Bearer"  # noqa: S105 - OAuth token type
    expires_in: int
    refresh_token: str
    refresh_expires_in: int
    session_id: UUID


class MfaChallengeResponse(ResponseModel):
    status: Literal["mfa_required"] = "mfa_required"
    mfa_token: str
    expires_in: int


class SessionInfo(ResponseModel):
    id: UUID
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    ip_address: str | None
    user_agent: str | None
    auth_method: str
    mfa_verified: bool
    current: bool = False


class MeResponse(ResponseModel):
    id: UUID
    email: str
    full_name: str
    email_verified: bool
    mfa_enabled: bool
    is_platform_admin: bool
    created_at: datetime


class TotpEnrollResponse(ResponseModel):
    secret: str
    otpauth_uri: str


class RecoveryCodesResponse(ResponseModel):
    recovery_codes: list[str]
    detail: str = (
        "Store these codes somewhere safe. Each can be used once and they are shown only now."
    )
