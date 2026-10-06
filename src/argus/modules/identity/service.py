"""Authentication use cases.

Design rules applied throughout:

* **No account enumeration** - registration, resend-verification and forgot-password always give
  the same answer; login answers identically for an unknown e-mail and a wrong password, and
  spends the same Argon2 work either way; lockout is keyed by the *attempted* e-mail string, so
  unknown addresses lock exactly like real ones.
* **State first, exception after commit** - failure paths that change state (failed-attempt
  counters, MFA attempt counters, reuse detection) commit before raising, otherwise the rollback
  would silently undo the security bookkeeping.
* **Single-use secrets** - one-time tokens, MFA challenges, refresh tokens and recovery codes are
  looked up by digest under ``SELECT ... FOR UPDATE`` and consumed in the same transaction.
* **E-mails after commit** - messages are queued during the transaction and delivered only once
  it has committed (no e-mail for a rolled-back registration).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from argus.core.clock import Clock
from argus.core.config import AuthSettings, EmailSettings
from argus.core.crypto import Keyring, sha256
from argus.core.errors import (
    InvalidCredentials,
    NotFound,
    PermissionDenied,
    RateLimited,
    ValidationFailed,
)
from argus.core.ids import secret_token
from argus.core.logging import get_logger
from argus.core.scope import Actor, ActorType
from argus.infrastructure.db import Database
from argus.infrastructure.email import EmailMessage, Mailer
from argus.modules.audit.service import AuditCategory, AuditEvent, AuditOutcome, AuditService
from argus.modules.identity import emails
from argus.modules.identity.models import (
    MfaTotp,
    OneTimeToken,
    RefreshToken,
    User,
    UserSession,
)
from argus.modules.identity.repository import IdentityRepository
from argus.modules.identity.schemas import (
    MeResponse,
    MfaChallengeResponse,
    SessionInfo,
    TokenResponse,
    TotpEnrollResponse,
)
from argus.modules.identity.session_cache import SessionCache, SessionState
from argus.security import totp
from argus.security.passwords import PasswordHasher, validate_password
from argus.security.principals import ClientInfo, Principal
from argus.security.ratelimit import POLICIES, RateLimiter
from argus.security.tokens import TokenService

log = get_logger(__name__)

_GENERIC_LOGIN_FAILURE = "The e-mail address or password is incorrect."
_GENERIC_TOKEN_FAILURE = "The link is invalid or has expired."  # noqa: S105  # nosec B105
_LOCKED = "Too many sign-in attempts. Try again later."


@dataclass
class _Outbox:
    messages: list[EmailMessage] = field(default_factory=list)

    def add(self, message: EmailMessage) -> None:
        self.messages.append(message)


@dataclass(frozen=True)
class AuthDependencies:
    database: Database
    hasher: PasswordHasher
    tokens: TokenService
    encryption: Keyring
    pepper: bytes
    audit: AuditService
    mailer: Mailer
    limiter: RateLimiter
    sessions: SessionCache
    clock: Clock
    auth: AuthSettings
    email: EmailSettings


def _digest(token: str) -> bytes:
    return sha256(token)


def _email_fingerprint(email: str) -> str:
    """Correlates repeated attempts in audit records without storing the attempted address."""
    return sha256(email.lower()).hex()[:16]


class AuthService:
    def __init__(self, deps: AuthDependencies) -> None:
        self._d = deps

    # ------------------------------------------------------------------ helpers
    @property
    def _now(self) -> datetime:
        return self._d.clock.now()

    async def _limit(self, policy: str, key: str) -> None:
        decision = await self._d.limiter.hit(POLICIES[policy], key)
        if not decision.allowed:
            raise RateLimited(decision.retry_after_s)

    async def _deliver(self, outbox: _Outbox) -> None:
        for message in outbox.messages:
            try:
                await self._d.mailer.send(message)
            except Exception as exc:  # noqa: BLE001 - delivery is best effort; state is committed
                log.error(
                    "email.delivery_failed",
                    category=message.category,
                    error_type=type(exc).__name__,
                )

    def _event(
        self,
        action: str,
        *,
        client: ClientInfo,
        user_id: UUID | None = None,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        category: AuditCategory = AuditCategory.AUTHENTICATION,
        details: dict[str, object] | None = None,
    ) -> AuditEvent:
        actor = Actor(ActorType.USER, user_id, user_id) if user_id else Actor.anonymous()
        return AuditEvent(
            action=action,
            category=category,
            actor=actor,
            outcome=outcome,
            target_type="user" if user_id else None,
            target_id=str(user_id) if user_id else None,
            client=client,
            details=details or {},
        )

    def _issue_one_time(
        self, repo: IdentityRepository, user: User, purpose: str, ttl_s: int
    ) -> str:
        token = secret_token("argus_ot")
        repo.add(
            OneTimeToken(
                user_id=user.id,
                purpose=purpose,
                token_hash=_digest(token),
                expires_at=self._now + timedelta(seconds=ttl_s),
            )
        )
        return token

    async def _consume_one_time(
        self, repo: IdentityRepository, token: str, purpose: str
    ) -> OneTimeToken | None:
        record = await repo.one_time_token(_digest(token), purpose)
        if record is None or record.consumed_at is not None or record.expires_at <= self._now:
            return None
        record.consumed_at = self._now
        return record

    # --------------------------------------------------------------- bootstrap
    async def create_user(
        self,
        *,
        email: str,
        password: str,
        full_name: str,
        verified: bool = False,
        platform_admin: bool = False,
    ) -> UUID:
        """Administrative creation (CLI). Applies the same password policy."""
        validate_password(password, email=email)
        async with self._d.database.session() as session:
            repo = IdentityRepository(session)
            if await repo.user_by_email(email) is not None:
                raise ValidationFailed("A user with this e-mail address already exists.")
            user = User(
                email=email,
                full_name=full_name,
                password_hash=self._d.hasher.hash(password),
                email_verified_at=self._now if verified else None,
                is_platform_admin=platform_admin,
                password_changed_at=self._now,
            )
            repo.add(user)
            await session.flush()
            await self._d.audit.record(
                session,
                self._event(
                    "user.created_by_admin",
                    client=ClientInfo.system(),
                    user_id=user.id,
                    category=AuditCategory.ADMINISTRATION,
                    details={"platform_admin": platform_admin},
                ),
            )
            return user.id

    # ------------------------------------------------------------ registration
    async def register(
        self, *, email: str, password: str, full_name: str, client: ClientInfo
    ) -> None:
        await self._limit("auth.register.ip", client.ip_address or "unknown")
        validate_password(password, email=email)
        outbox = _Outbox()
        async with self._d.database.session() as session:
            repo = IdentityRepository(session)
            existing = await repo.user_by_email(email)
            if existing is not None:
                self._d.hasher.dummy_verify(password)  # same work as the new-account path
                outbox.add(
                    emails.already_registered(email, base_url=str(self._d.email.app_base_url))
                )
                await self._d.audit.record(
                    session,
                    self._event(
                        "user.register_existing_email",
                        client=client,
                        user_id=existing.id,
                        category=AuditCategory.ACCOUNT,
                    ),
                )
            else:
                user = User(
                    email=email,
                    full_name=full_name,
                    password_hash=self._d.hasher.hash(password),
                    password_changed_at=self._now,
                )
                repo.add(user)
                await session.flush()
                token = self._issue_one_time(
                    repo, user, "email_verification", self._d.auth.email_verification_ttl_s
                )
                outbox.add(
                    emails.verification(
                        email,
                        base_url=str(self._d.email.app_base_url),
                        token=token,
                        ttl_hours=self._d.auth.email_verification_ttl_s // 3600,
                    )
                )
                await self._d.audit.record(
                    session,
                    self._event(
                        "user.registered",
                        client=client,
                        user_id=user.id,
                        category=AuditCategory.ACCOUNT,
                    ),
                )
        await self._deliver(outbox)

    async def verify_email(self, *, token: str, client: ClientInfo) -> None:
        async with self._d.database.session() as session:
            repo = IdentityRepository(session)
            record = await self._consume_one_time(repo, token, "email_verification")
            if record is None:
                raise ValidationFailed(_GENERIC_TOKEN_FAILURE)
            user = await repo.user_by_id(record.user_id, for_update=True)
            if user is None:  # pragma: no cover - FK guarantees existence
                raise ValidationFailed(_GENERIC_TOKEN_FAILURE)
            if user.email_verified_at is None:
                user.email_verified_at = self._now
            await self._d.audit.record(
                session,
                self._event(
                    "user.email_verified",
                    client=client,
                    user_id=user.id,
                    category=AuditCategory.ACCOUNT,
                ),
            )

    async def resend_verification(self, *, email: str, client: ClientInfo) -> None:
        await self._limit("auth.register.ip", client.ip_address or "unknown")
        await self._limit("auth.verification.account", email)
        outbox = _Outbox()
        async with self._d.database.session() as session:
            repo = IdentityRepository(session)
            user = await repo.user_by_email(email)
            if user is not None and user.email_verified_at is None and user.status == "active":
                await repo.consume_user_tokens(user.id, "email_verification", self._now)
                token = self._issue_one_time(
                    repo, user, "email_verification", self._d.auth.email_verification_ttl_s
                )
                outbox.add(
                    emails.verification(
                        email,
                        base_url=str(self._d.email.app_base_url),
                        token=token,
                        ttl_hours=self._d.auth.email_verification_ttl_s // 3600,
                    )
                )
        await self._deliver(outbox)

    # ------------------------------------------------------------------- login
    async def login(
        self, *, email: str, password: str, client: ClientInfo
    ) -> TokenResponse | MfaChallengeResponse:
        await self._limit("auth.login.ip", client.ip_address or "unknown")
        await self._limit("auth.login.account", email)
        outcome: Literal["unknown", "locked", "wrong", "disabled", "unverified", "ok"]
        result: TokenResponse | MfaChallengeResponse | None = None
        lock_remaining = 0.0
        async with self._d.database.session() as session:
            repo = IdentityRepository(session)
            user = await repo.user_by_email(email, for_update=True)
            if user is None:
                self._d.hasher.dummy_verify(password)
                outcome = "unknown"
            elif user.locked_until is not None and user.locked_until > self._now:
                self._d.hasher.dummy_verify(password)
                outcome = "locked"
                lock_remaining = (user.locked_until - self._now).total_seconds()
            elif not self._d.hasher.verify(user.password_hash, password):
                outcome = "wrong"
                self._register_failure(user)
            elif user.status != "active":
                outcome = "disabled"
            elif self._d.auth.require_email_verification and user.email_verified_at is None:
                outcome = "unverified"
            else:
                outcome = "ok"
                if self._d.hasher.needs_rehash(user.password_hash):
                    user.password_hash = self._d.hasher.hash(password)
                if user.mfa_enabled:
                    result = await self._start_mfa_challenge(repo, user)
                    await self._d.audit.record(
                        session,
                        self._event("auth.login.mfa_challenge", client=client, user_id=user.id),
                    )
                else:
                    result = await self._start_session(
                        session, repo, user, client, auth_method="password", amr=("pwd",)
                    )
            if outcome != "ok":
                await self._d.audit.record(
                    session,
                    self._event(
                        "auth.login.failed",
                        client=client,
                        user_id=user.id if user is not None and outcome != "unknown" else None,
                        outcome=AuditOutcome.FAILURE,
                        details={"reason": outcome, "email_fingerprint": _email_fingerprint(email)},
                    ),
                )
        if outcome == "locked":
            raise RateLimited(lock_remaining, _LOCKED)
        if outcome in {"unknown", "wrong"}:
            raise InvalidCredentials(_GENERIC_LOGIN_FAILURE)
        if outcome == "disabled":
            raise PermissionDenied("This account is disabled.")
        if outcome == "unverified":
            raise PermissionDenied("Verify your e-mail address before signing in.")
        if result is None:  # every other outcome has returned or raised above
            raise InvalidCredentials
        return result

    def _register_failure(self, user: User) -> None:
        user.failed_login_count += 1
        over = user.failed_login_count - self._d.auth.lockout_threshold
        if over >= 0:
            lock_s = min(self._d.auth.lockout_base_s * (2**over), self._d.auth.lockout_max_s)
            user.locked_until = self._now + timedelta(seconds=lock_s)

    async def _start_mfa_challenge(
        self, repo: IdentityRepository, user: User
    ) -> MfaChallengeResponse:
        token = secret_token("argus_mc")
        repo.add(
            OneTimeToken(
                user_id=user.id,
                purpose="mfa_challenge",
                token_hash=_digest(token),
                expires_at=self._now + timedelta(seconds=self._d.auth.mfa_challenge_ttl_s),
                payload={"auth_method": "password"},
            )
        )
        return MfaChallengeResponse(mfa_token=token, expires_in=self._d.auth.mfa_challenge_ttl_s)

    async def _start_session(
        self,
        session: AsyncSession,
        repo: IdentityRepository,
        user: User,
        client: ClientInfo,
        *,
        auth_method: str,
        amr: tuple[str, ...],
    ) -> TokenResponse:
        now = self._now
        user_session = UserSession(
            user_id=user.id,
            last_seen_at=now,
            expires_at=now + timedelta(seconds=self._d.auth.session_max_age_s),
            ip_address=client.ip_address,
            user_agent=(client.user_agent or "")[:256] or None,
            auth_method=auth_method,
            mfa_verified="otp" in amr,
        )
        repo.add(user_session)
        await session.flush()
        refresh, refresh_expires = self._new_refresh_token(repo, user_session, parent_id=None)
        access = self._d.tokens.issue_access_token(
            user_id=user.id, session_id=user_session.id, amr=amr, now=now
        )
        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = now
        await self._d.audit.record(
            session,
            self._event(
                "auth.login.succeeded",
                client=client,
                user_id=user.id,
                details={"session_id": str(user_session.id), "method": auth_method},
            ),
        )
        await self._d.sessions.put(
            user_session.id, SessionState(True, is_platform_admin=user.is_platform_admin)
        )
        return TokenResponse(
            access_token=access.token,
            expires_in=int((access.expires_at - now).total_seconds()),
            refresh_token=refresh,
            refresh_expires_in=int((refresh_expires - now).total_seconds()),
            session_id=user_session.id,
        )

    def _new_refresh_token(
        self, repo: IdentityRepository, user_session: UserSession, *, parent_id: UUID | None
    ) -> tuple[str, datetime]:
        token = secret_token("argus_rt")
        expires_at = min(
            self._now + timedelta(seconds=self._d.auth.refresh_token_ttl_s),
            user_session.expires_at,
        )
        repo.add(
            RefreshToken(
                session_id=user_session.id,
                token_hash=_digest(token),
                parent_id=parent_id,
                expires_at=expires_at,
            )
        )
        return token, expires_at

    # --------------------------------------------------------------------- MFA
    async def verify_mfa(self, *, mfa_token: str, code: str, client: ClientInfo) -> TokenResponse:
        await self._limit("auth.mfa", mfa_token)
        await self._limit("auth.login.ip", client.ip_address or "unknown")
        result: TokenResponse | None = None
        failure: str | None = None
        user_id: UUID | None = None
        async with self._d.database.session() as session:
            repo = IdentityRepository(session)
            challenge = await repo.one_time_token(_digest(mfa_token), "mfa_challenge")
            if (
                challenge is None
                or challenge.consumed_at is not None
                or challenge.expires_at <= self._now
            ):
                failure = "invalid_challenge"
            else:
                user_id = challenge.user_id
                challenge.attempts += 1
                user = await repo.user_by_id(challenge.user_id, for_update=True)
                if user is None or user.status != "active" or not user.mfa_enabled:
                    failure = "invalid_challenge"
                    challenge.consumed_at = self._now
                elif challenge.attempts > self._d.auth.mfa_max_attempts:
                    failure = "too_many_attempts"
                    challenge.consumed_at = self._now
                else:
                    method = await self._check_second_factor(repo, user, code)
                    if method is None:
                        failure = "wrong_code"
                    else:
                        challenge.consumed_at = self._now
                        result = await self._start_session(
                            session,
                            repo,
                            user,
                            client,
                            auth_method=f"password+{method}",
                            amr=("pwd", "otp"),
                        )
            if failure is not None:
                await self._d.audit.record(
                    session,
                    self._event(
                        "auth.mfa.failed",
                        client=client,
                        user_id=user_id,
                        outcome=AuditOutcome.FAILURE,
                        details={"reason": failure},
                    ),
                )
        if failure is not None or result is None:
            raise InvalidCredentials("The verification code is invalid or has expired.")
        return result

    async def _check_second_factor(
        self, repo: IdentityRepository, user: User, code: str
    ) -> Literal["totp", "recovery_code"] | None:
        if totp.looks_like_recovery_code(code):
            record = await repo.recovery_code(
                user.id, totp.hash_recovery_code(self._d.pepper, code)
            )
            if record is None:
                return None
            record.used_at = self._now
            return "recovery_code"
        enrolment = await repo.totp(user.id, for_update=True)
        if enrolment is None or enrolment.confirmed_at is None:
            return None
        secret = self._decrypt_totp(enrolment)
        step = totp.verify_code(
            secret, code, now=self._now, last_used_step=enrolment.last_used_step
        )
        if step is None:
            return None
        enrolment.last_used_step = step
        return "totp"

    def _decrypt_totp(self, enrolment: MfaTotp) -> str:
        aad = f"totp:{enrolment.user_id}".encode()
        return self._d.encryption.decrypt(bytes(enrolment.secret_ciphertext), aad=aad).decode()

    async def enroll_totp(self, principal: Principal) -> TotpEnrollResponse:
        user_id = self._require_user(principal)
        async with self._d.database.session(user_id=user_id) as session:
            repo = IdentityRepository(session)
            user = await repo.user_by_id(user_id, for_update=True)
            if user is None:
                raise NotFound
            if user.mfa_enabled:
                raise ValidationFailed("Multi-factor authentication is already enabled.")
            secret = totp.new_secret()
            ciphertext = self._d.encryption.encrypt(secret.encode(), aad=f"totp:{user_id}".encode())
            existing = await repo.totp(user_id, for_update=True)
            if existing is None:
                repo.add(MfaTotp(user_id=user_id, secret_ciphertext=ciphertext))
            else:
                existing.secret_ciphertext = ciphertext
                existing.confirmed_at = None
                existing.last_used_step = None
            return TotpEnrollResponse(
                secret=secret, otpauth_uri=totp.provisioning_uri(secret, account=user.email)
            )

    async def confirm_totp(
        self, principal: Principal, *, code: str, client: ClientInfo
    ) -> list[str]:
        user_id = self._require_user(principal)
        await self._limit("auth.mfa", str(user_id))
        codes: list[str] = []
        ok = False
        async with self._d.database.session(user_id=user_id) as session:
            repo = IdentityRepository(session)
            user = await repo.user_by_id(user_id, for_update=True)
            enrolment = await repo.totp(user_id, for_update=True)
            if user is not None and enrolment is not None and not user.mfa_enabled:
                step = totp.verify_code(
                    self._decrypt_totp(enrolment),
                    code,
                    now=self._now,
                    last_used_step=enrolment.last_used_step,
                )
                if step is not None:
                    ok = True
                    enrolment.confirmed_at = self._now
                    enrolment.last_used_step = step
                    user.mfa_enabled = True
                    codes = totp.new_recovery_codes()
                    await repo.replace_recovery_codes(
                        user_id, [totp.hash_recovery_code(self._d.pepper, c) for c in codes]
                    )
                    await self._d.audit.record(
                        session,
                        self._event(
                            "auth.mfa.enabled",
                            client=client,
                            user_id=user_id,
                            category=AuditCategory.ACCOUNT,
                        ),
                    )
        if not ok:
            raise ValidationFailed("The verification code is invalid.")
        return codes

    async def disable_mfa(
        self, principal: Principal, *, password: str, code: str, client: ClientInfo
    ) -> None:
        user_id = self._require_user(principal)
        await self._limit("auth.mfa", str(user_id))
        outbox = _Outbox()
        ok = False
        async with self._d.database.session(user_id=user_id) as session:
            repo = IdentityRepository(session)
            user = await repo.user_by_id(user_id, for_update=True)
            if (
                user is not None
                and user.mfa_enabled
                and self._d.hasher.verify(user.password_hash, password)
                and await self._check_second_factor(repo, user, code) is not None
            ):
                ok = True
                await repo.delete_mfa(user_id)
                user.mfa_enabled = False
                outbox.add(
                    emails.security_notice(
                        user.email,
                        subject="two-step verification disabled",
                        body="Two-step verification was turned off for your Argus account.",
                    )
                )
                await self._d.audit.record(
                    session,
                    self._event(
                        "auth.mfa.disabled",
                        client=client,
                        user_id=user_id,
                        category=AuditCategory.ACCOUNT,
                    ),
                )
        if not ok:
            await self._d.audit.record_detached(
                self._event(
                    "auth.mfa.disable_failed",
                    client=client,
                    user_id=user_id,
                    outcome=AuditOutcome.FAILURE,
                    category=AuditCategory.ACCOUNT,
                )
            )
            raise InvalidCredentials("The password or verification code is incorrect.")
        await self._deliver(outbox)

    async def regenerate_recovery_codes(
        self, principal: Principal, *, code: str, client: ClientInfo
    ) -> list[str]:
        user_id = self._require_user(principal)
        await self._limit("auth.mfa", str(user_id))
        codes: list[str] = []
        if totp.looks_like_recovery_code(code):
            # regenerating needs the authenticator itself; never burn a recovery code here
            raise InvalidCredentials("Enter a code from your authenticator app.")
        async with self._d.database.session(user_id=user_id) as session:
            repo = IdentityRepository(session)
            user = await repo.user_by_id(user_id, for_update=True)
            if (
                user is not None
                and user.mfa_enabled
                and await self._check_second_factor(repo, user, code) == "totp"
            ):
                codes = totp.new_recovery_codes()
                await repo.replace_recovery_codes(
                    user_id, [totp.hash_recovery_code(self._d.pepper, c) for c in codes]
                )
                await self._d.audit.record(
                    session,
                    self._event(
                        "auth.mfa.recovery_codes_regenerated",
                        client=client,
                        user_id=user_id,
                        category=AuditCategory.ACCOUNT,
                    ),
                )
        if not codes:
            raise InvalidCredentials("The verification code is invalid.")
        return codes

    # ----------------------------------------------------------------- refresh
    async def refresh(self, *, refresh_token: str, client: ClientInfo) -> TokenResponse:
        reuse_session: UserSession | None = None
        result: TokenResponse | None = None
        notify: EmailMessage | None = None
        async with self._d.database.session() as session:
            repo = IdentityRepository(session)
            record = await repo.refresh_token_by_hash(_digest(refresh_token))
            if record is not None:
                await self._limit("auth.refresh.session", str(record.session_id))
                user_session = await repo.get_session(record.session_id, for_update=True)
                now = self._now
                if user_session is None:
                    pass
                elif record.used_at is not None or record.revoked_at is not None:
                    if user_session.revoked_at is None:
                        # A rotated token came back: it was stolen, or the client is broken.
                        # Either way the whole session is no longer trustworthy.
                        reuse_session = user_session
                        await repo.revoke_session(user_session.id, reason="refresh_reuse", now=now)
                        user = await repo.user_by_id(user_session.user_id)
                        if user is not None:
                            notify = emails.security_notice(
                                user.email,
                                subject="a session was signed out",
                                body="A session token was presented twice, which can mean it was "
                                "copied. That session has been signed out.",
                            )
                        await self._d.audit.record(
                            session,
                            self._event(
                                "auth.refresh.reuse_detected",
                                client=client,
                                user_id=user_session.user_id,
                                outcome=AuditOutcome.DENIED,
                                category=AuditCategory.SECURITY,
                                details={"session_id": str(user_session.id)},
                            ),
                        )
                elif (
                    user_session.revoked_at is None
                    and user_session.expires_at > now
                    and record.expires_at > now
                ):
                    user = await repo.user_by_id(user_session.user_id)
                    if user is not None and user.status == "active":
                        record.used_at = now
                        user_session.last_seen_at = now
                        new_refresh, refresh_expires = self._new_refresh_token(
                            repo, user_session, parent_id=record.id
                        )
                        amr = ("pwd", "otp") if user_session.mfa_verified else ("pwd",)
                        access = self._d.tokens.issue_access_token(
                            user_id=user.id, session_id=user_session.id, amr=amr, now=now
                        )
                        result = TokenResponse(
                            access_token=access.token,
                            expires_in=int((access.expires_at - now).total_seconds()),
                            refresh_token=new_refresh,
                            refresh_expires_in=int((refresh_expires - now).total_seconds()),
                            session_id=user_session.id,
                        )
        if reuse_session is not None:
            await self._d.sessions.revoke(reuse_session.id)
            if notify is not None:
                await self._deliver(_Outbox([notify]))
        if result is None:
            raise InvalidCredentials("The refresh token is invalid or expired.")
        return result

    # --------------------------------------------------------- authentication
    async def authenticate(self, access_token: str) -> Principal:
        claims = self._d.tokens.verify_access_token(access_token)
        return await self.principal_for_session(claims.user_id, claims.session_id, claims.amr)

    async def principal_for_session(
        self, user_id: UUID, session_id: UUID, amr: tuple[str, ...]
    ) -> Principal:
        """The principal of a still-active session (revocation and account status checked)."""
        state = await self._d.sessions.get(session_id)
        if state is None:
            async with self._d.database.session(user_id=user_id, read_only=True) as session:
                row = (
                    await session.execute(
                        select(
                            UserSession.revoked_at,
                            UserSession.expires_at,
                            User.status,
                            User.is_platform_admin,
                        )
                        .join(User, User.id == UserSession.user_id)
                        .where(
                            UserSession.id == session_id,
                            UserSession.user_id == user_id,
                        )
                    )
                ).one_or_none()
            active = (
                row is not None
                and row.revoked_at is None
                and row.expires_at > self._now
                and row.status == "active"
            )
            state = SessionState(active, bool(row.is_platform_admin) if row is not None else False)
            await self._d.sessions.put(session_id, state)
        if not state.active:
            raise InvalidCredentials("The session has ended. Sign in again.")
        return Principal.user(
            user_id,
            session_id=session_id,
            amr=amr,
            is_platform_admin=state.is_platform_admin,
        )

    @staticmethod
    def _require_user(principal: Principal) -> UUID:
        if principal.user_id is None or principal.session_id is None:
            raise PermissionDenied("This action requires an interactive user session.")
        return principal.user_id

    # ---------------------------------------------------------------- sessions
    async def logout(self, principal: Principal, *, client: ClientInfo) -> None:
        user_id = self._require_user(principal)
        if principal.session_id is None:  # API keys have no session to end
            raise PermissionDenied("Only an interactive session can sign out.")
        async with self._d.database.session(user_id=user_id) as session:
            repo = IdentityRepository(session)
            await repo.revoke_session(principal.session_id, reason="logout", now=self._now)
            await self._d.audit.record(
                session, self._event("auth.logout", client=client, user_id=user_id)
            )
        await self._d.sessions.revoke(principal.session_id)

    async def logout_all(self, principal: Principal, *, client: ClientInfo) -> int:
        user_id = self._require_user(principal)
        async with self._d.database.session(user_id=user_id) as session:
            repo = IdentityRepository(session)
            revoked = await repo.revoke_user_sessions(user_id, reason="logout_all", now=self._now)
            await self._d.audit.record(
                session,
                self._event(
                    "auth.logout_all",
                    client=client,
                    user_id=user_id,
                    details={"sessions": len(revoked)},
                ),
            )
        for session_id in revoked:
            await self._d.sessions.revoke(session_id)
        return len(revoked)

    async def list_sessions(self, principal: Principal) -> list[SessionInfo]:
        user_id = self._require_user(principal)
        async with self._d.database.session(user_id=user_id, read_only=True) as session:
            rows = await IdentityRepository(session).active_sessions(user_id, self._now)
            return [
                SessionInfo.model_validate(row).model_copy(
                    update={"current": row.id == principal.session_id}
                )
                for row in rows
            ]

    async def revoke_session(
        self, principal: Principal, session_id: UUID, *, client: ClientInfo
    ) -> None:
        user_id = self._require_user(principal)
        async with self._d.database.session(user_id=user_id) as session:
            repo = IdentityRepository(session)
            target = await repo.get_session(session_id, user_id=user_id, for_update=True)
            if target is None or target.revoked_at is not None:
                raise NotFound
            await repo.revoke_session(session_id, reason="revoked_by_user", now=self._now)
            await self._d.audit.record(
                session,
                self._event(
                    "auth.session_revoked",
                    client=client,
                    user_id=user_id,
                    details={"session_id": str(session_id)},
                ),
            )
        await self._d.sessions.revoke(session_id)

    async def me(self, principal: Principal) -> MeResponse:
        user_id = self._require_user(principal)
        async with self._d.database.session(user_id=user_id, read_only=True) as session:
            user = await IdentityRepository(session).user_by_id(user_id)
            if user is None:
                raise NotFound
            return MeResponse(
                id=user.id,
                email=user.email,
                full_name=user.full_name,
                email_verified=user.email_verified_at is not None,
                mfa_enabled=user.mfa_enabled,
                is_platform_admin=user.is_platform_admin,
                created_at=user.created_at,
            )

    # ---------------------------------------------------------------- passwords
    async def change_password(
        self, principal: Principal, *, current_password: str, new_password: str, client: ClientInfo
    ) -> None:
        user_id = self._require_user(principal)
        await self._limit("auth.login.account", str(user_id))
        outbox = _Outbox()
        ok = False
        revoked: list[UUID] = []
        async with self._d.database.session(user_id=user_id) as session:
            repo = IdentityRepository(session)
            user = await repo.user_by_id(user_id, for_update=True)
            if user is None:
                raise NotFound
            validate_password(new_password, email=user.email)
            if self._d.hasher.verify(user.password_hash, current_password):
                ok = True
                user.password_hash = self._d.hasher.hash(new_password)
                user.password_changed_at = self._now
                revoked = await repo.revoke_user_sessions(
                    user_id, reason="password_changed", now=self._now, keep=principal.session_id
                )
                outbox.add(
                    emails.security_notice(
                        user.email,
                        subject="password changed",
                        body="The password of your Argus account was changed. Other sessions were "
                        "signed out.",
                    )
                )
                await self._d.audit.record(
                    session,
                    self._event(
                        "auth.password_changed",
                        client=client,
                        user_id=user_id,
                        category=AuditCategory.ACCOUNT,
                        details={"other_sessions_revoked": len(revoked)},
                    ),
                )
        if not ok:
            await self._d.audit.record_detached(
                self._event(
                    "auth.password_change_failed",
                    client=client,
                    user_id=user_id,
                    outcome=AuditOutcome.FAILURE,
                    category=AuditCategory.ACCOUNT,
                )
            )
            raise InvalidCredentials("The current password is incorrect.")
        for session_id in revoked:
            await self._d.sessions.revoke(session_id)
        await self._deliver(outbox)

    async def forgot_password(self, *, email: str, client: ClientInfo) -> None:
        await self._limit("auth.password_reset.ip", client.ip_address or "unknown")
        await self._limit("auth.password_reset.account", email)
        outbox = _Outbox()
        async with self._d.database.session() as session:
            repo = IdentityRepository(session)
            user = await repo.user_by_email(email)
            if user is not None and user.status == "active":
                await repo.consume_user_tokens(user.id, "password_reset", self._now)
                token = self._issue_one_time(
                    repo, user, "password_reset", self._d.auth.password_reset_ttl_s
                )
                outbox.add(
                    emails.password_reset(
                        email,
                        base_url=str(self._d.email.app_base_url),
                        token=token,
                        ttl_minutes=self._d.auth.password_reset_ttl_s // 60,
                    )
                )
                await self._d.audit.record(
                    session,
                    self._event(
                        "auth.password_reset_requested",
                        client=client,
                        user_id=user.id,
                        category=AuditCategory.ACCOUNT,
                    ),
                )
        await self._deliver(outbox)

    async def reset_password(self, *, token: str, new_password: str, client: ClientInfo) -> None:
        outbox = _Outbox()
        revoked: Sequence[UUID] = []
        async with self._d.database.session() as session:
            repo = IdentityRepository(session)
            record = await self._consume_one_time(repo, token, "password_reset")
            if record is None:
                raise ValidationFailed(_GENERIC_TOKEN_FAILURE)
            user = await repo.user_by_id(record.user_id, for_update=True)
            if user is None or user.status != "active":
                raise ValidationFailed(_GENERIC_TOKEN_FAILURE)
            validate_password(new_password, email=user.email)
            user.password_hash = self._d.hasher.hash(new_password)
            user.password_changed_at = self._now
            user.failed_login_count = 0
            user.locked_until = None
            if user.email_verified_at is None:
                user.email_verified_at = self._now  # the reset link proved control of the inbox
            revoked = await repo.revoke_user_sessions(
                user.id, reason="password_reset", now=self._now
            )
            outbox.add(
                emails.security_notice(
                    user.email,
                    subject="password reset",
                    body="The password of your Argus account was reset and every session was signed out.",
                )
            )
            await self._d.audit.record(
                session,
                self._event(
                    "auth.password_reset",
                    client=client,
                    user_id=user.id,
                    category=AuditCategory.ACCOUNT,
                    details={"sessions_revoked": len(revoked)},
                ),
            )
        for session_id in revoked:
            await self._d.sessions.revoke(session_id)
        await self._deliver(outbox)
