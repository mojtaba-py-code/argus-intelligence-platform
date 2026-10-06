"""Identity e-mail templates.

Plain text, no user-supplied free text (see :mod:`argus.infrastructure.email`), and every token
travels in the URL fragment so it never reaches a server log.
"""

from __future__ import annotations

from argus.infrastructure.email import EmailMessage


def _link(base: str, path: str, token: str) -> str:
    return f"{base.rstrip('/')}/{path}#token={token}"


def verification(to: str, *, base_url: str, token: str, ttl_hours: int) -> EmailMessage:
    return EmailMessage(
        to=to,
        subject="Verify your e-mail address for Argus",
        text=(
            "Welcome to Argus.\n\n"
            "Confirm your e-mail address by opening this link:\n"
            f"{_link(base_url, 'verify-email', token)}\n\n"
            f"The link expires in {ttl_hours} hours. If you did not create an account, ignore "
            "this message."
        ),
    )


def already_registered(to: str, *, base_url: str) -> EmailMessage:
    return EmailMessage(
        to=to,
        subject="Argus sign-up attempt with your e-mail address",
        text=(
            "Someone tried to create an Argus account with this e-mail address, which already "
            "has an account.\n\n"
            "If it was you, sign in - or reset your password at "
            f"{base_url.rstrip('/')}/forgot-password.\n"
            "If it was not you, no action is needed; your account was not changed."
        ),
    )


def password_reset(to: str, *, base_url: str, token: str, ttl_minutes: int) -> EmailMessage:
    return EmailMessage(
        to=to,
        subject="Reset your Argus password",
        text=(
            "A password reset was requested for your Argus account.\n\n"
            f"{_link(base_url, 'reset-password', token)}\n\n"
            f"The link expires in {ttl_minutes} minutes and works once. Resetting signs out every "
            "session. If you did not request this, ignore this message."
        ),
    )


def security_notice(to: str, *, subject: str, body: str) -> EmailMessage:
    return EmailMessage(
        to=to,
        subject=f"Argus security notice: {subject}",
        text=f"{body}\n\nIf this was not you, reset your password immediately and contact your "
        "administrator.",
        category="security",
    )
