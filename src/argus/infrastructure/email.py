"""Outbound e-mail.

Messages are plain text only: no HTML means no HTML injection through user-influenced values, and
templates never include free text supplied by other users (a display name like
"Click http://evil.example" would otherwise turn our notification e-mails into a phishing relay).
Links that carry tokens put the token in the URL *fragment* (``#token=...``), which browsers never
send to servers, proxies or analytics.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from email.message import EmailMessage as MIMEMessage
from email.utils import make_msgid
from typing import Protocol

import aiosmtplib

from argus.core.config import EmailSettings
from argus.core.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class EmailMessage:
    to: str
    subject: str
    text: str
    category: str = "transactional"


class Mailer(Protocol):
    async def send(self, message: EmailMessage) -> None: ...


@dataclass
class MemoryMailer:
    """Test double: keeps messages in memory."""

    outbox: list[EmailMessage] = field(default_factory=list)

    async def send(self, message: EmailMessage) -> None:
        self.outbox.append(message)

    def last_to(self, address: str) -> EmailMessage:
        for message in reversed(self.outbox):
            if message.to == address:
                return message
        msg = f"no e-mail sent to {address}"
        raise LookupError(msg)


class ConsoleMailer:
    """Development only (refused in production by the configuration guard): prints to stderr,
    never through the logger, so tokens in links cannot reach log storage."""

    async def send(self, message: EmailMessage) -> None:
        banner = "=" * 72
        sys.stderr.write(
            f"\n{banner}\nDEVELOPMENT E-MAIL to {message.to}\nSubject: {message.subject}\n\n"
            f"{message.text}\n{banner}\n"
        )


class SmtpMailer:
    def __init__(self, settings: EmailSettings) -> None:
        if not settings.smtp_host:
            msg = "ARGUS_EMAIL__SMTP_HOST is required for the smtp backend"
            raise ValueError(msg)
        self._settings = settings

    async def send(self, message: EmailMessage) -> None:
        mime = MIMEMessage()
        mime["From"] = self._settings.from_address
        mime["To"] = message.to
        mime["Subject"] = message.subject
        mime["Message-ID"] = make_msgid(domain="argus.local")
        mime["Auto-Submitted"] = "auto-generated"
        mime.set_content(message.text)
        password = self._settings.smtp_password
        await aiosmtplib.send(
            mime,
            hostname=self._settings.smtp_host,
            port=self._settings.smtp_port,
            username=self._settings.smtp_username,
            password=password.get_secret_value() if password else None,
            start_tls=self._settings.smtp_starttls,
            timeout=15,
        )
        log.info("email.sent", category=message.category)


def create_mailer(settings: EmailSettings) -> Mailer:
    if settings.backend == "smtp":
        return SmtpMailer(settings)
    if settings.backend == "console":
        return ConsoleMailer()
    return MemoryMailer()
