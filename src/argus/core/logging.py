"""Structured logging (structlog) with context propagation and mandatory redaction.

One JSON object per event, always containing the diagnostic context (request id, organisation,
job, agent run, tool call...). Standard-library loggers (uvicorn, SQLAlchemy, httpx) are routed
through the same processor chain, so *every* line - ours or a library's - passes the redaction
processor before it reaches a sink.
"""

from __future__ import annotations

import logging
import logging.config
import sys
from collections.abc import Sequence
from typing import Any

import structlog
from structlog.types import EventDict, Processor, WrappedLogger

from argus.core import context
from argus.core.redaction import redact

_CONFIGURED = False


def _add_context(_: WrappedLogger, __: str, event_dict: EventDict) -> EventDict:
    for key, value in context.snapshot().items():
        event_dict.setdefault(key, value)
    return event_dict


def _redact_event(_: WrappedLogger, __: str, event_dict: EventDict) -> EventDict:
    redacted: EventDict = redact(dict(event_dict))
    return redacted


def _drop_color_message(_: WrappedLogger, __: str, event_dict: EventDict) -> EventDict:
    event_dict.pop("color_message", None)  # uvicorn duplicates the message with ANSI codes
    return event_dict


def configure_logging(
    *,
    level: str = "INFO",
    fmt: str = "json",
    service: str = "argus",
    processors: Sequence[Processor] = (),
) -> None:
    """Configure structlog and the standard library once per process (idempotent).

    ``processors`` run before redaction (the process entry points add trace correlation here,
    which keeps this kernel module free of tracing dependencies).
    """
    global _CONFIGURED

    shared: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _add_context,
        _drop_color_message,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        *processors,
        _redact_event,  # last: also covers rendered exception text
    ]
    renderer: Processor = (
        structlog.processors.JSONRenderer(sort_keys=True)
        if fmt == "json"
        else structlog.dev.ConsoleRenderer(colors=False)
    )

    structlog.configure(
        processors=[*shared, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    for noisy in ("uvicorn.access", "httpx", "httpcore", "asyncio"):
        logging.getLogger(noisy).setLevel("WARNING")
    for name in ("uvicorn", "uvicorn.error"):
        lib_logger = logging.getLogger(name)
        lib_logger.handlers.clear()
        lib_logger.propagate = True
    structlog.contextvars.bind_contextvars(service=service)
    _CONFIGURED = True


def get_logger(name: str | None = None, **initial: Any) -> structlog.stdlib.BoundLogger:
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name, **initial)
    return logger


def is_configured() -> bool:
    return _CONFIGURED
