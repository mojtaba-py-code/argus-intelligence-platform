"""Entry point of the parser sandbox process.

    python -I -B -X utf8 -m argus.security.parsing.worker <limits-json> <kind> <memory-mb> <cpu-s>

Reads one document from stdin and writes exactly one JSON object to stdout. The parent starts this
process with an empty environment (no secrets, no proxy settings), in a private temporary
directory, with ``-I`` (no user site-packages, no ``PYTHON*`` variables) and ``-B`` (no bytecode
writes). On POSIX it lowers its own resource limits *after* importing the parsers and *before*
reading any input: address space, CPU seconds, file size (no file writes at all), open files,
no core dumps and no child processes.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Final

from argus.security.parsing.formats import parse_document
from argus.security.parsing.model import ParseError, ParseLimits


def _limit_resources(memory_mb: int, cpu_s: int) -> None:
    """POSIX only; Windows has no rlimits, so there the parent's timeout is the control."""
    if sys.platform != "win32":
        import resource

        for limit, value in (
            (resource.RLIMIT_AS, memory_mb * 1024 * 1024),
            (resource.RLIMIT_CPU, cpu_s),
            (resource.RLIMIT_FSIZE, 0),
            (resource.RLIMIT_NOFILE, 32),
            (resource.RLIMIT_CORE, 0),
            (resource.RLIMIT_NPROC, 0),
        ):
            try:
                resource.setrlimit(limit, (value, value))
            except (ValueError, OSError):
                # Acceptable only when the existing hard limit is already stricter than ours.
                _, hard = resource.getrlimit(limit)
                if hard == resource.RLIM_INFINITY or hard > value:
                    raise


# Encoded while memory is unrestricted, so the reply to an exhausted address space needs no new
# allocation at the moment it is written.
_OUT_OF_MEMORY: Final = b'{"ok": false, "error": "memory_limit"}'


def _encode(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def _write(output: bytes) -> None:
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()


def _emit(payload: dict[str, Any]) -> None:
    _write(_encode(payload))


def _parse(kind: str, limits: ParseLimits) -> bytes:
    """The encoded reply for the document on stdin; ``MemoryError`` propagates to :func:`main`."""
    data = sys.stdin.buffer.read(limits.max_input_bytes + 1)
    if len(data) > limits.max_input_bytes:
        return _encode({"ok": False, "error": "too_large"})
    try:
        document = parse_document(kind, data, limits)
    except ParseError as exc:
        return _encode({"ok": False, "error": exc.code, "detail": exc.detail[:200]})
    except MemoryError:
        raise
    except RecursionError:
        return _encode({"ok": False, "error": "too_complex"})
    except Exception as exc:  # noqa: BLE001 - report the type only; never the message (may echo content)
        return _encode({"ok": False, "error": "parser_crashed", "detail": type(exc).__name__})
    # Encoding a large document can exhaust the limit as well, so it stays inside main's guard.
    return _encode({"ok": True, "document": document.model_dump(mode="json")})


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        _emit({"ok": False, "error": "bad_invocation"})
        return 2
    limits = ParseLimits.from_json(argv[1])
    kind = argv[2]
    _limit_resources(int(argv[3]), int(argv[4]))
    try:
        output = _parse(kind, limits)
    except MemoryError:
        # Only record it here: while the handler runs, the traceback still holds the partly built
        # document, so building a reply could fail again. Leaving the handler releases it.
        output = _OUT_OF_MEMORY
    _write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
