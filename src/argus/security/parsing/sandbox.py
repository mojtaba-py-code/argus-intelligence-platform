"""Parent side of the parser sandbox.

Each document is parsed in a fresh process (:mod:`.worker`):

* **no secrets** - the environment is replaced, not inherited (no keys, DSNs or proxy settings);
* **isolated interpreter** - ``-I`` ignores ``PYTHON*`` variables and user site-packages;
* **private scratch space** - a new temporary directory is the working directory and is removed
  afterwards;
* **resource limits** - wall-clock timeout enforced here (the process group is killed), plus
  address-space/CPU/file limits applied by the child on POSIX;
* **bounded I/O** - stdout and stderr are read with hard caps, so a compromised parser cannot
  exhaust the parent's memory;
* **untrusted output** - the JSON that comes back is schema-validated with size bounds, error
  codes are checked against a pattern, and the text is sanitised again by the caller.

What this does *not* provide is kernel-level isolation (seccomp, namespaces, gVisor): deployments
that parse documents from untrusted tenants at scale should run the worker in a sandboxed
container runtime as well - see docs/security/security-model.md.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import signal
import sys
import tempfile
from typing import Final

from pydantic import ValidationError

from argus.security.parsing.model import KINDS, ParsedDocument, ParseError, ParseLimits

WORKER_MODULE: Final = "argus.security.parsing.worker"
_STDERR_CAP: Final = 64 * 1024
_ERROR_CODE: Final = re.compile(r"[a-z_]{1,40}")


class _OutputTooLarge(Exception):
    pass


def _environment(workdir: str) -> dict[str, str]:
    """A fresh environment: nothing is inherited, so no secret can leak into the parser."""
    if sys.platform == "win32":
        env = {
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows"),
            "TEMP": workdir,
            "TMP": workdir,
        }
    else:
        env = {"PATH": "/usr/bin:/bin", "HOME": workdir, "TMPDIR": workdir, "LANG": "C.UTF-8"}
    return env


async def _read_capped(stream: asyncio.StreamReader | None, cap: int) -> bytes:
    if stream is None:
        return b""
    chunks = bytearray()
    while chunk := await stream.read(64 * 1024):
        chunks += chunk
        if len(chunks) > cap:
            raise _OutputTooLarge
    return bytes(chunks)


async def _feed(process: asyncio.subprocess.Process, data: bytes) -> None:
    if process.stdin is None:  # spawned with stdin=PIPE; never None in practice
        return
    with contextlib.suppress(BrokenPipeError, ConnectionResetError):
        process.stdin.write(data)
        await process.stdin.drain()
        process.stdin.close()
        await process.stdin.wait_closed()


def _kill(process: asyncio.subprocess.Process) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        if sys.platform == "win32":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)  # the whole group, not just the leader


class SandboxedParser:
    def __init__(
        self,
        limits: ParseLimits,
        *,
        timeout_s: float,
        memory_mb: int,
        max_concurrency: int = 2,
        python: str | None = None,
    ) -> None:
        self.limits = limits
        self._timeout = timeout_s
        self._memory_mb = memory_mb
        self._python = python or sys.executable
        self._slots = asyncio.Semaphore(max_concurrency)
        # JSON may need up to ~4 bytes per character plus escaping; metadata is small.
        self._stdout_cap = limits.max_text_chars * 8 + 2 * 1024 * 1024

    async def parse(self, data: bytes, kind: str) -> ParsedDocument:
        if kind not in KINDS:
            raise ParseError("unsupported_kind", kind[:20])
        if len(data) > self.limits.max_input_bytes:
            raise ParseError("too_large")
        async with self._slots:
            return await self._run(data, kind)

    async def _run(self, data: bytes, kind: str) -> ParsedDocument:
        with tempfile.TemporaryDirectory(prefix="argus-parse-") as workdir:
            process = await asyncio.create_subprocess_exec(
                self._python,
                "-I",
                "-B",
                "-X",
                "utf8",
                "-m",
                WORKER_MODULE,
                self.limits.to_json(),
                kind,
                str(self._memory_mb),
                str(int(self._timeout) + 1),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=workdir,
                env=_environment(workdir),
                start_new_session=sys.platform != "win32",
            )
            try:
                async with asyncio.timeout(self._timeout):
                    _, stdout, _ = await asyncio.gather(
                        _feed(process, data),
                        _read_capped(process.stdout, self._stdout_cap),
                        _read_capped(process.stderr, _STDERR_CAP),
                    )
                    returncode = await process.wait()
            except TimeoutError:
                _kill(process)
                await process.wait()
                raise ParseError("timeout", f"parsing exceeded {self._timeout:.0f} s") from None
            except _OutputTooLarge:
                _kill(process)
                await process.wait()
                raise ParseError("output_too_large") from None
            except BaseException:
                _kill(process)
                await process.wait()
                raise
        return self._result(stdout, returncode)

    @staticmethod
    def _result(stdout: bytes, returncode: int) -> ParsedDocument:
        if returncode != 0:
            # Negative: killed by a signal (RLIMIT_CPU/AS on POSIX); positive: interpreter failure.
            raise ParseError(
                "resource_limit" if returncode < 0 else "parser_crashed", str(returncode)
            )
        try:
            payload = json.loads(stdout)
        except ValueError:
            raise ParseError("parser_crashed", "malformed output") from None
        if not isinstance(payload, dict):
            raise ParseError("parser_crashed", "malformed output")
        if payload.get("ok") is not True:
            code = str(payload.get("error", ""))
            detail = str(payload.get("detail", ""))[:200]
            raise ParseError(code if _ERROR_CODE.fullmatch(code) else "parser_error", detail)
        try:
            return ParsedDocument.model_validate(payload.get("document"))
        except ValidationError:
            raise ParseError("parser_crashed", "output failed validation") from None
