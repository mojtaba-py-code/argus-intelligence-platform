"""Untrusted-document parsing.

The API and worker processes never parse PDF, DOCX or other document formats themselves: they
hand the bytes to :class:`SandboxedParser`, which runs :mod:`argus.security.parsing.worker` in a
separate, resource-limited process with no secrets in its environment. The parsers
(:mod:`argus.security.parsing.formats`) only ever execute inside that process, and the parent
treats whatever comes back as untrusted (schema-validated, re-sanitised, size-capped).
"""

from argus.security.parsing.model import KINDS, ParsedDocument, ParseError, ParseLimits
from argus.security.parsing.sandbox import SandboxedParser

__all__ = ["KINDS", "ParseError", "ParseLimits", "ParsedDocument", "SandboxedParser"]
