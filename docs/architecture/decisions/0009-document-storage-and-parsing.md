# ADR 0009 - Encrypted blob storage, sandboxed parsing, API-mediated downloads

**Context.** Uploaded documents are confidential *and* hostile: a PDF or DOCX may carry exploits
for its parser, decompression bombs, XML entity tricks, malware for the colleagues who download it,
or instructions aimed at the language model. Object storage is the usual place where documents
leak (public buckets, over-broad pre-signed URLs, leaked credentials).

**Decision.**

1. **Envelope encryption in the application** (`argus.security.sealed`). Each object is encrypted
   with its own random 256-bit data key (AES-256-GCM); the data key is wrapped by the platform
   keyring (key-encryption key with a key id). Both layers bind the object's storage key as
   associated data. The storage backend - local disk or any S3-compatible bucket - only ever holds
   ciphertext; bucket-side encryption may be added on top but is not relied upon.
2. **Server-generated storage keys** `org/<id>/project/<id>/documents/<id>`, validated against a
   strict pattern at the storage layer. User-supplied file names are display-only.
3. **Type by content.** Magic bytes decide the type; extension and declared MIME must agree;
   executables and archives are refused. DOCX is accepted only when its ZIP directory contains a
   Word document.
4. **Scan before use.** A document stays `pending_scan` - unparsed, undownloadable - until the
   malware scanner (ClamAV over `INSTREAM`) reports it clean. Scanner outages retry the job; they
   never skip the scan. Infected files are quarantined and audited as security events.
5. **Parse in a sandbox.** Parsers run only in a fresh child process: empty environment (no
   secrets), isolated interpreter, private temporary directory, wall-clock timeout with
   process-group kill, POSIX resource limits (address space, CPU, no file writes, no child
   processes), capped output - and the parent validates and re-sanitises whatever comes back.
6. **Downloads through the API.** No pre-signed bucket URLs. API clients download with their
   credentials; browsers get short-lived HMAC-signed links that are **re-authorised at click
   time** (session still active, membership and permission still valid, document still clean).
   Responses are `Content-Disposition: attachment`, `nosniff`, `no-store`, CSP `sandbox`; HTML is
   served as `application/octet-stream`. Every download is audited; tokens are redacted from
   access logs.

**Consequences.** Downloads consume API bandwidth (documents are capped at 25 MB, so this is
acceptable); a stolen bucket or storage credential exposes nothing; revoking a user revokes their
links immediately. The process sandbox is not kernel isolation: deployments that accept documents
from untrusted tenants at scale should also run workers under gVisor/seccomp (phase 19/23).

**Rejected.** Pre-signed bucket URLs (no revocation, no audit, plaintext in the bucket);
server-side encryption alone (the storage provider holds the keys); parsing in the API/worker
process ("in-process sandboxes" are not sandboxes); python-docx/lxml for DOCX (entity handling is
easy to get wrong - a minimal defusedxml reader is smaller and safer).
