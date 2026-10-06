# Phase 7 - Document processing

## 1. Purpose
Let organisations bring their own documents - PDF, Word, text, Markdown, CSV, JSON, HTML - into
research, while treating every file as **confidential** (it must not leak) and **hostile** (it may
attack the parser, the people who download it, or the language model that later reads it).

## 2. Architecture
```
POST /documents (multipart, ≤ 25 MB while streaming, one file)
  └─ type by content (magic bytes; extension + MIME must agree; executables/archives refused)
  └─ duplicate? → 200 with the existing document
  └─ seal (AES-256-GCM data key, wrapped by the keyring) → object store (local disk or S3)
  └─ one transaction: documents row (pending_scan) + documents.process job + audit
worker: documents.process
  └─ unseal + verify SHA-256 → malware scan (ClamAV INSTREAM)
       ├─ infected → quarantined (+ security audit)          ├─ scanner down → retry later
       └─ clean → processing → sandboxed parse (fresh process, limits) → re-sanitise
            → injection assessment (hidden text as evidence) → ready | failed
GET .../content (API clients)   POST .../download-link → GET /downloads/<token> (browsers,
re-authorised on use)   DELETE → row + storage.delete job (retried until the blob is gone)
```

## 3. Why these technologies
* **pypdf** (pure Python) for PDF text: no native code to exploit, and it runs in the sandbox anyway.
* **A 100-line WordprocessingML reader on defusedxml** instead of python-docx: DOCX is a ZIP of
  XML; reading only `w:t`/`w:tab`/`w:br` with DTDs forbidden is smaller and safer than a full
  object model, and it can see hidden runs.
* **A child process, not threads**: only a separate process can be killed reliably, given its own
  memory limit, and denied the parent's secrets.
* **boto3 (optional extra)** for S3/MinIO; the local backend needs nothing.
* **ClamAV** via its stable `INSTREAM` protocol - no library, 60 lines of asyncio.

## 4. Security considerations
See [ADR 0009](../architecture/decisions/0009-document-storage-and-parsing.md) and threat model
rows D1-D6. Highlights:
* The **bytes decide the type**; the name and MIME type are claims that must agree.
* **Nothing is parsed or downloadable before a clean scan**, and a scanner outage cannot change
  that - the job retries.
* **The parser is assumed compromisable**: it runs with no secrets, no write access, bounded
  memory/CPU/time, and its output is validated like any other untrusted input.
* **ZIP and XML bombs** are stopped from the central directory and by refusing DTDs - before any
  decompression or entity expansion happens.
* **Encryption at rest is the application's job**, so neither a leaked bucket nor a misconfigured
  ACL exposes content, and an object moved to another tenant's path fails authentication.
* **Download links are capabilities with a conscience**: five minutes, HMAC-signed, redacted
  from logs, and re-checked against the creator's session and permissions when clicked.
* **Hidden text is evidence, not content** - invisible Word runs, Markdown comments and hidden HTML
  feed the injection score but never the text a model will read.

## 5. Files
`infrastructure/storage/{store,s3}.py`, `infrastructure/malware.py`, `security/sealed.py`,
`security/links.py`, `security/parsing/{model,formats,worker,sandbox}.py`,
`modules/documents/{models,schemas,validation,service,tasks}.py`, `apps/api/v1/documents.py`,
`migrations/versions/0006_documents.py`, ADR 0009.

## 6. Code worth reading
* `security/parsing/sandbox.py::_run` - how a child process is started, fed, bounded and killed.
* `security/parsing/worker.py::_limit_resources` - why limits are set *after* imports and *before*
  input is read.
* `security/parsing/formats.py::vet_archive` and `_wordml_text` - zip-bomb checks from metadata
  alone, and a streaming XML reader that separates hidden runs.
* `security/sealed.py` - envelope encryption in 40 lines, and why the storage key is AAD.
* `apps/api/v1/documents.py::download_with_link` - capability verification followed by full
  re-authorisation.

## 7. Tests
* `tests/security/test_documents_parsing.py` - every format, encrypted and active-content PDFs,
  XXE/entity bombs, zip bombs, hostile archive paths, CSV formula cells, JSON depth without
  recursion, linear-time Markdown comment splitting; the sandbox's environment, timeout, refusal
  of bad requests, untrusted-output handling, and (Linux CI) the memory limit.
* `tests/security/test_documents_storage.py` - key validation, local and S3 (moto) stores,
  encryption at rest, AAD binding, tampering, KEK rotation, link forgery and expiry, the scanners
  (including a fake clamd), file-type decisions and file-name sanitising.
* `tests/integration/test_documents.py` - upload → scan → parse → read; dedup; ciphertext on disk;
  spoofed/dangerous files; request validation; size limit; EICAR quarantine; hidden Word
  instructions; unparseable files; scanner outage; download headers; link re-authorisation
  (expiry, tampering, member removal, logout); API keys; restricted classification; deletion;
  tenant isolation.

Fixtures (PDFs, DOCX, zip bombs, the EICAR test file) are generated at test time - nothing hostile
is committed, and the EICAR string is stored reversed so local antivirus does not quarantine the
repository.

## 8. Common mistakes avoided
Trusting the extension; parsing in the web process; `zipfile.extractall`; python-docx/lxml with
default entity handling; pre-signed bucket URLs; storing plaintext in the bucket and calling SSE
"encryption"; treating a scanner timeout as clean; serving HTML inline; filenames in storage paths;
logging download URLs.

## 9. Scalability
Uploads are bounded and streamed; processing scales with worker replicas (queue `documents`), with
a per-worker cap on concurrent sandboxes; storage scales with the bucket; identical uploads are
stored once per project.

## 10. Next phases
Phase 8 chunks `documents.text` (page offsets give citations a page number), phase 9 embeds the
chunks, phase 10 retrieves them under the same classification rules. Retention sweeps (phase 24)
and the KEK re-wrap job (phase 19) build on `needs_rewrap`.

## 11. Acceptance criteria
- [x] Polyglot/disguised files, zip bombs, XXE and the EICAR test file are rejected or quarantined.
- [x] Nothing is parsed or downloadable before a clean scan; scanner outages delay, never skip.
- [x] Parsers run in a resource-limited process without secrets; a timeout kills it.
- [x] Blobs are ciphertext at rest and bound to their storage key.
- [x] Download links expire, cannot be forged, and die with the creator's session or membership.
- [x] Restricted documents are invisible without `documents:read_restricted`; tenants are isolated.
- [x] Deleting a document removes the row immediately and the blob through a retried job.
