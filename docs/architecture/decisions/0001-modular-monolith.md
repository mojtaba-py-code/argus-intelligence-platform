# ADR 0001 - Modular monolith with three process roles

**Context.** The specification lists more than fifteen subsystems. Building them as separate
services from day one would mean distributed transactions (a research job, its queue entry and its
audit record must commit together), a network hop and an authentication boundary between every
module, and an operations burden far above the value it returns at this stage.

**Decision.** One Python package (`argus`) organised as bounded-context modules
(`argus.modules.<context>`) on top of shared kernels (`core`, `infrastructure`, `security`).
The same image runs as `api`, `worker` or `scheduler`. Module boundaries are executable:
`import-linter` contracts in `pyproject.toml` fail CI when a layer imports upward or when business
modules import FastAPI.

**Consequences.** One transactional store and one deployment pipeline. A module can later become a
service because its public surface (service classes and Pydantic schemas) is already explicit.
The cost is discipline: the contracts must stay strict, and a slow module can affect the shared
database - mitigated by per-process connection pools and statement timeouts.

**Rejected.** Microservices (premature); a single package without contracts (the default outcome
of skipping this decision).
