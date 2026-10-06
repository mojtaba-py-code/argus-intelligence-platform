# Configuration data

Data that changes more often than code and must be reviewed like code: LLM routing and pricing,
source reputation tiers, the common-password list. Loaded with `yaml.safe_load` only and validated
by Pydantic models at start-up. Secrets never live here - see `.env.example` and
[docs/security/security-model.md](../docs/security/security-model.md#5-secrets-and-cryptography).
