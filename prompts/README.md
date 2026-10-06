# Prompt registry

One directory per prompt, one YAML file per version: `prompts/<name>/v<N>.yaml`.
Files are validated at start-up by `argus.modules.llm.prompts.PromptRegistry`; the active version
per environment is stored in the `prompt_deployments` table (rollback without redeploying).
See [docs/ai/ai-architecture.md](../docs/ai/ai-architecture.md#2-prompt-management-prompts-argusmodulesllmprompts).
