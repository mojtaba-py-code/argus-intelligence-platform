"""OpenAI-compatible chat completions: OpenAI, or a self-hosted server (vLLM, Ollama, LM Studio).

Each model's locality is declared in the routing file (``openai/<model>`` entries): a self-hosted
endpoint inside the network may receive data an external API may not. Structured outputs are requested with
``response_format: json_schema`` (non-strict, for compatibility across servers); the gateway
validates and repairs the result either way.
"""

from __future__ import annotations

from typing import Any, Final

import httpx2
import openai

from argus.modules.llm.types import (
    ProviderCall,
    ProviderError,
    ProviderRefused,
    ProviderResult,
    ProviderRetryable,
    ProviderTruncated,
)

_RETRYABLE_STATUS: Final = frozenset({408, 409, 429, 500, 502, 503, 504})


class OpenAICompatibleProvider:
    name = "openai"

    def __init__(
        self,
        api_key: str | None,
        *,
        base_url: str | None = None,
        timeout_s: float = 180.0,
        http_client: httpx2.AsyncClient | None = None,
    ) -> None:
        options: dict[str, Any] = {"http_client": http_client} if http_client is not None else {}
        self._client = openai.AsyncOpenAI(
            api_key=api_key or "not-required-by-self-hosted-servers",
            base_url=base_url,
            timeout=timeout_s,
            max_retries=0,
            **options,
        )

    async def complete(self, call: ProviderCall) -> ProviderResult:
        params: dict[str, Any] = {
            "model": call.model,
            "messages": [
                {"role": "system", "content": call.system},
                {"role": "user", "content": call.user},
            ],
            "max_completion_tokens": call.max_tokens,
        }
        if call.output_model is not None:
            params["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "output",
                    "schema": call.output_model.model_json_schema(),
                    "strict": False,
                },
            }
        try:
            response = await self._client.chat.completions.create(**params)
        except openai.APIStatusError as exc:
            if exc.status_code in _RETRYABLE_STATUS:
                raise ProviderRetryable(
                    f"HTTP {exc.status_code}", code=f"http_{exc.status_code}"
                ) from exc
            raise ProviderError(f"HTTP {exc.status_code}", code=f"http_{exc.status_code}") from exc
        except openai.APITimeoutError as exc:
            raise ProviderRetryable("timeout", code="timeout") from exc
        except openai.APIConnectionError as exc:
            raise ProviderRetryable("connection error", code="connection") from exc
        except openai.APIError as exc:
            raise ProviderError("provider error", code="api_error") from exc

        if not response.choices:
            raise ProviderError("no choices returned", code="empty")
        choice = response.choices[0]
        if getattr(choice.message, "refusal", None):
            raise ProviderRefused("model")
        if choice.finish_reason == "content_filter":
            raise ProviderRefused("content_filter")
        if choice.finish_reason == "length":
            raise ProviderTruncated("the output reached max_completion_tokens")
        usage = response.usage
        return ProviderResult(
            text=choice.message.content or "",
            served_model=response.model or call.model,
            input_tokens=int(usage.prompt_tokens) if usage else 0,
            output_tokens=int(usage.completion_tokens) if usage else 0,
            request_id=getattr(response, "_request_id", None),
        )

    async def aclose(self) -> None:
        await self._client.close()
