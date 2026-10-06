"""Claude through the official Anthropic SDK.

* ``AsyncAnthropic(max_retries=0)``: the gateway owns retries, backoff and fallback.
* Streaming (``beta.messages.stream`` + ``get_final_message``) for every call, so long outputs
  never hit request timeouts. ``max_tokens`` covers thinking *and* the reply.
* No ``thinking`` parameter: current models think adaptively by default (Claude Opus 5.5 always
  does); ``output_config.effort`` is the control. No sampling parameters (rejected by current models).
* Structured outputs through ``output_config.format`` with a JSON schema; the gateway validates the
  result against the Pydantic model anyway.
* ``stop_reason`` is checked before content is read: ``refusal`` and ``max_tokens`` are distinct
  outcomes. The server-side refusal fallback (``fallbacks: "default"``, beta
  ``server-side-fallback-2026-07-01``) is enabled for models that support it, so a safety-classifier
  false positive is retried on Anthropic's recommended model instead of failing the request; the
  served model is read from the response for accounting.
"""

from __future__ import annotations

from typing import Any, Final

import anthropic
import httpx2

from argus.modules.llm.types import (
    ProviderCall,
    ProviderError,
    ProviderRefused,
    ProviderResult,
    ProviderRetryable,
    ProviderTruncated,
)

FALLBACK_BETA: Final = "server-side-fallback-2026-07-01"
_RETRYABLE_STATUS: Final = frozenset({408, 409, 429, 500, 502, 503, 504, 529})


def _retry_after(response: httpx2.Response | None) -> float | None:
    if response is None:
        return None
    value = response.headers.get("retry-after", "")
    return float(value) if value.replace(".", "", 1).isdigit() else None


class ClaudeProvider:
    name = "anthropic"

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str | None = None,
        timeout_s: float = 180.0,
        refusal_fallback: bool = True,
        http_client: httpx2.AsyncClient | None = None,
    ) -> None:
        options: dict[str, Any] = {"http_client": http_client} if http_client is not None else {}
        self._client = anthropic.AsyncAnthropic(
            api_key=api_key, base_url=base_url, timeout=timeout_s, max_retries=0, **options
        )
        self._refusal_fallback = refusal_fallback

    def _params(self, call: ProviderCall) -> dict[str, Any]:
        params: dict[str, Any] = {
            "model": call.model,
            "max_tokens": call.max_tokens,
            "system": call.system,
            "messages": [{"role": "user", "content": call.user}],
        }
        output_config: dict[str, Any] = {}
        if call.effort is not None:
            output_config["effort"] = call.effort
        if call.output_model is not None:
            # The SDK's transform keeps the schema within what structured outputs accept; the
            # gateway still validates the reply against the full Pydantic model.
            output_config["format"] = {
                "type": "json_schema",
                "schema": anthropic.transform_schema(call.output_model),
            }
        if output_config:
            params["output_config"] = output_config
        if self._refusal_fallback and call.refusal_fallback:
            params["betas"] = [FALLBACK_BETA]
            params["fallbacks"] = "default"
        return params

    async def complete(self, call: ProviderCall) -> ProviderResult:
        try:
            async with self._client.beta.messages.stream(**self._params(call)) as stream:
                message = await stream.get_final_message()
        except anthropic.APIStatusError as exc:
            if exc.status_code in _RETRYABLE_STATUS:
                raise ProviderRetryable(
                    f"HTTP {exc.status_code}",
                    retry_after_s=_retry_after(exc.response),
                    code=f"http_{exc.status_code}",
                ) from exc
            raise ProviderError(f"HTTP {exc.status_code}", code=f"http_{exc.status_code}") from exc
        except anthropic.APITimeoutError as exc:
            raise ProviderRetryable("timeout", code="timeout") from exc
        except anthropic.APIConnectionError as exc:
            raise ProviderRetryable("connection error", code="connection") from exc
        except anthropic.APIResponseValidationError as exc:
            raise ProviderError("unexpected response shape", code="bad_response") from exc
        except anthropic.APIError as exc:  # e.g. an error event in the middle of a stream
            raise ProviderRetryable("stream error", code="stream_error") from exc

        if message.stop_reason == "refusal":
            details = getattr(message, "stop_details", None)
            raise ProviderRefused(getattr(details, "category", None))
        if message.stop_reason == "max_tokens":
            raise ProviderTruncated("the output reached max_tokens")
        text = "".join(block.text for block in message.content if block.type == "text")
        usage = message.usage
        iterations = getattr(usage, "iterations", None) or []
        return ProviderResult(
            text=text,
            served_model=str(message.model),
            input_tokens=int(usage.input_tokens or 0),
            output_tokens=int(usage.output_tokens or 0),
            cache_read_tokens=int(getattr(usage, "cache_read_input_tokens", 0) or 0),
            cache_write_tokens=int(getattr(usage, "cache_creation_input_tokens", 0) or 0),
            fallback_used=any(
                getattr(entry, "type", None) == "fallback_message" for entry in iterations
            ),
            request_id=getattr(message, "_request_id", None),
        )

    async def aclose(self) -> None:
        await self._client.close()
