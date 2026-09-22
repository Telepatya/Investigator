"""Anthropic Claude LLM provider."""

from __future__ import annotations

from collections.abc import AsyncIterator

from anthropic import AsyncAnthropic

from app.config import get_api_key
from app.llm.base import LLMProvider
from app.llm.endpoints import provider_http_client, validate_endpoint
from app.models.schemas import ModelInfo


DEFAULT_MODELS = [
    "claude-sonnet-4-20250514",
    "claude-3-5-sonnet-20241022",
    "claude-3-5-haiku-20241022",
    "claude-3-opus-20240229",
]


class AnthropicProvider(LLMProvider):
    provider = "anthropic"

    def _client(self) -> AsyncAnthropic:
        key = get_api_key("anthropic")
        if not key:
            raise ValueError("Anthropic API key not configured")
        base_url = validate_endpoint("anthropic")
        return AsyncAnthropic(
            api_key=key, base_url=base_url,
            http_client=provider_http_client("anthropic", base_url),
        )

    async def list_models(self) -> list[ModelInfo]:
        return [ModelInfo(id=m, name=m, provider="anthropic") for m in DEFAULT_MODELS]

    async def test_connection(self) -> tuple[bool, str]:
        try:
            client = self._client()
            await client.messages.create(
                model=self.model if self.model in DEFAULT_MODELS else DEFAULT_MODELS[0],
                max_tokens=16,
                messages=[{"role": "user", "content": "ping"}],
            )
            return True, "Anthropic API key is valid"
        except Exception as e:
            return False, str(e)

    async def complete(self, messages: list[dict[str, str]], stream: bool = False) -> str | AsyncIterator[str]:
        client = self._client()
        system = ""
        chat_messages = []
        for m in messages:
            if m["role"] == "system":
                system = m["content"]
            else:
                chat_messages.append({"role": m["role"], "content": m["content"]})

        if not stream:
            resp = await client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=system or None,
                messages=chat_messages,
                temperature=self.temperature,
            )
            return "".join(block.text for block in resp.content if hasattr(block, "text"))

        async def _stream() -> AsyncIterator[str]:
            async with client.messages.stream(
                model=self.model,
                max_tokens=self.max_tokens,
                system=system or None,
                messages=chat_messages,
                temperature=self.temperature,
            ) as stream:
                async for text in stream.text_stream:
                    yield text

        return _stream()
