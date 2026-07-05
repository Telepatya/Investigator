"""OpenAI LLM provider."""

from __future__ import annotations

from collections.abc import AsyncIterator

from openai import AsyncOpenAI

from app.config import get_api_key
from app.llm.base import LLMProvider
from app.models.schemas import ModelInfo


DEFAULT_MODELS = [
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-4-turbo",
    "o1-mini",
]


class OpenAIProvider(LLMProvider):
    provider = "openai"

    def _client(self) -> AsyncOpenAI:
        key = get_api_key("openai")
        if not key:
            raise ValueError("OpenAI API key not configured")
        return AsyncOpenAI(api_key=key)

    async def list_models(self) -> list[ModelInfo]:
        try:
            client = self._client()
            models = await client.models.list()
            chat_models = [
                m.id for m in models.data
                if any(x in m.id for x in ("gpt", "o1", "o3", "o4"))
            ]
            chat_models = sorted(set(chat_models)) or DEFAULT_MODELS
            return [ModelInfo(id=m, name=m, provider="openai") for m in chat_models]
        except Exception:
            return [ModelInfo(id=m, name=m, provider="openai") for m in DEFAULT_MODELS]

    async def test_connection(self) -> tuple[bool, str]:
        try:
            client = self._client()
            await client.models.list()
            return True, "OpenAI API key is valid"
        except Exception as e:
            return False, str(e)

    async def complete(self, messages: list[dict[str, str]], stream: bool = False) -> str | AsyncIterator[str]:
        client = self._client()
        if not stream:
            resp = await client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            return resp.choices[0].message.content or ""

        async def _stream() -> AsyncIterator[str]:
            stream_resp = await client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                stream=True,
            )
            async for chunk in stream_resp:
                delta = chunk.choices[0].delta.content
                if delta:
                    yield delta

        return _stream()
