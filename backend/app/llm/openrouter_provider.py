"""OpenRouter LLM provider using its OpenAI-compatible API."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
from openai import AsyncOpenAI

from app.config import get_api_key
from app.llm.base import LLMProvider
from app.models.schemas import ModelInfo


DEFAULT_MODELS = [
    "openrouter/auto",
    "~openai/gpt-latest",
    "~anthropic/claude-sonnet-latest",
    "~google/gemini-flash-latest",
]


class OpenRouterProvider(LLMProvider):
    provider = "openrouter"

    @property
    def base_url(self) -> str:
        return self.config.llm.openrouter_base_url.rstrip("/")

    def _api_key(self) -> str:
        key = get_api_key("openrouter")
        if not key:
            raise ValueError("OpenRouter API key not configured")
        return key

    def _client(self) -> AsyncOpenAI:
        return AsyncOpenAI(
            api_key=self._api_key(),
            base_url=self.base_url,
            default_headers={"X-OpenRouter-Title": "Investigator"},
        )

    async def list_models(self) -> list[ModelInfo]:
        try:
            models = await self._client().models.list()
            available = sorted(
                (
                    ModelInfo(
                        id=model.id,
                        name=getattr(model, "name", None) or model.id,
                        provider="openrouter",
                    )
                    for model in models.data
                    if getattr(model, "id", None)
                ),
                key=lambda model: model.id,
            )
            return available or self._default_models()
        except Exception:
            return self._default_models()

    async def test_connection(self) -> tuple[bool, str]:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{self.base_url}/key",
                    headers={"Authorization": f"Bearer {self._api_key()}"},
                )
                response.raise_for_status()
            return True, "OpenRouter API key is valid"
        except Exception as exc:
            return False, str(exc)

    async def complete(
        self, messages: list[dict[str, str]], stream: bool = False,
    ) -> str | AsyncIterator[str]:
        client = self._client()
        if not stream:
            response = await client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            return response.choices[0].message.content or ""

        async def _stream() -> AsyncIterator[str]:
            response = await client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                stream=True,
            )
            async for chunk in response:
                delta = chunk.choices[0].delta.content
                if delta:
                    yield delta

        return _stream()

    @staticmethod
    def _default_models() -> list[ModelInfo]:
        return [
            ModelInfo(id=model, name=model, provider="openrouter")
            for model in DEFAULT_MODELS
        ]
