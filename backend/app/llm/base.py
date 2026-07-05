"""LLM provider abstraction."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import Any

from app.config import AppConfig, get_api_key, load_config
from app.models.schemas import ModelInfo, ProviderType


class LLMProvider(ABC):
    provider: ProviderType

    def __init__(self, config: AppConfig | None = None):
        self.config = config or load_config()

    @abstractmethod
    async def list_models(self) -> list[ModelInfo]:
        ...

    @abstractmethod
    async def test_connection(self) -> tuple[bool, str]:
        ...

    @abstractmethod
    async def complete(self, messages: list[dict[str, str]], stream: bool = False) -> str | AsyncIterator[str]:
        ...

    @property
    def model(self) -> str:
        return self.config.llm.model

    @property
    def temperature(self) -> float:
        return self.config.llm.temperature

    @property
    def max_tokens(self) -> int:
        return self.config.llm.max_tokens


def get_provider(config: AppConfig | None = None) -> LLMProvider:
    cfg = config or load_config()
    provider = cfg.llm.provider

    if provider == "ollama":
        from app.llm.ollama import OllamaProvider
        return OllamaProvider(cfg)
    if provider == "openai":
        from app.llm.openai_provider import OpenAIProvider
        return OpenAIProvider(cfg)
    if provider == "gemini":
        from app.llm.gemini_provider import GeminiProvider
        return GeminiProvider(cfg)
    if provider == "anthropic":
        from app.llm.anthropic_provider import AnthropicProvider
        return AnthropicProvider(cfg)
    raise ValueError(f"Unknown provider: {provider}")


async def list_models_for_provider(provider: ProviderType, config: AppConfig | None = None) -> list[ModelInfo]:
    cfg = config or load_config()
    original = cfg.llm.provider
    cfg.llm.provider = provider
    try:
        return await get_provider(cfg).list_models()
    finally:
        cfg.llm.provider = original


async def test_provider(provider: ProviderType, config: AppConfig | None = None) -> tuple[bool, str, list[ModelInfo]]:
    cfg = config or load_config()
    original = cfg.llm.provider
    cfg.llm.provider = provider
    try:
        p = get_provider(cfg)
        ok, msg = await p.test_connection()
        models = await p.list_models() if ok else []
        return ok, msg, models
    finally:
        cfg.llm.provider = original
