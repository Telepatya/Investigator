"""Ollama local LLM provider."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx

from app.llm.base import LLMProvider
from app.models.schemas import ModelInfo


class OllamaProvider(LLMProvider):
    provider = "ollama"

    @property
    def base_url(self) -> str:
        return self.config.llm.ollama_base_url.rstrip("/")

    async def list_models(self) -> list[ModelInfo]:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                resp.raise_for_status()
                data = resp.json()
                return [
                    ModelInfo(id=m["name"], name=m["name"], provider="ollama")
                    for m in data.get("models", [])
                ]
        except Exception:
            return [
                ModelInfo(id="llama3.2", name="llama3.2", provider="ollama"),
                ModelInfo(id="mistral", name="mistral", provider="ollama"),
            ]

    async def test_connection(self) -> tuple[bool, str]:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                resp.raise_for_status()
                count = len(resp.json().get("models", []))
                return True, f"Connected to Ollama ({count} models available)"
        except Exception as e:
            return False, f"Cannot reach Ollama at {self.base_url}: {e}"

    async def complete(self, messages: list[dict[str, str]], stream: bool = False) -> str | AsyncIterator[str]:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": stream,
            "options": {"temperature": self.temperature, "num_predict": self.max_tokens},
        }
        if not stream:
            async with httpx.AsyncClient(timeout=300) as client:
                resp = await client.post(f"{self.base_url}/api/chat", json=payload)
                resp.raise_for_status()
                return resp.json().get("message", {}).get("content", "")

        base_url = self.base_url

        async def _stream() -> AsyncIterator[str]:
            import json
            async with httpx.AsyncClient(timeout=300) as client:
                async with client.stream("POST", f"{base_url}/api/chat", json=payload) as resp:
                    resp.raise_for_status()
                    async for line in resp.aiter_lines():
                        if not line:
                            continue
                        chunk = json.loads(line)
                        content = chunk.get("message", {}).get("content", "")
                        if content:
                            yield content

        return _stream()
