"""Google Gemini LLM provider."""

from __future__ import annotations

from collections.abc import AsyncIterator

import google.generativeai as genai

from app.config import get_api_key
from app.llm.base import LLMProvider
from app.models.schemas import ModelInfo


DEFAULT_MODELS = [
    "gemini-2.5-flash",
    "gemini-2.5-pro",
    "gemini-2.0-flash",
    "gemini-1.5-pro",
    "gemini-1.5-flash",
]


def _response_text(response) -> str:
    """Extract text without asking the SDK to stringify non-text parts.

    Gemini's ``response.text`` convenience property raises a ``ValueError``
    when a streamed candidate contains a structured function-call part. Tool
    gathering is handled by Investigator's own protocol, so those parts should
    be ignored while any text parts in the same response continue streaming.
    """
    candidates = getattr(response, "candidates", None) or []
    pieces: list[str] = []
    for candidate in candidates:
        content = getattr(candidate, "content", None)
        for part in getattr(content, "parts", None) or []:
            value = getattr(part, "text", None)
            if value:
                pieces.append(str(value))
    if pieces:
        return "".join(pieces)

    try:
        value = response.text
    except (AttributeError, ValueError):
        return ""
    return str(value) if value else ""


class GeminiProvider(LLMProvider):
    provider = "gemini"

    def _configure(self) -> None:
        key = get_api_key("gemini")
        if not key:
            raise ValueError("Gemini API key not configured")
        genai.configure(api_key=key)

    def _model_name(self) -> str:
        """Return a valid Gemini model name, guarding against stale/cross-provider values."""
        name = (self.model or "").strip()
        if name.startswith("models/"):
            name = name[len("models/"):]
        # Reject names that clearly aren't Gemini models (e.g. leftover Ollama ids
        # like 'hf.co/...:tag' or 'llama3.2'), which cause 400 'unexpected model
        # name format' errors from the API.
        if not name or not name.startswith("gemini") or "/" in name or ":" in name:
            return DEFAULT_MODELS[0]
        return name

    async def list_models(self) -> list[ModelInfo]:
        try:
            self._configure()
            models = []
            for m in genai.list_models():
                if "generateContent" in getattr(m, "supported_generation_methods", []):
                    name = m.name.replace("models/", "")
                    models.append(ModelInfo(id=name, name=name, provider="gemini"))
            return models or [ModelInfo(id=m, name=m, provider="gemini") for m in DEFAULT_MODELS]
        except Exception:
            return [ModelInfo(id=m, name=m, provider="gemini") for m in DEFAULT_MODELS]

    async def test_connection(self) -> tuple[bool, str]:
        try:
            self._configure()
            model = genai.GenerativeModel(self._model_name())
            resp = model.generate_content("ping")
            _ = resp.text
            return True, f"Gemini API key is valid (using {self._model_name()})"
        except Exception as e:
            return False, str(e)

    async def complete(self, messages: list[dict[str, str]], stream: bool = False) -> str | AsyncIterator[str]:
        self._configure()
        model = genai.GenerativeModel(self._model_name())

        # Flatten to single prompt for simplicity
        parts = []
        for m in messages:
            parts.append(f"{m['role'].upper()}: {m['content']}")
        prompt = "\n\n".join(parts)

        if not stream:
            resp = model.generate_content(
                prompt,
                generation_config=genai.GenerationConfig(
                    temperature=self.temperature,
                    max_output_tokens=self.max_tokens,
                ),
            )
            return _response_text(resp)

        async def _stream() -> AsyncIterator[str]:
            resp = model.generate_content(
                prompt,
                stream=True,
                generation_config=genai.GenerationConfig(
                    temperature=self.temperature,
                    max_output_tokens=self.max_tokens,
                ),
            )
            for chunk in resp:
                text = _response_text(chunk)
                if text:
                    yield text

        return _stream()
