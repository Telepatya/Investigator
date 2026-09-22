"""Google Gemini LLM provider (google-genai SDK).

Uses the actively maintained ``google-genai`` client library. Google now
classifies the older ``google-generativeai`` package as legacy, so this provider
targets ``from google import genai`` and its ``Client`` API.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from google import genai
from google.genai import types as genai_types

from app.config import get_api_key
from app.llm.base import LLMProvider
from app.llm.endpoints import provider_http_client, validate_endpoint
from app.models.schemas import ModelInfo


DEFAULT_MODELS = [
    "gemini-2.5-flash",
    "gemini-2.5-pro",
    "gemini-2.0-flash",
    "gemini-1.5-pro",
    "gemini-1.5-flash",
]
# Long forensic prompts can take several minutes on Gemini. The async client
# keeps FastAPI responsive during this wait, so this deadline can be generous
# without reintroducing the UI freeze caused by the old synchronous call.
GEMINI_REQUEST_TIMEOUT_MS = 300_000


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

    def _client(self) -> genai.Client:
        key = get_api_key("gemini")
        if not key:
            raise ValueError("Gemini API key not configured")
        base_url = validate_endpoint("gemini")
        return genai.Client(
            api_key=key, vertexai=False,
            http_options=genai_types.HttpOptions(
                timeout=GEMINI_REQUEST_TIMEOUT_MS, base_url=base_url,
                httpx_async_client=provider_http_client("gemini", base_url),
                client_args={"trust_env": False, "follow_redirects": False},
            ),
        )

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

    def _config(self) -> genai_types.GenerateContentConfig:
        return genai_types.GenerateContentConfig(
            temperature=self.temperature,
            max_output_tokens=self.max_tokens,
        )

    async def list_models(self) -> list[ModelInfo]:
        try:
            client = self._client()
            models = []
            page = await client.aio.models.list()
            async for m in page:
                actions = (
                    getattr(m, "supported_actions", None)
                    or getattr(m, "supported_generation_methods", None)
                    or []
                )
                if "generateContent" in actions:
                    name = (getattr(m, "name", "") or "").replace("models/", "")
                    if name:
                        models.append(ModelInfo(id=name, name=name, provider="gemini"))
            return models or [ModelInfo(id=m, name=m, provider="gemini") for m in DEFAULT_MODELS]
        except Exception:
            return [ModelInfo(id=m, name=m, provider="gemini") for m in DEFAULT_MODELS]

    async def test_connection(self) -> tuple[bool, str]:
        try:
            client = self._client()
            resp = await client.aio.models.generate_content(
                model=self._model_name(), contents="ping"
            )
            _ = _response_text(resp)
            return True, f"Gemini API key is valid (using {self._model_name()})"
        except Exception as e:
            return False, str(e)

    async def complete(self, messages: list[dict[str, str]], stream: bool = False) -> str | AsyncIterator[str]:
        client = self._client()
        model_name = self._model_name()

        # Flatten to single prompt for simplicity
        parts = []
        for m in messages:
            parts.append(f"{m['role'].upper()}: {m['content']}")
        prompt = "\n\n".join(parts)

        if not stream:
            resp = await client.aio.models.generate_content(
                model=model_name, contents=prompt, config=self._config(),
            )
            return _response_text(resp)

        async def _stream() -> AsyncIterator[str]:
            async for chunk in await client.aio.models.generate_content_stream(
                model=model_name, contents=prompt, config=self._config(),
            ):
                text = _response_text(chunk)
                if text:
                    yield text

        return _stream()
