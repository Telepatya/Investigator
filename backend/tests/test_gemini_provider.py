from __future__ import annotations

# ruff: noqa: E402

import sys
import types
import unittest
from unittest.mock import patch


class _BaseModel:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


sys.modules.setdefault("keyring", types.SimpleNamespace(
    get_password=lambda *_a, **_k: None,
    set_password=lambda *_a, **_k: None,
    delete_password=lambda *_a, **_k: None,
    errors=types.SimpleNamespace(PasswordDeleteError=Exception),
))
sys.modules.setdefault("pydantic", types.SimpleNamespace(
    BaseModel=_BaseModel,
    Field=lambda default=None, default_factory=None, **_k: (
        default_factory() if default_factory else default
    ),
))
_google_mod = types.ModuleType("google")
_genai_mod = types.ModuleType("google.genai")
_genai_types_mod = types.ModuleType("google.genai.types")
_genai_types_mod.GenerateContentConfig = lambda **_k: None
_genai_types_mod.HttpOptions = lambda **_k: None
_genai_mod.types = _genai_types_mod
_genai_mod.Client = lambda **_k: None
_google_mod.genai = _genai_mod
sys.modules.setdefault("google", _google_mod)
sys.modules.setdefault("google.genai", _genai_mod)
sys.modules.setdefault("google.genai.types", _genai_types_mod)

from app.llm.gemini_provider import (
    GEMINI_REQUEST_TIMEOUT_MS,
    GeminiProvider,
    _response_text,
)
from app.llm.orchestrator import _chat_tool_context, _retry_plain_text_answer


class _FunctionCallResponse:
    candidates = [types.SimpleNamespace(content=types.SimpleNamespace(parts=[
        types.SimpleNamespace(text="", function_call=types.SimpleNamespace(name="open_event")),
    ]))]

    @property
    def text(self):
        raise ValueError("Could not convert `part.function_call` to text.")


class GeminiResponseTextTests(unittest.TestCase):
    def test_function_call_only_part_is_ignored(self) -> None:
        self.assertEqual(_response_text(_FunctionCallResponse()), "")

    def test_text_is_preserved_alongside_function_call_part(self) -> None:
        response = types.SimpleNamespace(candidates=[
            types.SimpleNamespace(content=types.SimpleNamespace(parts=[
                types.SimpleNamespace(text="Downloaded files:"),
                types.SimpleNamespace(
                    text="",
                    function_call=types.SimpleNamespace(name="open_event"),
                ),
                types.SimpleNamespace(text=" file.exe"),
            ])),
        ])

        self.assertEqual(
            _response_text(response),
            "Downloaded files: file.exe",
        )


class GeminiPlainTextRetryTests(unittest.IsolatedAsyncioTestCase):
    async def test_empty_stream_can_be_retried_as_plain_text(self) -> None:
        class Provider:
            async def complete(self, messages, stream=False):
                self.messages = messages
                self.stream = stream
                return "Downloaded files: payload.exe"

        provider = Provider()
        answer = await _retry_plain_text_answer(
            provider,
            [{"role": "user", "content": "List downloads"}],
        )

        self.assertEqual(answer, "Downloaded files: payload.exe")
        self.assertFalse(provider.stream)
        self.assertIn("Do not call functions", provider.messages[-1]["content"])


class GeminiAsyncClientTests(unittest.IsolatedAsyncioTestCase):
    def test_forensic_request_timeout_allows_slow_async_responses(self) -> None:
        self.assertEqual(GEMINI_REQUEST_TIMEOUT_MS, 300_000)

    async def test_non_streaming_completion_uses_async_client(self) -> None:
        response = types.SimpleNamespace(candidates=[
            types.SimpleNamespace(content=types.SimpleNamespace(parts=[
                types.SimpleNamespace(text="async response"),
            ])),
        ])

        class AsyncModels:
            async def generate_content(self, **kwargs):
                self.kwargs = kwargs
                return response

        class SyncModels:
            def generate_content(self, **_kwargs):
                raise AssertionError("synchronous Gemini client blocked the event loop")

        async_models = AsyncModels()
        client = types.SimpleNamespace(
            aio=types.SimpleNamespace(models=async_models),
            models=SyncModels(),
        )
        provider = object.__new__(GeminiProvider)
        with (
            patch.object(GeminiProvider, "_client", return_value=client),
            patch.object(GeminiProvider, "_model_name", return_value="gemini-test"),
            patch.object(GeminiProvider, "_config", return_value=None),
        ):
            result = await provider.complete([{"role": "user", "content": "ping"}])

        self.assertEqual(result, "async response")
        self.assertEqual(async_models.kwargs["model"], "gemini-test")


class ChatToolContextTests(unittest.TestCase):
    def test_context_keeps_evidence_beyond_old_twelve_thousand_character_cap(self) -> None:
        marker = "https://downloads.example/final-payload.exe"
        context = _chat_tool_context([{
            "tool": "list_downloads",
            "args": {"limit": 200},
            "result_preview": "",
            "result": "x" * 20000 + marker,
        }])

        self.assertIn(marker, context)


if __name__ == "__main__":
    unittest.main()
