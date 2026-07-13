from __future__ import annotations

# ruff: noqa: E402

import sys
import types
import unittest


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
sys.modules.setdefault("google", types.ModuleType("google"))
sys.modules.setdefault("google.generativeai", types.SimpleNamespace())

from app.llm.gemini_provider import _response_text
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
