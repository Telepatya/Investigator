from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY, AsyncMock, MagicMock, patch

from app import config as config_module
from app.config import AppConfig
from app.llm.base import get_provider
from app.llm.openrouter_provider import OpenRouterProvider


def _config() -> AppConfig:
    config = AppConfig()
    config.llm.provider = "openrouter"
    config.llm.model = "openrouter/auto"
    config.llm.openrouter_base_url = "https://openrouter.ai/api/v1/"
    return config


class OpenRouterProviderTests(unittest.IsolatedAsyncioTestCase):
    def test_config_accepts_openrouter_and_has_official_default_url(self) -> None:
        config = AppConfig.model_validate({"llm": {"provider": "openrouter"}})

        self.assertEqual(config.llm.provider, "openrouter")
        self.assertEqual(
            config.llm.openrouter_base_url,
            "https://openrouter.ai/api/v1",
        )

    def test_version_three_config_migrates_openrouter_settings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_dir = Path(directory)
            config_file = config_dir / "config.json"
            config_file.write_text(
                json.dumps({"config_version": 3, "llm": {"provider": "ollama"}}),
                encoding="utf-8",
            )
            with (
                patch.object(config_module, "DEFAULT_CONFIG_DIR", config_dir),
                patch.object(config_module, "DEFAULT_CASES_DIR", config_dir / "cases"),
                patch.object(config_module, "CONFIG_FILE", config_file),
            ):
                config = config_module.load_config()

            saved = json.loads(config_file.read_text(encoding="utf-8"))

        self.assertEqual(config.config_version, 4)
        self.assertEqual(
            config.llm.openrouter_base_url,
            "https://openrouter.ai/api/v1",
        )
        self.assertEqual(saved["config_version"], 4)
        self.assertEqual(
            saved["llm"]["openrouter_base_url"],
            "https://openrouter.ai/api/v1",
        )

    def test_factory_builds_openrouter_provider(self) -> None:
        provider = get_provider(_config())

        self.assertIsInstance(provider, OpenRouterProvider)
        self.assertEqual(provider.base_url, "https://openrouter.ai/api/v1")

    def test_client_uses_dedicated_key_and_configured_base_url(self) -> None:
        client = MagicMock()
        with (
            patch("app.llm.openrouter_provider.get_api_key", return_value="sk-or-test"),
            patch(
                "app.llm.openrouter_provider.AsyncOpenAI", return_value=client,
            ) as constructor,
        ):
            result = OpenRouterProvider(_config())._client()

        self.assertIs(result, client)
        constructor.assert_called_once_with(
            api_key="sk-or-test",
            base_url="https://openrouter.ai/api/v1",
            http_client=ANY,
            default_headers={"X-OpenRouter-Title": "Investigator"},
        )

    async def test_list_models_preserves_openrouter_names(self) -> None:
        models_api = SimpleNamespace(list=AsyncMock(return_value=SimpleNamespace(data=[
            SimpleNamespace(id="vendor/model-b", name="Model B"),
            SimpleNamespace(id="vendor/model-a", name=None),
        ])))
        provider = OpenRouterProvider(_config())

        with patch.object(
            provider, "_client", return_value=SimpleNamespace(models=models_api),
        ):
            models = await provider.list_models()

        self.assertEqual(
            [(model.id, model.name, model.provider) for model in models],
            [
                ("vendor/model-a", "vendor/model-a", "openrouter"),
                ("vendor/model-b", "Model B", "openrouter"),
            ],
        )

    async def test_non_streaming_completion_uses_generation_settings(self) -> None:
        create = AsyncMock(return_value=SimpleNamespace(choices=[
            SimpleNamespace(message=SimpleNamespace(content="answer")),
        ]))
        provider = OpenRouterProvider(_config())
        provider.config.llm.temperature = 0.35
        provider.config.llm.max_tokens = 1234

        with patch.object(
            provider,
            "_client",
            return_value=SimpleNamespace(chat=SimpleNamespace(
                completions=SimpleNamespace(create=create),
            )),
        ):
            result = await provider.complete([
                {"role": "user", "content": "question"},
            ])

        self.assertEqual(result, "answer")
        create.assert_awaited_once_with(
            model="openrouter/auto",
            messages=[{"role": "user", "content": "question"}],
            temperature=0.35,
            max_tokens=1234,
        )

    async def test_streaming_completion_yields_text_deltas(self) -> None:
        async def chunks():
            for content in ("first", None, " second"):
                yield SimpleNamespace(choices=[
                    SimpleNamespace(delta=SimpleNamespace(content=content)),
                ])

        create = AsyncMock(return_value=chunks())
        provider = OpenRouterProvider(_config())
        with patch.object(
            provider,
            "_client",
            return_value=SimpleNamespace(chat=SimpleNamespace(
                completions=SimpleNamespace(create=create),
            )),
        ):
            stream = await provider.complete(
                [{"role": "user", "content": "question"}],
                stream=True,
            )
            result = [chunk async for chunk in stream]

        self.assertEqual(result, ["first", " second"])
        self.assertTrue(create.await_args.kwargs["stream"])

    async def test_connection_uses_authenticated_key_endpoint(self) -> None:
        response = MagicMock()
        response.raise_for_status.return_value = None
        http_client = AsyncMock()
        http_client.get.return_value = response
        context = AsyncMock()
        context.__aenter__.return_value = http_client

        with (
            patch("app.llm.openrouter_provider.get_api_key", return_value="sk-or-test"),
            patch("app.llm.openrouter_provider.provider_http_client", return_value=context),
        ):
            ok, message = await OpenRouterProvider(_config()).test_connection()

        self.assertTrue(ok)
        self.assertEqual(message, "OpenRouter API key is valid")
        http_client.get.assert_awaited_once_with(
            "https://openrouter.ai/api/v1/key",
            headers={"Authorization": "Bearer sk-or-test"},
        )


if __name__ == "__main__":
    unittest.main()
