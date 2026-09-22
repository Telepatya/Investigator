from __future__ import annotations

import os
import unittest
from unittest.mock import patch

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import settings_router
from app.config import AppConfig
from app.llm.endpoints import ProviderEndpointError, normalize_endpoint, provider_http_client, validate_endpoint
from app.llm.openrouter_provider import OpenRouterProvider
from app.llm.ollama import OllamaProvider


class ProviderEndpointTests(unittest.IsolatedAsyncioTestCase):
    def test_local_custom_endpoints_preserve_paths_and_loopback(self):
        with patch.dict(os.environ, {"INVESTIGATOR_AUTH_ENABLED": "false"}):
            self.assertEqual(validate_endpoint("ollama", "http://localhost:11434/proxy/"), "http://localhost:11434/proxy")
            self.assertEqual(validate_endpoint("openrouter", "https://gateway.example.invalid/vendor/v1"), "https://gateway.example.invalid/vendor/v1")

    def test_malformed_endpoints_are_rejected(self):
        for value in ("file:///tmp/key", "https://user:pass@example.invalid/api", "https://example.invalid/api?key=value", "https://example.invalid/#part", "https://example.invalid/../api", "https://example.invalid/%2e%2e", "http://example.invalid:99999", "http://example.invalid:0", "https://example.invalid\\@localhost/", " https://example.invalid", "https://example.invalid\n"):
            with self.subTest(value=value), self.assertRaises(ProviderEndpointError):
                normalize_endpoint(value)

    def test_sso_exact_provider_specific_operator_approval(self):
        with patch.dict(os.environ, {"INVESTIGATOR_AUTH_ENABLED": "true", "INVESTIGATOR_OPENROUTER_APPROVED_URLS": "https://gateway.example.invalid/vendor/v1"}, clear=True):
            self.assertEqual(validate_endpoint("openrouter"), "https://openrouter.ai/api/v1")
            self.assertEqual(validate_endpoint("openrouter", "https://gateway.example.invalid/vendor/v1/"), "https://gateway.example.invalid/vendor/v1")
            for provider, value in (("ollama", "https://gateway.example.invalid/vendor/v1"), ("openrouter", "https://gateway.example.invalid/other"), ("openrouter", "http://127.0.0.1/private"), ("openrouter", "https://openrouter.ai.example.invalid/api/v1")):
                with self.subTest(provider=provider, value=value), self.assertRaises(ProviderEndpointError):
                    validate_endpoint(provider, value)

    def test_hosted_http_gateway_is_denied_even_when_operator_approved(self):
        for host in ("gateway.example.invalid", "10.0.0.1", "localhost.example.invalid", "127.0.0.1.example.invalid"):
            endpoint = f"http://{host}/v1"
            with self.subTest(host=host), patch.dict(os.environ, {"INVESTIGATOR_AUTH_ENABLED": "true", "INVESTIGATOR_OPENROUTER_APPROVED_URLS": endpoint}, clear=True):
                with self.assertRaisesRegex(ProviderEndpointError, "HTTPS"):
                    validate_endpoint("openrouter", endpoint)

    def test_hosted_approved_loopback_http_and_local_remote_http_remain_supported(self):
        for endpoint in ("http://localhost:11434", "http://127.0.0.1:11434", "http://[::1]:11434"):
            with self.subTest(endpoint=endpoint), patch.dict(os.environ, {"INVESTIGATOR_AUTH_ENABLED": "true", "INVESTIGATOR_OLLAMA_APPROVED_URLS": endpoint}, clear=True):
                self.assertEqual(validate_endpoint("ollama", endpoint), endpoint)
        with patch.dict(os.environ, {"INVESTIGATOR_AUTH_ENABLED": "false"}, clear=True):
            self.assertEqual(validate_endpoint("openrouter", "http://gateway.example.invalid/v1"), "http://gateway.example.invalid/v1")

    async def test_persisted_approved_remote_http_never_retrieves_key_or_constructs_client(self):
        endpoint = "http://gateway.example.invalid/v1"
        cfg = AppConfig()
        cfg.llm.openrouter_base_url = endpoint
        with patch.dict(os.environ, {"INVESTIGATOR_AUTH_ENABLED": "true", "INVESTIGATOR_OPENROUTER_APPROVED_URLS": endpoint}, clear=True), patch("app.llm.openrouter_provider.get_api_key") as key, patch("app.llm.openrouter_provider.AsyncOpenAI") as sdk:
            with self.assertRaisesRegex(ProviderEndpointError, "HTTPS"):
                OpenRouterProvider(cfg)._client()
            key.assert_not_called()
            sdk.assert_not_called()

    async def test_persisted_and_mutated_settings_cannot_send_key_or_request(self):
        cfg = AppConfig()
        cfg.llm.openrouter_base_url = "http://127.0.0.1/private"
        cfg.llm.ollama_base_url = "http://127.0.0.1/private"
        with patch.dict(os.environ, {"INVESTIGATOR_AUTH_ENABLED": "true"}, clear=True), patch("app.llm.openrouter_provider.get_api_key") as key, patch("app.llm.openrouter_provider.AsyncOpenAI") as sdk:
            with self.assertRaises(ProviderEndpointError):
                OpenRouterProvider(cfg)._client()
            ok, _ = await OpenRouterProvider(cfg).test_connection()
            self.assertFalse(ok)
            ok, _ = await OllamaProvider(cfg).test_connection()
            self.assertFalse(ok)
            key.assert_not_called()
            sdk.assert_not_called()

    async def test_transport_does_not_follow_redirect_or_leave_base(self):
        requests = []

        def handler(request):
            requests.append(request)
            return httpx.Response(302, headers={"Location": "https://elsewhere.example.invalid/key"})

        with patch.dict(os.environ, {"INVESTIGATOR_AUTH_ENABLED": "true", "HTTPS_PROXY": "http://proxy.example.invalid:8080"}, clear=True):
            async with provider_http_client("openrouter", validate_endpoint("openrouter")) as client:
                client._transport = httpx.MockTransport(handler)
                response = await client.get("https://openrouter.ai/api/v1/key", headers={"Authorization": "Bearer synthetic-test-key"})
                self.assertEqual(response.status_code, 302)
                self.assertFalse(client.trust_env)
                for url in ("https://elsewhere.example.invalid/key", "https://openrouter.ai/other", "https://openrouter.ai/api/v10/key"):
                    with self.assertRaises(ProviderEndpointError):
                        await client.get(url, headers={"Authorization": "Bearer synthetic-test-key"})
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].url.host, "openrouter.ai")

    def test_denied_settings_save_has_no_config_key_or_network_side_effect(self):
        app = FastAPI()
        app.include_router(settings_router.router)
        cfg = AppConfig()
        with patch.dict(os.environ, {"INVESTIGATOR_AUTH_ENABLED": "true"}, clear=True), patch.object(settings_router, "load_config", return_value=cfg), patch.object(settings_router, "save_config") as save, patch.object(settings_router, "save_api_key") as key, patch.object(settings_router, "list_models_for_provider") as models:
            response = TestClient(app).put("/api/settings/llm", json={"provider": "openrouter", "openrouter_base_url": "http://127.0.0.1/private", "api_key": "synthetic-test-key"})
            self.assertEqual(response.status_code, 422)
            self.assertEqual(cfg.llm.provider, "ollama")
            save.assert_not_called()
            key.assert_not_called()
            models.assert_not_called()
