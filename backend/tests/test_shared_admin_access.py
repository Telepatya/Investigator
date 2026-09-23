from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from fastapi.testclient import TestClient

import app.config as app_config
from app.auth.config import get_auth_config
from app.auth.session import clear_auth_state, create_session, sync_auth_policy


ADMIN_ENV = {
    "INVESTIGATOR_AUTH_ENABLED": "true",
    "INVESTIGATOR_PUBLIC_ORIGIN": "http://localhost:8400",
    "INVESTIGATOR_OIDC_ISSUER": "http://localhost:9000",
    "INVESTIGATOR_OIDC_CLIENT_ID": "client",
    "INVESTIGATOR_OIDC_CLIENT_SECRET": "secret",
    "INVESTIGATOR_SSO_CLAIMS": "groups",
    "INVESTIGATOR_SSO_ALLOWED_VALUES": "Analysts",
    "INVESTIGATOR_SSO_ADMIN_CLAIM": "groups",
    "INVESTIGATOR_SSO_ADMIN_VALUE": "Admins",
}
ORIGIN_HEADERS = {"origin": "http://localhost:8400"}


class SharedAdminAccessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.old_config_dir = app_config.DEFAULT_CONFIG_DIR
        self.old_cases_dir = app_config.DEFAULT_CASES_DIR
        self.old_config_file = app_config.CONFIG_FILE
        app_config.DEFAULT_CONFIG_DIR = Path(self.temp.name)
        app_config.DEFAULT_CASES_DIR = Path(self.temp.name) / "cases"
        app_config.CONFIG_FILE = Path(self.temp.name) / "config.json"
        clear_auth_state()

        self.env = patch.dict(os.environ, ADMIN_ENV, clear=True)
        self.env.start()
        sync_auth_policy(get_auth_config().policy_fingerprint)
        from app.main import app

        self.client = TestClient(app, base_url="http://localhost:8400")
        self.set_user(is_admin=False)

    def tearDown(self) -> None:
        self.client.close()
        clear_auth_state()
        self.env.stop()
        app_config.DEFAULT_CONFIG_DIR = self.old_config_dir
        app_config.DEFAULT_CASES_DIR = self.old_cases_dir
        app_config.CONFIG_FILE = self.old_config_file
        self.temp.cleanup()

    def set_user(self, *, is_admin: bool) -> None:
        token, _ = create_session(
            subject="shared-admin-test",
            display_name="Admin test",
            email=None,
            is_admin=is_admin,
            idle_seconds=3600,
            absolute_seconds=7200,
        )
        self.client.cookies.set("investigator_session", token)

    def test_non_admin_settings_mutations_are_denied_without_side_effects(self) -> None:
        from app.api import settings_router

        with (
            patch.object(settings_router, "load_config", wraps=settings_router.load_config) as load_config,
            patch.object(settings_router, "save_config") as save_config,
            patch.object(settings_router, "save_api_key") as save_api_key,
            patch.object(settings_router, "delete_api_key") as delete_api_key,
            patch.object(settings_router, "test_provider", new=AsyncMock()) as test_provider,
        ):
            responses = [
                self.client.put(
                    "/api/settings/llm",
                    json={"provider": "openai", "api_key": "must-not-persist"},
                    headers=ORIGIN_HEADERS,
                ),
                self.client.post(
                    "/api/settings/llm/key/openai",
                    json={"api_key": "must-not-persist"},
                    headers=ORIGIN_HEADERS,
                ),
                self.client.delete("/api/settings/llm/key/openai", headers=ORIGIN_HEADERS),
                self.client.post("/api/settings/llm/test/openai", headers=ORIGIN_HEADERS),
                self.client.put(
                    "/api/settings/general",
                    json={"yara_rules_dir": "must-not-persist"},
                    headers=ORIGIN_HEADERS,
                ),
                self.client.put(
                    "/api/settings/reverse",
                    json={"sandbox_memory_limit_mb": 4096},
                    headers=ORIGIN_HEADERS,
                ),
            ]

        self.assertEqual([response.status_code for response in responses], [403] * 6)
        load_config.assert_not_called()
        save_config.assert_not_called()
        save_api_key.assert_not_called()
        delete_api_key.assert_not_called()
        test_provider.assert_not_awaited()
        self.assertFalse(app_config.CONFIG_FILE.exists())

        access = self.client.get("/api/settings/access")
        self.assertEqual(access.status_code, 200)
        self.assertEqual(
            access.json(),
            {"admin_required": True, "can_manage_shared_state": False},
        )
        self.assertEqual(access.headers["cache-control"], "no-store")

    def test_non_admin_cannot_delete_shared_cases_or_reverse_projects(self) -> None:
        from app.api import cases_router
        from app.reverse import router as reverse_router

        with (
            patch.object(cases_router.case_store, "case_exists", return_value=True) as case_exists,
            patch.object(cases_router.case_store, "delete_case") as delete_case,
            patch.object(cases_router, "_discard_case_uploads") as discard_uploads,
            patch.object(reverse_router, "validate_project_id") as validate_project_id,
            patch.object(reverse_router, "_project_or_404") as get_project,
            patch.object(reverse_router, "delete_project") as delete_project,
            patch.object(reverse_router.analysis_manager, "stop", new=AsyncMock()) as stop_analysis,
            patch.object(reverse_router.sandbox_manager, "stop") as stop_sandbox,
        ):
            case_response = self.client.delete("/api/cases/1234abcd", headers=ORIGIN_HEADERS)
            project_response = self.client.delete(
                "/api/reverse/projects/00000000-0000-4000-8000-000000000001",
                headers=ORIGIN_HEADERS,
            )

        self.assertEqual(case_response.status_code, 403)
        self.assertEqual(project_response.status_code, 403)
        case_exists.assert_not_called()
        delete_case.assert_not_called()
        discard_uploads.assert_not_called()
        validate_project_id.assert_not_called()
        get_project.assert_not_called()
        stop_analysis.assert_not_awaited()
        stop_sandbox.assert_not_called()
        delete_project.assert_not_called()

    def test_non_admin_cannot_mutate_global_rules_without_side_effects(self) -> None:
        from app.rules import router as rules_router

        with (
            patch.object(rules_router.store, "set_builtin_state") as set_builtin_state,
            patch.object(rules_router.store, "create_custom_rule") as create_custom_rule,
            patch.object(rules_router.store, "update_custom_rule") as update_custom_rule,
            patch.object(rules_router.store, "delete_custom_rule") as delete_custom_rule,
            patch.object(rules_router.store, "import_rules") as import_rules,
            patch.object(rules_router.fork_module, "build_fork_yaml") as build_fork_yaml,
        ):
            responses = [
                self.client.patch(
                    "/api/rules/builtin/lolbin.certutil",
                    json={"enabled": False},
                    headers=ORIGIN_HEADERS,
                ),
                self.client.post(
                    "/api/rules/custom",
                    json={"yaml_source": "title: test\\nid: test\\n"},
                    headers=ORIGIN_HEADERS,
                ),
                self.client.patch(
                    "/api/rules/custom/00000000-0000-4000-8000-000000000001",
                    json={"enabled": False},
                    headers=ORIGIN_HEADERS,
                ),
                self.client.delete(
                    "/api/rules/custom/00000000-0000-4000-8000-000000000001",
                    headers=ORIGIN_HEADERS,
                ),
                self.client.post(
                    "/api/rules/builtin/lolbin.mshta/fork",
                    json={"disable_builtin": True},
                    headers=ORIGIN_HEADERS,
                ),
                self.client.post(
                    "/api/rules/import",
                    json={"yaml_source": "title: test\\nid: test\\n"},
                    headers=ORIGIN_HEADERS,
                ),
            ]

        self.assertEqual([response.status_code for response in responses], [403] * 6)
        set_builtin_state.assert_not_called()
        create_custom_rule.assert_not_called()
        update_custom_rule.assert_not_called()
        delete_custom_rule.assert_not_called()
        import_rules.assert_not_called()
        build_fork_yaml.assert_not_called()

    def test_admin_can_change_global_settings_and_credentials(self) -> None:
        from app.api import settings_router

        self.set_user(is_admin=True)
        cfg = app_config.AppConfig(cases_dir=str(app_config.DEFAULT_CASES_DIR))
        with (
            patch.object(settings_router, "load_config", return_value=cfg),
            patch.object(settings_router, "save_config") as save_config,
            patch.object(settings_router, "save_api_key") as save_api_key,
            patch.object(settings_router, "list_models_for_provider", new=AsyncMock(return_value=[])),
            patch.object(settings_router, "test_provider", new=AsyncMock(return_value=(True, "ok", []))) as test_provider,
        ):
            general = self.client.put(
                "/api/settings/general",
                json={"yara_rules_dir": "admin-rules"},
                headers=ORIGIN_HEADERS,
            )
            credential = self.client.post(
                "/api/settings/llm/key/openai",
                json={"api_key": "admin-secret"},
                headers=ORIGIN_HEADERS,
            )
            provider_test = self.client.post(
                "/api/settings/llm/test/openai",
                headers=ORIGIN_HEADERS,
            )

        self.assertEqual(general.status_code, 200, general.text)
        self.assertEqual(credential.status_code, 200, credential.text)
        self.assertEqual(provider_test.status_code, 200, provider_test.text)
        self.assertGreaterEqual(save_config.call_count, 1)
        save_api_key.assert_called_once_with("openai", "admin-secret")
        test_provider.assert_awaited_once_with("openai")

    def test_local_auth_and_sso_without_admin_claim_preserve_existing_access(self) -> None:
        from app.api import settings_router

        cfg = app_config.AppConfig(cases_dir=str(app_config.DEFAULT_CASES_DIR))
        with (
            patch.object(settings_router, "load_config", return_value=cfg),
            patch.object(settings_router, "save_config") as save_config,
        ):
            sso_env = {key: value for key, value in ADMIN_ENV.items() if "ADMIN_" not in key}
            with patch.dict(os.environ, sso_env, clear=True):
                sync_auth_policy(get_auth_config().policy_fingerprint)
                self.set_user(is_admin=False)
                sso_response = self.client.put(
                    "/api/settings/general",
                    json={"yara_rules_dir": "analyst-rules"},
                    headers=ORIGIN_HEADERS,
                )

            self.client.cookies.clear()
            with patch.dict(os.environ, {}, clear=True):
                local_response = self.client.put(
                    "/api/settings/general",
                    json={"yara_rules_dir": "local-rules"},
                    headers=ORIGIN_HEADERS,
                )

        self.assertEqual(sso_response.status_code, 200, sso_response.text)
        self.assertEqual(local_response.status_code, 200, local_response.text)
        self.assertEqual(save_config.call_count, 2)


class ReverseSandboxErrorMappingTests(unittest.TestCase):
    def test_resume_and_replay_keep_sandbox_unavailable_as_503(self) -> None:
        from app.reverse import router as reverse_router
        from app.reverse.sandbox import SandboxUnavailable

        async def check() -> None:
            with (
                patch.object(reverse_router, "_project_or_404"),
                patch.object(
                    reverse_router.analysis_manager,
                    "resume",
                    new=AsyncMock(side_effect=SandboxUnavailable("sandbox missing")),
                ),
            ):
                with self.assertRaises(HTTPException) as resume_error:
                    await reverse_router.resume_analysis("00000000-0000-4000-8000-000000000001")
            self.assertEqual(resume_error.exception.status_code, 503)

            with (
                patch.object(reverse_router, "_project_or_404"),
                patch.object(
                    reverse_router.analysis_manager,
                    "replay",
                    new=AsyncMock(side_effect=SandboxUnavailable("sandbox missing")),
                ),
            ):
                with self.assertRaises(HTTPException) as replay_error:
                    await reverse_router.replay_analysis("00000000-0000-4000-8000-000000000001")
            self.assertEqual(replay_error.exception.status_code, 503)

        asyncio.run(check())


if __name__ == "__main__":
    unittest.main()
