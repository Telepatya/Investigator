from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from app.auth.config import AuthConfig, get_auth_config
from app.auth.oidc import OIDCError, identity_from_claims
from app.auth.session import clear_auth_state, consume_transaction, create_session, create_transaction, get_session, revoke_session
import app.config as app_config


def _auth_config(**overrides) -> AuthConfig:
    values = {
        "enabled": True,
        "issuer": "https://idp.example.test/oauth2/default",
        "client_id": "client",
        "client_secret": "secret",
        "public_origin": "https://investigator.example.test",
        "claim_names": ("groups", "roles"),
        "allowed_values": ("Analysts", "00000000-0000-0000-0000-000000000001"),
        "admin_claim": "roles",
        "admin_value": "Investigator.Admin",
        "idle_seconds": 60,
        "absolute_seconds": 3600,
        "transaction_seconds": 600,
    }
    values.update(overrides)
    return AuthConfig(**values)


class AuthConfigTests(unittest.TestCase):
    def test_disabled_defaults_without_idp_configuration(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            cfg = get_auth_config()
        self.assertFalse(cfg.enabled)
        self.assertFalse(cfg.configured)

    def test_enabled_incomplete_configuration_fails_closed(self) -> None:
        with patch.dict(os.environ, {"INVESTIGATOR_AUTH_ENABLED": "true"}, clear=True):
            cfg = get_auth_config()
        self.assertTrue(cfg.enabled)
        self.assertFalse(cfg.configured)
        self.assertIn("OIDC issuer is required", cfg.error or "")

    def test_auth_disabled_does_not_discover_an_idp(self) -> None:
        from fastapi.testclient import TestClient
        from app.auth import oidc
        from app.main import app
        with patch.dict(os.environ, {}, clear=True), patch.object(oidc, "discover", new=AsyncMock()) as discover:
            response = TestClient(app, base_url="http://localhost").get("/api/auth/bootstrap")
        self.assertEqual(response.status_code, 200)
        discover.assert_not_awaited()


class IdentityClaimTests(unittest.TestCase):
    def test_okta_group_allowlist_and_admin_are_exact(self) -> None:
        identity = identity_from_claims(
            _auth_config(claim_names=("groups",), allowed_values=("IR-Analysts",), admin_claim="groups", admin_value="IR-Admins"),
            {"sub": "okta-sub", "groups": ["IR-Analysts", "IR-Admins"], "email": "analyst@example.test"},
        )
        self.assertEqual(identity.subject, "okta-sub")
        self.assertTrue(identity.is_admin)

    def test_entra_role_and_group_overage_fail_closed(self) -> None:
        identity = identity_from_claims(_auth_config(claim_names=("roles",), allowed_values=("Investigator.Analyst",)), {"sub": "entra-sub", "roles": ["Investigator.Analyst"]})
        self.assertEqual(identity.subject, "entra-sub")
        for claims in (
            {"sub": "x", "roles": ["Investigator.Analyst"], "hasgroups": True},
            {"sub": "x", "roles": ["Investigator.Analyst"], "_claim_names": {"groups": "src"}},
        ):
            with self.assertRaises(OIDCError):
                identity_from_claims(_auth_config(claim_names=("roles",), allowed_values=("Investigator.Analyst",)), claims)

    def test_missing_malformed_and_wrong_allowlist_fail_closed(self) -> None:
        cfg = _auth_config(claim_names=("groups",), allowed_values=("Allowed",))
        for claims in ({"sub": "x"}, {"sub": "x", "groups": "Allowed"}, {"sub": "x", "groups": ["Other"]}):
            with self.assertRaises(OIDCError):
                identity_from_claims(cfg, claims)


class SessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.old = app_config.DEFAULT_CONFIG_DIR
        app_config.DEFAULT_CONFIG_DIR = Path(self.temp.name)
        clear_auth_state()

    def tearDown(self) -> None:
        app_config.DEFAULT_CONFIG_DIR = self.old
        self.temp.cleanup()

    def test_transaction_is_one_time_and_expires(self) -> None:
        state = create_transaction(nonce="nonce", code_verifier="verifier", return_path="/cases", expires_at=100)
        self.assertIsNone(consume_transaction(state, now=101))
        state = create_transaction(nonce="nonce", code_verifier="verifier", return_path="/cases", expires_at=200)
        self.assertEqual(consume_transaction(state, now=150), {"nonce": "nonce", "code_verifier": "verifier", "return_path": "/cases"})
        self.assertIsNone(consume_transaction(state, now=150))

    def test_session_tamper_expiry_rotation_and_logout(self) -> None:
        token, _session = create_session(subject="sub", display_name="A", email=None, is_admin=False, idle_seconds=10, absolute_seconds=100, now=100)
        self.assertEqual(get_session(token, idle_seconds=10, now=105).subject, "sub")
        self.assertIsNone(get_session(token + "tampered", idle_seconds=10, now=105))
        self.assertIsNone(get_session(token, idle_seconds=10, now=200))
        token2, _ = create_session(subject="sub", display_name="A", email=None, is_admin=False, idle_seconds=10, absolute_seconds=100, now=100)
        self.assertNotEqual(token, token2)
        revoke_session(token2)
        self.assertIsNone(get_session(token2, idle_seconds=10, now=101))


class AuthBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.old = app_config.DEFAULT_CONFIG_DIR
        app_config.DEFAULT_CONFIG_DIR = Path(self.temp.name)
        self.env = patch.dict(os.environ, {
            "INVESTIGATOR_AUTH_ENABLED": "true",
            "INVESTIGATOR_PUBLIC_ORIGIN": "http://localhost:8400",
            "INVESTIGATOR_OIDC_ISSUER": "http://localhost:9000",
            "INVESTIGATOR_OIDC_CLIENT_ID": "client",
            "INVESTIGATOR_OIDC_CLIENT_SECRET": "secret",
            "INVESTIGATOR_SSO_CLAIMS": "groups",
            "INVESTIGATOR_SSO_ALLOWED_VALUES": "Analysts",
        }, clear=True)
        self.env.start()
        from fastapi.testclient import TestClient
        from app.main import app
        self.client = TestClient(app, base_url="http://localhost:8400")

    def tearDown(self) -> None:
        self.client.close()
        self.env.stop()
        app_config.DEFAULT_CONFIG_DIR = self.old
        self.temp.cleanup()

    def test_anonymous_api_and_websocket_are_denied_but_health_bootstrap_are_public(self) -> None:
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        self.assertEqual(self.client.get("/api/auth/bootstrap").status_code, 200)
        denied = self.client.get("/api/cases")
        self.assertEqual(denied.status_code, 401)
        self.assertEqual(denied.json(), {"detail": "Authentication required"})

    def test_authenticated_session_and_origin_policy(self) -> None:
        token, _ = create_session(subject="sub", display_name="Analyst", email=None, is_admin=False, idle_seconds=60, absolute_seconds=3600)
        self.client.cookies.set("investigator_session", token)
        self.assertEqual(self.client.get("/api/auth/session").json()["authenticated"], True)
        self.assertEqual(self.client.post("/api/auth/logout").status_code, 403)
        self.assertEqual(self.client.post("/api/auth/logout", headers={"origin": "http://localhost:8400"}).status_code, 200)

    def test_login_return_path_state_and_callback_replay_protection(self) -> None:
        from app.auth.oidc import Identity
        from app.auth import router as auth_router
        from urllib.parse import urlencode

        async def fake_authorization_url(_config, **kwargs):
            return "https://idp.example.test/authorize?" + urlencode({"state": kwargs["state"]})

        with patch.object(auth_router, "authorization_url", new=AsyncMock(side_effect=fake_authorization_url)):
            unsafe = self.client.get("/api/auth/login?return_to=https://evil.example/", follow_redirects=False)
            self.assertEqual(unsafe.status_code, 400)
            started = self.client.get("/api/auth/login?return_to=/cases", follow_redirects=False)
        self.assertEqual(started.status_code, 303)
        location = started.headers["location"]
        from urllib.parse import parse_qs, urlsplit
        state = parse_qs(urlsplit(location).query).get("state", [""])[0]
        self.assertTrue(state)
        with (
            patch.object(auth_router, "exchange_code", new=AsyncMock(return_value={"id_token": "opaque-test-token"})),
            patch.object(auth_router, "validate_id_token", new=AsyncMock(return_value=Identity("sub", "Analyst", None, False))),
        ):
            callback = self.client.get(f"/api/auth/callback?code=code&state={state}", follow_redirects=False)
        self.assertEqual(callback.status_code, 303)
        self.assertEqual(callback.headers["location"], "/cases")
        replay = self.client.get(f"/api/auth/callback?code=code&state={state}", follow_redirects=False)
        self.assertEqual(replay.status_code, 400)


if __name__ == "__main__":
    unittest.main()
