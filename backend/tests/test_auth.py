from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import AsyncMock, patch

from authlib.jose import JsonWebKey, JsonWebToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.auth.config import AuthConfig, get_auth_config
from app.auth.oidc import (
    OIDCError,
    OIDCMetadata,
    authorization_url,
    exchange_code,
    identity_from_claims,
    validate_id_token,
)
from app.auth.session import (
    COOKIE_NAME,
    LOGIN_LIMIT_PER_CLIENT,
    LOGIN_LIMIT_WINDOW_SECONDS,
    LEGACY_OIDC_BINDING_COOKIE_NAME,
    OIDC_BINDING_COOKIE_NAME,
    clear_auth_state,
    consume_transaction,
    create_session,
    create_transaction,
    get_session,
    revoke_session,
    sync_auth_policy,
    sync_auth_policy_if_store_exists,
)
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

    def test_remote_plaintext_public_origin_fails_closed(self) -> None:
        with patch.dict(os.environ, {
            "INVESTIGATOR_AUTH_ENABLED": "true",
            "INVESTIGATOR_PUBLIC_ORIGIN": "http://investigator.example.test",
            "INVESTIGATOR_OIDC_ISSUER": "https://idp.example.test",
            "INVESTIGATOR_OIDC_CLIENT_ID": "client",
            "INVESTIGATOR_OIDC_CLIENT_SECRET": "secret",
            "INVESTIGATOR_SSO_ALLOWED_VALUES": "Analysts",
        }, clear=True):
            cfg = get_auth_config()
        self.assertFalse(cfg.configured)
        self.assertIn("HTTPS", (cfg.error or "").upper())

    def test_loopback_plaintext_origin_and_scope_configuration(self) -> None:
        with patch.dict(os.environ, {
            "INVESTIGATOR_AUTH_ENABLED": "true",
            "INVESTIGATOR_PUBLIC_ORIGIN": "http://localhost:8400",
            "INVESTIGATOR_OIDC_ISSUER": "http://localhost:9000",
            "INVESTIGATOR_OIDC_CLIENT_ID": "client",
            "INVESTIGATOR_OIDC_CLIENT_SECRET": "secret",
            "INVESTIGATOR_OIDC_SCOPES": "profile email groups",
            "INVESTIGATOR_SSO_ALLOWED_VALUES": "Analysts",
        }, clear=True):
            cfg = get_auth_config()
        self.assertTrue(cfg.configured)
        self.assertEqual(cfg.scopes, ("openid", "profile", "email", "groups"))

    def test_unsafe_scope_configuration_fails_closed(self) -> None:
        with patch.dict(os.environ, {
            "INVESTIGATOR_AUTH_ENABLED": "true",
            "INVESTIGATOR_PUBLIC_ORIGIN": "https://investigator.example.test",
            "INVESTIGATOR_OIDC_ISSUER": "https://idp.example.test",
            "INVESTIGATOR_OIDC_CLIENT_ID": "client",
            "INVESTIGATOR_OIDC_CLIENT_SECRET": "secret",
            "INVESTIGATOR_OIDC_SCOPES": "openid profile\nemail",
            "INVESTIGATOR_SSO_ALLOWED_VALUES": "Analysts",
        }, clear=True):
            cfg = get_auth_config()
        self.assertFalse(cfg.configured)
        self.assertIn("scope", (cfg.error or "").lower())

    def test_policy_fingerprint_changes_with_authorization_policy(self) -> None:
        initial = _auth_config()
        self.assertEqual(initial.policy_fingerprint, _auth_config().policy_fingerprint)
        self.assertNotEqual(
            initial.policy_fingerprint,
            _auth_config(allowed_values=("Administrators",)).policy_fingerprint,
        )
        self.assertNotEqual(
            initial.policy_fingerprint,
            _auth_config(client_secret="rotated-secret").policy_fingerprint,
        )

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


class OIDCValidationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        from app.auth import oidc

        self.oidc = oidc
        self.config = _auth_config(scopes=("openid", "profile", "email", "groups"))
        self.metadata = OIDCMetadata(
            authorization_endpoint="https://idp.example.test/authorize",
            token_endpoint="https://idp.example.test/token",
            jwks_uri="https://idp.example.test/jwks",
            issuer=self.config.issuer or "",
            token_endpoint_auth_methods_supported=("client_secret_basic",),
        )
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.private_pem = self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_pem = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_jwk = JsonWebKey.import_key(public_pem).as_dict()
        self.public_jwk["kid"] = "test-key"

    def _token(self, **overrides) -> str:
        now = int(time.time())
        claims = {
            "iss": self.config.issuer,
            "sub": "subject",
            "aud": self.config.client_id,
            "exp": now + 300,
            "iat": now,
            "nonce": "nonce",
            "groups": ["Analysts"],
        }
        claims.update(overrides)
        token = JsonWebToken(["RS256"]).encode(
            {"alg": "RS256", "kid": "test-key", "typ": "JWT"},
            claims,
            self.private_pem,
        )
        return token.decode("ascii") if isinstance(token, bytes) else token

    async def _validate(self, token: str, jwks: dict | None = None):
        metadata = self.metadata
        jwks_document = jwks or {"keys": [self.public_jwk]}

        class FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return jwks_document

        class FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def get(self, _url):
                return FakeResponse()

        with (
            patch.object(self.oidc, "discover", new=AsyncMock(return_value=metadata)),
            patch.object(self.oidc.httpx, "AsyncClient", FakeClient),
        ):
            return await validate_id_token(self.config, id_token=token, nonce="nonce")

    async def test_authorization_url_preserves_configured_safe_scopes(self) -> None:
        with patch.object(self.oidc, "discover", new=AsyncMock(return_value=self.metadata)):
            url = await authorization_url(self.config, state="state", nonce="nonce", verifier="verifier")
        from urllib.parse import parse_qs, urlsplit

        self.assertEqual(parse_qs(urlsplit(url).query)["scope"], ["openid profile email groups"])

    async def test_signed_id_token_success_and_strict_azp(self) -> None:
        identity = await self._validate(self._token())
        self.assertEqual(identity.subject, "subject")

        multi_audience = await self._validate(self._token(aud=["client", "other"], azp="client"))
        self.assertEqual(multi_audience.subject, "subject")
        for claims in (
            {"aud": ["client", "other"]},
            {"aud": ["client", "other"], "azp": "other"},
            {"azp": "other"},
        ):
            with self.subTest(claims=claims):
                with self.assertRaises(OIDCError):
                    await self._validate(self._token(**claims))

    async def test_signed_id_token_rejects_bad_claims_key_and_algorithm(self) -> None:
        now = int(time.time())
        bad_claims = (
            {"iss": "https://wrong.example.test"},
            {"aud": "other"},
            {"exp": now - 120},
            {"iat": now + 120},
            {"nonce": "wrong"},
        )
        for claims in bad_claims:
            with self.subTest(claims=claims):
                with self.assertRaises(OIDCError):
                    await self._validate(self._token(**claims))

        now = int(time.time())
        unknown_kid = JsonWebToken(["RS256"]).encode(
            {"alg": "RS256", "kid": "unknown-key"},
            {"iss": self.config.issuer, "sub": "subject", "aud": "client", "exp": now + 300, "iat": now, "nonce": "nonce", "groups": ["Analysts"]},
            self.private_pem,
        )
        with self.assertRaises(OIDCError):
            await self._validate(unknown_kid.decode("ascii") if isinstance(unknown_kid, bytes) else unknown_kid)

        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_pem = other_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        bad_signature = JsonWebToken(["RS256"]).encode(
            {"alg": "RS256", "kid": "test-key"},
            {"iss": self.config.issuer, "sub": "subject", "aud": "client", "exp": now + 300, "iat": now, "nonce": "nonce", "groups": ["Analysts"]},
            other_pem,
        )
        with self.assertRaises(OIDCError):
            await self._validate(bad_signature.decode("ascii") if isinstance(bad_signature, bytes) else bad_signature)

        hs_token = JsonWebToken(["HS256"]).encode(
            {"alg": "HS256", "kid": "test-key"},
            {"iss": self.config.issuer, "sub": "subject", "aud": "client", "exp": now + 300, "iat": now, "nonce": "nonce", "groups": ["Analysts"]},
            b"symmetric-test-secret",
        )
        with self.assertRaises(OIDCError):
            await self._validate(hs_token.decode("ascii") if isinstance(hs_token, bytes) else hs_token)

    async def test_exchange_honors_advertised_client_auth_method(self) -> None:
        for methods, expected_basic in ((
            ("client_secret_basic",), True),
            (("client_secret_post",), False),
        ):
            with self.subTest(methods=methods):
                metadata = OIDCMetadata(
                    self.metadata.authorization_endpoint,
                    self.metadata.token_endpoint,
                    self.metadata.jwks_uri,
                    self.metadata.issuer,
                    methods,
                )
                requests: list[dict] = []

                class FakeResponse:
                    def raise_for_status(self):
                        return None

                    def json(self):
                        return {"id_token": "signed-token"}

                class FakeClient:
                    def __init__(self, *args, **kwargs):
                        pass

                    async def __aenter__(self):
                        return self

                    async def __aexit__(self, *args):
                        return None

                    async def post(self, _url, **kwargs):
                        requests.append(kwargs)
                        return FakeResponse()

                with (
                    patch.object(self.oidc, "discover", new=AsyncMock(return_value=metadata)),
                    patch.object(self.oidc.httpx, "AsyncClient", FakeClient),
                ):
                    await exchange_code(self.config, code="code", verifier="verifier")
                self.assertEqual(len(requests), 1)
                if expected_basic:
                    self.assertEqual(requests[0]["auth"], ("client", "secret"))
                    self.assertNotIn("client_secret", requests[0]["data"])
                else:
                    self.assertNotIn("auth", requests[0])
                    self.assertEqual(requests[0]["data"]["client_secret"], "secret")
                self.assertNotIn("secret", requests[0].get("url", ""))

        unsupported = OIDCMetadata(
            self.metadata.authorization_endpoint,
            self.metadata.token_endpoint,
            self.metadata.jwks_uri,
            self.metadata.issuer,
            ("private_key_jwt",),
        )
        with patch.object(self.oidc, "discover", new=AsyncMock(return_value=unsupported)):
            with self.assertRaises(OIDCError):
                await exchange_code(self.config, code="code", verifier="verifier")


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
        state = create_transaction(nonce="nonce", code_verifier="verifier", browser_binding="binding", return_path="/cases", expires_at=100)
        self.assertIsNone(consume_transaction(state, "binding", now=101))
        state = create_transaction(nonce="nonce", code_verifier="verifier", browser_binding="binding", return_path="/cases", expires_at=200)
        self.assertIsNone(consume_transaction(state, "wrong-browser", now=150))
        self.assertEqual(consume_transaction(state, "binding", now=150), {"nonce": "nonce", "code_verifier": "verifier", "return_path": "/cases"})
        self.assertIsNone(consume_transaction(state, "binding", now=150))

    def test_login_initiation_limit_is_bounded_and_recovers_after_window(self) -> None:
        def start_login() -> str | None:
            return create_transaction(
                nonce="nonce",
                code_verifier="verifier",
                browser_binding="binding",
                return_path="/cases",
                expires_at=1200,
                client_key="192.0.2.40",
            )

        with patch("app.auth.session.time.time", return_value=1000):
            accepted = [start_login() for _ in range(LOGIN_LIMIT_PER_CLIENT)]
            rejected = start_login()
        self.assertTrue(all(accepted))
        self.assertIsNone(rejected)
        with closing(sqlite3.connect(app_config.DEFAULT_CONFIG_DIR / "auth.db")) as db:
            transaction_count = db.execute("SELECT COUNT(*) FROM oidc_transactions").fetchone()[0]
        self.assertEqual(transaction_count, LOGIN_LIMIT_PER_CLIENT)

        with patch(
            "app.auth.session.time.time",
            return_value=1000 + LOGIN_LIMIT_WINDOW_SECONDS,
        ):
            recovered = start_login()
        self.assertIsNotNone(recovered)

    def test_live_transaction_capacity_is_enforced_atomically(self) -> None:
        def start_login(expiry: float) -> str | None:
            return create_transaction(
                nonce="nonce",
                code_verifier="verifier",
                browser_binding="binding",
                return_path="/cases",
                expires_at=expiry,
                client_key="192.0.2.41",
            )

        with (
            patch("app.auth.session.time.time", return_value=2000),
            patch("app.auth.session.ACTIVE_TRANSACTION_LIMIT", 1),
        ):
            first = start_login(2060)
            second = start_login(2061)
        self.assertIsNotNone(first)
        self.assertIsNone(second)

        with (
            patch("app.auth.session.time.time", return_value=2060),
            patch("app.auth.session.ACTIVE_TRANSACTION_LIMIT", 1),
        ):
            after_expiry = start_login(2120)
        self.assertIsNotNone(after_expiry)

    def test_concurrent_login_starts_cannot_exceed_per_client_limit(self) -> None:
        def start_login(_index: int) -> str | None:
            return create_transaction(
                nonce="nonce",
                code_verifier="verifier",
                browser_binding=f"binding-{_index}",
                return_path="/cases",
                expires_at=time.time() + 60,
                client_key="192.0.2.42",
            )

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(start_login, range(LOGIN_LIMIT_PER_CLIENT + 10)))
        self.assertEqual(sum(state is not None for state in results), LOGIN_LIMIT_PER_CLIENT)
        with closing(sqlite3.connect(app_config.DEFAULT_CONFIG_DIR / "auth.db")) as db:
            transaction_count = db.execute("SELECT COUNT(*) FROM oidc_transactions").fetchone()[0]
        self.assertEqual(transaction_count, LOGIN_LIMIT_PER_CLIENT)

    def test_policy_change_invalidates_sessions_and_pending_transactions(self) -> None:
        self.assertTrue(sync_auth_policy("policy-a"))
        token, _session = create_session(
            subject="sub",
            display_name="Analyst",
            email=None,
            is_admin=False,
            idle_seconds=60,
            absolute_seconds=3600,
        )
        state = create_transaction(
            nonce="nonce",
            code_verifier="verifier",
            browser_binding="binding",
            return_path="/cases",
            expires_at=time.time() + 60,
        )
        self.assertIsNotNone(state)
        self.assertFalse(sync_auth_policy("policy-a"))
        self.assertEqual(get_session(token, idle_seconds=60).subject, "sub")

        self.assertTrue(sync_auth_policy("policy-b"))
        self.assertIsNone(get_session(token, idle_seconds=60))
        self.assertIsNone(consume_transaction(state, "binding"))

    def test_disabled_policy_sync_does_not_create_missing_auth_db(self) -> None:
        path = app_config.DEFAULT_CONFIG_DIR / "auth.db"
        path.unlink(missing_ok=True)
        self.assertFalse(sync_auth_policy_if_store_exists("disabled-policy"))
        self.assertFalse(path.exists())

    def test_legacy_auth_db_migration_invalidates_unversioned_sessions(self) -> None:
        path = app_config.DEFAULT_CONFIG_DIR / "auth.db"
        path.unlink(missing_ok=True)
        token = "legacy-session-token"
        state = "legacy-transaction-state"
        now = time.time()
        with closing(sqlite3.connect(path)) as db:
            db.executescript(
                """
                CREATE TABLE auth_sessions (
                    token_hash TEXT PRIMARY KEY,
                    subject TEXT NOT NULL,
                    display_name TEXT,
                    email TEXT,
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    absolute_expires_at REAL NOT NULL
                );
                CREATE TABLE oidc_transactions (
                    state_hash TEXT PRIMARY KEY,
                    nonce TEXT NOT NULL,
                    code_verifier TEXT NOT NULL,
                    return_path TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );
                """
            )
            db.execute(
                "INSERT INTO auth_sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (hashlib.sha256(token.encode()).hexdigest(), "legacy-sub", None, None, 0, now, now, now + 60, now + 3600),
            )
            db.execute(
                "INSERT INTO oidc_transactions VALUES (?, ?, ?, ?, ?, ?)",
                (hashlib.sha256(state.encode()).hexdigest(), "nonce", "verifier", "/cases", now, now + 60),
            )
            db.commit()

        self.assertTrue(sync_auth_policy("migrated-policy"))
        self.assertIsNone(get_session(token, idle_seconds=60))
        self.assertIsNone(consume_transaction(state, "binding"))
        with closing(sqlite3.connect(path)) as db:
            migrated_columns = {
                row[1] for row in db.execute("PRAGMA table_info(oidc_transactions)")
            }
            remaining_transactions = db.execute(
                "SELECT COUNT(*) FROM oidc_transactions"
            ).fetchone()[0]
        self.assertIn("binding_hash", migrated_columns)
        self.assertEqual(remaining_transactions, 0)

    def test_transaction_persists_only_hashes_of_browser_values(self) -> None:
        browser_binding = "unique-browser-binding"
        state = create_transaction(
            nonce="nonce",
            code_verifier="verifier",
            browser_binding=browser_binding,
            return_path="/cases",
            expires_at=time.time() + 60,
        )
        with closing(sqlite3.connect(app_config.DEFAULT_CONFIG_DIR / "auth.db")) as db:
            stored_state, stored_binding = db.execute(
                "SELECT state_hash, binding_hash FROM oidc_transactions"
            ).fetchone()
        self.assertEqual(stored_state, hashlib.sha256(state.encode()).hexdigest())
        self.assertEqual(
            stored_binding, hashlib.sha256(browser_binding.encode()).hexdigest()
        )
        self.assertNotEqual(stored_state, state)
        self.assertNotEqual(stored_binding, browser_binding)

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
        from starlette.websockets import WebSocketDisconnect

        self.assertEqual(self.client.get("/api/health").status_code, 200)
        self.assertEqual(self.client.get("/api/auth/bootstrap").status_code, 200)
        self.assertEqual(self.client.get("/openapi.json").status_code, 401)
        denied = self.client.get("/api/cases")
        self.assertEqual(denied.status_code, 401)
        self.assertEqual(denied.json(), {"detail": "Authentication required"})
        with self.assertRaises(WebSocketDisconnect):
            with self.client.websocket_connect(
                "/api/cases/deadbeef/ingestion-ws",
                headers={"origin": "http://localhost:8400"},
            ):
                pass

    def test_authenticated_session_and_origin_policy(self) -> None:
        sync_auth_policy(get_auth_config().policy_fingerprint)
        token, _ = create_session(subject="sub", display_name="Analyst", email=None, is_admin=False, idle_seconds=60, absolute_seconds=3600)
        self.client.cookies.set("investigator_session", token)
        self.assertEqual(self.client.get("/api/auth/bootstrap").json()["authenticated"], True)
        self.assertEqual(self.client.get("/api/auth/session").json()["authenticated"], True)
        self.assertEqual(self.client.post("/api/auth/logout").status_code, 403)
        self.assertEqual(self.client.post("/api/auth/logout", headers={"origin": "http://localhost:8400"}).status_code, 200)

    def _create_websocket_session(self) -> str:
        sync_auth_policy(get_auth_config().policy_fingerprint)
        token, _ = create_session(
            subject="sub",
            display_name="Analyst",
            email=None,
            is_admin=False,
            idle_seconds=60,
            absolute_seconds=3600,
        )
        self.client.cookies.set(COOKIE_NAME, token)
        return token

    def _websocket_headers(self, token: str) -> dict[str, str]:
        # TestClient's WebSocket helper targets ``ws://testserver`` regardless
        # of its HTTP base URL, so provide the SSO origin/host and cookie.
        return {
            "origin": "http://localhost:8400",
            "host": "localhost:8400",
            "cookie": f"{COOKIE_NAME}={token}",
        }

    def test_logout_revokes_open_chat_socket_before_next_model_or_case_work(self) -> None:
        from app.api import analysis_router
        from starlette.websockets import WebSocketDisconnect

        token = self._create_websocket_session()
        with patch.object(analysis_router.case_store, "case_exists", return_value=True) as exists:
            with patch.object(analysis_router, "chat_stream") as chat:
                with self.client.websocket_connect(
                    "/api/cases/deadbeef/chat-ws",
                    headers=self._websocket_headers(token),
                ) as websocket:
                    logout = self.client.post(
                        "/api/auth/logout",
                        headers={"origin": "http://localhost:8400"},
                    )
                    self.assertEqual(logout.status_code, 200)
                    websocket.send_json({"message": "run this", "chat_id": "chat"})
                    with self.assertRaises(WebSocketDisconnect) as closed:
                        websocket.receive_json()
                    self.assertEqual(closed.exception.code, 1008)
                chat.assert_not_called()
            exists.assert_called_once_with("deadbeef")

    def test_logout_suppresses_queued_analysis_progress_for_open_socket(self) -> None:
        from app.api import analysis_router
        from starlette.websockets import WebSocketDisconnect

        token = self._create_websocket_session()
        with patch.object(analysis_router.case_store, "case_exists", return_value=True):
            with self.client.websocket_connect(
                "/api/cases/deadbeef/analyze-ws",
                headers=self._websocket_headers(token),
            ) as websocket:
                self.assertEqual(websocket.receive_json()["phase"], "connected")
                logout = self.client.post(
                    "/api/auth/logout",
                    headers={"origin": "http://localhost:8400"},
                )
                self.assertEqual(logout.status_code, 200)
                websocket.portal.call(
                    analysis_router._broadcast_analysis,
                    "deadbeef",
                    {"phase": "done", "message": "must not be disclosed", "percent": 100},
                )
                with self.assertRaises(WebSocketDisconnect) as closed:
                    websocket.receive_json()
                self.assertEqual(closed.exception.code, 1008)

    def test_policy_change_revokes_open_entity_socket_before_provider_dispatch(self) -> None:
        from app.api import analysis_router
        from starlette.websockets import WebSocketDisconnect

        token = self._create_websocket_session()
        with patch.object(analysis_router.case_store, "case_exists", return_value=True):
            with patch.object(analysis_router, "investigate_entity_stream") as investigate:
                with self.client.websocket_connect(
                    "/api/cases/deadbeef/investigate-entity-ws",
                    headers=self._websocket_headers(token),
                ) as websocket:
                    with patch.dict(os.environ, {"INVESTIGATOR_SSO_ALLOWED_VALUES": "Administrators"}):
                        websocket.send_json({"entity_id": "host-1"})
                        with self.assertRaises(WebSocketDisconnect) as closed:
                            websocket.receive_json()
                    self.assertEqual(closed.exception.code, 1008)
                investigate.assert_not_called()

    def test_public_health_and_static_requests_skip_middleware_session_lookup(self) -> None:
        from app.auth import middleware as auth_middleware

        cookie = f"{COOKIE_NAME}=untrusted-session"
        with patch.object(
            auth_middleware,
            "get_session",
            side_effect=AssertionError("public request should not look up a session"),
        ):
            health = self.client.get("/api/health", headers={"cookie": cookie})
            static = self.client.get("/", headers={"cookie": cookie})

        self.assertEqual(health.status_code, 200)
        self.assertIn(static.status_code, (200, 404))

    def test_oidc_allowlist_change_invalidates_existing_browser_session(self) -> None:
        sync_auth_policy(get_auth_config().policy_fingerprint)
        token, _ = create_session(
            subject="sub",
            display_name="Analyst",
            email=None,
            is_admin=False,
            idle_seconds=60,
            absolute_seconds=3600,
        )
        self.client.cookies.set("investigator_session", token)

        with patch.dict(os.environ, {"INVESTIGATOR_SSO_ALLOWED_VALUES": "Administrators"}):
            denied = self.client.get("/api/cases")

        self.assertEqual(denied.status_code, 401)
        self.assertEqual(denied.json(), {"detail": "Authentication required"})

    def test_disable_then_reenable_auth_revokes_existing_session(self) -> None:
        sync_auth_policy(get_auth_config().policy_fingerprint)
        token, _ = create_session(
            subject="sub",
            display_name="Analyst",
            email=None,
            is_admin=False,
            idle_seconds=60,
            absolute_seconds=3600,
        )
        self.client.cookies.set("investigator_session", token)

        with patch.dict(os.environ, {"INVESTIGATOR_AUTH_ENABLED": "false"}):
            disabled = self.client.get("/api/auth/bootstrap")
        self.assertFalse(disabled.json()["enabled"])

        reenabled = self.client.get("/api/cases")
        self.assertEqual(reenabled.status_code, 401)
        self.assertEqual(reenabled.json(), {"detail": "Authentication required"})

    def test_malformed_callbacks_do_not_sync_policy_or_open_auth_db(self) -> None:
        from app.auth import router as auth_router
        from app.auth import session as auth_session

        malformed_paths = (
            "/api/auth/callback",
            "/api/auth/callback?state=state",
            "/api/auth/callback?code=code",
            "/api/auth/callback?code=code&state=" + ("x" * 257),
            "/api/auth/callback?error=access_denied",
        )
        cookie = "; ".join(
            (
                f"{COOKIE_NAME}=stale-session",
                f"{OIDC_BINDING_COOKIE_NAME}=binding",
            )
        )
        with (
            patch.object(auth_router, "sync_auth_policy") as sync_policy,
            patch.object(auth_router, "consume_transaction") as consume,
            patch.object(auth_session, "_connect", side_effect=AssertionError("unexpected auth DB access")) as connect,
        ):
            for path in malformed_paths:
                with self.subTest(path=path[:100]):
                    response = self.client.get(path, headers={"cookie": cookie}, follow_redirects=False)
                    self.assertEqual(response.status_code, 400)

        sync_policy.assert_not_called()
        consume.assert_not_called()
        connect.assert_not_called()

    def test_provider_denial_skips_database_and_leaves_transaction_to_expire(self) -> None:
        from app.auth import router as auth_router
        from app.auth import session as auth_session

        cookie = "; ".join(
            (
                f"{COOKIE_NAME}=stale-session",
                f"{OIDC_BINDING_COOKIE_NAME}=" + ("B" * 43),
            )
        )
        with (
            patch.object(auth_router, "sync_auth_policy") as sync_policy,
            patch.object(auth_router, "consume_transaction") as consume,
            patch.object(auth_session, "_connect", side_effect=AssertionError("unexpected auth DB access")) as connect,
        ):
            response = self.client.get(
                "/api/auth/callback?error=access_denied&state=" + ("S" * 43),
                headers={"cookie": cookie},
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 400)
        sync_policy.assert_not_called()
        consume.assert_not_called()
        connect.assert_not_called()

    def test_callback_policy_change_during_exchange_cannot_mint_stale_session(self) -> None:
        from app.auth import router as auth_router
        from app.auth import session as auth_session
        from app.auth.oidc import Identity

        auth_config = get_auth_config()
        sync_auth_policy(auth_config.policy_fingerprint)
        events: list[str] = []
        real_sync = auth_router.sync_auth_policy

        def record_sync(fingerprint: str) -> bool:
            events.append("sync")
            return real_sync(fingerprint)

        def consume(_state: str, _binding: str):
            events.append("consume")
            return {"nonce": "nonce", "code_verifier": "verifier", "return_path": "/cases"}

        async def change_policy_during_exchange(_config, **_kwargs):
            events.append("exchange")
            auth_session.sync_auth_policy("newer-policy")
            return {"id_token": "opaque-test-token"}

        async def validate(_config, **_kwargs):
            events.append("validate")
            return Identity("subject", "Analyst", None, False)

        with (
            patch.object(auth_router, "sync_auth_policy", side_effect=record_sync),
            patch.object(auth_router, "consume_transaction", side_effect=consume),
            patch.object(auth_router, "exchange_code", new=AsyncMock(side_effect=change_policy_during_exchange)),
            patch.object(auth_router, "validate_id_token", new=AsyncMock(side_effect=validate)),
        ):
            response = self.client.get(
                "/api/auth/callback?code=code&state=" + ("S" * 43),
                headers={"cookie": f"{OIDC_BINDING_COOKIE_NAME}=" + ("B" * 43)},
                follow_redirects=False,
            )

        self.assertEqual(events, ["sync", "consume", "exchange", "validate"])
        self.assertEqual(response.status_code, 400)
        self.assertIn("policy changed", response.json()["detail"])
        with closing(sqlite3.connect(app_config.DEFAULT_CONFIG_DIR / "auth.db")) as db:
            session_count = db.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0]
            policy = db.execute(
                "SELECT value FROM auth_metadata WHERE key = 'policy_fingerprint'"
            ).fetchone()[0]
        self.assertEqual(session_count, 0)
        self.assertEqual(policy, "newer-policy")

    def test_rate_limited_login_does_not_contact_identity_provider_or_store_transaction(self) -> None:
        from app.auth import router as auth_router
        from app.auth import session as auth_session
        from urllib.parse import urlencode

        async def fake_authorization_url(_config, **kwargs):
            return "https://idp.example.test/authorize?" + urlencode({"state": kwargs["state"]})

        with patch.object(auth_session, "LOGIN_LIMIT_PER_CLIENT", 1), patch.object(
            auth_router,
            "authorization_url",
            new=AsyncMock(side_effect=fake_authorization_url),
        ) as authorization:
            first = self.client.get("/api/auth/login", follow_redirects=False)
            self.assertEqual(first.status_code, 303)
            authorization.reset_mock()
            limited = self.client.get("/api/auth/login", follow_redirects=False)

        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.headers["retry-after"], "60")
        authorization.assert_not_awaited()
        with closing(sqlite3.connect(app_config.DEFAULT_CONFIG_DIR / "auth.db")) as db:
            transaction_count = db.execute("SELECT COUNT(*) FROM oidc_transactions").fetchone()[0]
        self.assertEqual(transaction_count, 1)

    def test_login_return_path_state_and_callback_replay_protection(self) -> None:
        from app.auth.oidc import Identity
        from app.auth import router as auth_router
        from urllib.parse import urlencode

        sync_auth_policy(get_auth_config().policy_fingerprint)
        old_token, _ = create_session(
            subject="previous-subject",
            display_name="Previous analyst",
            email=None,
            is_admin=False,
            idle_seconds=60,
            absolute_seconds=3600,
        )
        self.client.cookies.set(COOKIE_NAME, old_token)

        async def fake_authorization_url(_config, **kwargs):
            return "https://idp.example.test/authorize?" + urlencode({"state": kwargs["state"]})

        with patch.object(auth_router, "authorization_url", new=AsyncMock(side_effect=fake_authorization_url)):
            unsafe = self.client.get("/api/auth/login?return_to=https://evil.example/", follow_redirects=False)
            self.assertEqual(unsafe.status_code, 400)
            started = self.client.get("/api/auth/login?return_to=/cases", follow_redirects=False)
        self.assertEqual(started.status_code, 303)
        binding_cookie = next(
            value
            for value in started.headers.get_list("set-cookie")
            if value.startswith(f"{OIDC_BINDING_COOKIE_NAME}=")
            and "Max-Age=0" not in value
        )
        self.assertIn("HttpOnly", binding_cookie)
        self.assertIn("SameSite=lax", binding_cookie)
        self.assertIn("Path=/api/auth/callback", binding_cookie)
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
        self.assertIsNone(get_session(old_token, idle_seconds=60))
        replay = self.client.get(f"/api/auth/callback?code=code&state={state}", follow_redirects=False)
        self.assertEqual(replay.status_code, 400)

    def test_rotated_binding_cookie_ignores_duplicate_legacy_root_cookie(self) -> None:
        from app.auth import router as auth_router
        from app.auth.oidc import Identity
        from urllib.parse import parse_qs, urlsplit

        async def fake_authorization_url(_config, **kwargs):
            return "https://idp.example.test/authorize?state=" + kwargs["state"]

        self.client.cookies.set(
            LEGACY_OIDC_BINDING_COOKIE_NAME,
            "stale-root-binding",
            path="/",
        )
        with patch.object(
            auth_router,
            "authorization_url",
            new=AsyncMock(side_effect=fake_authorization_url),
        ):
            started = self.client.get("/api/auth/login", follow_redirects=False)

        set_cookie_headers = started.headers.get_list("set-cookie")
        self.assertTrue(
            any(
                header.startswith(f"{LEGACY_OIDC_BINDING_COOKIE_NAME}=")
                and "Max-Age=0" in header
                and "Path=/" in header
                for header in set_cookie_headers
            )
        )
        binding_header = next(
            header
            for header in set_cookie_headers
            if header.startswith(f"{OIDC_BINDING_COOKIE_NAME}=")
            and "Max-Age=0" not in header
        )
        browser_binding = binding_header.split(";", 1)[0].split("=", 1)[1]
        state = parse_qs(urlsplit(started.headers["location"]).query)["state"][0]

        # Browsers order cookies by path length. Reproduce the problematic
        # duplicate legacy name explicitly; the rotated cookie remains unique.
        cookie_header = "; ".join(
            (
                f"{LEGACY_OIDC_BINDING_COOKIE_NAME}=stale-callback-binding",
                f"{LEGACY_OIDC_BINDING_COOKIE_NAME}=stale-root-binding",
                f"{OIDC_BINDING_COOKIE_NAME}={browser_binding}",
            )
        )
        with (
            patch.object(
                auth_router,
                "exchange_code",
                new=AsyncMock(return_value={"id_token": "opaque-test-token"}),
            ),
            patch.object(
                auth_router,
                "validate_id_token",
                new=AsyncMock(
                    return_value=Identity("sub", "Analyst", None, False)
                ),
            ),
        ):
            callback = self.client.get(
                f"/api/auth/callback?code=code&state={state}",
                headers={"cookie": cookie_header},
                follow_redirects=False,
            )

        self.assertEqual(callback.status_code, 303)

    def test_login_transaction_is_bound_to_initiating_browser(self) -> None:
        from app.auth import router as auth_router
        from app.auth.oidc import Identity
        from urllib.parse import parse_qs, urlsplit
        from fastapi.testclient import TestClient

        async def fake_authorization_url(_config, **kwargs):
            return "https://idp.example.test/authorize?state=" + kwargs["state"]

        other_client = TestClient(__import__("app.main", fromlist=["app"]).app, base_url="http://localhost:8400")
        try:
            with patch.object(auth_router, "authorization_url", new=AsyncMock(side_effect=fake_authorization_url)):
                started_a = self.client.get("/api/auth/login?return_to=/cases", follow_redirects=False)
                started_b = other_client.get("/api/auth/login?return_to=/cases", follow_redirects=False)
            state_a = parse_qs(urlsplit(started_a.headers["location"]).query)["state"][0]
            self.assertNotEqual(state_a, parse_qs(urlsplit(started_b.headers["location"]).query)["state"][0])
            with (
                patch.object(auth_router, "exchange_code", new=AsyncMock(return_value={"id_token": "opaque-test-token"})),
                patch.object(auth_router, "validate_id_token", new=AsyncMock(return_value=Identity("sub", "Analyst", None, False))),
            ):
                wrong_browser = other_client.get(
                    f"/api/auth/callback?code=code&state={state_a}",
                    follow_redirects=False,
                )
                self.assertEqual(wrong_browser.status_code, 400)
                right_browser = self.client.get(
                    f"/api/auth/callback?code=code&state={state_a}",
                    follow_redirects=False,
                )
            self.assertEqual(right_browser.status_code, 303)
        finally:
            other_client.close()


if __name__ == "__main__":
    unittest.main()
