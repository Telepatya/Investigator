"""ASGI-boundary authentication for HTTP and WebSocket requests."""

from __future__ import annotations

from typing import Any, Callable

from fastapi.responses import JSONResponse

from .config import get_auth_config
from .session import COOKIE_NAME, get_session, sync_auth_policy_if_store_exists
from app.api.security import has_allowed_public_host


PUBLIC_HTTP_PATHS = frozenset({
    "/api/health",
    "/api/auth/bootstrap",
    "/api/auth/session",
    "/api/auth/login",
    "/api/auth/callback",
})
DOCUMENTATION_HTTP_PATHS = frozenset({"/docs", "/redoc", "/openapi.json"})


def _cookie(scope: dict[str, Any]) -> str | None:
    headers = dict(scope.get("headers") or [])
    raw = headers.get(b"cookie", b"").decode("latin-1")
    for item in raw.split(";"):
        name, separator, value = item.strip().partition("=")
        if separator and name == COOKIE_NAME:
            return value
    return None


def _path(scope: dict[str, Any]) -> str:
    return (scope.get("path") or "").rstrip("/") or "/"


class AuthMiddleware:
    """Reject anonymous product traffic before route handlers execute.

    The middleware intentionally re-reads environment configuration per request
    so tests and supervised local deployments can change settings without a
    process restart. Disabled mode returns immediately and performs no issuer
    discovery or network work.
    """

    def __init__(self, app: Callable[..., Any]) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        config = get_auth_config()
        if not config.enabled:
            sync_auth_policy_if_store_exists(config.policy_fingerprint)
            await self.app(scope, receive, send)
            return
        path = _path(scope)
        if scope["type"] == "http":
            if path in PUBLIC_HTTP_PATHS or (
                not path.startswith("/api/") and path not in DOCUMENTATION_HTTP_PATHS
            ):
                await self.app(scope, receive, send)
                return
            if not config.configured:
                response = JSONResponse(status_code=503, content={"detail": "Authentication is misconfigured"})
                await response(scope, receive, send)
                return
            session_token = _cookie(scope)
            session = (
                get_session(
                    session_token,
                    idle_seconds=config.idle_seconds,
                    policy_fingerprint=config.policy_fingerprint,
                )
                if session_token
                else None
            )
            if session is None:
                response = JSONResponse(status_code=401, content={"detail": "Authentication required"})
                await response(scope, receive, send)
                return
            scope.setdefault("state", {})["user"] = session
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            # No product websocket is anonymous. Closing before accept emits a
            # denial response in Starlette and prevents route code running.
            headers = dict(scope.get("headers") or [])
            origin = headers.get(b"origin", b"").decode("latin-1") or None
            session_token = _cookie(scope)
            session = (
                get_session(
                    session_token,
                    idle_seconds=config.idle_seconds,
                    policy_fingerprint=config.policy_fingerprint,
                )
                if config.configured and session_token
                else None
            )
            if not config.configured or session is None or origin != config.public_origin or not has_allowed_public_host(headers.get(b"host", b"").decode("latin-1") or None):
                await send({"type": "websocket.close", "code": 1008})
                return
            scope.setdefault("state", {})["user"] = session
            await self.app(scope, receive, send)
            return
        await self.app(scope, receive, send)
