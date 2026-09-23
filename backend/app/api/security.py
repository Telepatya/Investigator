"""Shared request-origin controls for a local-only backend.

The app binds to loopback, but "bound to localhost" does not stop a hostile web
page (or a DNS-rebinding attack) from issuing requests to it from the user's own
browser. CORS covers cross-origin *reads* of normal HTTP responses but does not
apply to WebSocket handshakes, so WebSocket routes must validate the browser
``Origin`` header themselves. These helpers centralize the allowlist so the CORS
config, the trusted-host list, and the WebSocket guards all agree.
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit

from fastapi import Request, WebSocket
from starlette.websockets import WebSocketDisconnect

from app.store import cases as case_store
from app.auth.config import get_auth_config
from app.auth.session import COOKIE_NAME, get_session

# Hosts the loopback server legitimately answers to. A rebound name such as
# ``evil.example`` resolving to 127.0.0.1 arrives with that name in the Host
# header and is rejected by TrustedHostMiddleware built from this list.


def allowed_hosts() -> list[str]:
    """Return hosts explicitly allowed by the configured public origin."""
    config = get_auth_config()
    if config.enabled and config.public_origin:
        parsed = urlsplit(config.public_origin)
        host = parsed.hostname or ""
        return [host]
    return ["localhost", "127.0.0.1"]


# Kept as a compatibility export for existing callers/tests. ``main`` uses the
# dynamic helper so a supervised test process can set the explicit origin before
# app construction.
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]
STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def allowed_origins() -> list[str]:
    """Browser origins permitted to talk to this backend."""
    config = get_auth_config()
    if config.enabled:
        return [config.public_origin] if config.configured and config.public_origin else []
    port = os.environ.get("INVESTIGATOR_PORT", "8400")
    return [
        f"http://localhost:{port}",
        f"http://127.0.0.1:{port}",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]


def has_allowed_origin(origin: str | None) -> bool:
    """Allow non-browser clients and our known browser origins only.

    Command-line clients generally omit ``Origin``. Browsers include it for
    cross-origin requests, so a present value is authoritative and must match
    the frontend allowlist.
    """
    config = get_auth_config()
    if config.enabled:
        # SSO browser mutations must carry the exact configured Origin. This
        # also rejects ``null`` and command-line requests without Origin while
        # authentication is enabled.
        return origin is not None and origin in set(allowed_origins())
    return origin is None or origin in set(allowed_origins())


def has_allowed_public_host(host_header: str | None) -> bool:
    """Require the request Host to match the configured origin, including port."""
    config = get_auth_config()
    if not config.enabled or not config.configured or not config.public_origin:
        return True
    expected = urlsplit(config.public_origin)
    if not host_header:
        return False
    try:
        actual = urlsplit(f"//{host_header}")
    except ValueError:
        return False
    if actual.hostname != expected.hostname:
        return False
    expected_port = expected.port or (443 if expected.scheme == "https" else 80)
    try:
        actual_port = actual.port or expected_port
    except ValueError:
        return False
    return actual_port == expected_port


def authorize_http(request: Request) -> bool:
    """Reject cross-origin browser writes; CORS alone only hides responses."""
    if not has_allowed_public_host(request.headers.get("host")):
        return False
    if request.method.upper() not in STATE_CHANGING_METHODS:
        return True
    return has_allowed_origin(request.headers.get("origin"))


async def authorize_ws_session(websocket: WebSocket) -> bool:
    """Recheck a WebSocket's browser session against the active auth policy.

    WebSocket handshakes are authenticated once by the ASGI middleware, but a
    connection can outlive its session. Routes call this before accepting new
    client work and before sending progress/model output.
    """
    config = get_auth_config()
    if not has_allowed_origin(websocket.headers.get("origin")):
        await websocket.close(code=1008)
        return False
    if not config.enabled:
        return True
    if not config.configured or not has_allowed_public_host(websocket.headers.get("host")):
        await websocket.close(code=1008)
        return False
    token = websocket.cookies.get(COOKIE_NAME)
    if get_session(
        token,
        idle_seconds=config.idle_seconds,
        policy_fingerprint=config.policy_fingerprint,
    ) is None:
        await websocket.close(code=1008)
        return False
    return True


async def require_ws_session(websocket: WebSocket) -> None:
    """Close and stop route work when a WebSocket session is no longer valid."""
    if not await authorize_ws_session(websocket):
        raise WebSocketDisconnect(code=1008)


async def authorize_ws(websocket: WebSocket, case_id: str) -> bool:
    """Reject a WebSocket handshake from a disallowed origin or unknown case.

    Returns True when the connection may proceed. A browser always sends an
    ``Origin`` header on the WebSocket handshake, so a present-but-unlisted
    origin (including ``null`` and a rebound attacker page) is refused. A missing
    ``Origin`` means a non-browser client, which cannot be a cross-site vector.
    Closing before ``accept()`` denies the handshake with an HTTP 403.
    """
    if not await authorize_ws_session(websocket):
        return False
    if not case_store.case_exists(case_id):
        await websocket.close(code=1008)
        return False
    return True
