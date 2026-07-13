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

from fastapi import Request, WebSocket

from app.store import cases as case_store

# Hosts the loopback server legitimately answers to. A rebound name such as
# ``evil.example`` resolving to 127.0.0.1 arrives with that name in the Host
# header and is rejected by TrustedHostMiddleware built from this list.
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]
STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def allowed_origins() -> list[str]:
    """Browser origins permitted to talk to this backend (built UI + Vite dev)."""
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
    return origin is None or origin in set(allowed_origins())


def authorize_http(request: Request) -> bool:
    """Reject cross-origin browser writes; CORS alone only hides responses."""
    if request.method.upper() not in STATE_CHANGING_METHODS:
        return True
    return has_allowed_origin(request.headers.get("origin"))


async def authorize_ws(websocket: WebSocket, case_id: str) -> bool:
    """Reject a WebSocket handshake from a disallowed origin or unknown case.

    Returns True when the connection may proceed. A browser always sends an
    ``Origin`` header on the WebSocket handshake, so a present-but-unlisted
    origin (including ``null`` and a rebound attacker page) is refused. A missing
    ``Origin`` means a non-browser client, which cannot be a cross-site vector.
    Closing before ``accept()`` denies the handshake with an HTTP 403.
    """
    if not has_allowed_origin(websocket.headers.get("origin")):
        await websocket.close(code=1008)
        return False
    if not case_store.case_exists(case_id):
        await websocket.close(code=1008)
        return False
    return True
