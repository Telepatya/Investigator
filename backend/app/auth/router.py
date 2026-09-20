"""Anonymous OIDC bootstrap/login endpoints and authenticated logout."""

from __future__ import annotations

import secrets
import time
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from .config import get_auth_config
from .oidc import OIDCError, authorization_url, exchange_code, pkce_verifier, validate_id_token
from .session import COOKIE_NAME, consume_transaction, create_session, create_transaction, get_session, revoke_session

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _return_path(value: str | None) -> str:
    candidate = value or "/"
    parsed = urlsplit(candidate)
    if (
        not candidate.startswith("/")
        or candidate.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or "\\" in candidate
        or len(candidate) > 512
    ):
        raise HTTPException(400, "Invalid return path")
    return candidate


def _cookie_value(request: Request) -> str | None:
    return request.cookies.get(COOKIE_NAME)


@router.get("/bootstrap")
def auth_bootstrap(request: Request) -> dict[str, object | None]:
    config = get_auth_config()
    session = get_session(_cookie_value(request), idle_seconds=config.idle_seconds) if config.configured else None
    return {
        "enabled": config.enabled,
        "configured": config.configured,
        "authenticated": session is not None,
        "user": session.public_dict() if session else None,
        "login_url": "/api/auth/login" if config.configured else None,
    }


@router.get("/session")
def auth_session(request: Request) -> dict[str, object | None]:
    config = get_auth_config()
    session = get_session(_cookie_value(request), idle_seconds=config.idle_seconds) if config.configured else None
    return {"authenticated": session is not None, "user": session.public_dict() if session else None}


@router.get("/login")
async def auth_login(return_to: str | None = None) -> RedirectResponse:
    config = get_auth_config()
    if not config.configured:
        raise HTTPException(503, "Authentication is misconfigured")
    safe_return = _return_path(return_to)
    verifier = pkce_verifier()
    nonce = secrets.token_urlsafe(32)
    state = create_transaction(
        nonce=nonce,
        code_verifier=verifier,
        return_path=safe_return,
        expires_at=time.time() + config.transaction_seconds,
    )
    try:
        target = await authorization_url(config, state=state, nonce=nonce, verifier=verifier)
    except OIDCError as exc:
        consume_transaction(state)
        raise HTTPException(502, "Identity provider is unavailable") from exc
    return RedirectResponse(target, status_code=303)


@router.get("/callback")
async def auth_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> RedirectResponse:
    config = get_auth_config()
    if not config.configured:
        raise HTTPException(503, "Authentication is misconfigured")
    if error or not code or not state or len(state) > 256:
        raise HTTPException(400, "Authentication transaction failed")
    transaction = consume_transaction(state)
    if transaction is None:
        raise HTTPException(400, "Authentication transaction expired or already used")
    try:
        token_document = await exchange_code(config, code=code, verifier=transaction["code_verifier"])
        identity = await validate_id_token(config, id_token=token_document["id_token"], nonce=transaction["nonce"])
    except OIDCError as exc:
        raise HTTPException(401, "Authentication failed") from exc
    # A successful callback always rotates the browser credential. Revoke a
    # pre-existing session presented on the callback request so login cannot
    # leave an older bearer cookie active.
    revoke_session(_cookie_value(request))
    token, _session = create_session(
        subject=identity.subject,
        display_name=identity.display_name,
        email=identity.email,
        is_admin=identity.is_admin,
        idle_seconds=config.idle_seconds,
        absolute_seconds=config.absolute_seconds,
    )
    response = RedirectResponse(transaction["return_path"], status_code=303)
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=config.absolute_seconds,
        httponly=True,
        secure=config.cookie_secure,
        samesite="lax",
        path="/",
    )
    return response


@router.post("/logout")
def auth_logout(request: Request, response: Response) -> dict[str, bool]:
    revoke_session(_cookie_value(request))
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}
