"""Anonymous OIDC bootstrap/login endpoints and authenticated logout."""

from __future__ import annotations

import secrets
import time
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from .config import get_auth_config
from .oidc import OIDCError, authorization_url, exchange_code, pkce_verifier, validate_id_token
from .session import (
    COOKIE_NAME,
    OIDC_BINDING_COOKIE_NAME,
    consume_transaction,
    create_session,
    create_transaction,
    get_session,
    revoke_session,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])
OIDC_BINDING_COOKIE_PATH = "/api/auth/callback"


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


def _binding_cookie_value(request: Request) -> str | None:
    return request.cookies.get(OIDC_BINDING_COOKIE_NAME)


def _callback_failure(detail: str, status_code: int) -> JSONResponse:
    response = JSONResponse(status_code=status_code, content={"detail": detail})
    response.delete_cookie(OIDC_BINDING_COOKIE_NAME, path=OIDC_BINDING_COOKIE_PATH)
    return response


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
    # This opaque, one-time browser correlation handle is stored only as a
    # hash server-side. It is not an identity-provider or application secret.
    browser_binding = secrets.token_urlsafe(32)
    state = create_transaction(
        nonce=nonce,
        code_verifier=verifier,
        browser_binding=browser_binding,
        return_path=safe_return,
        expires_at=time.time() + config.transaction_seconds,
    )
    try:
        target = await authorization_url(config, state=state, nonce=nonce, verifier=verifier)
    except OIDCError as exc:
        consume_transaction(state, browser_binding)
        raise HTTPException(502, "Identity provider is unavailable") from exc
    response = RedirectResponse(target, status_code=303)
    response.set_cookie(
        OIDC_BINDING_COOKIE_NAME,
        browser_binding,
        max_age=config.transaction_seconds,
        httponly=True,
        secure=config.cookie_secure,
        samesite="lax",
        path=OIDC_BINDING_COOKIE_PATH,
    )
    return response


@router.get("/callback")
async def auth_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> Response:
    config = get_auth_config()
    if not config.configured:
        return _callback_failure("Authentication is misconfigured", 503)
    browser_binding = _binding_cookie_value(request)
    if (error or not code) and state and len(state) <= 256 and browser_binding:
        # A provider denial is terminal for the matching browser, but a
        # mismatched browser must not consume the initiator's transaction.
        consume_transaction(state, browser_binding)
    if error or not code or not state or len(state) > 256 or not browser_binding:
        return _callback_failure("Authentication transaction failed", 400)
    transaction = consume_transaction(state, browser_binding)
    if transaction is None:
        return _callback_failure("Authentication transaction expired, already used, or bound to another browser", 400)
    try:
        token_document = await exchange_code(config, code=code, verifier=transaction["code_verifier"])
        identity = await validate_id_token(config, id_token=token_document["id_token"], nonce=transaction["nonce"])
    except OIDCError:
        return _callback_failure("Authentication failed", 401)
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
    response.delete_cookie(OIDC_BINDING_COOKIE_NAME, path=OIDC_BINDING_COOKIE_PATH)
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
