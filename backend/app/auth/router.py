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
    AuthPolicyChanged,
    COOKIE_NAME,
    LEGACY_OIDC_BINDING_COOKIE_NAME,
    OIDC_BINDING_COOKIE_NAME,
    consume_transaction,
    create_session,
    create_transaction,
    get_session,
    revoke_session,
    sync_auth_policy,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])
OIDC_BINDING_COOKIE_PATH = "/api/auth/callback"
_OIDC_HANDLE_LENGTH = 43
_OIDC_HANDLE_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)


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


def _valid_oidc_handle(value: str | None) -> bool:
    return (
        value is not None
        and len(value) == _OIDC_HANDLE_LENGTH
        and all(character in _OIDC_HANDLE_CHARACTERS for character in value)
    )


def _clear_oidc_binding_cookies(response: Response) -> None:
    response.delete_cookie(OIDC_BINDING_COOKIE_NAME, path=OIDC_BINDING_COOKIE_PATH)
    # The original binding cookie used the root path. Clear both legacy path
    # variants during rollout so either prior deployment is upgraded safely.
    response.delete_cookie(LEGACY_OIDC_BINDING_COOKIE_NAME, path="/")
    response.delete_cookie(
        LEGACY_OIDC_BINDING_COOKIE_NAME,
        path=OIDC_BINDING_COOKIE_PATH,
    )


def _callback_failure(detail: str, status_code: int) -> JSONResponse:
    response = JSONResponse(status_code=status_code, content={"detail": detail})
    _clear_oidc_binding_cookies(response)
    return response


@router.get("/bootstrap")
def auth_bootstrap(request: Request) -> dict[str, object | None]:
    config = get_auth_config()
    token = _cookie_value(request)
    session = (
        get_session(
            token,
            idle_seconds=config.idle_seconds,
            policy_fingerprint=config.policy_fingerprint,
        )
        if config.configured and token
        else None
    )
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
    token = _cookie_value(request)
    session = (
        get_session(
            token,
            idle_seconds=config.idle_seconds,
            policy_fingerprint=config.policy_fingerprint,
        )
        if config.configured and token
        else None
    )
    return {"authenticated": session is not None, "user": session.public_dict() if session else None}


@router.get("/login")
async def auth_login(request: Request, return_to: str | None = None) -> RedirectResponse:
    config = get_auth_config()
    if config.enabled:
        sync_auth_policy(config.policy_fingerprint)
    if not config.configured:
        raise HTTPException(503, "Authentication is misconfigured")
    safe_return = _return_path(return_to)
    verifier = pkce_verifier()
    nonce = secrets.token_urlsafe(32)
    # This opaque, one-time browser correlation handle is stored only as a
    # hash server-side. It is not an identity-provider or application secret.
    browser_binding = secrets.token_urlsafe(32)
    # Rate limit on the ASGI peer only. Forwarded address headers are
    # intentionally ignored because they are not trusted at this boundary.
    state = create_transaction(
        nonce=nonce,
        code_verifier=verifier,
        browser_binding=browser_binding,
        return_path=safe_return,
        expires_at=time.time() + config.transaction_seconds,
        client_key=request.client.host if request.client is not None else None,
    )
    if state is None:
        raise HTTPException(
            429,
            "Login is temporarily unavailable; retry later",
            headers={"Retry-After": "60"},
        )
    try:
        target = await authorization_url(config, state=state, nonce=nonce, verifier=verifier)
    except OIDCError as exc:
        consume_transaction(state, browser_binding)
        raise HTTPException(502, "Identity provider is unavailable") from exc
    response = RedirectResponse(target, status_code=303)
    _clear_oidc_binding_cookies(response)
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

    valid_state = _valid_oidc_handle(state)
    valid_binding = _valid_oidc_handle(browser_binding)
    if error:
        if not valid_state or not valid_binding:
            return _callback_failure("Authentication transaction failed", 400)
        # A denial has no authorization code to redeem. Leave its bounded,
        # short-lived transaction for normal expiry instead of doing anonymous
        # database work from caller-supplied state and cookie values.
        return _callback_failure("Authentication transaction failed", 400)

    if not code or not valid_state or not valid_binding:
        return _callback_failure("Authentication transaction failed", 400)

    # Only a syntactically plausible success callback reaches the database.
    # Policy changes must be applied before consuming the one-time transaction.
    sync_auth_policy(config.policy_fingerprint)
    transaction = consume_transaction(state, browser_binding)
    if transaction is None:
        return _callback_failure("Authentication transaction expired, already used, or bound to another browser", 400)
    try:
        token_document = await exchange_code(config, code=code, verifier=transaction["code_verifier"])
        identity = await validate_id_token(config, id_token=token_document["id_token"], nonce=transaction["nonce"])
    except OIDCError:
        return _callback_failure("Authentication failed", 401)
    try:
        token, _session = create_session(
            subject=identity.subject,
            display_name=identity.display_name,
            email=identity.email,
            is_admin=identity.is_admin,
            idle_seconds=config.idle_seconds,
            absolute_seconds=config.absolute_seconds,
            expected_policy_fingerprint=config.policy_fingerprint,
        )
    except AuthPolicyChanged:
        return _callback_failure("Authentication policy changed; restart login", 400)
    # A successful callback always rotates the browser credential. Revoke a
    # pre-existing session only after the new one is safely committed.
    revoke_session(_cookie_value(request))
    response = RedirectResponse(transaction["return_path"], status_code=303)
    _clear_oidc_binding_cookies(response)
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
