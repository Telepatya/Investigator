"""OIDC discovery, authorization-code exchange, and claim validation."""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx
from authlib.jose import JsonWebToken

from .config import AuthConfig

logger = logging.getLogger(__name__)

# Explicitly exclude ``none`` and symmetric algorithms.  A confidential web
# app validates signatures with the issuer's JWKS, so accepting HS* would let a
# client secret be misused as a verification key.
SAFE_JWT_ALGORITHMS = (
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512",
)


class OIDCError(RuntimeError):
    """A user-safe authentication failure without token/claim details."""


@dataclass(frozen=True)
class OIDCMetadata:
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    issuer: str


@dataclass(frozen=True)
class Identity:
    subject: str
    display_name: str | None
    email: str | None
    is_admin: bool


def pkce_verifier() -> str:
    return secrets.token_urlsafe(48)


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


async def discover(config: AuthConfig) -> OIDCMetadata:
    if not config.configured or not config.issuer:
        raise OIDCError("SSO is not configured")
    url = config.issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            response = await client.get(url)
            response.raise_for_status()
            document = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("OIDC discovery failed: %s", type(exc).__name__)
        raise OIDCError("Identity provider discovery failed") from exc
    try:
        metadata = OIDCMetadata(
            authorization_endpoint=str(document["authorization_endpoint"]),
            token_endpoint=str(document["token_endpoint"]),
            jwks_uri=str(document["jwks_uri"]),
            issuer=str(document["issuer"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise OIDCError("Identity provider metadata is incomplete") from exc
    if metadata.issuer.rstrip("/") != config.issuer.rstrip("/"):
        raise OIDCError("Identity provider issuer does not match configuration")
    for endpoint in (metadata.authorization_endpoint, metadata.token_endpoint, metadata.jwks_uri):
        try:
            parsed_endpoint = urlsplit(endpoint)
        except ValueError:
            raise OIDCError("Identity provider endpoint is invalid") from None
        if parsed_endpoint.scheme == "https" and parsed_endpoint.hostname:
            continue
        if parsed_endpoint.scheme == "http" and parsed_endpoint.hostname in {"localhost", "127.0.0.1", "::1"}:
            continue
        raise OIDCError("Identity provider endpoint must use HTTPS")
    return metadata


async def authorization_url(config: AuthConfig, *, state: str, nonce: str, verifier: str) -> str:
    metadata = await discover(config)
    if not config.client_id or not config.callback_url():
        raise OIDCError("SSO is not configured")
    query = urlencode({
        "client_id": config.client_id,
        "response_type": "code",
        "redirect_uri": config.callback_url(),
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": pkce_challenge(verifier),
        "code_challenge_method": "S256",
    })
    return f"{metadata.authorization_endpoint}?{query}"


async def exchange_code(config: AuthConfig, *, code: str, verifier: str) -> dict[str, Any]:
    metadata = await discover(config)
    if not config.client_id or not config.client_secret or not config.callback_url():
        raise OIDCError("SSO is not configured")
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": config.callback_url(),
        "client_id": config.client_id,
        "code_verifier": verifier,
    }
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
            response = await client.post(
                metadata.token_endpoint,
                data=payload,
                auth=(config.client_id, config.client_secret),
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            token_document = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("OIDC token exchange failed: %s", type(exc).__name__)
        raise OIDCError("Identity provider token exchange failed") from exc
    if not isinstance(token_document, dict) or not isinstance(token_document.get("id_token"), str):
        raise OIDCError("Identity provider did not return an ID token")
    return {"id_token": token_document["id_token"]}


async def validate_id_token(config: AuthConfig, *, id_token: str, nonce: str) -> Identity:
    metadata = await discover(config)
    if not config.client_id or not config.issuer:
        raise OIDCError("SSO is not configured")
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            response = await client.get(metadata.jwks_uri)
            response.raise_for_status()
            jwks = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("OIDC JWKS retrieval failed: %s", type(exc).__name__)
        raise OIDCError("Identity provider keys could not be loaded") from exc
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise OIDCError("Identity provider keys are invalid")
    try:
        token = JsonWebToken(SAFE_JWT_ALGORITHMS)
        claims = token.decode(
            id_token,
            jwks,
            claims_options={
                "iss": {"essential": True, "value": config.issuer},
                "sub": {"essential": True},
                "aud": {"essential": True, "value": config.client_id},
                "exp": {"essential": True},
                "iat": {"essential": True},
                "nonce": {"essential": True, "value": nonce},
            },
        )
        claims.validate(leeway=60)
    except Exception as exc:
        # Authlib's errors intentionally stay out of the response and logs;
        # they can include token fragments or issuer-specific details.
        logger.info("OIDC ID token validation rejected (%s)", type(exc).__name__)
        raise OIDCError("Identity provider token validation failed") from exc
    if not isinstance(claims, dict):
        raise OIDCError("Identity provider claims are invalid")
    return identity_from_claims(config, claims)


def _claim_values(value: Any) -> tuple[str, ...] | None:
    if isinstance(value, str):
        # A scalar group/role claim is ambiguous and fails closed.  This also
        # avoids accidentally treating a malformed JSON string as a list.
        return None
    if not isinstance(value, (list, tuple)) or not value:
        return None
    if any(not isinstance(item, str) or not item for item in value):
        return None
    return tuple(value)


def identity_from_claims(config: AuthConfig, claims: dict[str, Any]) -> Identity:
    """Apply exact group/role allowlisting without retaining full claims."""
    if claims.get("hasgroups") is not None:
        # Microsoft Entra emits hasgroups when group membership is over the
        # token limit.  Calling Graph is intentionally out of scope.
        raise OIDCError("Identity provider group membership is incomplete")
    overage = claims.get("_claim_names")
    if overage is not None:
        # A token containing the overage indirection is not self-contained;
        # do not attempt to guess whether a configured claim is complete.
        raise OIDCError("Identity provider group membership is incomplete")
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise OIDCError("Identity provider subject is missing")
    allowed = set(config.allowed_values)
    matched = False
    parsed_claims: dict[str, tuple[str, ...]] = {}
    for name in config.claim_names:
        if name not in claims:
            continue
        values = _claim_values(claims[name])
        if values is None:
            raise OIDCError("Identity provider group or role claim is malformed")
        parsed_claims[name] = values
        if allowed.intersection(values):
            matched = True
    if not parsed_claims or not matched:
        raise OIDCError("Identity provider account is not allowed")
    is_admin = False
    if config.admin_claim and config.admin_value:
        admin_values = _claim_values(claims.get(config.admin_claim))
        if admin_values is not None:
            is_admin = config.admin_value in admin_values
        elif config.admin_claim in claims:
            raise OIDCError("Identity provider admin claim is malformed")
    display_name = claims.get("name") or claims.get("preferred_username") or claims.get("email")
    email = claims.get("email")
    return Identity(
        subject=subject,
        display_name=display_name if isinstance(display_name, str) else None,
        email=email if isinstance(email, str) else None,
        is_admin=is_admin,
    )
