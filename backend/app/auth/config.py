"""Environment-only configuration for the optional OIDC integration.

Authentication configuration deliberately does not use ``config.json``.  In
particular, the client secret and any session material must remain outside the
application's regular settings export and backup paths.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
FALSE_VALUES = frozenset({"0", "false", "no", "off", ""})


def _env(name: str, *aliases: str) -> str | None:
    for key in (name, *aliases):
        value = os.environ.get(key)
        if value is not None:
            return value.strip()
    return None


def _parse_bool(name: str, default: bool = False) -> tuple[bool, str | None]:
    raw = _env(name, "INVESTIGATOR_SSO_ENABLED")
    if raw is None:
        return default, None
    lowered = raw.lower()
    if lowered in TRUE_VALUES:
        return True, None
    if lowered in FALSE_VALUES:
        return False, None
    return True, f"{name} must be one of true/false"


def _split_values(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ()
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def normalize_origin(raw: str | None) -> str | None:
    """Validate and normalize an explicit public origin.

    Redirect and origin URLs are never derived from a request ``Host`` or
    forwarded headers.  A path, credentials, query, and fragment are rejected
    so the value is an origin rather than an arbitrary redirect target.
    """
    if not raw:
        return None
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return None
    if parsed.path not in {"", "/"}:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    host = parsed.hostname.lower()
    rendered_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    netloc = rendered_host if port is None else f"{rendered_host}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, "", "", ""))


@dataclass(frozen=True)
class AuthConfig:
    enabled: bool
    issuer: str | None
    client_id: str | None
    client_secret: str | None
    public_origin: str | None
    claim_names: tuple[str, ...]
    allowed_values: tuple[str, ...]
    admin_claim: str | None
    admin_value: str | None
    idle_seconds: int
    absolute_seconds: int
    transaction_seconds: int
    error: str | None = None

    @property
    def configured(self) -> bool:
        return self.enabled and self.error is None

    @property
    def cookie_secure(self) -> bool:
        return self.public_origin is not None and self.public_origin.startswith("https://")

    @property
    def callback_path(self) -> str:
        return "/api/auth/callback"

    def callback_url(self) -> str | None:
        if not self.public_origin:
            return None
        return f"{self.public_origin}{self.callback_path}"


def get_auth_config() -> AuthConfig:
    enabled, error = _parse_bool("INVESTIGATOR_AUTH_ENABLED")
    issuer = _env("INVESTIGATOR_OIDC_ISSUER", "INVESTIGATOR_SSO_ISSUER")
    client_id = _env("INVESTIGATOR_OIDC_CLIENT_ID", "INVESTIGATOR_SSO_CLIENT_ID")
    client_secret = _env("INVESTIGATOR_OIDC_CLIENT_SECRET", "INVESTIGATOR_SSO_CLIENT_SECRET")
    public_origin = normalize_origin(
        _env("INVESTIGATOR_PUBLIC_ORIGIN", "INVESTIGATOR_AUTH_PUBLIC_ORIGIN", "INVESTIGATOR_SSO_PUBLIC_ORIGIN")
    )
    raw_origin = _env("INVESTIGATOR_PUBLIC_ORIGIN", "INVESTIGATOR_AUTH_PUBLIC_ORIGIN", "INVESTIGATOR_SSO_PUBLIC_ORIGIN")
    claim_names = _split_values(
        _env("INVESTIGATOR_SSO_CLAIMS", "INVESTIGATOR_AUTH_CLAIMS") or "groups,roles"
    )
    allowed_values = _split_values(
        _env("INVESTIGATOR_SSO_ALLOWED_VALUES", "INVESTIGATOR_AUTH_ALLOWED_VALUES", "INVESTIGATOR_AUTH_ALLOWED_GROUPS")
    )
    admin_claim = _env("INVESTIGATOR_SSO_ADMIN_CLAIM", "INVESTIGATOR_AUTH_ADMIN_CLAIM")
    admin_value = _env("INVESTIGATOR_SSO_ADMIN_VALUE", "INVESTIGATOR_AUTH_ADMIN_VALUE")

    issues: list[str] = []
    if enabled:
        if error:
            issues.append(error)
        if not issuer:
            issues.append("OIDC issuer is required")
        if not client_id:
            issues.append("OIDC client id is required")
        if not client_secret:
            issues.append("OIDC client secret is required")
        if not public_origin:
            issues.append("explicit public origin is required")
        elif raw_origin and normalize_origin(raw_origin) != raw_origin.rstrip("/"):
            issues.append("public origin must be an exact http(s) origin without a path")
        if not claim_names:
            issues.append("at least one token claim name is required")
        if not allowed_values:
            issues.append("at least one exact allowlist value is required")
        if (admin_claim is None) != (admin_value is None):
            issues.append("admin claim and admin value must be supplied together")
        if issuer:
            parsed_issuer = urlsplit(issuer)
            if parsed_issuer.scheme not in {"https", "http"} or not parsed_issuer.netloc:
                issues.append("OIDC issuer must be an absolute URL")
            elif parsed_issuer.username or parsed_issuer.password or parsed_issuer.query or parsed_issuer.fragment:
                issues.append("OIDC issuer must not include credentials, query, or fragment")
            elif parsed_issuer.scheme == "http" and parsed_issuer.hostname not in {"localhost", "127.0.0.1", "::1"}:
                issues.append("OIDC issuer must use HTTPS except for loopback development")
    try:
        idle_seconds = max(60, min(int(_env("INVESTIGATOR_SSO_IDLE_SECONDS") or "1800"), 86400))
        absolute_seconds = max(idle_seconds, min(int(_env("INVESTIGATOR_SSO_ABSOLUTE_SECONDS") or "28800"), 604800))
        transaction_seconds = max(60, min(int(_env("INVESTIGATOR_SSO_TRANSACTION_SECONDS") or "600"), 1800))
    except ValueError:
        idle_seconds, absolute_seconds, transaction_seconds = 1800, 28800, 600
        if enabled:
            issues.append("session expiry values must be integers")
    return AuthConfig(
        enabled=enabled,
        issuer=issuer,
        client_id=client_id,
        client_secret=client_secret,
        public_origin=public_origin,
        claim_names=claim_names,
        allowed_values=allowed_values,
        admin_claim=admin_claim,
        admin_value=admin_value,
        idle_seconds=idle_seconds,
        absolute_seconds=absolute_seconds,
        transaction_seconds=transaction_seconds,
        error="; ".join(issues) if issues else None,
    )
