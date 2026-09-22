"""Provider destinations are an operator trust decision in hosted deployments."""

from __future__ import annotations

import os
import re
import ipaddress
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.auth.config import get_auth_config

DEFAULT_ENDPOINTS = {
    "ollama": "http://localhost:11434",
    "openrouter": "https://openrouter.ai/api/v1",
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
    "gemini": "https://generativelanguage.googleapis.com",
}


class ProviderEndpointError(ValueError):
    """An endpoint was malformed or was not approved by the server operator."""


def normalize_endpoint(value: str) -> str:
    # Reject ambiguous parser inputs rather than relying on SDK normalization.
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ProviderEndpointError("Invalid provider URL")
    if re.search(r"[\s\\\x00-\x1f\x7f]", value):
        raise ProviderEndpointError("Invalid provider URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
        host = parsed.hostname
    except ValueError as exc:
        raise ProviderEndpointError("Invalid provider URL") from exc
    if (
        parsed.scheme not in {"http", "https"} or not host
        or parsed.username is not None or parsed.password is not None
        or "?" in value or "#" in value or "%" in parsed.netloc
        or not re.fullmatch(r"[/A-Za-z0-9._~-]*", parsed.path)
        or any(part in {".", ".."} for part in parsed.path.split("/"))
        or port == 0
    ):
        raise ProviderEndpointError("Provider URL must be an absolute HTTP(S) base without credentials, query or fragment")
    host = host.lower()
    rendered_host = f"[{host}]" if ":" in host else host
    if port is not None and port != {"http": 80, "https": 443}[parsed.scheme]:
        rendered_host += f":{port}"
    return urlunsplit((parsed.scheme, rendered_host, parsed.path.rstrip("/"), "", ""))


def validate_endpoint(provider: str, value: str | None = None) -> str:
    endpoint = normalize_endpoint(value if value is not None else DEFAULT_ENDPOINTS[provider])
    if get_auth_config().enabled:
        parsed = urlsplit(endpoint)
        host = parsed.hostname
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if parsed.scheme != "https" and not loopback:
            raise ProviderEndpointError("Hosted provider URLs require HTTPS except for loopback services")
        # These values cannot be set through the application settings API. Exact
        # bases (including paths) also prevent one provider receiving another's key.
        approved = {DEFAULT_ENDPOINTS[provider]}
        raw = os.environ.get(f"INVESTIGATOR_{provider.upper()}_APPROVED_URLS", "")
        for item in raw.split(","):
            if item.strip():
                approved.add(normalize_endpoint(item.strip()))
        if endpoint not in approved:
            raise ProviderEndpointError(f"{provider} URL is not approved by the server operator")
    return endpoint


def provider_http_client(provider: str, base_url: str, *, timeout: float = 300) -> httpx.AsyncClient:
    base = validate_endpoint(provider, base_url)
    expected = httpx.URL(base)

    async def check_destination(request: httpx.Request) -> None:
        validate_endpoint(provider, base)
        target = request.url
        if (
            (target.scheme, target.host, target.port) != (expected.scheme, expected.host, expected.port)
            or not (target.path == expected.path.rstrip("/") or target.path.startswith(expected.path.rstrip("/") + "/"))
        ):
            raise ProviderEndpointError("Provider request left its configured base URL")

    return httpx.AsyncClient(
        timeout=timeout, follow_redirects=False, trust_env=False,
        event_hooks={"request": [check_destination]},
    )
