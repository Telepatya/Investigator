"""Access checks for shared deployment administration."""

from __future__ import annotations

from fastapi import HTTPException, Request

from .config import get_auth_config


def shared_admin_required() -> bool:
    """Whether this deployment has opted into SSO admin-only controls.

    Local deployments and SSO deployments without an explicitly configured
    admin claim keep their existing access behavior.
    """
    config = get_auth_config()
    return bool(config.enabled and config.admin_claim and config.admin_value)


def can_manage_shared_state(request: Request) -> bool:
    if not shared_admin_required():
        return True
    user = getattr(request.state, "user", None)
    return bool(getattr(user, "is_admin", False))


def require_shared_admin(request: Request) -> None:
    """Reject shared administrative mutations before they perform side effects."""
    if not can_manage_shared_state(request):
        raise HTTPException(
            status_code=403,
            detail="An SSO administrator role is required for this shared deployment change",
        )
