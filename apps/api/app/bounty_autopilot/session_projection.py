"""Opaque session projections for Autopilot (no raw secrets)."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field

from app.bounty_autopilot.contracts import StrictContract


class LoginStateClass(str, Enum):
    UNKNOWN = "unknown"
    LOGGED_OUT = "logged_out"
    LOGGED_IN = "logged_in"
    EXPIRED = "expired"
    LOCKED = "locked"


class SessionHandleProjection(StrictContract):
    """Renderer/API-visible session projection. Secrets never appear here."""

    handle_id: str = Field(min_length=8, max_length=128)
    campaign_id: str
    account_alias: str
    role_label: str = Field(min_length=1, max_length=64)
    login_state: LoginStateClass = LoginStateClass.UNKNOWN
    generation: int = Field(ge=1)
    pod_id: str = Field(min_length=1, max_length=128)
    revoked: bool = False
    raw_secret_present: Literal[False] = False


def project_session_handle(
    *,
    handle_id: str,
    campaign_id: str,
    account_alias: str,
    role_label: str,
    login_state: LoginStateClass,
    generation: int,
    pod_id: str,
    revoked: bool = False,
) -> SessionHandleProjection:
    return SessionHandleProjection(
        handle_id=handle_id,
        campaign_id=campaign_id,
        account_alias=account_alias,
        role_label=role_label,
        login_state=login_state,
        generation=generation,
        pod_id=pod_id,
        revoked=revoked,
    )


def revoke_handle(projection: SessionHandleProjection) -> SessionHandleProjection:
    return projection.model_copy(update={"revoked": True, "login_state": LoginStateClass.EXPIRED})


__all__ = [
    "LoginStateClass",
    "SessionHandleProjection",
    "project_session_handle",
    "revoke_handle",
]
