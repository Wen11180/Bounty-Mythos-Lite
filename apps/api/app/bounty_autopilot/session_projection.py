"""Opaque, secret-free session projection helpers."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from app.bounty_autopilot.contracts import SessionHandleProjection

LoginStateClass = Literal[
    "unknown",
    "logged_out",
    "logged_in",
    "expired",
    "locked",
]
for _state in ("UNKNOWN", "LOGGED_OUT", "LOGGED_IN", "EXPIRED", "LOCKED"):
    setattr(LoginStateClass, _state, _state.lower())


def project_session_handle(
    *,
    handle_id: str,
    campaign_id: str,
    account_alias: str,
    login_state: LoginStateClass,
    generation: int,
    pod_id: str,
    issued_at: datetime,
    expires_at: datetime,
    revoked: bool = False,
) -> SessionHandleProjection:
    return SessionHandleProjection(
        handle_id=handle_id,
        campaign_id=campaign_id,
        account_alias=account_alias,
        role_label="owned",
        login_state=login_state,
        generation=generation,
        pod_id=pod_id,
        issued_at=issued_at,
        expires_at=expires_at,
        revoked=revoked,
    )


def revoke_handle(projection: SessionHandleProjection) -> SessionHandleProjection:
    return projection.model_copy(update={"revoked": True, "login_state": "expired"})


__all__ = [
    "LoginStateClass",
    "SessionHandleProjection",
    "project_session_handle",
    "revoke_handle",
]
