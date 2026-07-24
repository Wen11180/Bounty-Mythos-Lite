"""Durable Campaign authorization helpers for Bounty Autopilot."""

from __future__ import annotations

from datetime import datetime, timezone

from app.bounty_autopilot.contracts import (
    CampaignAuthorization,
    SCHEMA_VERSION,
    campaign_authorization_digest,
    campaign_authorization_from_payload,
)


class AuthorizationValidationError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def build_campaign_authorization(
    authorization: CampaignAuthorization,
) -> CampaignAuthorization:
    """Return a fully validated immutable Campaign authorization."""

    return authorization


def authorization_from_payload(payload: dict) -> CampaignAuthorization:
    stored_digest = payload.get("authorization_digest")
    canonical_payload = {
        key: value for key, value in payload.items() if key != "authorization_digest"
    }
    auth = campaign_authorization_from_payload(canonical_payload)
    if stored_digest is not None and stored_digest != campaign_authorization_digest(auth):
        raise AuthorizationValidationError("authorization_digest_invalid")
    return auth


def validate_current_authorization(
    auth: CampaignAuthorization,
    *,
    now: datetime | None = None,
    expected_scope_snapshot_digest: str | None = None,
) -> None:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    expires_at = auth.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if current >= expires_at:
        raise AuthorizationValidationError("authorization_expired")
    if expected_scope_snapshot_digest is not None:
        if auth.scope_snapshot_digest != expected_scope_snapshot_digest:
            raise AuthorizationValidationError("authorization_scope_stale")
    if auth.schema_version != SCHEMA_VERSION:
        raise AuthorizationValidationError("authorization_schema_unsupported")


__all__ = [
    "AuthorizationValidationError",
    "authorization_from_payload",
    "build_campaign_authorization",
    "validate_current_authorization",
]
