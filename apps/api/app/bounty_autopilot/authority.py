"""Durable Campaign authorization helpers for Bounty Autopilot."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.bounty_autopilot.contracts import (
    CampaignAuthorization,
    CampaignAuthorizationCreate,
    SCHEMA_VERSION,
    canonicalize_authorization_payload,
    compute_authorization_digest,
)
from app.bounty_autopilot.recipes import get_recipe


class AuthorizationValidationError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def build_campaign_authorization(
    create: CampaignAuthorizationCreate,
) -> CampaignAuthorization:
    """Validate registered recipes then build an immutable authorization."""

    for recipe_ref in create.recipe_refs:
        if get_recipe(recipe_ref.recipe_id, recipe_ref.version) is None:
            raise AuthorizationValidationError("unknown_recipe_ref")
    return CampaignAuthorization.from_create(create)


def authorization_from_payload(payload: dict) -> CampaignAuthorization:
    auth = CampaignAuthorization.model_validate(payload)
    recomputed = compute_authorization_digest(
        canonicalize_authorization_payload(auth)
    )
    if recomputed != auth.authorization_digest:
        raise AuthorizationValidationError("authorization_digest_invalid")
    return auth


def validate_current_authorization(
    auth: CampaignAuthorization,
    *,
    now: datetime | None = None,
    expected_scope_snapshot_digest: str | None = None,
    expected_policy_digest: str | None = None,
) -> None:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    expires_at = auth.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if current >= expires_at:
        raise AuthorizationValidationError("authorization_expired")
    if current.hour not in auth.active_hours_utc:
        raise AuthorizationValidationError("active_hours_closed")
    if expected_scope_snapshot_digest is not None:
        if auth.scope_snapshot_digest != expected_scope_snapshot_digest:
            raise AuthorizationValidationError("authorization_scope_stale")
    if expected_policy_digest is not None and auth.policy_digest != expected_policy_digest:
        raise AuthorizationValidationError("authorization_policy_stale")
    recomputed = compute_authorization_digest(
        canonicalize_authorization_payload(auth)
    )
    if recomputed != auth.authorization_digest:
        raise AuthorizationValidationError("authorization_digest_invalid")
    if auth.schema_version != SCHEMA_VERSION:
        raise AuthorizationValidationError("authorization_schema_unsupported")


def current_execution_authority_reason(
    *,
    campaign: Any,
    repository: Any,
    source_snapshot_digest: str | None = None,
    now: datetime | None = None,
) -> str | None:
    """Return a fail-closed reason for stale Autopilot execution authority."""

    if (getattr(campaign, "campaign_mode", None) or "legacy") != "bounty_autopilot":
        return None
    row = repository.get_current_campaign_authorization(campaign.id)
    if row is None:
        return "authorization_missing"
    try:
        authorization = authorization_from_payload(row.payload)
        policy_hash = str(getattr(campaign, "policy_text_hash", "")).removeprefix(
            "sha256:"
        )
        validate_current_authorization(
            authorization,
            now=now,
            expected_policy_digest=f"sha256:{policy_hash}",
        )
    except AuthorizationValidationError as exc:
        return exc.reason
    except Exception:  # noqa: BLE001 - persisted authority fails closed
        return "authorization_invalid"
    payload = campaign.payload if isinstance(campaign.payload, dict) else {}
    if payload.get("current_authorization_id") != row.id:
        return "authorization_stale"
    if payload.get("current_authorization_digest") != authorization.authorization_digest:
        return "authorization_stale"
    if payload.get("scope_snapshot_digest") != authorization.scope_snapshot_digest:
        return "authorization_scope_stale"
    if source_snapshot_digest is not None and source_snapshot_digest != payload.get(
        "source_snapshot_digest"
    ):
        return "source_snapshot_changed"
    return None


__all__ = [
    "AuthorizationValidationError",
    "authorization_from_payload",
    "build_campaign_authorization",
    "current_execution_authority_reason",
    "validate_current_authorization",
]
