"""Phase 1 contract tests for Bounty Autopilot authorization digests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.bounty_autopilot.contracts import (
    AuthorizationBudget,
    CampaignAuthorization,
    CampaignAuthorizationCreate,
    PolicyMode,
    RecipeRef,
    RiskTier,
    canonicalize_authorization_payload,
    compute_authorization_digest,
)


def _digest(seed: str = "scope") -> str:
    # Stable looking digest; not derived from seed content intentionally.
    import hashlib

    return f"sha256:{hashlib.sha256(seed.encode('utf-8')).hexdigest()}"


def _budget(**overrides):
    payload = {
        "max_requests": 100,
        "max_concurrent_requests": 2,
        "max_response_bytes": 250_000,
        "max_duration_seconds": 3600,
        "max_accounts": 2,
        "max_cost_units": 100,
    }
    payload.update(overrides)
    return AuthorizationBudget(**payload)


def _create(**overrides) -> CampaignAuthorizationCreate:
    payload = {
        "campaign_id": "campaign_lab_1",
        "scope_snapshot_id": "scope_snap_1",
        "scope_snapshot_digest": _digest("scope"),
        "policy_digest": _digest("policy"),
        "asset_ids": ("asset_loopback_api", "asset_loopback_web"),
        "account_aliases": ("account_a", "account_b"),
        "recipe_refs": (
            RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),
            RecipeRef(recipe_id="passive_rule_snapshot_analysis", version="1.0"),
        ),
        "risk_ceiling": RiskTier.R2,
        "active_hours_utc": (9, 10, 11, 12, 13, 14, 15, 16, 17),
        "budget": _budget(),
        "expires_at": datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        "operator_id": "operator_alice",
        "policy_mode": PolicyMode.AUTHORIZED_LOCAL_LAB,
    }
    payload.update(overrides)
    return CampaignAuthorizationCreate(**payload)


def test_authorization_requires_all_authority_bearing_fields():
    auth = CampaignAuthorization.from_create(_create())
    assert auth.campaign_id == "campaign_lab_1"
    assert auth.scope_snapshot_digest.startswith("sha256:")
    assert auth.policy_digest.startswith("sha256:")
    assert auth.asset_ids
    assert auth.account_aliases
    assert auth.recipe_refs
    assert auth.risk_ceiling is RiskTier.R2
    assert auth.active_hours_utc
    assert auth.budget.max_requests == 100
    assert auth.expires_at.year == 2026
    assert auth.operator_id == "operator_alice"
    assert auth.authorization_digest.startswith("sha256:")


def test_missing_asset_set_is_rejected():
    with pytest.raises(ValidationError):
        _create(asset_ids=())


def test_duplicate_account_aliases_are_rejected():
    with pytest.raises(ValidationError):
        _create(account_aliases=("account_a", "account_a"))


def test_account_aliases_cannot_exceed_authorization_budget():
    with pytest.raises(ValidationError, match="account_budget_exceeded"):
        _create(
            account_aliases=("account_a", "account_b", "account_c"),
            budget=_budget(max_accounts=2),
        )


def test_unbounded_budgets_are_rejected():
    with pytest.raises(ValidationError):
        _budget(max_requests=0)
    with pytest.raises(ValidationError):
        _budget(max_concurrent_requests=0)


def test_canonical_serialization_is_order_insensitive():
    left = _create(
        asset_ids=("asset_b", "asset_a"),
        account_aliases=("account_b", "account_a"),
        recipe_refs=(
            RecipeRef(recipe_id="passive_rule_snapshot_analysis", version="1.0"),
            RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),
        ),
        active_hours_utc=(17, 9, 12),
    )
    right = _create(
        asset_ids=("asset_a", "asset_b"),
        account_aliases=("account_a", "account_b"),
        recipe_refs=(
            RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),
            RecipeRef(recipe_id="passive_rule_snapshot_analysis", version="1.0"),
        ),
        active_hours_utc=(9, 12, 17),
    )
    left_auth = CampaignAuthorization.from_create(left)
    right_auth = CampaignAuthorization.from_create(right)
    assert left_auth.authorization_digest == right_auth.authorization_digest
    assert canonicalize_authorization_payload(left) == canonicalize_authorization_payload(right)


def test_changing_authority_field_changes_digest():
    base = CampaignAuthorization.from_create(_create())
    changed = CampaignAuthorization.from_create(
        _create(scope_snapshot_digest=_digest("other-scope"))
    )
    assert base.authorization_digest != changed.authorization_digest
    operator_changed = CampaignAuthorization.from_create(
        _create(operator_id="operator_bob")
    )
    assert base.authorization_digest != operator_changed.authorization_digest


def test_risk_ceiling_cannot_be_r4():
    with pytest.raises(ValidationError):
        _create(risk_ceiling=RiskTier.R4)


def test_policy_mode_blocks_active_risk_ceiling_outside_lab():
    with pytest.raises(ValidationError):
        _create(
            policy_mode=PolicyMode.RESEARCH_PASSIVE_ONLY,
            risk_ceiling=RiskTier.R1,
        )


def test_public_target_active_automation_is_not_a_policy_mode():
    # Phase 0/1 fixture: current policy forbids public-target active automation.
    assert not hasattr(PolicyMode, "PUBLIC_TARGET_ACTIVE")
    assert {mode.value for mode in PolicyMode} == {
        "authorized_local_lab",
        "research_passive_only",
    }


def test_compute_authorization_digest_matches_from_create():
    create = _create()
    payload = canonicalize_authorization_payload(create)
    digest = compute_authorization_digest(payload)
    auth = CampaignAuthorization.from_create(create)
    assert auth.authorization_digest == digest


def test_authorization_expiry_is_preserved():
    expires = datetime.now(timezone.utc) + timedelta(hours=2)
    auth = CampaignAuthorization.from_create(_create(expires_at=expires))
    assert auth.expires_at == expires
