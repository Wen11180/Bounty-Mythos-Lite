"""Phase 1 risk decision tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.bounty_autopilot.contracts import (
    AuthorizationBudget,
    CampaignAuthorization,
    CampaignAuthorizationCreate,
    PolicyMode,
    RecipeRef,
    RiskDecision,
    RiskDecisionStatus,
    RiskTier,
)
from app.bounty_autopilot.risk import classify_risk, evaluate_action_risk
from app.bounty_autopilot.recipes import get_recipe


def _digest(seed: str) -> str:
    import hashlib

    return f"sha256:{hashlib.sha256(seed.encode('utf-8')).hexdigest()}"


def _auth(
    *,
    risk_ceiling: RiskTier = RiskTier.R2,
    policy_mode: PolicyMode = PolicyMode.AUTHORIZED_LOCAL_LAB,
    recipes: tuple[RecipeRef, ...] | None = None,
    expires_at: datetime | None = None,
) -> CampaignAuthorization:
    recipe_refs = recipes or (
        RecipeRef(recipe_id="passive_rule_snapshot_analysis", version="1.0"),
        RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),
        RecipeRef(recipe_id="lab_two_owned_account_readonly_authz", version="1.0"),
    )
    create = CampaignAuthorizationCreate(
        campaign_id="campaign_lab_1",
        scope_snapshot_id="scope_snap_1",
        scope_snapshot_digest=_digest("scope"),
        policy_digest=_digest("policy"),
        asset_ids=("asset_loopback_api",),
        account_aliases=("account_a", "account_b"),
        recipe_refs=recipe_refs,
        risk_ceiling=risk_ceiling,
        active_hours_utc=(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23),
        budget=AuthorizationBudget(
            max_requests=50,
            max_concurrent_requests=1,
            max_response_bytes=100_000,
            max_duration_seconds=1800,
            max_accounts=2,
            max_cost_units=50,
        ),
        expires_at=expires_at
        or (datetime.now(timezone.utc) + timedelta(hours=6)),
        operator_id="operator_alice",
        policy_mode=policy_mode,
    )
    return CampaignAuthorization.from_create(create)


def test_r0_can_run_without_network_profile():
    decision = evaluate_action_risk(
        authorization=_auth(),
        recipe_ref=RecipeRef(recipe_id="passive_rule_snapshot_analysis", version="1.0"),
        asset_id="asset_loopback_api",
        method_class="local_document_analysis",
    )
    assert decision.status is RiskDecisionStatus.ALLOWED
    assert decision.risk_tier is RiskTier.R0
    assert decision.allowed_to_execute is True
    recipe = get_recipe("passive_rule_snapshot_analysis", "1.0")
    assert recipe is not None
    assert recipe.network_profile == "none"


def test_r1_and_r2_require_exact_target_method_accounts_and_budget_context():
    decision = evaluate_action_risk(
        authorization=_auth(),
        recipe_ref=RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),
        asset_id="asset_loopback_api",
        method_class="read_only_browser_map",
    )
    assert decision.status is RiskDecisionStatus.ALLOWED
    assert decision.risk_tier is RiskTier.R1

    missing_asset = evaluate_action_risk(
        authorization=_auth(),
        recipe_ref=RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),
        asset_id="asset_other",
        method_class="read_only_browser_map",
    )
    assert missing_asset.status is RiskDecisionStatus.REJECTED
    assert missing_asset.reason == "asset_not_authorized"

    r2 = evaluate_action_risk(
        authorization=_auth(),
        recipe_ref=RecipeRef(
            recipe_id="lab_two_owned_account_readonly_authz", version="1.0"
        ),
        asset_id="asset_loopback_api",
        account_aliases=("account_a", "account_b"),
        method_class="read_only_authorization_differential",
    )
    assert r2.status is RiskDecisionStatus.ALLOWED
    assert r2.risk_tier is RiskTier.R2

    missing_alias = evaluate_action_risk(
        authorization=_auth(),
        recipe_ref=RecipeRef(
            recipe_id="lab_two_owned_account_readonly_authz", version="1.0"
        ),
        asset_id="asset_loopback_api",
        account_aliases=("account_a",),
        method_class="read_only_authorization_differential",
    )
    assert missing_alias.status is RiskDecisionStatus.REJECTED
    assert missing_alias.reason == "required_account_aliases_missing"


def test_active_execution_outside_local_lab_is_blocked():
    auth = _auth(
        risk_ceiling=RiskTier.R0,
        policy_mode=PolicyMode.RESEARCH_PASSIVE_ONLY,
        recipes=(
            RecipeRef(recipe_id="passive_rule_snapshot_analysis", version="1.0"),
        ),
    )
    # Construct a lab auth then force passive-only mode via model_copy is frozen;
    # instead evaluate R1 against an authorization that only has passive recipes
    # after rebuilding with lab mode but assert the named reason when mode is not lab.
    lab_auth = _auth()
    # Direct object construction for the blocked mode with only R0 ceiling is
    # already covered; force evaluation by temporarily using allowed R1 recipe
    # under passive-only is rejected at create time. Simulate by building lab
    # auth and overriding policy_mode through canonicalize path is blocked by
    # frozen model. Use model_construct for this policy fixture only.
    blocked = CampaignAuthorization.model_construct(
        schema_version=lab_auth.schema_version,
        campaign_id=lab_auth.campaign_id,
        scope_snapshot_id=lab_auth.scope_snapshot_id,
        scope_snapshot_digest=lab_auth.scope_snapshot_digest,
        policy_digest=lab_auth.policy_digest,
        asset_ids=lab_auth.asset_ids,
        account_aliases=lab_auth.account_aliases,
        recipe_refs=lab_auth.recipe_refs,
        risk_ceiling=RiskTier.R2,
        active_hours_utc=lab_auth.active_hours_utc,
        budget=lab_auth.budget,
        expires_at=lab_auth.expires_at,
        operator_id=lab_auth.operator_id,
        policy_mode=PolicyMode.RESEARCH_PASSIVE_ONLY,
        authorization_digest=lab_auth.authorization_digest,
    )
    decision = evaluate_action_risk(
        authorization=blocked,
        recipe_ref=RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),
        asset_id="asset_loopback_api",
        method_class="read_only_browser_map",
    )
    assert decision.status is RiskDecisionStatus.POLICY_MODE_BLOCKS_ACTIVE_EXECUTION
    assert decision.reason == "policy_mode_blocks_active_execution"
    assert decision.allowed_to_execute is False
    assert auth.policy_mode is PolicyMode.RESEARCH_PASSIVE_ONLY


def test_r3_always_awaits_exact_approval():
    decision = evaluate_action_risk(
        authorization=_auth(risk_ceiling=RiskTier.R3),
        recipe_ref=RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),
        asset_id="asset_loopback_api",
        method_class="read_only_browser_map",
        model_risk_hint=RiskTier.R3,
    )
    assert decision.status is RiskDecisionStatus.AWAITING_EXACT_APPROVAL
    assert decision.reason == "awaiting_exact_approval"
    assert decision.requires_exact_approval is True
    assert decision.allowed_to_execute is False


def test_r4_is_prohibited_with_no_approval_transition():
    decision = evaluate_action_risk(
        authorization=_auth(risk_ceiling=RiskTier.R3),
        recipe_ref=RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),
        asset_id="asset_loopback_api",
        method_class="read_only_browser_map",
        action_categories={"dos", "resource_exhaustion"},
    )
    assert decision.status is RiskDecisionStatus.PROHIBITED
    assert decision.risk_tier is RiskTier.R4
    assert decision.allowed_to_execute is False
    with pytest.raises(Exception):
        RiskDecision(
            status=RiskDecisionStatus.ALLOWED,
            risk_tier=RiskTier.R4,
            reason="should_fail",
            allowed_to_execute=True,
        )


def test_runtime_recipe_definition_is_rejected():
    decision = evaluate_action_risk(
        authorization=_auth(),
        recipe_ref=RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),
        asset_id="asset_loopback_api",
        method_class="read_only_browser_map",
        recipe_definition={"recipe_id": "invented", "version": "1.0"},
    )
    assert decision.status is RiskDecisionStatus.REJECTED
    assert decision.reason == "runtime_recipe_definition_rejected"


def test_risk_cannot_be_lowered_by_client_or_model_hint():
    recipe = get_recipe("lab_two_owned_account_readonly_authz", "1.0")
    assert recipe is not None
    lowered = classify_risk(
        recipe=recipe,
        client_risk_hint=RiskTier.R0,
        model_risk_hint=RiskTier.R0,
        tool_metadata_risk_hint=RiskTier.R0,
    )
    assert lowered is RiskTier.R2

    raised = classify_risk(
        recipe=recipe,
        client_risk_hint=RiskTier.R3,
    )
    assert raised is RiskTier.R3


def test_unknown_recipe_is_rejected():
    decision = evaluate_action_risk(
        authorization=_auth(),
        recipe_ref=RecipeRef(recipe_id="not_registered", version="1.0"),
        asset_id="asset_loopback_api",
        method_class="read_only_browser_map",
    )
    assert decision.status is RiskDecisionStatus.REJECTED
    assert decision.reason == "unknown_recipe_ref"


def test_promotion_and_submission_always_false():
    decision = evaluate_action_risk(
        authorization=_auth(),
        recipe_ref=RecipeRef(recipe_id="passive_rule_snapshot_analysis", version="1.0"),
        asset_id="asset_loopback_api",
        method_class="local_document_analysis",
    )
    assert decision.candidate_promotion_allowed is False
    assert decision.report_submission_allowed is False
