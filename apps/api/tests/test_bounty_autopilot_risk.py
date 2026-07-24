from datetime import datetime, timezone

import pytest
from pydantic import TypeAdapter, ValidationError

from app.bounty_autopilot.contracts import (
    ActiveHoursWindow,
    AutopilotBudgets,
    CampaignAuthorization,
    RecipeSelection,
    RiskDecision,
)
from app.bounty_autopilot.recipes import default_recipe_registry
from app.bounty_autopilot.risk import decide_recipe_risk
from app.scope_guard import ScopeGuardRule


NOW = datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc)
DIGEST_A = "sha256:" + ("a" * 64)
DIGEST_B = "sha256:" + ("b" * 64)


def _budget(**updates: int) -> AutopilotBudgets:
    values = {
        "max_requests": 1,
        "max_concurrency": 1,
        "max_response_bytes": 65_536,
        "max_duration_seconds": 60,
        "max_account_operations": 1,
        "max_cost_microusd": 100_000,
    }
    values.update(updates)
    return AutopilotBudgets(**values)


def _authorization(
    recipe_id: str,
    *,
    max_risk: str = "R2",
    policy_mode: str = "authorized_local_lab",
    network_profile: str = "authorized_local_lab",
) -> CampaignAuthorization:
    recipe = default_recipe_registry().require(recipe_id, "1.0.0")
    return CampaignAuthorization(
        campaign_id="campaign_lab_1",
        scope_snapshot_id="scope_snapshot_1",
        scope_review_state="approved",
        scope_snapshot_digest=DIGEST_A,
        policy_digest=DIGEST_B,
        asset_ids=("asset_api",),
        account_aliases=("owned_alpha", "owned_beta"),
        recipe_refs=(recipe.ref,),
        max_automatic_risk=max_risk,
        policy_mode=policy_mode,
        network_profile=network_profile,
        allowed_method_classes=("passive", "read_only"),
        active_hours_utc=(
            ActiveHoursWindow(
                days_utc=(0, 1, 2, 3, 4, 5, 6),
                start_minute_utc=0,
                end_minute_utc=1440,
            ),
        ),
        budgets=_budget(max_requests=8, max_duration_seconds=120),
        issued_at=datetime(2026, 7, 23, 12, 0, tzinfo=timezone.utc),
        expires_at=datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc),
        operator_identity="operator.local",
    )


def _selection(
    recipe_id: str,
    *,
    accounts: tuple[str, ...] = (),
    **updates: object,
) -> RecipeSelection:
    values = {
        "recipe_id": recipe_id,
        "version": "1.0.0",
        "target_asset_id": "asset_api",
        "method_class": (
            "passive" if recipe_id.startswith("passive_") else "read_only"
        ),
        "account_aliases": accounts,
        "requested_budgets": _budget(),
        "client_risk_hint": None,
        "model_risk_hint": None,
        "tool_risk_hint": None,
        "action_categories": (),
    }
    values.update(updates)
    return RecipeSelection(**values)


def _scope(recipe_id: str, *, asset: str = "asset_api") -> ScopeGuardRule:
    recipe = default_recipe_registry().require(recipe_id, "1.0.0")
    return ScopeGuardRule(
        asset=asset,
        scope_status="in_scope",
        automation="limited",
        allowed_validation=[recipe.validation_type],
        forbidden=[],
        human_approval_required=False,
    )


def _decide(
    recipe_id: str,
    *,
    authorization: CampaignAuthorization | None = None,
    selection: RecipeSelection | None = None,
):
    return decide_recipe_risk(
        authorization=authorization or _authorization(recipe_id),
        selection=selection or _selection(recipe_id),
        scope_rule=_scope(recipe_id),
        evaluated_at=NOW,
    )


def test_r0_is_eligible_without_an_execution_capable_network_profile():
    recipe_id = "passive_rule_snapshot_analysis"
    decision = _decide(
        recipe_id,
        authorization=_authorization(
            recipe_id,
            max_risk="R0",
            policy_mode="passive_only",
            network_profile="none",
        ),
    )

    assert decision.status == "authorized"
    assert decision.risk_tier == "R0"
    assert decision.eligible_for_plan is True
    assert decision.execution_authorized is False


def test_r0_still_composes_the_existing_scope_guard():
    recipe_id = "passive_rule_snapshot_analysis"
    rule = ScopeGuardRule(
        asset="asset_api",
        scope_status="in_scope",
        automation="none",
        allowed_validation=[],
        forbidden=[],
        human_approval_required=False,
    )
    decision = decide_recipe_risk(
        authorization=_authorization(
            recipe_id,
            max_risk="R0",
            policy_mode="passive_only",
            network_profile="none",
        ),
        selection=_selection(recipe_id),
        scope_rule=rule,
        evaluated_at=NOW,
    )

    assert decision.status == "denied"
    assert decision.reason == "automation_not_allowed"


def test_r2_requires_exact_recipe_target_method_accounts_and_budget():
    recipe_id = "lab_two_account_authorization_differential"
    valid = _selection(recipe_id, accounts=("owned_alpha", "owned_beta"))

    assert _decide(recipe_id, selection=valid).status == "authorized"

    cases = [
        (
            _selection(
                recipe_id,
                accounts=("owned_alpha", "owned_beta"),
                target_asset_id="other_asset",
            ),
            "target_not_authorized",
        ),
        (
            _selection(
                recipe_id,
                accounts=("owned_alpha", "owned_beta"),
                method_class="reversible_owned_account",
            ),
            "method_class_not_authorized",
        ),
        (
            _selection(
                recipe_id,
                accounts=("owned_alpha", "unapproved_alias"),
            ),
            "account_alias_not_authorized",
        ),
        (
            _selection(
                recipe_id,
                accounts=("owned_alpha", "owned_beta"),
                requested_budgets=_budget(max_requests=25),
            ),
            "recipe_budget_exceeded",
        ),
    ]
    for selection, reason in cases:
        decision = _decide(recipe_id, selection=selection)
        assert decision.status == "denied"
        assert decision.reason == reason


def test_recipe_must_be_bound_to_the_campaign_authorization():
    selected = "lab_two_account_authorization_differential"
    authorization = _authorization("lab_browser_mapping")
    decision = decide_recipe_risk(
        authorization=authorization,
        selection=_selection(
            selected, accounts=("owned_alpha", "owned_beta")
        ),
        scope_rule=_scope(selected),
        evaluated_at=NOW,
    )

    assert decision.status == "denied"
    assert decision.reason == "recipe_not_authorized"


@pytest.mark.parametrize(
    ("recipe_id", "accounts"),
    [
        ("lab_browser_mapping", ()),
        (
            "lab_two_account_authorization_differential",
            ("owned_alpha", "owned_beta"),
        ),
    ],
)
def test_r1_and_r2_are_blocked_outside_authorized_local_lab(
    recipe_id: str, accounts: tuple[str, ...]
):
    decision = _decide(
        recipe_id,
        authorization=_authorization(
            recipe_id,
            policy_mode="passive_only",
            network_profile="none",
        ),
        selection=_selection(recipe_id, accounts=accounts),
    )

    assert decision.status == "policy_mode_blocks_active_execution"
    assert decision.eligible_for_plan is False


def test_effective_active_risk_from_a_passive_recipe_is_still_lab_gated():
    recipe_id = "passive_rule_snapshot_analysis"
    decision = _decide(
        recipe_id,
        authorization=_authorization(
            recipe_id,
            max_risk="R2",
            policy_mode="passive_only",
            network_profile="none",
        ),
        selection=_selection(
            recipe_id,
            action_categories=("owned_account_read",),
        ),
    )

    assert decision.status == "policy_mode_blocks_active_execution"
    assert decision.risk_tier == "R2"


def test_effective_active_risk_cannot_expand_a_passive_recipe():
    recipe_id = "passive_rule_snapshot_analysis"
    decision = _decide(
        recipe_id,
        authorization=_authorization(
            recipe_id,
            max_risk="R2",
            policy_mode="authorized_local_lab",
            network_profile="authorized_local_lab",
        ),
        selection=_selection(
            recipe_id,
            action_categories=("owned_account_read",),
        ),
    )

    assert decision.status == "denied"
    assert decision.reason == "active_risk_requires_active_recipe"


def test_action_category_cannot_expand_an_active_recipe_capability():
    recipe_id = "lab_browser_mapping"
    decision = _decide(
        recipe_id,
        selection=_selection(
            recipe_id,
            action_categories=("two_owned_account_differential",),
        ),
    )

    assert decision.status == "denied"
    assert decision.reason == "action_category_not_supported_by_recipe"


def test_r3_always_waits_for_exact_approval():
    recipe_id = "lab_browser_mapping"
    decision = _decide(
        recipe_id,
        selection=_selection(recipe_id, client_risk_hint="R3"),
    )

    assert decision.status == "awaiting_exact_approval"
    assert decision.risk_tier == "R3"
    assert decision.eligible_for_plan is False
    assert decision.exact_approval_required is True
    assert decision.execution_authorized is False


def test_r3_waits_for_exact_approval_even_outside_the_active_lab_mode():
    recipe_id = "lab_browser_mapping"
    decision = _decide(
        recipe_id,
        authorization=_authorization(
            recipe_id,
            policy_mode="passive_only",
            network_profile="none",
        ),
        selection=_selection(recipe_id, client_risk_hint="R3"),
    )

    assert decision.status == "awaiting_exact_approval"
    assert decision.risk_tier == "R3"
    assert decision.execution_authorized is False


@pytest.mark.parametrize(
    "category",
    [
        "dos_resource_exhaustion",
        "credential_attack",
        "social_engineering",
        "destructive_irreversible_transaction",
        "persistence_malware",
        "scope_or_gate_bypass",
        "intentional_third_party_data_collection",
        "raw_secret_retention",
        "automatic_report_submission",
    ],
)
def test_r4_categories_are_prohibited_without_an_approval_transition(
    category: str,
):
    recipe_id = "lab_browser_mapping"
    decision = _decide(
        recipe_id,
        selection=_selection(recipe_id, action_categories=(category,)),
    )

    assert decision.status == "prohibited"
    assert decision.risk_tier == "R4"
    assert decision.eligible_for_plan is False
    assert decision.exact_approval_allowed is False
    assert decision.execution_authorized is False


def test_r4_cannot_be_represented_as_an_authorized_decision():
    with pytest.raises(ValidationError):
        TypeAdapter(RiskDecision).validate_python(
            {
                "status": "authorized",
                "risk_tier": "R4",
                "reason": "invalid",
                "eligible_for_plan": True,
                "execution_authorized": False,
                "exact_approval_required": False,
            }
        )


@pytest.mark.parametrize(
    "hint_field", ["client_risk_hint", "model_risk_hint", "tool_risk_hint"]
)
def test_untrusted_hints_cannot_lower_recipe_risk(hint_field: str):
    recipe_id = "lab_two_account_authorization_differential"
    decision = _decide(
        recipe_id,
        selection=_selection(
            recipe_id,
            accounts=("owned_alpha", "owned_beta"),
            **{hint_field: "R0"},
        ),
    )

    assert decision.status == "authorized"
    assert decision.risk_tier == "R2"


def test_scope_guard_denial_and_campaign_risk_ceiling_fail_closed():
    recipe_id = "lab_two_account_authorization_differential"
    selection = _selection(
        recipe_id, accounts=("owned_alpha", "owned_beta")
    )
    scope_denied = decide_recipe_risk(
        authorization=_authorization(recipe_id),
        selection=selection,
        scope_rule=_scope(recipe_id, asset="other_asset"),
        evaluated_at=NOW,
    )
    ceiling_denied = _decide(
        recipe_id,
        authorization=_authorization(recipe_id, max_risk="R1"),
        selection=selection,
    )

    assert scope_denied.status == "denied"
    assert scope_denied.reason == "out_of_scope"
    assert ceiling_denied.status == "denied"
    assert ceiling_denied.reason == "risk_ceiling_exceeded"
