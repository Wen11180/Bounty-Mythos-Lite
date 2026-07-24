"""Deterministic, monotonic risk decisions for registered Autopilot recipes."""

from __future__ import annotations

from datetime import datetime, timezone

from app.bounty_autopilot.contracts import (
    ActionCategory,
    AuthorizedRiskDecision,
    AwaitingExactApprovalRiskDecision,
    AutopilotBudgets,
    CampaignAuthorization,
    DeniedRiskDecision,
    PolicyBlockedRiskDecision,
    ProhibitedRiskDecision,
    RecipeRef,
    RecipeSelection,
    RiskDecision,
    RiskTier,
    VersionedRecipe,
)
from app.bounty_autopilot.recipes import default_recipe_registry
from app.scope_guard import (
    ScopeGuardRule,
    ValidationRequest,
    evaluate_validation_request,
)


_RISK_RANK: dict[RiskTier, int] = {
    "R0": 0,
    "R1": 1,
    "R2": 2,
    "R3": 3,
    "R4": 4,
}
_CATEGORY_RISK: dict[ActionCategory, RiskTier] = {
    "passive_analysis": "R0",
    "browser_mapping": "R1",
    "owned_account_read": "R2",
    "two_owned_account_differential": "R2",
    "novel_active": "R3",
    "reversible_owned_account_write": "R3",
    "dos_resource_exhaustion": "R4",
    "credential_attack": "R4",
    "social_engineering": "R4",
    "destructive_irreversible_transaction": "R4",
    "persistence_malware": "R4",
    "scope_or_gate_bypass": "R4",
    "intentional_third_party_data_collection": "R4",
    "raw_secret_retention": "R4",
    "automatic_report_submission": "R4",
}
_BUDGET_FIELDS = (
    "max_requests",
    "max_concurrency",
    "max_response_bytes",
    "max_duration_seconds",
    "max_account_operations",
    "max_cost_microusd",
)


def decide_recipe_risk(
    *,
    authorization: CampaignAuthorization,
    selection: RecipeSelection,
    scope_rule: ScopeGuardRule,
    evaluated_at: datetime | None = None,
) -> RiskDecision:
    """Return planning eligibility; this phase never grants execution."""
    recipe = default_recipe_registry().get(
        selection.recipe_id, selection.version
    )
    risk_tier = _effective_risk(recipe, selection)

    if risk_tier == "R4":
        return ProhibitedRiskDecision(
            reason=_prohibited_reason(recipe, selection),
            recipe_ref=recipe.ref if recipe is not None else None,
        )
    if recipe is None:
        return _denied(risk_tier, "unknown_recipe")

    recipe_ref = recipe.ref
    if recipe_ref not in authorization.recipe_refs:
        return _denied(risk_tier, "recipe_not_authorized", recipe_ref)

    authority_reason = _authority_denial_reason(
        authorization,
        recipe,
        selection,
        scope_rule,
        evaluated_at or datetime.now(timezone.utc),
    )
    if authority_reason is not None:
        return _denied(risk_tier, authority_reason, recipe_ref)

    if risk_tier == "R3":
        return AwaitingExactApprovalRiskDecision(recipe_ref=recipe_ref)

    if risk_tier in {"R1", "R2"} and (
        authorization.policy_mode != "authorized_local_lab"
        or authorization.network_profile != "authorized_local_lab"
    ):
        return PolicyBlockedRiskDecision(
            risk_tier=risk_tier,
            recipe_ref=recipe_ref,
        )
    if risk_tier in {"R1", "R2"} and (
        not recipe.mutation_inventory.network_access
        or recipe.policy_modes != ("authorized_local_lab",)
        or recipe.network_profile != "authorized_local_lab"
    ):
        return _denied(
            risk_tier, "active_risk_requires_active_recipe", recipe_ref
        )
    if _has_unsupported_action_category(recipe, selection):
        return _denied(
            risk_tier,
            "action_category_not_supported_by_recipe",
            recipe_ref,
        )

    if _RISK_RANK[risk_tier] > _RISK_RANK[
        authorization.max_automatic_risk
    ]:
        return _denied(risk_tier, "risk_ceiling_exceeded", recipe_ref)

    return AuthorizedRiskDecision(
        risk_tier=risk_tier,
        reason="eligible_for_plan",
        recipe_ref=recipe_ref,
    )


def _effective_risk(
    recipe: VersionedRecipe | None, selection: RecipeSelection
) -> RiskTier:
    tiers: list[RiskTier] = [recipe.risk_floor if recipe is not None else "R3"]
    if recipe is not None:
        inventory = recipe.mutation_inventory
        if inventory.prohibited_categories:
            tiers.append("R4")
        if inventory.state_change:
            tiers.append("R3")
        elif inventory.two_owned_account_differential:
            tiers.append("R2")
        elif inventory.network_access:
            tiers.append("R1")
    tiers.extend(_CATEGORY_RISK[category] for category in selection.action_categories)
    tiers.extend(
        hint
        for hint in (
            selection.client_risk_hint,
            selection.model_risk_hint,
            selection.tool_risk_hint,
        )
        if hint is not None
    )
    return max(tiers, key=_RISK_RANK.__getitem__)


def _prohibited_reason(
    recipe: VersionedRecipe | None, selection: RecipeSelection
) -> str:
    prohibited = sorted(
        category
        for category in selection.action_categories
        if _CATEGORY_RISK[category] == "R4"
    )
    if prohibited:
        return f"prohibited_category:{prohibited[0]}"
    if (
        recipe is not None
        and recipe.mutation_inventory.prohibited_categories
    ):
        return (
            "prohibited_category:"
            f"{recipe.mutation_inventory.prohibited_categories[0]}"
        )
    return "risk_tier_r4_prohibited"


def _authority_denial_reason(
    authorization: CampaignAuthorization,
    recipe: VersionedRecipe,
    selection: RecipeSelection,
    scope_rule: ScopeGuardRule,
    evaluated_at: datetime,
) -> str | None:
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        return "timezone_aware_evaluation_required"
    now = evaluated_at.astimezone(timezone.utc)
    if now < authorization.issued_at:
        return "authorization_not_yet_active"
    if now >= authorization.expires_at:
        return "authorization_expired"
    if not _inside_active_hours(authorization, now):
        return "outside_active_hours"

    if selection.target_asset_id not in authorization.asset_ids:
        return "target_not_authorized"
    if selection.method_class not in authorization.allowed_method_classes:
        return "method_class_not_authorized"
    if selection.method_class not in recipe.method_classes:
        return "recipe_method_class_not_allowed"
    if any(
        alias not in authorization.account_aliases
        for alias in selection.account_aliases
    ):
        return "account_alias_not_authorized"
    if len(selection.account_aliases) != recipe.required_account_aliases:
        return "recipe_account_alias_count_mismatch"
    if _exceeds(selection.requested_budgets, recipe.max_budgets):
        return "recipe_budget_exceeded"
    if _exceeds(selection.requested_budgets, authorization.budgets):
        return "campaign_budget_exceeded"

    if (
        scope_rule.asset != selection.target_asset_id
        or scope_rule.scope_status != "in_scope"
    ):
        return "out_of_scope"
    if recipe.validation_type in scope_rule.forbidden:
        return "forbidden_validation"
    scope_decision = evaluate_validation_request(
        scope_rule,
        ValidationRequest(
            asset=selection.target_asset_id,
            validation_type=recipe.validation_type,
            human_approved=True,
        ),
    )
    if not scope_decision.allowed:
        return scope_decision.reason
    return None


def _inside_active_hours(
    authorization: CampaignAuthorization, evaluated_at: datetime
) -> bool:
    minute = evaluated_at.hour * 60 + evaluated_at.minute
    return any(
        evaluated_at.weekday() in window.days_utc
        and window.start_minute_utc <= minute < window.end_minute_utc
        for window in authorization.active_hours_utc
    )


def _has_unsupported_action_category(
    recipe: VersionedRecipe, selection: RecipeSelection
) -> bool:
    inventory = recipe.mutation_inventory
    for category in selection.action_categories:
        if category == "browser_mapping" and not inventory.browser_automation:
            return True
        if category == "owned_account_read" and not inventory.reads_owned_account_data:
            return True
        if (
            category == "two_owned_account_differential"
            and not inventory.two_owned_account_differential
        ):
            return True
        if category == "reversible_owned_account_write" and not (
            inventory.state_change and inventory.reversible
        ):
            return True
    return False


def _exceeds(requested: AutopilotBudgets, allowed: AutopilotBudgets) -> bool:
    return any(
        getattr(requested, field) > getattr(allowed, field)
        for field in _BUDGET_FIELDS
    )


def _denied(
    risk_tier: RiskTier,
    reason: str,
    recipe_ref: RecipeRef | None = None,
) -> DeniedRiskDecision:
    return DeniedRiskDecision(
        risk_tier=risk_tier,
        reason=reason,
        recipe_ref=recipe_ref,
    )


__all__ = ["decide_recipe_risk"]
