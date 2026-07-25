"""Deterministic, monotonic risk classification for Bounty Autopilot."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.bounty_autopilot.contracts import (
    CampaignAuthorization,
    PolicyMode,
    RecipeRef,
    RiskDecision,
    RiskDecisionStatus,
    RiskTier,
    VersionedRecipe,
)
from app.bounty_autopilot.recipes import get_recipe, resolve_recipe_ref


_RISK_ORDER = {
    RiskTier.R0: 0,
    RiskTier.R1: 1,
    RiskTier.R2: 2,
    RiskTier.R3: 3,
    RiskTier.R4: 4,
}

_R4_CATEGORIES = {
    "dos",
    "resource_exhaustion",
    "credential_stuffing",
    "password_spraying",
    "account_takeover",
    "social_engineering",
    "destructive_transaction",
    "irreversible_transaction",
    "malware",
    "persistence",
    "scope_bypass",
    "gate_bypass",
    "third_party_data_collection",
    "raw_secret_retention",
    "automatic_report_submission",
}


def _raise_tier(current: RiskTier, candidate: RiskTier) -> RiskTier:
    if _RISK_ORDER[candidate] > _RISK_ORDER[current]:
        return candidate
    return current


def classify_risk(
    *,
    recipe: VersionedRecipe | None,
    action_categories: set[str] | frozenset[str] | None = None,
    client_risk_hint: RiskTier | str | None = None,
    model_risk_hint: RiskTier | str | None = None,
    tool_metadata_risk_hint: RiskTier | str | None = None,
) -> RiskTier:
    """Classify risk monotonically. Client/model/tool hints may only raise."""

    tier = recipe.risk_tier if recipe is not None else RiskTier.R0
    categories = {item.lower() for item in (action_categories or set())}
    if categories & _R4_CATEGORIES:
        tier = RiskTier.R4

    for hint in (client_risk_hint, model_risk_hint, tool_metadata_risk_hint):
        if hint is None:
            continue
        if isinstance(hint, RiskTier):
            tier = _raise_tier(tier, hint)
            continue
        try:
            hinted = RiskTier(str(hint))
        except ValueError:
            # Unknown hints fail closed by raising to R3 for human review.
            tier = _raise_tier(tier, RiskTier.R3)
            continue
        tier = _raise_tier(tier, hinted)
    return tier


def evaluate_action_risk(
    *,
    authorization: CampaignAuthorization,
    recipe_ref: RecipeRef,
    asset_id: str,
    account_aliases: tuple[str, ...] = (),
    method_class: str,
    action_categories: set[str] | frozenset[str] | None = None,
    client_risk_hint: RiskTier | str | None = None,
    model_risk_hint: RiskTier | str | None = None,
    tool_metadata_risk_hint: RiskTier | str | None = None,
    now: datetime | None = None,
    recipe_definition: dict[str, Any] | VersionedRecipe | None = None,
) -> RiskDecision:
    """Fail-closed risk decision for one planned action."""

    if recipe_definition is not None:
        return RiskDecision(
            status=RiskDecisionStatus.REJECTED,
            risk_tier=RiskTier.R3,
            reason="runtime_recipe_definition_rejected",
            recipe_ref=recipe_ref,
            policy_mode=authorization.policy_mode,
            requires_exact_approval=False,
            allowed_to_execute=False,
        )

    recipe = get_recipe(recipe_ref.recipe_id, recipe_ref.version)
    if recipe is None:
        return RiskDecision(
            status=RiskDecisionStatus.REJECTED,
            risk_tier=RiskTier.R3,
            reason="unknown_recipe_ref",
            recipe_ref=recipe_ref,
            policy_mode=authorization.policy_mode,
            requires_exact_approval=False,
            allowed_to_execute=False,
        )

    if not authorization.permits_recipe(recipe_ref):
        return RiskDecision(
            status=RiskDecisionStatus.REJECTED,
            risk_tier=recipe.risk_tier,
            reason="recipe_not_authorized",
            recipe_ref=recipe_ref,
            policy_mode=authorization.policy_mode,
            requires_exact_approval=False,
            allowed_to_execute=False,
        )

    if asset_id not in authorization.asset_ids:
        return RiskDecision(
            status=RiskDecisionStatus.REJECTED,
            risk_tier=recipe.risk_tier,
            reason="asset_not_authorized",
            recipe_ref=recipe_ref,
            policy_mode=authorization.policy_mode,
            requires_exact_approval=False,
            allowed_to_execute=False,
        )

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    expires_at = authorization.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if current >= expires_at:
        return RiskDecision(
            status=RiskDecisionStatus.REJECTED,
            risk_tier=recipe.risk_tier,
            reason="authorization_expired",
            recipe_ref=recipe_ref,
            policy_mode=authorization.policy_mode,
            requires_exact_approval=False,
            allowed_to_execute=False,
        )

    if method_class not in recipe.allowed_method_classes:
        return RiskDecision(
            status=RiskDecisionStatus.REJECTED,
            risk_tier=recipe.risk_tier,
            reason="method_class_not_permitted",
            recipe_ref=recipe_ref,
            policy_mode=authorization.policy_mode,
            requires_exact_approval=False,
            allowed_to_execute=False,
        )

    required_aliases = set(recipe.required_account_aliases)
    provided_aliases = set(account_aliases)
    if required_aliases and not required_aliases.issubset(provided_aliases):
        return RiskDecision(
            status=RiskDecisionStatus.REJECTED,
            risk_tier=recipe.risk_tier,
            reason="required_account_aliases_missing",
            recipe_ref=recipe_ref,
            policy_mode=authorization.policy_mode,
            requires_exact_approval=False,
            allowed_to_execute=False,
        )
    if provided_aliases and not provided_aliases.issubset(set(authorization.account_aliases)):
        return RiskDecision(
            status=RiskDecisionStatus.REJECTED,
            risk_tier=recipe.risk_tier,
            reason="account_alias_not_authorized",
            recipe_ref=recipe_ref,
            policy_mode=authorization.policy_mode,
            requires_exact_approval=False,
            allowed_to_execute=False,
        )

    classified = classify_risk(
        recipe=recipe,
        action_categories=action_categories,
        client_risk_hint=client_risk_hint,
        model_risk_hint=model_risk_hint,
        tool_metadata_risk_hint=tool_metadata_risk_hint,
    )

    # Monotonic: never below recipe tier; never below classified tier.
    effective = _raise_tier(recipe.risk_tier, classified)

    if effective is RiskTier.R4:
        return RiskDecision(
            status=RiskDecisionStatus.PROHIBITED,
            risk_tier=RiskTier.R4,
            reason="prohibited",
            recipe_ref=recipe_ref,
            policy_mode=authorization.policy_mode,
            requires_exact_approval=False,
            allowed_to_execute=False,
        )

    if _RISK_ORDER[effective] > _RISK_ORDER[authorization.risk_ceiling]:
        return RiskDecision(
            status=RiskDecisionStatus.REJECTED,
            risk_tier=effective,
            reason="risk_ceiling_exceeded",
            recipe_ref=recipe_ref,
            policy_mode=authorization.policy_mode,
            requires_exact_approval=effective is RiskTier.R3,
            allowed_to_execute=False,
        )

    if effective is RiskTier.R3:
        return RiskDecision(
            status=RiskDecisionStatus.AWAITING_EXACT_APPROVAL,
            risk_tier=RiskTier.R3,
            reason="awaiting_exact_approval",
            recipe_ref=recipe_ref,
            policy_mode=authorization.policy_mode,
            requires_exact_approval=True,
            allowed_to_execute=False,
        )

    if effective in {RiskTier.R1, RiskTier.R2}:
        if authorization.policy_mode is not PolicyMode.AUTHORIZED_LOCAL_LAB:
            return RiskDecision(
                status=RiskDecisionStatus.POLICY_MODE_BLOCKS_ACTIVE_EXECUTION,
                risk_tier=effective,
                reason="policy_mode_blocks_active_execution",
                recipe_ref=recipe_ref,
                policy_mode=authorization.policy_mode,
                requires_exact_approval=False,
                allowed_to_execute=False,
            )
        if PolicyMode.AUTHORIZED_LOCAL_LAB not in recipe.policy_modes:
            return RiskDecision(
                status=RiskDecisionStatus.POLICY_MODE_BLOCKS_ACTIVE_EXECUTION,
                risk_tier=effective,
                reason="policy_mode_blocks_active_execution",
                recipe_ref=recipe_ref,
                policy_mode=authorization.policy_mode,
                requires_exact_approval=False,
                allowed_to_execute=False,
            )
        if recipe.network_profile not in {"lab_loopback", "scope_enforced"}:
            return RiskDecision(
                status=RiskDecisionStatus.REJECTED,
                risk_tier=effective,
                reason="active_recipe_network_profile_invalid",
                recipe_ref=recipe_ref,
                policy_mode=authorization.policy_mode,
                requires_exact_approval=False,
                allowed_to_execute=False,
            )

    if effective is RiskTier.R0 and recipe.network_profile != "none":
        return RiskDecision(
            status=RiskDecisionStatus.REJECTED,
            risk_tier=effective,
            reason="r0_network_profile_invalid",
            recipe_ref=recipe_ref,
            policy_mode=authorization.policy_mode,
            requires_exact_approval=False,
            allowed_to_execute=False,
        )

    return RiskDecision(
        status=RiskDecisionStatus.ALLOWED,
        risk_tier=effective,
        reason="allowed",
        recipe_ref=recipe_ref,
        policy_mode=authorization.policy_mode,
        requires_exact_approval=False,
        allowed_to_execute=True,
    )


def decide_execution_risk(
    *,
    authorization: CampaignAuthorization,
    recipe_ref: RecipeRef,
    asset_id: str,
    account_aliases: tuple[str, ...] = (),
    method_class: str,
    action_categories: set[str] | frozenset[str] | None = None,
    client_risk_hint: RiskTier | str | None = None,
    model_risk_hint: RiskTier | str | None = None,
    tool_metadata_risk_hint: RiskTier | str | None = None,
    now: datetime | None = None,
    recipe_definition: dict[str, Any] | VersionedRecipe | None = None,
) -> RiskDecision:
    """Alias used by callers that expect a gateway-style decide API."""

    return evaluate_action_risk(
        authorization=authorization,
        recipe_ref=recipe_ref,
        asset_id=asset_id,
        account_aliases=account_aliases,
        method_class=method_class,
        action_categories=action_categories,
        client_risk_hint=client_risk_hint,
        model_risk_hint=model_risk_hint,
        tool_metadata_risk_hint=tool_metadata_risk_hint,
        now=now,
        recipe_definition=recipe_definition,
    )


# Keep resolve import reachable for type checkers / tests.
_ = resolve_recipe_ref


__all__ = [
    "classify_risk",
    "decide_execution_risk",
    "evaluate_action_risk",
]
