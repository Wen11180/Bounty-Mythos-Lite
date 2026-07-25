"""Code-owned Bounty Autopilot recipe registry.

Runtime selection accepts only recipe ID/version pairs registered here.
Model- or task-payload recipe definitions are rejected by the decision layer.
"""

from __future__ import annotations

from app.bounty_autopilot.contracts import (
    MutationInventory,
    PolicyMode,
    RecipeRef,
    RiskTier,
    VersionedRecipe,
)


def _passive_methods() -> tuple[str, ...]:
    return ("GET", "HEAD", "OPTIONS")


_RECIPES: tuple[VersionedRecipe, ...] = (
    VersionedRecipe(
        recipe_id="passive_rule_snapshot_analysis",
        version="1.0",
        risk_tier=RiskTier.R0,
        policy_modes=(PolicyMode.AUTHORIZED_LOCAL_LAB, PolicyMode.RESEARCH_PASSIVE_ONLY),
        network_profile="none",
        mutation_inventory=MutationInventory(
            methods=("GET",),
            mutates_state=False,
            reversible=True,
            requires_owned_accounts=False,
        ),
        required_account_aliases=(),
        allowed_method_classes=("local_document_analysis",),
        description="Passive analysis of approved program rules and scope snapshots.",
    ),
    VersionedRecipe(
        recipe_id="passive_artifact_served_resource_analysis",
        version="1.0",
        risk_tier=RiskTier.R0,
        policy_modes=(PolicyMode.AUTHORIZED_LOCAL_LAB, PolicyMode.RESEARCH_PASSIVE_ONLY),
        network_profile="none",
        mutation_inventory=MutationInventory(
            methods=("GET",),
            mutates_state=False,
            reversible=True,
            requires_owned_accounts=False,
        ),
        required_account_aliases=(),
        allowed_method_classes=("local_artifact_analysis",),
        description="Passive analysis of authorized artifacts and served-resource maps.",
    ),
    VersionedRecipe(
        recipe_id="lab_browser_mapping",
        version="1.0",
        risk_tier=RiskTier.R1,
        policy_modes=(PolicyMode.AUTHORIZED_LOCAL_LAB,),
        network_profile="lab_loopback",
        mutation_inventory=MutationInventory(
            methods=_passive_methods(),
            mutates_state=False,
            reversible=True,
            requires_owned_accounts=False,
        ),
        required_account_aliases=(),
        allowed_method_classes=("read_only_browser_map",),
        description="Lab-only browser mapping over admitted loopback assets.",
    ),
    VersionedRecipe(
        recipe_id="lab_two_owned_account_readonly_authz",
        version="1.0",
        risk_tier=RiskTier.R2,
        policy_modes=(PolicyMode.AUTHORIZED_LOCAL_LAB,),
        network_profile="lab_loopback",
        mutation_inventory=MutationInventory(
            methods=_passive_methods(),
            mutates_state=False,
            reversible=True,
            requires_owned_accounts=True,
        ),
        required_account_aliases=("account_a", "account_b"),
        allowed_method_classes=("read_only_authorization_differential",),
        description="Lab two-owned-account read-only authorization differential.",
    ),
)


RECIPE_REGISTRY: dict[tuple[str, str], VersionedRecipe] = {
    (recipe.recipe_id, recipe.version): recipe for recipe in _RECIPES
}


def list_recipes() -> list[VersionedRecipe]:
    return [
        RECIPE_REGISTRY[key]
        for key in sorted(RECIPE_REGISTRY, key=lambda item: (item[0], item[1]))
    ]


def get_recipe(recipe_id: str, version: str) -> VersionedRecipe | None:
    return RECIPE_REGISTRY.get((recipe_id, version))


def resolve_recipe_ref(recipe_ref: RecipeRef) -> VersionedRecipe:
    recipe = get_recipe(recipe_ref.recipe_id, recipe_ref.version)
    if recipe is None:
        raise ValueError("unknown_recipe_ref")
    return recipe


__all__ = [
    "RECIPE_REGISTRY",
    "get_recipe",
    "list_recipes",
    "resolve_recipe_ref",
]
