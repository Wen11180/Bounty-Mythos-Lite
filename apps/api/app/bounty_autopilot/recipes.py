"""Code-owned, exact-version recipe registry for bounty Autopilot."""

from __future__ import annotations

from collections.abc import Iterable
from types import MappingProxyType

from app.bounty_autopilot.contracts import (
    AutopilotBudgets,
    MutationInventory,
    VersionedRecipe,
)


class RecipeRegistry:
    def __init__(self, recipes: Iterable[VersionedRecipe]) -> None:
        by_key: dict[tuple[str, str], VersionedRecipe] = {}
        for recipe in recipes:
            key = (recipe.recipe_id, recipe.version)
            if key in by_key:
                raise ValueError(
                    f"duplicate_recipe:{recipe.recipe_id}@{recipe.version}"
                )
            by_key[key] = recipe
        self._by_key = MappingProxyType(by_key)

    def get(self, recipe_id: str, version: str) -> VersionedRecipe | None:
        return self._by_key.get((recipe_id, version))

    def require(self, recipe_id: str, version: str) -> VersionedRecipe:
        recipe = self.get(recipe_id, version)
        if recipe is None:
            raise KeyError(f"unknown_recipe:{recipe_id}@{version}")
        return recipe

    def list_recipes(self) -> list[VersionedRecipe]:
        return [self._by_key[key] for key in sorted(self._by_key)]


_PASSIVE_INVENTORY = MutationInventory(
    network_access=False,
    browser_automation=False,
    reads_owned_account_data=False,
    two_owned_account_differential=False,
    state_change=False,
    reversible=False,
    external_side_effect=False,
)

_DEFAULT_RECIPES = (
    VersionedRecipe(
        recipe_id="passive_rule_snapshot_analysis",
        version="1.0.0",
        title="Passive rule and snapshot analysis",
        validation_type="passive_rule_snapshot_analysis",
        risk_floor="R0",
        policy_modes=("authorized_local_lab", "passive_only"),
        network_profile="none",
        method_classes=("passive",),
        required_account_aliases=0,
        max_budgets=AutopilotBudgets(
            max_requests=1,
            max_concurrency=1,
            max_response_bytes=262_144,
            max_duration_seconds=120,
            max_account_operations=1,
            max_cost_microusd=500_000,
        ),
        mutation_inventory=_PASSIVE_INVENTORY,
    ),
    VersionedRecipe(
        recipe_id="passive_artifact_analysis",
        version="1.0.0",
        title="Passive artifact and served-resource analysis",
        validation_type="passive_artifact_analysis",
        risk_floor="R0",
        policy_modes=("authorized_local_lab", "passive_only"),
        network_profile="none",
        method_classes=("passive",),
        required_account_aliases=0,
        max_budgets=AutopilotBudgets(
            max_requests=1,
            max_concurrency=1,
            max_response_bytes=524_288,
            max_duration_seconds=120,
            max_account_operations=1,
            max_cost_microusd=500_000,
        ),
        mutation_inventory=_PASSIVE_INVENTORY,
    ),
    VersionedRecipe(
        recipe_id="lab_browser_mapping",
        version="1.0.0",
        title="Authorized local-lab browser mapping",
        validation_type="lab_browser_mapping",
        risk_floor="R1",
        policy_modes=("authorized_local_lab",),
        network_profile="authorized_local_lab",
        method_classes=("read_only",),
        required_account_aliases=0,
        max_budgets=AutopilotBudgets(
            max_requests=10,
            max_concurrency=1,
            max_response_bytes=262_144,
            max_duration_seconds=120,
            max_account_operations=1,
            max_cost_microusd=500_000,
        ),
        mutation_inventory=MutationInventory(
            network_access=True,
            browser_automation=True,
            reads_owned_account_data=False,
            two_owned_account_differential=False,
            state_change=False,
            reversible=False,
            external_side_effect=False,
        ),
    ),
    VersionedRecipe(
        recipe_id="lab_two_account_authorization_differential",
        version="1.0.0",
        title="Authorized local-lab two-owned-account differential",
        validation_type="lab_two_account_authorization_differential",
        risk_floor="R2",
        policy_modes=("authorized_local_lab",),
        network_profile="authorized_local_lab",
        method_classes=("read_only",),
        required_account_aliases=2,
        max_budgets=AutopilotBudgets(
            max_requests=2,
            max_concurrency=1,
            max_response_bytes=131_072,
            max_duration_seconds=120,
            max_account_operations=2,
            max_cost_microusd=500_000,
        ),
        mutation_inventory=MutationInventory(
            network_access=True,
            browser_automation=True,
            reads_owned_account_data=True,
            two_owned_account_differential=True,
            state_change=False,
            reversible=False,
            external_side_effect=False,
        ),
    ),
)

_DEFAULT_RECIPE_REGISTRY = RecipeRegistry(_DEFAULT_RECIPES)


def default_recipe_registry() -> RecipeRegistry:
    return _DEFAULT_RECIPE_REGISTRY


def get_recipe(recipe_id: str, version: str) -> VersionedRecipe | None:
    """Resolve only an exact, code-owned recipe version."""

    return _DEFAULT_RECIPE_REGISTRY.get(recipe_id, version)


__all__ = ["RecipeRegistry", "default_recipe_registry", "get_recipe"]
