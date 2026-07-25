"""Phase 1 recipe registry tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.bounty_autopilot.contracts import (
    MutationInventory,
    PolicyMode,
    RecipeRef,
    RiskTier,
    VersionedRecipe,
)
from app.bounty_autopilot.recipes import (
    RECIPE_REGISTRY,
    get_recipe,
    list_recipes,
    resolve_recipe_ref,
)


def test_registry_contains_required_initial_recipes():
    ids = {(recipe.recipe_id, recipe.version) for recipe in list_recipes()}
    assert ("passive_rule_snapshot_analysis", "1.0") in ids
    assert ("passive_artifact_served_resource_analysis", "1.0") in ids
    assert ("lab_browser_mapping", "1.0") in ids
    assert ("lab_two_owned_account_readonly_authz", "1.0") in ids


def test_unknown_recipe_id_and_version_fail_closed():
    assert get_recipe("not_a_recipe", "1.0") is None
    assert get_recipe("lab_browser_mapping", "9.9") is None
    with pytest.raises(ValueError, match="unknown_recipe_ref"):
        resolve_recipe_ref(RecipeRef(recipe_id="not_a_recipe", version="1.0"))


def test_active_recipes_are_lab_only():
    for recipe in list_recipes():
        if recipe.risk_tier in {RiskTier.R1, RiskTier.R2}:
            assert PolicyMode.AUTHORIZED_LOCAL_LAB in recipe.policy_modes
            assert recipe.network_profile in {"lab_loopback", "scope_enforced"}


def test_r0_recipes_have_no_network_profile():
    for recipe in list_recipes():
        if recipe.risk_tier is RiskTier.R0:
            assert recipe.network_profile == "none"


def test_two_account_recipe_requires_owned_aliases():
    recipe = get_recipe("lab_two_owned_account_readonly_authz", "1.0")
    assert recipe is not None
    assert recipe.required_account_aliases == ("account_a", "account_b")
    assert recipe.mutation_inventory.requires_owned_accounts is True
    assert recipe.mutation_inventory.third_party_data_allowed is False


def test_r4_recipe_is_unrepresentable():
    with pytest.raises(ValidationError):
        VersionedRecipe(
            recipe_id="evil_dos",
            version="1.0",
            risk_tier=RiskTier.R4,
            policy_modes=(PolicyMode.AUTHORIZED_LOCAL_LAB,),
            network_profile="lab_loopback",
            mutation_inventory=MutationInventory(
                methods=("GET",),
                mutates_state=False,
                reversible=True,
                requires_owned_accounts=False,
            ),
            allowed_method_classes=("x",),
            description="should fail",
        )


def test_active_recipe_without_lab_mode_is_rejected():
    with pytest.raises(ValidationError):
        VersionedRecipe(
            recipe_id="public_probe",
            version="1.0",
            risk_tier=RiskTier.R1,
            policy_modes=(PolicyMode.RESEARCH_PASSIVE_ONLY,),
            network_profile="lab_loopback",
            mutation_inventory=MutationInventory(
                methods=("GET",),
                mutates_state=False,
                reversible=True,
                requires_owned_accounts=False,
            ),
            allowed_method_classes=("read_only_browser_map",),
            description="should fail",
        )


def test_registry_has_no_duplicate_keys():
    assert len(RECIPE_REGISTRY) == len(list_recipes())
