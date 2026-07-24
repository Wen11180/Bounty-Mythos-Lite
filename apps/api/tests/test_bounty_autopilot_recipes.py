import pytest
from pydantic import ValidationError

from app.bounty_autopilot.contracts import (
    MutationInventory,
    RecipeSelection,
    VersionedRecipe,
)
from app.bounty_autopilot.recipes import default_recipe_registry


def test_registry_contains_only_the_initial_code_owned_recipes():
    recipes = default_recipe_registry().list_recipes()

    assert {(recipe.recipe_id, recipe.version) for recipe in recipes} == {
        ("passive_rule_snapshot_analysis", "1.0.0"),
        ("passive_artifact_analysis", "1.0.0"),
        ("lab_browser_mapping", "1.0.0"),
        ("lab_two_account_authorization_differential", "1.0.0"),
    }


@pytest.mark.parametrize(
    ("recipe_id", "version"),
    [
        ("missing_recipe", "1.0.0"),
        ("lab_browser_mapping", "2.0.0"),
    ],
)
def test_registry_requires_an_exact_known_id_and_version(
    recipe_id: str, version: str
):
    with pytest.raises(KeyError):
        default_recipe_registry().require(recipe_id, version)


def test_runtime_selection_rejects_a_caller_supplied_recipe_definition():
    with pytest.raises(ValidationError):
        RecipeSelection(
            recipe_id="lab_browser_mapping",
            version="1.0.0",
            target_asset_id="asset_web",
            method_class="read_only",
            account_aliases=(),
            requested_budgets={
                "max_requests": 2,
                "max_concurrency": 1,
                "max_response_bytes": 65_536,
                "max_duration_seconds": 60,
                "max_account_operations": 1,
                "max_cost_microusd": 100_000,
            },
            recipe_definition={"command": "arbitrary shell"},
        )


def test_recipe_definition_digest_is_stable_and_bound_into_its_ref():
    registry = default_recipe_registry()
    recipe = registry.require("lab_browser_mapping", "1.0.0")

    assert recipe.definition_digest.startswith("sha256:")
    assert recipe.ref.definition_digest == recipe.definition_digest
    assert registry.require(recipe.ref.recipe_id, recipe.ref.version) is recipe


def test_active_recipes_are_lab_only_and_passive_recipes_need_no_network():
    recipes = default_recipe_registry().list_recipes()

    for recipe in recipes:
        if recipe.risk_floor in {"R1", "R2"}:
            assert recipe.policy_modes == ("authorized_local_lab",)
            assert recipe.network_profile == "authorized_local_lab"
            assert recipe.mutation_inventory.network_access is True
        else:
            assert recipe.risk_floor == "R0"
            assert recipe.network_profile == "none"
            assert recipe.mutation_inventory.network_access is False


def test_versioned_recipe_cannot_express_arbitrary_shell_or_http():
    recipe = default_recipe_registry().require(
        "passive_artifact_analysis", "1.0.0"
    )
    payload = recipe.model_dump(exclude={"definition_digest"})
    payload["command"] = "curl https://example.test"

    with pytest.raises(ValidationError):
        VersionedRecipe.model_validate(payload)


def test_irreversible_state_change_requires_an_explicit_r4_category():
    with pytest.raises(ValidationError):
        MutationInventory(
            network_access=True,
            browser_automation=False,
            reads_owned_account_data=True,
            two_owned_account_differential=False,
            state_change=True,
            reversible=False,
            external_side_effect=False,
        )
