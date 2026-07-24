from __future__ import annotations

import pytest

from app.bounty_autopilot.authorization_model import (
    build_differential_request_intents,
    build_two_account_read_only_template,
    validate_differential_request_intent,
)
from app.bounty_autopilot.browser_mapper import build_browser_mapping
from app.bounty_autopilot.recipes import default_recipe_registry
from app.bounty_autopilot.workflow_model import build_demonstrated_owned_workflow


def _digest(character: str) -> str:
    return "sha256:" + (character * 64)


def _template():
    mapping = build_browser_mapping(
        mapping_id="mapping_document_read",
        asset_id="asset_lab_api",
        account_alias="owned_alpha",
        role_alias="member",
        session_alias="session_alpha",
        session_generation=7,
        object_alias="document_alpha",
        object_type="document",
        owner_account_alias="owned_alpha",
        ownership_proof_digest=_digest("a"),
        method="HEAD",
        route_template="/api/documents/{object}",
        source_projection_digest=_digest("b"),
    )
    workflow = build_demonstrated_owned_workflow(
        workflow_id="workflow_document_read",
        mapping=mapping,
        demonstration_observation_digest=_digest("c"),
    )
    return build_two_account_read_only_template(
        template_id="template_document_cross_account",
        campaign_id="campaign_lab",
        authorization_digest=_digest("d"),
        workflow=workflow,
        source_session_generation=7,
        comparison_account_alias="owned_beta",
        comparison_role_alias="member",
        comparison_session_alias="session_beta",
        comparison_session_generation=4,
        authorized_account_aliases=("owned_alpha", "owned_beta"),
    )


def test_only_mapping_and_two_account_read_only_recipe_families_are_enabled():
    registry = default_recipe_registry()
    differential = registry.require(
        "lab_two_account_authorization_differential", "1.0.0"
    )

    assert differential.max_budgets.max_requests == 2
    assert differential.max_budgets.max_concurrency == 1
    assert differential.mutation_inventory.state_change is False
    for disabled in (
        "lab_bfla_authorization_differential",
        "lab_graphql_field_authorization_differential",
        "lab_mass_assignment",
        "lab_workflow_transition",
    ):
        assert registry.get(disabled, "1.0.0") is None


def test_request_intents_are_derived_only_from_the_fixed_template():
    template = _template()
    first, second = build_differential_request_intents(template)

    assert validate_differential_request_intent(template, first) is first
    assert validate_differential_request_intent(template, second) is second

    substituted = second.model_copy(update={"object_alias": "document_other"})
    with pytest.raises(ValueError, match="request_intent_template_mismatch"):
        validate_differential_request_intent(template, substituted)

    paginated = second.model_copy(update={"query_parameter_names": ("page",)})
    with pytest.raises(ValueError, match="request_intent_template_mismatch"):
        validate_differential_request_intent(template, paginated)
