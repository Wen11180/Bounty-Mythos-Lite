from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.bounty_autopilot.authorization_model import (
    ReadOnlyDifferentialTemplate,
    build_differential_request_intents,
    build_two_account_read_only_template,
)
from app.bounty_autopilot.browser_mapper import build_browser_mapping
from app.bounty_autopilot.workflow_model import build_demonstrated_owned_workflow


def _digest(character: str) -> str:
    return "sha256:" + (character * 64)


def _workflow():
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
        method="GET",
        route_template="/api/documents/{object}",
        source_projection_digest=_digest("b"),
    )
    return build_demonstrated_owned_workflow(
        workflow_id="workflow_document_read",
        mapping=mapping,
        demonstration_observation_digest=_digest("c"),
    )


def _template(**updates: object):
    values: dict[str, object] = {
        "template_id": "template_document_cross_account",
        "campaign_id": "campaign_lab",
        "authorization_digest": _digest("d"),
        "workflow": _workflow(),
        "source_session_generation": 7,
        "comparison_account_alias": "owned_beta",
        "comparison_role_alias": "member",
        "comparison_session_alias": "session_beta",
        "comparison_session_generation": 4,
        "authorized_account_aliases": ("owned_alpha", "owned_beta"),
    }
    values.update(updates)
    return build_two_account_read_only_template(**values)


def test_template_is_fixed_to_two_sequential_read_only_requests():
    template = _template()
    intents = build_differential_request_intents(template)

    assert template.recipe_ref.recipe_id == "lab_two_account_authorization_differential"
    assert template.max_requests == 2
    assert template.max_concurrency == 1
    assert template.mutation_allowed is False
    assert template.enumeration_allowed is False
    assert template.pagination_allowed is False
    assert template.object_substitution_allowed is False
    assert len(intents) == 2
    assert [intent.ordinal for intent in intents] == [1, 2]
    assert {intent.account_alias for intent in intents} == {"owned_alpha", "owned_beta"}
    assert {intent.object_alias for intent in intents} == {"document_alpha"}
    assert {intent.route_template for intent in intents} == {"/api/documents/{object}"}
    assert [intent.session_generation for intent in intents] == [7, 4]


@pytest.mark.parametrize(
    ("updates", "reason"),
    [
        (
            {"comparison_account_alias": "owned_alpha"},
            "distinct_owned_accounts_required",
        ),
        ({"source_session_generation": 8}, "stale_source_session_generation"),
        (
            {
                "authorized_account_aliases": (
                    "owned_alpha",
                    "owned_beta",
                    "owned_gamma",
                )
            },
            "exact_two_authorized_accounts_required",
        ),
    ],
)
def test_template_fails_closed_for_unowned_or_stale_sessions(
    updates: dict[str, object], reason: str
):
    with pytest.raises(ValueError, match=reason):
        _template(**updates)


def test_template_digest_rejects_cross_boundary_tampering():
    payload = _template().model_dump(mode="json")
    payload["object_alias"] = "document_other"
    with pytest.raises(ValidationError, match="template_digest_mismatch"):
        ReadOnlyDifferentialTemplate.model_validate_json(json.dumps(payload))
