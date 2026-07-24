from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.bounty_autopilot.browser_mapper import build_browser_mapping
from app.bounty_autopilot.workflow_model import (
    DemonstratedOwnedWorkflow,
    build_demonstrated_owned_workflow,
)


def _digest(character: str) -> str:
    return "sha256:" + (character * 64)


def _mapping(*, owner: str = "owned_alpha"):
    return build_browser_mapping(
        mapping_id="mapping_document_read",
        asset_id="asset_lab_api",
        account_alias="owned_alpha",
        role_alias="member",
        session_alias="session_alpha",
        session_generation=7,
        object_alias="document_alpha",
        object_type="document",
        owner_account_alias=owner,
        ownership_proof_digest=_digest("a"),
        method="GET",
        route_template="/api/documents/{object}",
        source_projection_digest=_digest("b"),
    )


def test_demonstrated_owned_workflow_binds_mapping_and_safe_observation():
    workflow = build_demonstrated_owned_workflow(
        workflow_id="workflow_document_read",
        mapping=_mapping(),
        demonstration_observation_digest=_digest("c"),
    )

    assert workflow.mapping.subject.account_alias == "owned_alpha"
    assert workflow.mapping.obj.owner_account_alias == "owned_alpha"
    assert workflow.workflow_digest.startswith("sha256:")

    payload = workflow.model_dump(mode="json")
    payload["demonstration_observation_digest"] = _digest("d")
    with pytest.raises(ValidationError, match="workflow_digest_mismatch"):
        DemonstratedOwnedWorkflow.model_validate_json(json.dumps(payload))


def test_workflow_requires_source_account_to_own_the_demonstrated_object():
    with pytest.raises(ValueError, match="demonstrated_owned_object_required"):
        build_demonstrated_owned_workflow(
            workflow_id="workflow_document_read",
            mapping=_mapping(owner="owned_beta"),
            demonstration_observation_digest=_digest("c"),
        )


def test_workflow_accepts_only_a_digest_not_raw_demonstration_content():
    payload = {
        "workflow_id": "workflow_document_read",
        "mapping": _mapping().model_dump(mode="json"),
        "demonstration_observation_digest": _digest("c"),
        "workflow_digest": _digest("d"),
        "response_body": "secret",
    }
    with pytest.raises(ValidationError):
        DemonstratedOwnedWorkflow.model_validate(payload)
