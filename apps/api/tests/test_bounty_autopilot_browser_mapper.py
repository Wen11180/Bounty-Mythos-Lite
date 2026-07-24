from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.bounty_autopilot.browser_mapper import (
    MappedWorkflow,
    build_browser_mapping,
)


def _digest(character: str) -> str:
    return "sha256:" + (character * 64)


def _mapping(**updates: object) -> MappedWorkflow:
    values: dict[str, object] = {
        "mapping_id": "mapping_document_read",
        "asset_id": "asset_lab_api",
        "account_alias": "owned_alpha",
        "role_alias": "member",
        "session_alias": "session_alpha",
        "session_generation": 7,
        "object_alias": "document_alpha",
        "object_type": "document",
        "owner_account_alias": "owned_alpha",
        "ownership_proof_digest": _digest("a"),
        "method": "GET",
        "route_template": "/api/documents/{object}",
        "source_projection_digest": _digest("b"),
    }
    values.update(updates)
    return build_browser_mapping(**values)


def test_browser_mapping_is_structural_sanitized_and_digest_bound():
    mapping = _mapping()
    payload = mapping.model_dump(mode="json")

    assert mapping.recipe_ref.recipe_id == "lab_browser_mapping"
    assert mapping.action.path_parameters == ("object",)
    assert mapping.action.query_parameters == ()
    assert mapping.action.mutates_state is False
    assert mapping.mapping_digest.startswith("sha256:")
    assert not {
        "url",
        "headers",
        "cookies",
        "body",
        "dom",
        "screenshot",
    }.intersection(_nested_keys(payload))

    tampered = dict(payload)
    tampered["asset_id"] = "asset_other"
    with pytest.raises(ValidationError, match="mapping_digest_mismatch"):
        MappedWorkflow.model_validate_json(json.dumps(tampered))


@pytest.mark.parametrize(
    "route_template",
    [
        "/api/documents/{object}?token=secret",
        "/api/documents/{object}#fragment",
        "/api/documents/%7Bobject%7D",
        "https://127.0.0.1/api/documents/{object}",
        "/api/../documents/{object}",
        "/api/documents/{object}/{object}",
    ],
)
def test_browser_mapping_rejects_raw_or_non_normalized_routes(route_template: str):
    with pytest.raises((ValidationError, ValueError)):
        _mapping(route_template=route_template)


def test_browser_mapping_rejects_raw_capture_fields_and_concrete_object_ids():
    payload = _mapping().model_dump(mode="json")
    payload["raw_url"] = "http://127.0.0.1/api/documents/42?token=secret"
    with pytest.raises(ValidationError):
        MappedWorkflow.model_validate(payload)

    with pytest.raises((ValidationError, ValueError)):
        _mapping(object_alias="550e8400-e29b-41d4-a716-446655440000")


def _nested_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(
            *(_nested_keys(item) for item in value.values())
        )
    if isinstance(value, list):
        return set().union(*(_nested_keys(item) for item in value))
    return set()
