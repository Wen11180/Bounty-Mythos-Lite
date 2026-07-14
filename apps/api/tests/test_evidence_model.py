import pytest

from app.evidence import (
    EvidenceBundle,
    EvidenceItem,
    build_evidence_bundle,
)


def test_build_evidence_bundle_keeps_supported_items_and_default_safety_notes():
    bundle = build_evidence_bundle(
        "finding-123",
        [
            {
                "type": "request_response_diff",
                "content": {
                    "request": "GET /files/file_1",
                    "response": "403 Forbidden",
                },
            },
            {
                "type": "role_matrix_snapshot",
                "content": {
                    "owner": ["read", "write"],
                    "member": ["read"],
                },
            },
            {
                "type": "screenshot_ref",
                "content": {"path": "screenshots/finding-123-before.png"},
            },
            {
                "type": "log_ref",
                "content": {"line": "worker denied member export attempt"},
            },
            {
                "type": "local_code_reference",
                "content": {"file": "app/authz.py", "line": 42},
            },
        ],
    )

    assert isinstance(bundle, EvidenceBundle)
    assert all(isinstance(item, EvidenceItem) for item in bundle.items)
    assert bundle.finding_id == "finding-123"
    assert bundle.summary == "Evidence bundle for finding-123 with 5 item(s)."
    assert [item.type for item in bundle.items] == [
        "request_response_diff",
        "role_matrix_snapshot",
        "screenshot_ref",
        "log_ref",
        "local_code_reference",
    ]
    assert bundle.safety_notes == ["test_accounts_only", "no_real_user_data"]


def test_build_evidence_bundle_redacts_secret_like_strings_in_nested_content():
    secret_like_token = "sk" + "-live-secret should not remain"
    bundle = build_evidence_bundle(
        "finding-secret",
        [
            {
                "type": "request_response_diff",
                "content": {
                    "request": "Authorization: Bearer live-token",
                    "notes": [secret_like_token],
                },
            }
        ],
    )

    content = bundle.items[0].content
    assert content == {
        "request": "[REDACTED]",
        "notes": ["[REDACTED]"],
    }


def test_build_evidence_bundle_redacts_cookie_bearer_and_token_keys():
    bundle = build_evidence_bundle(
        "finding-secret-markers",
        [
            {
                "type": "request_response_diff",
                "content": {
                    "bearer_only": "Bearer live-token-123456789",
                    "gateway_header": "X-API-Key: live-token-123456789",
                    "headers": {"Cookie": "session=live-cookie-123456789"},
                    "access_token": "live-token-123456789",
                },
            }
        ],
    )

    assert bundle.items[0].content == {
        "bearer_only": "[REDACTED]",
        "gateway_header": "[REDACTED]",
        "headers": {"Cookie": "[REDACTED]"},
        "access_token": "[REDACTED]",
    }


def test_build_evidence_bundle_rejects_unsupported_evidence_type():
    with pytest.raises(ValueError, match="unsupported evidence type"):
        build_evidence_bundle(
            "finding-unsupported",
            [{"type": "raw_http_request", "content": "GET /admin"}],
        )


def test_build_evidence_bundle_accepts_only_sanitized_black_box_evidence_types():
    bundle = build_evidence_bundle(
        "black-box-review",
        [
            {
                "type": "sanitized_cross_account_diff",
                "content": {
                    "route": "GET /widgets/{object}",
                    "canary_match": True,
                },
            },
            {
                "type": "sanitized_parent_child_matrix",
                "content": {
                    "route": "GET /parents/{object}/children/{object}",
                    "state_effect": False,
                },
            },
        ],
    )

    assert [item.type for item in bundle.items] == [
        "sanitized_cross_account_diff",
        "sanitized_parent_child_matrix",
    ]


@pytest.mark.parametrize(
    ("evidence_type", "content"),
    [
        (
            "sanitized_cross_account_diff",
            {
                "route": "GET /widgets/{object}",
                "canary_match": True,
                "request_headers": {"X-Test": "raw"},
            },
        ),
        (
            "sanitized_cross_account_diff",
            {
                "route": "GET /widgets/{object}",
                "canary_match": True,
                "response_body": "raw response content",
            },
        ),
        (
            "sanitized_cross_account_diff",
            {
                "route": "GET /widgets/{object}",
                "canary_match": True,
                "query_values": {"object": "concrete-id"},
            },
        ),
        (
            "sanitized_parent_child_matrix",
            {
                "route": "GET /parents/{object}/children/{object}",
                "state_effect": False,
                "object_id": "concrete-id",
            },
        ),
        (
            "sanitized_cross_account_diff",
            {
                "route": "GET /widgets/{object}",
                "state_effect": True,
            },
        ),
        (
            "sanitized_parent_child_matrix",
            {
                "route": "GET /parents/{object}/children/{object}",
                "canary_match": True,
            },
        ),
    ],
)
def test_sanitized_black_box_evidence_rejects_raw_or_wrong_schema_fields(
    evidence_type,
    content,
):
    with pytest.raises(ValueError):
        build_evidence_bundle(
            "black-box-unsafe",
            [{"type": evidence_type, "content": content}],
        )


@pytest.mark.parametrize(
    "route",
    [
        "GET /widgets/{object}/123",
        "GET /widgets/{object}/550e8400-e29b-41d4-a716-446655440000",
        "GET https://api.example.com/widgets/{object}",
        "GET //api.example.com/widgets/{object}",
    ],
)
def test_sanitized_black_box_evidence_rejects_absolute_or_concrete_routes(route):
    with pytest.raises(ValueError, match="normalized_black_box_route_required"):
        build_evidence_bundle(
            "black-box-unsafe-route",
            [
                {
                    "type": "sanitized_cross_account_diff",
                    "content": {"route": route, "canary_match": True},
                }
            ],
        )


def test_sanitized_black_box_evidence_normalizes_route_placeholders():
    bundle = build_evidence_bundle(
        "black-box-normalized-route",
        [
            {
                "type": "sanitized_cross_account_diff",
                "content": {
                    "route": "GET /widgets/{widget_id}",
                    "canary_match": True,
                },
            }
        ],
    )

    assert bundle.items[0].content["route"] == "GET /widgets/{object}"


def test_sanitized_black_box_evidence_rejects_undeclared_slug_segment():
    with pytest.raises(ValueError, match="normalized_black_box_route_required"):
        build_evidence_bundle(
            "black-box-ambiguous-route",
            [
                {
                    "type": "sanitized_cross_account_diff",
                    "content": {
                        "route": "GET /widgets/{object}/customer-alpha",
                        "canary_match": True,
                    },
                }
            ],
        )


def test_sanitized_black_box_evidence_carries_declared_slug_metadata():
    bundle = build_evidence_bundle(
        "black-box-declared-route",
        [
            {
                "type": "sanitized_cross_account_diff",
                "content": {
                    "route": "GET /widgets/{object}/:customer_slug",
                    "path_parameters": [
                        {
                            "name": "customer_slug",
                            "segment": 3,
                            "value_type": "slug",
                        }
                    ],
                    "canary_match": True,
                },
            }
        ],
    )

    content = bundle.items[0].content
    assert content["route"] == "GET /widgets/{object}/{object}"
    assert content["path_parameters"] == [
        {"name": "customer_slug", "segment": 3, "value_type": "slug"}
    ]


def test_sanitized_black_box_evidence_preserves_static_state_literal():
    bundle = build_evidence_bundle(
        "black-box-static-route",
        [
            {
                "type": "sanitized_cross_account_diff",
                "content": {
                    "route": "GET /widgets/{object}/state",
                    "canary_match": True,
                },
            }
        ],
    )

    assert bundle.items[0].content["route"] == "GET /widgets/{object}/state"
