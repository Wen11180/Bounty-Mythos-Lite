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
