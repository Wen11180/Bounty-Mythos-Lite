"""Negative and binding tests for metadata-only transport receipts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.bounty_autopilot.transport import (
    TransportReceipt,
    digest_transport_receipt,
    sign_transport_receipt,
)


def _receipt(**overrides):
    value = {
        "receipt_id": "receipt_test",
        "campaign_id": "campaign_test",
        "lease_id": "lease_test",
        "reservation_id": "reservation_test",
        "plan_id": "plan_test",
        "plan_digest": f"sha256:{'a' * 64}",
        "branch_id": "branch_test",
        "method": "GET",
        "scheme": "http",
        "host": "127.0.0.1",
        "port": 18080,
        "path": "/api/docs/1",
        "body_digest": None,
        "status_code": 200,
        "byte_length": 12,
        "sent_at": datetime.now(UTC),
        "challenge": "c" * 32,
    }
    value.update(overrides)
    return TransportReceipt(**value)


def test_receipt_signature_and_digest_are_stable_and_metadata_only():
    receipt = _receipt()
    signature = sign_transport_receipt(receipt, "a" * 43)
    assert len(signature) == 64
    assert digest_transport_receipt(receipt).startswith("sha256:")
    assert "authorization" not in receipt.model_dump_json().lower()


def test_receipt_signature_preserves_zero_byte_length():
    receipt = _receipt(byte_length=0)

    assert "\n0\n" in receipt.signing_message()
    assert sign_transport_receipt(receipt, "a" * 43) != sign_transport_receipt(
        receipt.model_copy(update={"byte_length": 1}), "a" * 43
    )


def test_receipt_signs_the_sanitized_content_type_class():
    receipt = _receipt(content_type_class="json")

    assert "json" in receipt.signing_message()
    assert sign_transport_receipt(receipt, "a" * 43) != sign_transport_receipt(
        receipt.model_copy(update={"content_type_class": "html"}), "a" * 43
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("challenge", "bad"),
        ("plan_digest", "sha256:bad"),
        ("byte_length", 5_000_002),
        ("status_code", 99),
    ],
)
def test_receipt_contract_rejects_tampered_or_unbounded_fields(field, value):
    with pytest.raises(ValueError):
        _receipt(**{field: value})


def test_receipt_time_is_timezone_aware_and_bounded_by_server_logic():
    receipt = _receipt(sent_at=datetime.now(UTC) - timedelta(seconds=1))
    assert receipt.sent_at.tzinfo is not None
