"""Signed, metadata-only transport receipts for Autopilot execution."""

from __future__ import annotations

from datetime import datetime
import hashlib
import hmac
import json
import re
from typing import Any, Literal, Mapping

from pydantic import Field, field_validator

from app.bounty_autopilot.contracts import DIGEST_PATTERN, SAFE_ID_PATTERN, StrictContract


TRANSPORT_RECEIPT_SCHEMA = "autopilot_transport_receipt_v1"
_CHALLENGE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,256}$", re.ASCII)
_SIGNING_FIELDS = (
    "schema_version",
    "receipt_id",
    "campaign_id",
    "lease_id",
    "reservation_id",
    "plan_id",
    "plan_digest",
    "branch_id",
    "method",
    "scheme",
    "host",
    "port",
    "path",
    "body_digest",
    "status_code",
    "content_type_class",
    "byte_length",
    "sent_at",
    "transport",
    "challenge",
)


class TransportReceipt(StrictContract):
    """A signed receipt emitted only after the bounded transport returns."""

    schema_version: Literal["autopilot_transport_receipt_v1"] = TRANSPORT_RECEIPT_SCHEMA
    receipt_id: str = Field(min_length=1, max_length=128)
    campaign_id: str = Field(min_length=1, max_length=128)
    lease_id: str = Field(min_length=1, max_length=128)
    reservation_id: str = Field(min_length=1, max_length=128)
    plan_id: str = Field(min_length=1, max_length=128)
    plan_digest: str = Field(min_length=1, max_length=100)
    branch_id: str = Field(min_length=1, max_length=128)
    method: str = Field(min_length=1, max_length=16)
    scheme: Literal["http", "https"]
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    path: str = Field(min_length=1, max_length=1024)
    body_digest: str | None = None
    status_code: int = Field(ge=100, le=599)
    # This is a fixed classification, not a raw response header.  Signing it
    # lets a two-account observation prove its metadata-only differential.
    content_type_class: Literal["json", "html", "text", "other", "unknown"] = "unknown"
    # A bounded transport may return one sentinel byte beyond the configured
    # ceiling so the runner can record a size-ceiling outcome without storing
    # the response body.
    byte_length: int = Field(ge=0, le=5_000_001)
    sent_at: datetime
    transport: Literal["loopback_http_v1"] = "loopback_http_v1"
    challenge: str = Field(min_length=32, max_length=256)

    @field_validator(
        "receipt_id",
        "campaign_id",
        "lease_id",
        "reservation_id",
        "plan_id",
        "branch_id",
    )
    @classmethod
    def require_safe_ids(cls, value: str) -> str:
        if SAFE_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("safe_identifier_required")
        return value

    @field_validator("plan_digest")
    @classmethod
    def require_plan_digest(cls, value: str) -> str:
        if DIGEST_PATTERN.fullmatch(value) is None:
            raise ValueError("plan_digest_required")
        return value

    @field_validator("body_digest")
    @classmethod
    def require_body_digest(cls, value: str | None) -> str | None:
        if value is not None and DIGEST_PATTERN.fullmatch(value) is None:
            raise ValueError("body_digest_invalid")
        return value

    @field_validator("challenge")
    @classmethod
    def require_challenge(cls, value: str) -> str:
        if _CHALLENGE_PATTERN.fullmatch(value) is None:
            raise ValueError("transport_challenge_required")
        return value

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        method = value.upper()
        if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("unknown_http_method")
        return method

    def signing_message(self) -> str:
        payload = self.model_dump(mode="json")
        return receipt_signing_message(payload)


class TransportReceiptSubmission(StrictContract):
    """Runner submission envelope; raw response content is not representable."""

    receipt: TransportReceipt
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")


def receipt_signing_message(receipt: Mapping[str, Any]) -> str:
    """Build a stable cross-language message without signing arbitrary fields."""

    return "\n".join(
        "" if receipt.get(field) is None else str(receipt.get(field))
        for field in _SIGNING_FIELDS
    )


def sign_transport_receipt(receipt: TransportReceipt, capability: str) -> str:
    return hmac.new(
        capability.encode("utf-8"),
        receipt.signing_message().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def digest_transport_receipt(receipt: TransportReceipt) -> str:
    serialized = json.dumps(
        receipt.model_dump(mode="json"),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return f"sha256:{hashlib.sha256(serialized.encode('utf-8')).hexdigest()}"


__all__ = [
    "TRANSPORT_RECEIPT_SCHEMA",
    "TransportReceipt",
    "TransportReceiptSubmission",
    "digest_transport_receipt",
    "receipt_signing_message",
    "sign_transport_receipt",
]
