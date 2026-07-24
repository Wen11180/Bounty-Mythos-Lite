"""Sanitized response projections; never retain raw secrets or third-party data."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import Field, model_validator

from app.bounty_autopilot.contracts import StrictContract
from app.bounty_autopilot.gateway import GatewayOutcomeClass


_SECRET_PATTERNS = (
    re.compile(r"(?im)^\s*authorization\s*[:=]\s*[^\r\n]+"),
    re.compile(r"(?im)^\s*(cookie|set-cookie)\s*[:=]\s*[^\r\n]+"),
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[^\s&;,]+"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-+=/]+"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?i)([?&](?:token|key|secret|auth|session)=)[^&#\s]+"),
)

_THIRD_PARTY_MARKERS = (
    b'"third_party":true',
    b'"ownership":"foreign"',
    b'"pii_foreign":true',
    b"x-mythos-third-party-data",
)
_SENSITIVE_RESPONSE_MARKERS = (
    *_THIRD_PARTY_MARKERS,
    b'"authorization":',
    b'"cookie":',
    b'"email":',
    b'"password":',
    b'"session":',
    b'"session_id":',
    b'"sessionid":',
    b'"token":',
    b"set-cookie:",
)
_EMAIL_BYTES = re.compile(rb"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)


class SanitizedObservation(StrictContract):
    observation_id: str
    outcome_class: GatewayOutcomeClass
    status_code: int | None = None
    content_type_class: str = "unknown"
    byte_length: int = Field(ge=0)
    redacted_excerpt: str = Field(default="", max_length=512)
    third_party_data_discarded: bool = False
    raw_secret_retained: Literal[False] = False
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False

    @model_validator(mode="after")
    def reject_response_excerpt(self) -> SanitizedObservation:
        if self.redacted_excerpt:
            raise ValueError("raw_response_excerpt_forbidden")
        return self


def redact_text(value: str) -> str:
    if _EMAIL_BYTES.search(value.encode("utf-8", errors="ignore")):
        return "[REDACTED]"
    redacted = value
    for pattern in _SECRET_PATTERNS:
        if pattern.search(redacted):
            return "[REDACTED]"
    return redacted[:512]


def inspect_response_bytes(
    *,
    observation_id: str,
    status_code: int | None,
    content_type: str | None,
    chunks: tuple[bytes, ...] | list[bytes],
    max_response_bytes: int,
) -> SanitizedObservation:
    """Inspect bounded bytes in memory and emit only a safe projection."""

    if max_response_bytes < 1:
        raise ValueError("response_budget_required")
    retained = bytearray()
    for chunk in chunks:
        if not isinstance(chunk, bytes):
            raise TypeError("response_chunk_must_be_bytes")
        if len(retained) + len(chunk) > max_response_bytes:
            retained.clear()
            return project_response(
                observation_id=observation_id,
                outcome_class=GatewayOutcomeClass.SIZE_CEILING,
                status_code=status_code,
                content_type=content_type,
                body_preview="",
                byte_length=0,
            )
        retained.extend(chunk)
        lowered = re.sub(rb"\s+", b"", bytes(retained).lower())
        if (
            any(marker in lowered for marker in _SENSITIVE_RESPONSE_MARKERS)
            or _EMAIL_BYTES.search(bytes(retained)) is not None
        ):
            retained.clear()
            return project_response(
                observation_id=observation_id,
                outcome_class=GatewayOutcomeClass.THIRD_PARTY_DATA,
                status_code=status_code,
                content_type=content_type,
                body_preview="",
                byte_length=0,
            )
    byte_length = len(retained)
    retained.clear()
    return project_response(
        observation_id=observation_id,
        outcome_class=GatewayOutcomeClass.OK,
        status_code=status_code,
        content_type=content_type,
        body_preview="",
        byte_length=byte_length,
    )


def project_response(
    *,
    observation_id: str,
    outcome_class: GatewayOutcomeClass,
    status_code: int | None,
    content_type: str | None,
    body_preview: str,
    byte_length: int,
) -> SanitizedObservation:
    if outcome_class is GatewayOutcomeClass.THIRD_PARTY_DATA:
        return SanitizedObservation(
            observation_id=observation_id,
            outcome_class=outcome_class,
            status_code=status_code,
            content_type_class=_content_class(content_type),
            byte_length=0,
            redacted_excerpt="",
            third_party_data_discarded=True,
        )
    return SanitizedObservation(
        observation_id=observation_id,
        outcome_class=outcome_class,
        status_code=status_code,
        content_type_class=_content_class(content_type),
        byte_length=byte_length,
        redacted_excerpt="",
        third_party_data_discarded=False,
    )


def _content_class(content_type: str | None) -> str:
    if not content_type:
        return "unknown"
    lowered = content_type.lower()
    if "json" in lowered:
        return "json"
    if "html" in lowered:
        return "html"
    if "text" in lowered:
        return "text"
    return "other"


__all__ = [
    "SanitizedObservation",
    "inspect_response_bytes",
    "project_response",
    "redact_text",
]
