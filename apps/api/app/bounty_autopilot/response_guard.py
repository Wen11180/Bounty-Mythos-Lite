"""Sanitized response projections; never retain raw secrets or third-party data."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import Field

from app.bounty_autopilot.contracts import StrictContract
from app.bounty_autopilot.gateway import GatewayOutcomeClass


_SECRET_PATTERNS = (
    re.compile(r"(?i)authorization\s*[:=]\s*.+"),
    re.compile(r"(?i)(cookie|set-cookie)\s*[:=]\s*.+"),
    re.compile(r"(?i)(password|passwd|secret|token)\s*[:=]\s*\S+"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-+=/]+"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)


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


def redact_text(value: str) -> str:
    redacted = value
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted[:512]


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
        redacted_excerpt=redact_text(body_preview),
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
    "project_response",
    "redact_text",
]
