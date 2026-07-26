"""Sanitized response projections; never retain raw secrets or third-party data."""

from __future__ import annotations

import json
import re
from typing import Any, Literal
from urllib.parse import unquote_plus

from pydantic import Field

from app.bounty_autopilot.contracts import StrictContract
from app.bounty_autopilot.gateway import GatewayOutcomeClass


_SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "client_key",
        "client_secret",
        "cookie",
        "credential",
        "credentials",
        "id_token",
        "key",
        "password",
        "passwd",
        "private_key",
        "refresh_token",
        "secret",
        "secret_key",
        "session",
        "session_token",
        "set_cookie",
        "signing_key",
        "token",
    }
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)(?<![A-Za-z0-9_-])bearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(?<![A-Za-z0-9_-])basic\s+[A-Za-z0-9+/=]{8,}"),
    re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"(?i)(?<![A-Za-z0-9_-])gh[pousr]_[A-Za-z0-9_]{20,}(?![A-Za-z0-9_-])"),
    re.compile(r"(?i)(?<![A-Za-z0-9_-])github_pat_[A-Za-z0-9_]{20,}(?![A-Za-z0-9_-])"),
    re.compile(r"(?<![A-Za-z0-9_-])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9_-])"),
    re.compile(r"(?i)(?<![A-Za-z0-9_-])sk-(?:proj-)?[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"),
    re.compile(r"-----BEGIN(?: [A-Z]+){0,3} PRIVATE KEY-----"),
)
_ASSIGNMENT_KEY_PATTERN = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])(?P<key>(?:x[_-])?[A-Za-z][A-Za-z0-9_-]*(?:\[[^\]\r\n]{0,64}\]|\.[A-Za-z][A-Za-z0-9_-]*)*)(?:[\"']|\\[\"'])?\s*[:=：]"
)
_MAX_INPUT_CHARS = 8_192
_MAX_DECODE_PASSES = 4
_MAX_JSON_DEPTH = 3


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
    if _contains_secret(value):
        return "[REDACTED]"
    return value[:512]


def _contains_secret(value: str) -> bool:
    if len(value) > _MAX_INPUT_CHARS:
        return True
    decoded = value
    for _ in range(_MAX_DECODE_PASSES):
        if _contains_secret_text(decoded):
            return True
        next_decoded = unquote_plus(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded
    return False


def _contains_secret_text(value: str) -> bool:
    if any(pattern.search(value) for pattern in _SECRET_VALUE_PATTERNS):
        return True
    if any(
        _is_sensitive_key(match.group("key"))
        for match in _ASSIGNMENT_KEY_PATTERN.finditer(value)
    ):
        return True
    try:
        parsed = json.loads(value)
    except RecursionError:
        return True
    except (TypeError, ValueError):
        return False
    return _json_contains_secret(parsed, depth=0)


def _is_sensitive_key(value: str) -> bool:
    for component in re.split(r"[\[\].]+", value.strip().lower().replace("-", "_")):
        normalized = component.removeprefix("x_")
        if normalized in _SENSITIVE_KEYS:
            return True
    return False


def _json_contains_secret(value: Any, *, depth: int) -> bool:
    # Uninspected nested values must not reach a persisted excerpt.
    if depth >= _MAX_JSON_DEPTH:
        return True
    if isinstance(value, dict):
        return any(
            (isinstance(key, str) and _is_sensitive_key(key))
            or _json_contains_secret(nested, depth=depth + 1)
            for key, nested in value.items()
        )
    if isinstance(value, list):
        return any(_json_contains_secret(item, depth=depth + 1) for item in value)
    if not isinstance(value, str):
        return False
    if _contains_secret_text(value):
        return True
    try:
        nested = json.loads(value)
    except RecursionError:
        return True
    except (TypeError, ValueError):
        return False
    return _json_contains_secret(nested, depth=depth + 1)


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
