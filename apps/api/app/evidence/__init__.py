from typing import Any

from pydantic import BaseModel, Field


SUPPORTED_EVIDENCE_TYPES = {
    "request_response_diff",
    "role_matrix_snapshot",
    "screenshot_ref",
    "log_ref",
    "local_code_reference",
}
DEFAULT_SAFETY_NOTES = ["test_accounts_only", "no_real_user_data"]
REDACTED = "[REDACTED]"


class EvidenceItem(BaseModel):
    type: str
    content: Any


class EvidenceBundle(BaseModel):
    finding_id: str
    summary: str
    items: list[EvidenceItem] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=lambda: DEFAULT_SAFETY_NOTES.copy())


def build_evidence_bundle(finding_id: str, items: list[dict]) -> EvidenceBundle:
    evidence_items: list[EvidenceItem] = []

    for item in items:
        evidence_type = str(item.get("type", ""))
        if evidence_type not in SUPPORTED_EVIDENCE_TYPES:
            raise ValueError(f"unsupported evidence type: {evidence_type}")
        evidence_items.append(
            EvidenceItem(
                type=evidence_type,
                content=_redact_secret_like_strings(item.get("content")),
            )
        )

    return EvidenceBundle(
        finding_id=finding_id,
        summary=f"Evidence bundle for {finding_id} with {len(evidence_items)} item(s).",
        items=evidence_items,
        safety_notes=DEFAULT_SAFETY_NOTES.copy(),
    )


def _redact_secret_like_strings(value: Any) -> Any:
    if isinstance(value, str):
        return REDACTED if _is_secret_like(value) else value
    if isinstance(value, list):
        return [_redact_secret_like_strings(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_secret_like_strings(item) for item in value)
    if isinstance(value, dict):
        return {
            key: REDACTED
            if _is_secret_key(str(key))
            else _redact_secret_like_strings(nested_value)
            for key, nested_value in value.items()
        }
    return value


def _is_secret_key(value: str) -> bool:
    normalized = value.lower().replace("-", "_")
    return any(
        marker in normalized
        for marker in (
            "authorization",
            "api_key",
            "apikey",
            "cookie",
            "token",
            "secret",
            "password",
            "credential",
        )
    )


def _is_secret_like(value: str) -> bool:
    normalized = value.lower()
    return any(
        marker in normalized
        for marker in (
            "authorization:",
            "bearer ",
            "cookie:",
            "set-cookie:",
            "sk-",
        )
    )


__all__ = [
    "EvidenceBundle",
    "EvidenceItem",
    "build_evidence_bundle",
]
