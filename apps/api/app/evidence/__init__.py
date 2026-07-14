from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.black_box_hunter import WorkflowPathParameter, _normalize_route_template


SUPPORTED_EVIDENCE_TYPES = {
    "request_response_diff",
    "role_matrix_snapshot",
    "sanitized_cross_account_diff",
    "sanitized_parent_child_matrix",
    "screenshot_ref",
    "log_ref",
    "local_code_reference",
}
DEFAULT_SAFETY_NOTES = ["test_accounts_only", "no_real_user_data"]
REDACTED = "[REDACTED]"
BLACK_BOX_ROUTE_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH"}


class _SanitizedBlackBoxEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    route: str = Field(min_length=1, max_length=1024)
    path_parameters: list[WorkflowPathParameter] = Field(
        default_factory=list,
        exclude_if=lambda value: not value,
    )

    @model_validator(mode="after")
    def require_normalized_route(self):
        method, separator, path = self.route.partition(" ")
        if (
            separator != " "
            or method not in BLACK_BOX_ROUTE_METHODS
        ):
            raise ValueError("normalized_black_box_route_required")
        try:
            normalized_path = _normalize_route_template(
                path,
                self.path_parameters,
                reject_undeclared_slug_segments=True,
            )
        except ValueError as exc:
            raise ValueError("normalized_black_box_route_required") from exc
        if "{object}" not in normalized_path:
            raise ValueError("normalized_black_box_route_required")
        self.route = f"{method} {normalized_path}"
        return self


class SanitizedCrossAccountDiff(_SanitizedBlackBoxEvidence):
    canary_match: bool | None = None
    structural_identity_match: bool | None = None

    @model_validator(mode="after")
    def require_structural_signal(self):
        if self.canary_match is None and self.structural_identity_match is None:
            raise ValueError("sanitized_cross_account_signal_required")
        return self


class SanitizedParentChildMatrix(_SanitizedBlackBoxEvidence):
    state_effect: bool | None = None
    structural_identity_match: bool | None = None

    @model_validator(mode="after")
    def require_structural_signal(self):
        if self.state_effect is None and self.structural_identity_match is None:
            raise ValueError("sanitized_parent_child_signal_required")
        return self


BLACK_BOX_EVIDENCE_MODELS = {
    "sanitized_cross_account_diff": SanitizedCrossAccountDiff,
    "sanitized_parent_child_matrix": SanitizedParentChildMatrix,
}


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
        content = item.get("content")
        if evidence_model := BLACK_BOX_EVIDENCE_MODELS.get(evidence_type):
            content = evidence_model.model_validate(content).model_dump(
                exclude_none=True
            )
        evidence_items.append(
            EvidenceItem(
                type=evidence_type,
                content=_redact_secret_like_strings(content),
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
    import re

    normalized = value.lower()
    markers = (
        "authorization:",
        "api-key:",
        "api_key=",
        "bearer ",
        "cookie:",
        "secret=",
        "set-cookie:",
        "session=",
        "token=",
        "x-api-key:",
    )
    return any(marker in normalized for marker in markers) or (
        re.search(r"\bsk-[a-z0-9]", normalized) is not None
    )


__all__ = [
    "EvidenceBundle",
    "EvidenceItem",
    "build_evidence_bundle",
]
