from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.black_box_hunter import WorkflowPathParameter, _normalize_route_template
from app.bounty_autopilot.contracts import RiskTier, StrictContract
from app.bounty_autopilot.observations import ObservationGrade


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


class AutopilotEvidenceBundle(StrictContract):
    """Bounded evidence projection with the complete Autopilot authority chain."""

    finding_id: str
    hypothesis_id: str
    campaign_id: str
    observation_id: str
    refutation_lineage_digest: str
    lineage_digest: str
    authorization_id: str
    authorization_digest: str
    scope_snapshot_digest: str
    asset_id: str
    asset_identity_digest: str
    branch_id: str
    plan_id: str
    plan_digest: str
    risk_decision_id: str
    risk_tier: RiskTier
    recipe_id: str
    recipe_version: str
    recipe_definition_digest: str
    lease_id: str
    reservation_id: str
    session_generation: int = Field(ge=1)
    tool_run_id: str
    endpoint_method: str
    endpoint_route_template: str
    occurred_at: datetime
    evidence_grade: ObservationGrade
    evidence_refs: tuple[str, ...] = Field(min_length=1, max_length=16)
    safety_notes: tuple[str, ...] = (
        "owned_accounts_or_canary_only",
        "sanitized_projection_only",
        "automated_evidence_capped_at_l3",
    )
    lineage_complete: Literal[True] = True
    raw_content_retained: Literal[False] = False
    human_review_required: Literal[True] = True
    submission_blocked: Literal[True] = True
    automatic_submission_allowed: Literal[False] = False


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


def build_autopilot_evidence_bundle(
    *,
    observation: object,
    judge_result: object,
) -> AutopilotEvidenceBundle:
    """Build report-safe evidence only from typed retained Autopilot lineage."""

    from app.bounty_autopilot.evidence_judge import (
        EvidenceJudgeResult,
        EvidenceJudgeVerdict,
        evidence_lineage_digest,
    )
    from app.bounty_autopilot.observations import ObservationRecord

    if not isinstance(observation, ObservationRecord):
        raise TypeError("typed_autopilot_observation_required")
    if not isinstance(judge_result, EvidenceJudgeResult):
        raise TypeError("typed_autopilot_judge_result_required")
    if (
        judge_result.verdict is not EvidenceJudgeVerdict.RETAINED_CANDIDATE
        or judge_result.evidence_grade is not ObservationGrade.L3_ACTIONABLE
        or observation.grade is not judge_result.evidence_grade
        or observation.third_party_data_discarded
        or not observation.evidence_refs
        or not judge_result.lineage_complete
        or judge_result.campaign_id != observation.campaign_id
        or judge_result.branch_id != observation.branch_id
        or judge_result.observation_ids != (observation.observation_id,)
        or judge_result.lineage_digest
        != evidence_lineage_digest(
            observations=(observation,),
            refutation_lineage_digest=judge_result.refutation_lineage_digest,
        )
    ):
        raise ValueError("retained_sanitized_l3_autopilot_evidence_required")
    return AutopilotEvidenceBundle(
        finding_id=f"autopilot_evidence_{observation.observation_id}",
        hypothesis_id=judge_result.hypothesis_id,
        campaign_id=observation.campaign_id,
        observation_id=observation.observation_id,
        refutation_lineage_digest=judge_result.refutation_lineage_digest,
        lineage_digest=judge_result.lineage_digest,
        authorization_id=observation.authorization_id,
        authorization_digest=observation.authorization_digest,
        scope_snapshot_digest=observation.scope_snapshot_digest,
        asset_id=observation.asset_id,
        asset_identity_digest=observation.asset_identity_digest,
        branch_id=observation.branch_id,
        plan_id=observation.plan_id,
        plan_digest=observation.plan_digest,
        risk_decision_id=observation.risk_decision_id,
        risk_tier=observation.risk_tier,
        recipe_id=observation.recipe_ref.recipe_id,
        recipe_version=observation.recipe_ref.version,
        recipe_definition_digest=observation.recipe_ref.definition_digest,
        lease_id=observation.lease_id,
        reservation_id=observation.reservation_id,
        session_generation=observation.session_generation,
        tool_run_id=observation.tool_run_id,
        endpoint_method=observation.endpoint.method,
        endpoint_route_template=observation.endpoint.route_template,
        occurred_at=observation.occurred_at,
        evidence_grade=observation.grade,
        evidence_refs=observation.evidence_refs,
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
    "AutopilotEvidenceBundle",
    "EvidenceBundle",
    "EvidenceItem",
    "build_autopilot_evidence_bundle",
    "build_evidence_bundle",
]
