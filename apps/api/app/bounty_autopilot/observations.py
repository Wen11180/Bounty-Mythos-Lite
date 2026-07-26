"""Sanitized observation contracts for Autopilot evidence lineage."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from app.bounty_autopilot.contracts import DIGEST_PATTERN, SAFE_ID_PATTERN, StrictContract
from app.bounty_autopilot.gateway import GatewayOutcomeClass


class ObservationGrade(str, Enum):
    L0_NOISE = "L0_noise"
    L1_HINT = "L1_hint"
    L2_CORROBORATED = "L2_corroborated"
    L3_ACTIONABLE = "L3_actionable"


StatusClass = Literal["1xx", "2xx", "3xx", "4xx", "5xx", "unknown"]
ContentTypeClass = Literal["json", "html", "text", "other", "unknown"]
DifferenceLabel = Literal[
    "status_class_same",
    "status_class_different",
    "content_type_class_same",
    "content_type_class_different",
    "byte_length_same",
    "byte_length_different",
]


class AutopilotObservationInput(StrictContract):
    """Metadata-only runner observation accepted by the durable API."""

    observation_id: str = Field(min_length=1, max_length=128)
    branch_id: str = Field(min_length=1, max_length=128)
    plan_digest: str = Field(min_length=1, max_length=100)
    lease_id: str = Field(min_length=1, max_length=128)
    reservation_id: str = Field(min_length=1, max_length=128)
    comparison_reservation_id: str | None = Field(default=None, min_length=1, max_length=128)
    receipt_digest: str | None = None
    comparison_receipt_digest: str | None = None
    outcome_class: GatewayOutcomeClass
    grade: ObservationGrade = ObservationGrade.L1_HINT
    summary: str = Field(min_length=1, max_length=512)
    evidence_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    status_class: StatusClass = "unknown"
    content_type_class: ContentTypeClass = "unknown"
    byte_length: int = Field(default=0, ge=0, le=5_000_001)
    comparison_status_class: StatusClass | None = None
    comparison_content_type_class: ContentTypeClass | None = None
    comparison_byte_length: int | None = Field(default=None, ge=0, le=5_000_001)
    difference_labels: tuple[DifferenceLabel, ...] = Field(default_factory=tuple, max_length=3)
    third_party_data_discarded: bool = False

    @field_validator(
        "observation_id",
        "branch_id",
        "lease_id",
        "reservation_id",
        "comparison_reservation_id",
    )
    @classmethod
    def require_safe_identifier(cls, value: str | None) -> str | None:
        if value is not None and SAFE_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("safe_identifier_required")
        return value

    @field_validator("plan_digest")
    @classmethod
    def require_plan_digest(cls, value: str) -> str:
        if DIGEST_PATTERN.fullmatch(value) is None:
            raise ValueError("plan_digest_required")
        return value

    @field_validator("receipt_digest", "comparison_receipt_digest")
    @classmethod
    def require_receipt_digest(cls, value: str | None) -> str | None:
        if value is not None and DIGEST_PATTERN.fullmatch(value) is None:
            raise ValueError("receipt_digest_required")
        return value

    @field_validator("evidence_refs")
    @classmethod
    def require_bounded_evidence_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not value or len(value) > 128 for value in values):
            raise ValueError("evidence_ref_invalid")
        return values

    @model_validator(mode="after")
    def require_complete_differential_metadata(self):
        comparison_values = (
            self.comparison_reservation_id,
            self.comparison_receipt_digest,
            self.comparison_status_class,
            self.comparison_content_type_class,
            self.comparison_byte_length,
        )
        has_comparison = any(value is not None for value in comparison_values)
        if not has_comparison:
            if self.difference_labels:
                raise ValueError("difference_labels_require_comparison")
            return self
        if any(value is None for value in comparison_values):
            raise ValueError("comparison_metadata_required")
        if self.comparison_reservation_id == self.reservation_id:
            raise ValueError("comparison_reservation_must_differ")
        expected: tuple[DifferenceLabel, ...] = (
            "status_class_same"
            if self.status_class == self.comparison_status_class
            else "status_class_different",
            "content_type_class_same"
            if self.content_type_class == self.comparison_content_type_class
            else "content_type_class_different",
            "byte_length_same"
            if self.byte_length == self.comparison_byte_length
            else "byte_length_different",
        )
        if self.difference_labels != expected:
            raise ValueError("difference_labels_mismatch")
        return self


class ObservationRecord(StrictContract):
    observation_id: str
    campaign_id: str
    branch_id: str
    plan_digest: str
    lease_id: str | None = None
    reservation_id: str | None = None
    comparison_reservation_id: str | None = None
    receipt_digest: str | None = None
    comparison_receipt_digest: str | None = None
    outcome_class: GatewayOutcomeClass
    grade: ObservationGrade = ObservationGrade.L1_HINT
    summary: str = Field(min_length=1, max_length=512)
    evidence_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    difference_labels: tuple[DifferenceLabel, ...] = Field(default_factory=tuple, max_length=3)
    third_party_data_discarded: bool = False
    raw_content_retained: Literal[False] = False
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False


def build_observation(
    *,
    observation_id: str,
    campaign_id: str,
    branch_id: str,
    plan_digest: str,
    outcome_class: GatewayOutcomeClass,
    summary: str,
    grade: ObservationGrade = ObservationGrade.L1_HINT,
    evidence_refs: tuple[str, ...] = (),
    lease_id: str | None = None,
    reservation_id: str | None = None,
    comparison_reservation_id: str | None = None,
    comparison_receipt_digest: str | None = None,
    difference_labels: tuple[DifferenceLabel, ...] = (),
    third_party_data_discarded: bool = False,
) -> ObservationRecord:
    if outcome_class is GatewayOutcomeClass.THIRD_PARTY_DATA:
        third_party_data_discarded = True
        summary = "third_party_data_discarded"
        evidence_refs = ()
    return ObservationRecord(
        observation_id=observation_id,
        campaign_id=campaign_id,
        branch_id=branch_id,
        plan_digest=plan_digest,
        lease_id=lease_id,
        reservation_id=reservation_id,
        comparison_reservation_id=comparison_reservation_id,
        comparison_receipt_digest=comparison_receipt_digest,
        outcome_class=outcome_class,
        grade=grade,
        summary=summary[:512],
        evidence_refs=evidence_refs,
        difference_labels=difference_labels,
        third_party_data_discarded=third_party_data_discarded,
    )


__all__ = [
    "AutopilotObservationInput",
    "ObservationGrade",
    "ObservationRecord",
    "build_observation",
]
