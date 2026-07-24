"""Typed, sanitized observation lineage for Bounty Autopilot."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from app.bounty_autopilot.contracts import (
    DIGEST_PATTERN,
    RecipeRef,
    RiskTier,
    StrictContract,
)
from app.bounty_autopilot.gateway import GatewayOutcomeClass

_SAFE_REF = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$", re.ASCII)


class ObservationGrade(str, Enum):
    L0_NOISE = "L0_noise"
    L1_HINT = "L1_hint"
    L2_CORROBORATED = "L2_corroborated"
    L3_ACTIONABLE = "L3_actionable"


class ObservationSummaryCode(str, Enum):
    ROUTE_MAPPED = "route_mapped"
    OWNED_ACCOUNT_DIFFERENTIAL = "owned_account_differential"
    REQUEST_BLOCKED = "request_blocked"
    WAF_OBSERVED = "waf_observed"
    RATE_LIMITED = "rate_limited"
    SESSION_EXPIRED = "session_expired"
    THIRD_PARTY_DATA_DISCARDED = "third_party_data_discarded"


class HumanEvidenceGrade(str, Enum):
    L4_HUMAN_VERIFIED = "L4_human_verified"
    L5_HUMAN_REPRODUCED = "L5_human_reproduced"


class HumanReviewDecision(str, Enum):
    VERIFIED = "verified_sanitized_owned_account_evidence"
    REPRODUCED = "reproduced_sanitized_owned_account_evidence"
    INSUFFICIENT = "insufficient_evidence"
    REFUTED = "refuted"


class EndpointIdentity(StrictContract):
    method: Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
    route_template: str = Field(min_length=1, max_length=256)

    @field_validator("route_template")
    @classmethod
    def require_sanitized_route_template(cls, value: str) -> str:
        if (
            not value.startswith("/")
            or "://" in value
            or "?" in value
            or "#" in value
            or ".." in value.split("/")
            or any(character.isspace() for character in value)
        ):
            raise ValueError("sanitized_route_template_required")
        return value


class ObservationRecord(StrictContract):
    observation_id: str
    campaign_id: str
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
    recipe_ref: RecipeRef
    lease_id: str
    reservation_id: str
    session_generation: int = Field(ge=1)
    tool_run_id: str
    endpoint: EndpointIdentity
    occurred_at: datetime
    outcome_class: GatewayOutcomeClass
    grade: ObservationGrade
    summary_code: ObservationSummaryCode
    evidence_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    third_party_data_discarded: bool = False
    discard_completed: bool = False
    raw_content_retained: Literal[False] = False
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False

    @field_validator(
        "observation_id",
        "campaign_id",
        "authorization_id",
        "asset_id",
        "branch_id",
        "plan_id",
        "risk_decision_id",
        "lease_id",
        "reservation_id",
        "tool_run_id",
    )
    @classmethod
    def require_safe_reference(cls, value: str) -> str:
        if _SAFE_REF.fullmatch(value) is None:
            raise ValueError("safe_lineage_reference_required")
        return value

    @field_validator(
        "authorization_digest",
        "scope_snapshot_digest",
        "asset_identity_digest",
        "plan_digest",
    )
    @classmethod
    def require_digest(cls, value: str) -> str:
        if DIGEST_PATTERN.fullmatch(value) is None:
            raise ValueError("lineage_digest_required")
        return value

    @field_validator("evidence_refs")
    @classmethod
    def require_safe_evidence_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(values)) != len(values):
            raise ValueError("duplicate_evidence_ref")
        if any(_SAFE_REF.fullmatch(value) is None for value in values):
            raise ValueError("safe_evidence_ref_required")
        return tuple(sorted(values))

    @field_validator("occurred_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timezone_aware_datetime_required")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def enforce_discard_receipt(self) -> ObservationRecord:
        is_discard = self.outcome_class is GatewayOutcomeClass.THIRD_PARTY_DATA
        if is_discard and (
            not self.third_party_data_discarded
            or not self.discard_completed
            or self.summary_code is not ObservationSummaryCode.THIRD_PARTY_DATA_DISCARDED
            or self.evidence_refs
            or self.grade is not ObservationGrade.L0_NOISE
        ):
            raise ValueError("third_party_discard_receipt_required")
        if not is_discard and (self.third_party_data_discarded or self.discard_completed):
            raise ValueError("discard_flags_require_third_party_outcome")
        if not is_discard and self.summary_code is ObservationSummaryCode.THIRD_PARTY_DATA_DISCARDED:
            raise ValueError("third_party_summary_requires_discard")
        if self.grade is ObservationGrade.L3_ACTIONABLE:
            if (
                self.outcome_class is not GatewayOutcomeClass.OK
                or self.summary_code is not ObservationSummaryCode.OWNED_ACCOUNT_DIFFERENTIAL
            ):
                raise ValueError("l3_owned_differential_required")
            if not self.evidence_refs:
                raise ValueError("l3_evidence_refs_required")
        return self


class HumanEvidenceReview(StrictContract):
    review_id: str
    campaign_id: str
    hypothesis_id: str
    observation_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    grade: HumanEvidenceGrade
    decision: HumanReviewDecision
    reviewer_alias: str
    reviewed_at: datetime
    automated_source: Literal[False] = False
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False

    @field_validator(
        "review_id",
        "campaign_id",
        "hypothesis_id",
        "observation_ids",
        "reviewer_alias",
    )
    @classmethod
    def require_safe_review_reference(cls, value):
        values = value if isinstance(value, tuple) else (value,)
        if any(_SAFE_REF.fullmatch(item) is None for item in values):
            raise ValueError("safe_human_review_reference_required")
        return value

    @field_validator("reviewed_at")
    @classmethod
    def normalize_review_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timezone_aware_datetime_required")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def require_grade_decision_alignment(self) -> HumanEvidenceReview:
        if self.grade is HumanEvidenceGrade.L5_HUMAN_REPRODUCED:
            if self.decision is not HumanReviewDecision.REPRODUCED:
                raise ValueError("l5_requires_human_reproduction")
        elif self.decision not in {
            HumanReviewDecision.VERIFIED,
            HumanReviewDecision.REPRODUCED,
        }:
            raise ValueError("l4_requires_human_verification")
        return self


def build_observation(**fields: object) -> ObservationRecord:
    if fields.get("outcome_class") is GatewayOutcomeClass.THIRD_PARTY_DATA:
        fields = {
            **fields,
            "grade": ObservationGrade.L0_NOISE,
            "summary_code": ObservationSummaryCode.THIRD_PARTY_DATA_DISCARDED,
            "evidence_refs": (),
            "third_party_data_discarded": True,
            "discard_completed": True,
        }
    return ObservationRecord(**fields)


__all__ = [
    "EndpointIdentity",
    "HumanEvidenceGrade",
    "HumanEvidenceReview",
    "HumanReviewDecision",
    "ObservationGrade",
    "ObservationRecord",
    "ObservationSummaryCode",
    "build_observation",
]
