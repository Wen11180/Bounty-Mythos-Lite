"""Append-only, sanitized records used to audit an Autopilot lab run."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Literal

from pydantic import Field, field_validator, model_validator

from app.bounty_autopilot.contracts import DIGEST_PATTERN, RecipeRef, RiskTier, StrictContract
from app.bounty_autopilot.evidence_judge import EvidenceJudgeVerdict
from app.bounty_autopilot.gateway import GatewayOutcomeClass
from app.bounty_autopilot.observations import HumanEvidenceGrade, ObservationGrade
from app.bounty_autopilot.refutation import RefutationVerdict


_SAFE_REF = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$", re.ASCII)


def _require_safe_reference(value: str, reason: str) -> str:
    if _SAFE_REF.fullmatch(value) is None:
        raise ValueError(reason)
    return value


def _normalize_safe_references(values: tuple[str, ...], reason: str) -> tuple[str, ...]:
    if len(set(values)) != len(values):
        raise ValueError("duplicate_lineage_reference")
    if any(_SAFE_REF.fullmatch(value) is None for value in values):
        raise ValueError(reason)
    return tuple(sorted(values))


class AutopilotRiskDecisionRecord(StrictContract):
    """Server-derived planning decision, retained without model reasoning."""

    risk_decision_id: str
    campaign_id: str
    authorization_id: str
    authorization_digest: str
    scope_snapshot_digest: str
    asset_id: str
    branch_id: str
    recipe_ref: RecipeRef
    risk_tier: RiskTier
    status: Literal[
        "authorized",
        "denied",
        "policy_mode_blocks_active_execution",
        "awaiting_exact_approval",
        "prohibited",
    ]
    reason_code: str
    decided_at: datetime
    execution_authorized: Literal[False] = False
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False

    @field_validator(
        "risk_decision_id",
        "campaign_id",
        "authorization_id",
        "asset_id",
        "branch_id",
        "reason_code",
    )
    @classmethod
    def require_safe_references(cls, value: str) -> str:
        return _require_safe_reference(value, "safe_risk_decision_reference_required")

    @field_validator("authorization_digest", "scope_snapshot_digest")
    @classmethod
    def require_digests(cls, value: str) -> str:
        if DIGEST_PATTERN.fullmatch(value) is None:
            raise ValueError("risk_decision_digest_required")
        return value

    @field_validator("decided_at")
    @classmethod
    def normalize_decided_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timezone_aware_datetime_required")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def require_risk_state_alignment(self) -> AutopilotRiskDecisionRecord:
        if self.risk_tier == "R4" and self.status != "prohibited":
            raise ValueError("r4_decision_must_be_prohibited")
        if self.risk_tier == "R3" and self.status not in {
            "awaiting_exact_approval",
            "denied",
            "prohibited",
        }:
            raise ValueError("r3_decision_requires_exact_approval")
        return self


class AutopilotToolRunRecord(StrictContract):
    """One bounded execution attempt and its complete authority lineage."""

    tool_run_id: str
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
    isolation_profile: Literal["docker", "wsl"]
    gateway_decision: Literal["allowed", "blocked", "not_evaluated"]
    request_sent: bool = False
    run_status: Literal[
        "completed",
        "blocked",
        "discarded",
        "awaiting_human",
        "no_send_failure",
    ]
    outcome_class: GatewayOutcomeClass
    outcome_code: str
    occurred_at: datetime
    third_party_data_discarded: bool = False
    raw_content_retained: Literal[False] = False
    raw_secret_retained: Literal[False] = False
    request_content_retained: Literal[False] = False
    response_content_retained: Literal[False] = False
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False

    @field_validator(
        "tool_run_id",
        "campaign_id",
        "authorization_id",
        "asset_id",
        "branch_id",
        "plan_id",
        "risk_decision_id",
        "lease_id",
        "reservation_id",
        "outcome_code",
    )
    @classmethod
    def require_safe_references(cls, value: str) -> str:
        return _require_safe_reference(value, "safe_tool_run_reference_required")

    @field_validator(
        "authorization_digest",
        "scope_snapshot_digest",
        "asset_identity_digest",
        "plan_digest",
    )
    @classmethod
    def require_digests(cls, value: str) -> str:
        if DIGEST_PATTERN.fullmatch(value) is None:
            raise ValueError("tool_run_digest_required")
        return value

    @field_validator("occurred_at")
    @classmethod
    def normalize_occurred_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timezone_aware_datetime_required")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def require_safe_outcome(self) -> AutopilotToolRunRecord:
        if self.risk_tier == "R4":
            raise ValueError("r4_tool_run_impossible")
        is_third_party = self.outcome_class is GatewayOutcomeClass.THIRD_PARTY_DATA
        if is_third_party != self.third_party_data_discarded:
            raise ValueError("third_party_discard_state_required")
        if is_third_party and self.run_status != "discarded":
            raise ValueError("third_party_run_must_be_discarded")
        if self.gateway_decision != "allowed" and self.request_sent:
            raise ValueError("gateway_block_must_stop_before_send")
        if self.run_status == "blocked" and self.gateway_decision == "allowed":
            raise ValueError("blocked_run_requires_gateway_block")
        return self


class EvidenceClaimRecord(StrictContract):
    claim_id: str
    campaign_id: str
    hypothesis_id: str
    observation_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    evidence_grade: ObservationGrade
    lineage_digest: str
    summary_code: str
    created_at: datetime
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False

    @field_validator("claim_id", "campaign_id", "hypothesis_id", "summary_code")
    @classmethod
    def require_safe_references(cls, value: str) -> str:
        return _require_safe_reference(value, "safe_evidence_claim_reference_required")

    @field_validator("observation_ids")
    @classmethod
    def normalize_observation_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _normalize_safe_references(value, "safe_observation_reference_required")

    @field_validator("lineage_digest")
    @classmethod
    def require_lineage_digest(cls, value: str) -> str:
        if DIGEST_PATTERN.fullmatch(value) is None:
            raise ValueError("evidence_claim_lineage_digest_required")
        return value

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timezone_aware_datetime_required")
        return value.astimezone(timezone.utc)


class RefutationDecisionRecord(StrictContract):
    decision_id: str
    campaign_id: str
    case_id: str
    hypothesis_id: str
    branch_id: str
    observation_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    lineage_digest: str
    verdict: RefutationVerdict
    created_at: datetime
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False

    @field_validator("decision_id", "campaign_id", "case_id", "hypothesis_id", "branch_id")
    @classmethod
    def require_safe_references(cls, value: str) -> str:
        return _require_safe_reference(value, "safe_refutation_decision_reference_required")

    @field_validator("observation_ids")
    @classmethod
    def normalize_observation_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _normalize_safe_references(value, "safe_observation_reference_required")

    @field_validator("lineage_digest")
    @classmethod
    def require_lineage_digest(cls, value: str) -> str:
        if DIGEST_PATTERN.fullmatch(value) is None:
            raise ValueError("refutation_decision_lineage_digest_required")
        return value

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timezone_aware_datetime_required")
        return value.astimezone(timezone.utc)


class CandidateRevisionRecord(StrictContract):
    revision_id: str
    candidate_id: str
    campaign_id: str
    hypothesis_id: str
    branch_id: str
    evidence_claim_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    refutation_decision_id: str
    judge_verdict: EvidenceJudgeVerdict
    lineage_digest: str
    created_at: datetime
    confirmed: Literal[False] = False
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False

    @field_validator(
        "revision_id",
        "candidate_id",
        "campaign_id",
        "hypothesis_id",
        "branch_id",
        "refutation_decision_id",
    )
    @classmethod
    def require_safe_references(cls, value: str) -> str:
        return _require_safe_reference(value, "safe_candidate_revision_reference_required")

    @field_validator("evidence_claim_ids")
    @classmethod
    def normalize_claim_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _normalize_safe_references(value, "safe_evidence_claim_reference_required")

    @field_validator("lineage_digest")
    @classmethod
    def require_lineage_digest(cls, value: str) -> str:
        if DIGEST_PATTERN.fullmatch(value) is None:
            raise ValueError("candidate_revision_lineage_digest_required")
        return value

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timezone_aware_datetime_required")
        return value.astimezone(timezone.utc)


class ReportRevisionRecord(StrictContract):
    revision_id: str
    report_id: str
    candidate_id: str
    campaign_id: str
    evidence_claim_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    lineage_digest: str
    evidence_grade: ObservationGrade
    created_at: datetime
    submission_blocked: Literal[True] = True
    automatic_submission_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False

    @field_validator("revision_id", "report_id", "candidate_id", "campaign_id")
    @classmethod
    def require_safe_references(cls, value: str) -> str:
        return _require_safe_reference(value, "safe_report_revision_reference_required")

    @field_validator("evidence_claim_ids")
    @classmethod
    def normalize_claim_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _normalize_safe_references(value, "safe_evidence_claim_reference_required")

    @field_validator("lineage_digest")
    @classmethod
    def require_lineage_digest(cls, value: str) -> str:
        if DIGEST_PATTERN.fullmatch(value) is None:
            raise ValueError("report_revision_lineage_digest_required")
        return value

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timezone_aware_datetime_required")
        return value.astimezone(timezone.utc)


class HumanEvidenceReviewRecord(StrictContract):
    review_id: str
    campaign_id: str
    hypothesis_id: str
    observation_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    grade: HumanEvidenceGrade
    decision_code: Literal[
        "verified_sanitized_owned_account_evidence",
        "reproduced_sanitized_owned_account_evidence",
    ]
    reviewer_alias: str
    reviewed_at: datetime
    automated_source: Literal[False] = False
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False

    @field_validator("review_id", "campaign_id", "hypothesis_id", "reviewer_alias")
    @classmethod
    def require_safe_references(cls, value: str) -> str:
        return _require_safe_reference(value, "safe_human_review_reference_required")

    @field_validator("observation_ids")
    @classmethod
    def normalize_observation_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _normalize_safe_references(value, "safe_observation_reference_required")

    @field_validator("reviewed_at")
    @classmethod
    def normalize_reviewed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timezone_aware_datetime_required")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def require_grade_decision_alignment(self) -> HumanEvidenceReviewRecord:
        if self.grade is HumanEvidenceGrade.L4_HUMAN_VERIFIED and self.decision_code != (
            "verified_sanitized_owned_account_evidence"
        ):
            raise ValueError("l4_review_decision_required")
        if self.grade is HumanEvidenceGrade.L5_HUMAN_REPRODUCED and self.decision_code != (
            "reproduced_sanitized_owned_account_evidence"
        ):
            raise ValueError("l5_review_decision_required")
        return self


__all__ = [
    "AutopilotRiskDecisionRecord",
    "AutopilotToolRunRecord",
    "CandidateRevisionRecord",
    "EvidenceClaimRecord",
    "HumanEvidenceReviewRecord",
    "RefutationDecisionRecord",
    "ReportRevisionRecord",
]
