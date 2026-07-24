"""Bounded evidence judging and submission-blocked report drafts."""

from __future__ import annotations

import re
from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from app.bounty_autopilot.contracts import DIGEST_PATTERN, StrictContract, canonical_sha256
from app.bounty_autopilot.observations import ObservationGrade, ObservationRecord
from app.bounty_autopilot.refutation import (
    RefutationResult,
    RefutationVerdict,
    refutation_lineage_digest,
)

_SAFE_REPORT_REF = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$", re.ASCII)


class EvidenceJudgeVerdict(str, Enum):
    REFUTED = "refuted"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    RETAINED_CANDIDATE = "retained_candidate"
    NEEDS_HUMAN_REVIEW = "needs_human_review"
    BLOCKED_BY_POLICY = "blocked_by_policy"


class EvidenceJudgeResult(StrictContract):
    hypothesis_id: str
    campaign_id: str | None = None
    branch_id: str
    observation_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    refutation_lineage_digest: str
    lineage_digest: str | None = None
    lineage_complete: bool = False
    verdict: EvidenceJudgeVerdict
    evidence_grade: ObservationGrade
    reasons: tuple[str, ...] = Field(min_length=1, max_length=16)
    evidence_gap_codes: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False
    submission_blocked: Literal[True] = True

    @field_validator("hypothesis_id", "branch_id", "observation_ids")
    @classmethod
    def require_safe_refs(cls, value):
        values = value if isinstance(value, tuple) else (value,)
        if any(
            not isinstance(item, str)
            or not item
            or len(item) > 128
            or not item.replace("_", "").replace("-", "").replace(":", "").isalnum()
            for item in values
        ):
            raise ValueError("safe_evidence_judge_reference_required")
        return value

    @field_validator("refutation_lineage_digest", "lineage_digest")
    @classmethod
    def require_digests(cls, value: str | None) -> str | None:
        if value is not None and DIGEST_PATTERN.fullmatch(value) is None:
            raise ValueError("evidence_judge_lineage_digest_required")
        return value

    @model_validator(mode="after")
    def require_retained_lineage(self) -> EvidenceJudgeResult:
        if self.verdict is EvidenceJudgeVerdict.RETAINED_CANDIDATE and (
            self.evidence_grade is not ObservationGrade.L3_ACTIONABLE
            or self.campaign_id is None
            or not self.observation_ids
            or self.lineage_digest is None
            or not self.lineage_complete
        ):
            raise ValueError("retained_candidate_lineage_required")
        return self


def judge_evidence(
    *,
    hypothesis_id: str,
    observations: list[ObservationRecord] | tuple[ObservationRecord, ...],
    refutation: RefutationResult,
) -> EvidenceJudgeResult:
    observations = tuple(observations)
    lineage = _validated_lineage(
        hypothesis_id=hypothesis_id,
        observations=observations,
        refutation=refutation,
    )
    if refutation.verdict is RefutationVerdict.BLOCKED_BY_POLICY:
        return _judge_result(
            hypothesis_id,
            EvidenceJudgeVerdict.BLOCKED_BY_POLICY,
            "policy_blocked",
            lineage=lineage,
        )
    if refutation.verdict is RefutationVerdict.REFUTED:
        return _judge_result(
            hypothesis_id, EvidenceJudgeVerdict.REFUTED, "refuted", lineage=lineage
        )
    if refutation.verdict is RefutationVerdict.DUPLICATE_REVIEW:
        return _judge_result(
            hypothesis_id,
            EvidenceJudgeVerdict.NEEDS_HUMAN_REVIEW,
            "duplicate_review_required",
            grade=ObservationGrade.L1_HINT,
            lineage=lineage,
        )
    if any(item.third_party_data_discarded for item in observations):
        return _judge_result(
            hypothesis_id,
            EvidenceJudgeVerdict.BLOCKED_BY_POLICY,
            "third_party_data_discarded",
            lineage=lineage,
        )
    if refutation.verdict is RefutationVerdict.NEEDS_EVIDENCE or not observations:
        return _judge_result(
            hypothesis_id,
            EvidenceJudgeVerdict.INSUFFICIENT_EVIDENCE,
            "evidence_gaps_remain",
            grade=ObservationGrade.L1_HINT,
            gaps=refutation.reasons,
            lineage=lineage,
        )
    best = max(observations, key=lambda item: list(ObservationGrade).index(item.grade)).grade
    if best is ObservationGrade.L3_ACTIONABLE:
        return _judge_result(
            hypothesis_id,
            EvidenceJudgeVerdict.RETAINED_CANDIDATE,
            "sanitized_l3_retained",
            grade=best,
            lineage=lineage,
            lineage_complete=True,
        )
    return _judge_result(
        hypothesis_id,
        EvidenceJudgeVerdict.INSUFFICIENT_EVIDENCE,
        "l3_evidence_required",
        grade=best,
        gaps=("independent_l3_observation_required",),
        lineage=lineage,
    )


def _judge_result(
    hypothesis_id: str,
    verdict: EvidenceJudgeVerdict,
    reason: str,
    *,
    grade: ObservationGrade = ObservationGrade.L0_NOISE,
    gaps: tuple[str, ...] = (),
    lineage: dict[str, object],
    lineage_complete: bool = False,
) -> EvidenceJudgeResult:
    return EvidenceJudgeResult(
        hypothesis_id=hypothesis_id,
        campaign_id=lineage["campaign_id"],
        branch_id=str(lineage["branch_id"]),
        observation_ids=tuple(lineage["observation_ids"]),
        refutation_lineage_digest=str(lineage["refutation_lineage_digest"]),
        lineage_digest=lineage["lineage_digest"],
        lineage_complete=lineage_complete,
        verdict=verdict,
        evidence_grade=grade,
        reasons=(reason,),
        evidence_gap_codes=tuple(sorted(gaps)),
    )


class SubmissionBlockedReportDraft(StrictContract):
    report_id: str
    hypothesis_id: str
    campaign_id: str
    branch_id: str
    observation_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    lineage_digest: str
    title: str = Field(min_length=1, max_length=160)
    summary: str = Field(min_length=1, max_length=1000)
    evidence_grade: ObservationGrade
    evidence_refs: tuple[str, ...] = Field(min_length=1, max_length=32)
    evidence_gap_codes: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    lineage_complete: Literal[True]
    submission_blocked: Literal[True] = True
    automatic_submission_allowed: Literal[False] = False

    @field_validator("evidence_refs")
    @classmethod
    def require_safe_evidence_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(values)) != len(values):
            raise ValueError("duplicate_report_evidence_ref")
        if any(_SAFE_REPORT_REF.fullmatch(value) is None for value in values):
            raise ValueError("safe_report_evidence_ref_required")
        return tuple(sorted(values))

    @model_validator(mode="after")
    def require_sanitized_copy(self) -> SubmissionBlockedReportDraft:
        from app.mythos_report import safe_preview_text

        if (
            safe_preview_text(self.title) != self.title
            or safe_preview_text(self.summary) != self.summary
        ):
            raise ValueError("report_copy_contains_sensitive_material")
        return self


def build_submission_blocked_report(
    *,
    report_id: str,
    hypothesis_id: str,
    title: str,
    summary: str,
    evidence_refs: tuple[str, ...],
    judge_result: EvidenceJudgeResult,
    lineage_complete: bool | None = None,
) -> SubmissionBlockedReportDraft:
    if judge_result.verdict is not EvidenceJudgeVerdict.RETAINED_CANDIDATE:
        raise ValueError("retained_candidate_required")
    if hypothesis_id != judge_result.hypothesis_id:
        raise ValueError("judge_hypothesis_lineage_mismatch")
    if lineage_complete is False or not judge_result.lineage_complete:
        raise ValueError("autopilot_lineage_incomplete")
    return SubmissionBlockedReportDraft(
        report_id=report_id,
        hypothesis_id=hypothesis_id,
        campaign_id=judge_result.campaign_id or "",
        branch_id=judge_result.branch_id,
        observation_ids=judge_result.observation_ids,
        lineage_digest=judge_result.lineage_digest or "",
        title=title,
        summary=summary,
        evidence_grade=judge_result.evidence_grade,
        evidence_refs=evidence_refs,
        evidence_gap_codes=judge_result.evidence_gap_codes,
        lineage_complete=True,
    )


def _validated_lineage(
    *,
    hypothesis_id: str,
    observations: tuple[ObservationRecord, ...],
    refutation: RefutationResult,
) -> dict[str, object]:
    if refutation.hypothesis_id != hypothesis_id:
        raise ValueError("refutation_hypothesis_lineage_mismatch")
    expected_refutation_digest = refutation_lineage_digest(
        case_id=refutation.case_id,
        hypothesis_id=refutation.hypothesis_id,
        branch_id=refutation.branch_id,
        observations_cited=refutation.observations_cited,
        completed_checks=refutation.completed_checks,
    )
    if refutation.lineage_digest != expected_refutation_digest:
        raise ValueError("refutation_lineage_digest_mismatch")
    observation_ids = tuple(sorted(item.observation_id for item in observations))
    if observations and (
        len({item.campaign_id for item in observations}) != 1
        or len({item.branch_id for item in observations}) != 1
        or observations[0].branch_id != refutation.branch_id
        or observation_ids != tuple(sorted(refutation.observations_cited))
    ):
        raise ValueError("observation_refutation_lineage_mismatch")
    campaign_id = observations[0].campaign_id if observations else None
    branch_id = observations[0].branch_id if observations else refutation.branch_id
    lineage_digest = (
        evidence_lineage_digest(
            observations=observations,
            refutation_lineage_digest=refutation.lineage_digest,
        )
        if observations
        else None
    )
    return {
        "campaign_id": campaign_id,
        "branch_id": branch_id,
        "observation_ids": observation_ids,
        "refutation_lineage_digest": refutation.lineage_digest,
        "lineage_digest": lineage_digest,
    }


def evidence_lineage_digest(
    *,
    observations: tuple[ObservationRecord, ...],
    refutation_lineage_digest: str,
) -> str:
    if not observations:
        raise ValueError("observation_lineage_required")
    ordered_observations = tuple(
        sorted(observations, key=lambda item: item.observation_id)
    )
    return canonical_sha256(
        {
            "schema_version": "bounty-autopilot-evidence-lineage/v1",
            "campaign_id": ordered_observations[0].campaign_id,
            "branch_id": ordered_observations[0].branch_id,
            "refutation_lineage_digest": refutation_lineage_digest,
            "observations": [
                {
                    "observation_id": item.observation_id,
                    "authorization_id": item.authorization_id,
                    "authorization_digest": item.authorization_digest,
                    "scope_snapshot_digest": item.scope_snapshot_digest,
                    "asset_id": item.asset_id,
                    "asset_identity_digest": item.asset_identity_digest,
                    "plan_id": item.plan_id,
                    "plan_digest": item.plan_digest,
                    "risk_decision_id": item.risk_decision_id,
                    "risk_tier": str(item.risk_tier),
                    "recipe_ref": item.recipe_ref.model_dump(mode="json"),
                    "lease_id": item.lease_id,
                    "reservation_id": item.reservation_id,
                    "session_generation": item.session_generation,
                    "tool_run_id": item.tool_run_id,
                }
                for item in ordered_observations
            ],
        }
    )


__all__ = [
    "EvidenceJudgeResult",
    "EvidenceJudgeVerdict",
    "SubmissionBlockedReportDraft",
    "build_submission_blocked_report",
    "evidence_lineage_digest",
    "judge_evidence",
]
