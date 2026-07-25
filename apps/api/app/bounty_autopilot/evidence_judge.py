"""Evidence judge grades and submission-blocked report readiness."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field

from app.bounty_autopilot.contracts import StrictContract
from app.bounty_autopilot.observations import ObservationGrade, ObservationRecord
from app.bounty_autopilot.refutation import RefutationResult, RefutationVerdict


class EvidenceJudgeVerdict(str, Enum):
    DISCARD = "discard"
    NEEDS_EVIDENCE = "needs_evidence"
    RETAIN_CANDIDATE = "retain_candidate"
    REPORT_DRAFT_READY = "report_draft_ready"


class EvidenceJudgeResult(StrictContract):
    hypothesis_id: str
    verdict: EvidenceJudgeVerdict
    evidence_grade: ObservationGrade
    reasons: tuple[str, ...] = Field(min_length=1, max_length=16)
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False
    submission_blocked: Literal[True] = True


def judge_evidence(
    *,
    hypothesis_id: str,
    observations: list[ObservationRecord] | tuple[ObservationRecord, ...],
    refutation: RefutationResult,
) -> EvidenceJudgeResult:
    if refutation.verdict is RefutationVerdict.REFUTED:
        return EvidenceJudgeResult(
            hypothesis_id=hypothesis_id,
            verdict=EvidenceJudgeVerdict.DISCARD,
            evidence_grade=ObservationGrade.L0_NOISE,
            reasons=("refuted", *refutation.reasons),
        )
    if refutation.verdict is RefutationVerdict.DUPLICATE:
        return EvidenceJudgeResult(
            hypothesis_id=hypothesis_id,
            verdict=EvidenceJudgeVerdict.DISCARD,
            evidence_grade=ObservationGrade.L1_HINT,
            reasons=("duplicate",),
        )
    if refutation.verdict is RefutationVerdict.NEEDS_EVIDENCE or not observations:
        return EvidenceJudgeResult(
            hypothesis_id=hypothesis_id,
            verdict=EvidenceJudgeVerdict.NEEDS_EVIDENCE,
            evidence_grade=ObservationGrade.L1_HINT,
            reasons=("needs_evidence",),
        )
    if any(item.third_party_data_discarded for item in observations):
        return EvidenceJudgeResult(
            hypothesis_id=hypothesis_id,
            verdict=EvidenceJudgeVerdict.DISCARD,
            evidence_grade=ObservationGrade.L0_NOISE,
            reasons=("third_party_data_present",),
        )
    grades = [item.grade for item in observations]
    best = max(grades, key=lambda g: list(ObservationGrade).index(g))
    if best is ObservationGrade.L3_ACTIONABLE:
        return EvidenceJudgeResult(
            hypothesis_id=hypothesis_id,
            verdict=EvidenceJudgeVerdict.REPORT_DRAFT_READY,
            evidence_grade=best,
            reasons=("l3_actionable_sanitized_evidence", "submission_blocked"),
        )
    if best in {ObservationGrade.L2_CORROBORATED, ObservationGrade.L1_HINT}:
        return EvidenceJudgeResult(
            hypothesis_id=hypothesis_id,
            verdict=EvidenceJudgeVerdict.RETAIN_CANDIDATE,
            evidence_grade=best,
            reasons=("retained_for_human_review",),
        )
    return EvidenceJudgeResult(
        hypothesis_id=hypothesis_id,
        verdict=EvidenceJudgeVerdict.DISCARD,
        evidence_grade=ObservationGrade.L0_NOISE,
        reasons=("insufficient_grade",),
    )


class SubmissionBlockedReportDraft(StrictContract):
    report_id: str
    hypothesis_id: str
    title: str
    summary: str
    evidence_refs: tuple[str, ...]
    submission_blocked: Literal[True] = True
    automatic_submission_allowed: Literal[False] = False


def build_submission_blocked_report(
    *,
    report_id: str,
    hypothesis_id: str,
    title: str,
    summary: str,
    evidence_refs: tuple[str, ...],
) -> SubmissionBlockedReportDraft:
    return SubmissionBlockedReportDraft(
        report_id=report_id,
        hypothesis_id=hypothesis_id,
        title=title,
        summary=summary,
        evidence_refs=evidence_refs,
    )


__all__ = [
    "EvidenceJudgeResult",
    "EvidenceJudgeVerdict",
    "SubmissionBlockedReportDraft",
    "build_submission_blocked_report",
    "judge_evidence",
]
