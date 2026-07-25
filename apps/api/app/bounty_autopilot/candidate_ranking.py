"""Rank retained Autopilot hypotheses for human validation review."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field

from app.bounty_autopilot.contracts import StrictContract
from app.bounty_autopilot.observations import ObservationGrade
from app.bounty_autopilot.refutation import RefutationVerdict


class CandidateImpact(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CandidateReviewState(str, Enum):
    NEEDS_EVIDENCE = "needs_evidence"
    HUMAN_VALIDATION_REVIEW = "human_validation_review"
    REPORT_DRAFT_READY = "report_draft_ready"


class CandidateRankingInput(StrictContract):
    hypothesis_id: str = Field(min_length=1, max_length=128)
    branch_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=256)
    vulnerability_type: str = Field(min_length=1, max_length=128)
    affected_endpoint: str | None = Field(default=None, max_length=256)
    affected_code_path: str | None = Field(default=None, max_length=256)
    impact: CandidateImpact = CandidateImpact.MEDIUM
    confidence: int = Field(ge=0, le=100, default=50)
    evidence_grade: ObservationGrade = ObservationGrade.L1_HINT
    refutation_verdict: RefutationVerdict = RefutationVerdict.NEEDS_EVIDENCE
    evidence_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    safety_blockers: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    report_draft_ready: bool = False


class RankedCandidate(StrictContract):
    hypothesis_id: str
    branch_id: str
    title: str
    vulnerability_type: str
    affected_endpoint: str | None = None
    affected_code_path: str | None = None
    rank_score: int = Field(ge=0, le=100)
    rank_reasons: tuple[str, ...] = Field(min_length=1, max_length=16)
    review_state: CandidateReviewState
    evidence_grade: ObservationGrade
    evidence_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    safety_blockers: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    validation_allowed: Literal[False] = False
    validation_requires_human_approval: Literal[True] = True
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False
    submission_blocked: Literal[True] = True


_IMPACT_SCORE = {
    CandidateImpact.LOW: 8,
    CandidateImpact.MEDIUM: 18,
    CandidateImpact.HIGH: 30,
    CandidateImpact.CRITICAL: 38,
}
_EVIDENCE_SCORE = {
    ObservationGrade.L0_NOISE: 0,
    ObservationGrade.L1_HINT: 8,
    ObservationGrade.L2_CORROBORATED: 22,
    ObservationGrade.L3_ACTIONABLE: 34,
}


def rank_candidates(
    candidates: list[CandidateRankingInput] | tuple[CandidateRankingInput, ...],
    *,
    limit: int = 5,
) -> tuple[RankedCandidate, ...]:
    """Return a small, safe review queue of the strongest non-refuted candidates."""

    if limit < 1 or limit > 5:
        raise ValueError("candidate_rank_limit_must_be_1_to_5")

    ranked = [
        _rank_candidate(candidate)
        for candidate in candidates
        if candidate.refutation_verdict
        not in {RefutationVerdict.REFUTED, RefutationVerdict.DUPLICATE}
    ]
    ranked.sort(key=lambda item: (-item.rank_score, item.hypothesis_id))
    return tuple(ranked[:limit])


def _rank_candidate(candidate: CandidateRankingInput) -> RankedCandidate:
    reasons: list[str] = [
        f"impact:{candidate.impact.value}",
        f"evidence:{candidate.evidence_grade.value}",
    ]
    score = (
        _IMPACT_SCORE[candidate.impact]
        + _EVIDENCE_SCORE[candidate.evidence_grade]
        + candidate.confidence // 5
    )
    if candidate.affected_endpoint:
        score += 3
        reasons.append("endpoint_linked")
    if candidate.affected_code_path:
        score += 3
        reasons.append("code_path_linked")
    if candidate.refutation_verdict is RefutationVerdict.RETAINED:
        score += 12
        reasons.append("refutation_retained")
    if not candidate.evidence_refs:
        score -= 15
        reasons.append("needs_evidence")
    if candidate.safety_blockers:
        score -= 20 + min(10, 2 * (len(candidate.safety_blockers) - 1))
        reasons.append("safety_blocked")

    review_state = CandidateReviewState.HUMAN_VALIDATION_REVIEW
    if (
        candidate.report_draft_ready
        and candidate.evidence_grade is ObservationGrade.L3_ACTIONABLE
        and candidate.refutation_verdict is RefutationVerdict.RETAINED
        and not candidate.safety_blockers
    ):
        review_state = CandidateReviewState.REPORT_DRAFT_READY
        reasons.append("report_draft_ready")
    elif (
        candidate.refutation_verdict is RefutationVerdict.NEEDS_EVIDENCE
        or not candidate.evidence_refs
    ):
        review_state = CandidateReviewState.NEEDS_EVIDENCE

    return RankedCandidate(
        hypothesis_id=candidate.hypothesis_id,
        branch_id=candidate.branch_id,
        title=candidate.title,
        vulnerability_type=candidate.vulnerability_type,
        affected_endpoint=candidate.affected_endpoint,
        affected_code_path=candidate.affected_code_path,
        rank_score=max(0, min(100, score)),
        rank_reasons=tuple(reasons[:16]),
        review_state=review_state,
        evidence_grade=candidate.evidence_grade,
        evidence_refs=candidate.evidence_refs,
        safety_blockers=candidate.safety_blockers,
    )


__all__ = [
    "CandidateImpact",
    "CandidateRankingInput",
    "CandidateReviewState",
    "RankedCandidate",
    "rank_candidates",
]
