"""Autopilot candidate ranking stays evidence-led and approval-gated."""

import pytest

from app.bounty_autopilot.candidate_ranking import (
    CandidateImpact,
    CandidateRankingInput,
    CandidateReviewState,
    rank_candidates,
)
from app.bounty_autopilot.observations import ObservationGrade
from app.bounty_autopilot.refutation import RefutationVerdict


def _candidate(
    hypothesis_id: str,
    *,
    impact: CandidateImpact = CandidateImpact.MEDIUM,
    confidence: int = 50,
    evidence_grade: ObservationGrade = ObservationGrade.L1_HINT,
    refutation_verdict: RefutationVerdict = RefutationVerdict.RETAINED,
    evidence_refs: tuple[str, ...] = ("obs_1",),
    safety_blockers: tuple[str, ...] = (),
    report_draft_ready: bool = False,
) -> CandidateRankingInput:
    return CandidateRankingInput(
        hypothesis_id=hypothesis_id,
        branch_id=f"branch_{hypothesis_id}",
        title=f"Candidate {hypothesis_id}",
        vulnerability_type="object_authorization",
        affected_endpoint=f"/api/{hypothesis_id}",
        affected_code_path=f"handlers/{hypothesis_id}.py:read",
        impact=impact,
        confidence=confidence,
        evidence_grade=evidence_grade,
        refutation_verdict=refutation_verdict,
        evidence_refs=evidence_refs,
        safety_blockers=safety_blockers,
        report_draft_ready=report_draft_ready,
    )


def test_rank_candidates_prefers_actionable_retained_evidence():
    ranked = rank_candidates(
        (
            _candidate(
                "h_low_signal",
                impact=CandidateImpact.CRITICAL,
                confidence=90,
                evidence_grade=ObservationGrade.L1_HINT,
                refutation_verdict=RefutationVerdict.NEEDS_EVIDENCE,
                evidence_refs=(),
            ),
            _candidate(
                "h_actionable",
                impact=CandidateImpact.HIGH,
                confidence=85,
                evidence_grade=ObservationGrade.L3_ACTIONABLE,
                report_draft_ready=True,
            ),
            _candidate(
                "h_blocked",
                impact=CandidateImpact.CRITICAL,
                confidence=95,
                evidence_grade=ObservationGrade.L3_ACTIONABLE,
                safety_blockers=("scope_review_required",),
            ),
        )
    )

    assert [item.hypothesis_id for item in ranked] == [
        "h_actionable",
        "h_blocked",
        "h_low_signal",
    ]
    assert ranked[0].review_state is CandidateReviewState.REPORT_DRAFT_READY
    assert "report_draft_ready" in ranked[0].rank_reasons
    assert ranked[0].validation_allowed is False
    assert ranked[0].validation_requires_human_approval is True
    assert ranked[0].candidate_promotion_allowed is False
    assert ranked[0].report_submission_allowed is False
    assert ranked[0].submission_blocked is True


def test_rank_candidates_filters_refuted_and_duplicate_noise():
    ranked = rank_candidates(
        (
            _candidate("h_keep", evidence_grade=ObservationGrade.L2_CORROBORATED),
            _candidate(
                "h_refuted",
                impact=CandidateImpact.CRITICAL,
                evidence_grade=ObservationGrade.L3_ACTIONABLE,
                refutation_verdict=RefutationVerdict.REFUTED,
            ),
            _candidate(
                "h_duplicate",
                impact=CandidateImpact.CRITICAL,
                evidence_grade=ObservationGrade.L3_ACTIONABLE,
                refutation_verdict=RefutationVerdict.DUPLICATE,
            ),
        )
    )

    assert [item.hypothesis_id for item in ranked] == ["h_keep"]


def test_rank_candidates_limits_review_queue_to_five():
    ranked = rank_candidates(
        tuple(
            _candidate(
                f"h_{index}",
                impact=CandidateImpact.HIGH,
                confidence=80 - index,
                evidence_grade=ObservationGrade.L2_CORROBORATED,
            )
            for index in range(8)
        )
    )

    assert len(ranked) == 5
    assert [item.hypothesis_id for item in ranked] == [
        "h_0",
        "h_1",
        "h_2",
        "h_3",
        "h_4",
    ]


@pytest.mark.parametrize("limit", (0, 6))
def test_rank_candidates_rejects_limits_outside_north_star_queue_size(limit):
    with pytest.raises(ValueError, match="candidate_rank_limit_must_be_1_to_5"):
        rank_candidates((_candidate("h1"),), limit=limit)
