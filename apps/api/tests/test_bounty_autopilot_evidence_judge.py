"""Phase 8 evidence judge tests."""

from app.bounty_autopilot.evidence_judge import (
    EvidenceJudgeVerdict,
    build_submission_blocked_report,
    judge_evidence,
)
from app.bounty_autopilot.gateway import GatewayOutcomeClass
from app.bounty_autopilot.observations import ObservationGrade, build_observation
from app.bounty_autopilot.refutation import RefutationResult, RefutationVerdict


def test_l3_yields_submission_blocked_report_ready():
    obs = build_observation(
        observation_id="obs_1",
        campaign_id="c1",
        branch_id="b1",
        plan_digest="sha256:" + ("a" * 64),
        outcome_class=GatewayOutcomeClass.OK,
        summary="cross account denied missing",
        grade=ObservationGrade.L3_ACTIONABLE,
        evidence_refs=("sanitized_request_response",),
    )
    result = judge_evidence(
        hypothesis_id="h1",
        observations=[obs],
        refutation=RefutationResult(
            case_id="case_1",
            verdict=RefutationVerdict.RETAINED,
            reasons=("independent_refutation_incomplete",),
        ),
    )
    assert result.verdict is EvidenceJudgeVerdict.REPORT_DRAFT_READY
    assert result.submission_blocked is True
    assert result.report_submission_allowed is False
    draft = build_submission_blocked_report(
        report_id="rep_1",
        hypothesis_id="h1",
        title="Object authz failure",
        summary="sanitized",
        evidence_refs=("sanitized_request_response",),
    )
    assert draft.automatic_submission_allowed is False


def test_duplicate_refutation_discards_even_with_l3_observation():
    obs = build_observation(
        observation_id="obs_2",
        campaign_id="c1",
        branch_id="b1",
        plan_digest="sha256:" + ("d" * 64),
        outcome_class=GatewayOutcomeClass.OK,
        summary="same root already represented by canonical hypothesis",
        grade=ObservationGrade.L3_ACTIONABLE,
        evidence_refs=("sanitized_request_response",),
    )
    result = judge_evidence(
        hypothesis_id="h2",
        observations=[obs],
        refutation=RefutationResult(
            case_id="case_2",
            verdict=RefutationVerdict.DUPLICATE,
            reasons=("duplicate_hypothesis",),
            duplicate_of_hypothesis_id="h1",
        ),
    )

    assert result.verdict is EvidenceJudgeVerdict.DISCARD
    assert result.reasons == ("duplicate",)
    assert result.candidate_promotion_allowed is False
    assert result.report_submission_allowed is False
    assert result.submission_blocked is True
