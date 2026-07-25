"""Submission-blocked report readiness for Autopilot evidence."""

from app.bounty_autopilot.evidence_judge import (
    EvidenceJudgeVerdict,
    build_submission_blocked_report,
    judge_evidence,
)
from app.bounty_autopilot.gateway import GatewayOutcomeClass
from app.bounty_autopilot.observations import ObservationGrade, build_observation
from app.bounty_autopilot.refutation import RefutationCase, RefutationVerdict, refute_candidate


def _digest(n: str = "a") -> str:
    return "sha256:" + (n * 64)


def test_true_candidate_report_is_submission_blocked():
    obs = build_observation(
        observation_id="obs_true",
        campaign_id="lab",
        branch_id="branch_authz",
        plan_digest=_digest("a"),
        outcome_class=GatewayOutcomeClass.OK,
        summary="cross-account object readable",
        grade=ObservationGrade.L3_ACTIONABLE,
        evidence_refs=("diff:object_owner",),
    )
    retained = refute_candidate(
        RefutationCase(
            case_id="true_object_authz",
            hypothesis_id="h_object_authz",
            branch_id="branch_authz",
            claim_summary="object authz failure",
            counter_questions=("middleware?", "ownership?"),
            observations_cited=(obs.observation_id,),
        )
    )
    assert retained.verdict is RefutationVerdict.RETAINED
    judged = judge_evidence(
        hypothesis_id="h_object_authz",
        observations=[obs],
        refutation=retained,
    )
    assert judged.verdict is EvidenceJudgeVerdict.REPORT_DRAFT_READY
    assert judged.report_submission_allowed is False
    assert judged.submission_blocked is True
    assert judged.candidate_promotion_allowed is False

    draft = build_submission_blocked_report(
        report_id="rpt_lab",
        hypothesis_id="h_object_authz",
        title="Object authorization failure",
        summary="Owned account A could read owned account B object",
        evidence_refs=obs.evidence_refs,
    )
    assert draft.submission_blocked is True
    assert draft.automatic_submission_allowed is False
