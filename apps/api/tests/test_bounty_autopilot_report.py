"""Submission-blocked report readiness for Autopilot evidence."""

from datetime import UTC, datetime

from app.bounty_autopilot.evidence_judge import (
    EvidenceJudgeVerdict,
    build_submission_blocked_report,
    judge_evidence,
)
from app.bounty_autopilot.gateway import GatewayOutcomeClass
from app.bounty_autopilot.observations import (
    EndpointIdentity,
    ObservationGrade,
    ObservationSummaryCode,
    build_observation,
)
from app.bounty_autopilot.recipes import default_recipe_registry
from app.bounty_autopilot.refutation import (
    REQUIRED_REFUTATION_CHECKS,
    RefutationCase,
    RefutationVerdict,
    refute_candidate,
)


def _digest(n: str = "a") -> str:
    return "sha256:" + (n * 64)


def test_true_candidate_report_is_submission_blocked():
    recipe = default_recipe_registry().require(
        "lab_two_account_authorization_differential", "1.0.0"
    )
    obs = build_observation(
        observation_id="obs_true",
        campaign_id="lab",
        authorization_id="auth_1",
        authorization_digest=_digest("a"),
        scope_snapshot_digest=_digest("b"),
        asset_id="asset_1",
        asset_identity_digest=_digest("c"),
        branch_id="branch_authz",
        plan_id="plan_1",
        plan_digest=_digest("d"),
        risk_decision_id="risk_1",
        risk_tier="R2",
        recipe_ref=recipe.ref,
        lease_id="lease_1",
        reservation_id="request_1",
        session_generation=1,
        tool_run_id="toolrun_1",
        endpoint=EndpointIdentity(
            method="GET", route_template="/objects/{owned_object}"
        ),
        occurred_at=datetime.now(UTC),
        outcome_class=GatewayOutcomeClass.OK,
        summary_code=ObservationSummaryCode.OWNED_ACCOUNT_DIFFERENTIAL,
        grade=ObservationGrade.L3_ACTIONABLE,
        evidence_refs=("diff:object_owner",),
    )
    retained = refute_candidate(
        RefutationCase(
            case_id="true_object_authz",
            hypothesis_id="h_object_authz",
            branch_id="branch_authz",
            counter_questions=("middleware?", "ownership?"),
            observations_cited=(obs.observation_id,),
            reproducible=True,
            completed_checks=REQUIRED_REFUTATION_CHECKS,
        )
    )
    assert retained.verdict is RefutationVerdict.RETAINED
    judged = judge_evidence(
        hypothesis_id="h_object_authz",
        observations=[obs],
        refutation=retained,
    )
    assert judged.verdict is EvidenceJudgeVerdict.RETAINED_CANDIDATE
    assert judged.report_submission_allowed is False
    assert judged.submission_blocked is True
    assert judged.candidate_promotion_allowed is False

    draft = build_submission_blocked_report(
        report_id="rpt_lab",
        hypothesis_id="h_object_authz",
        title="Object authorization failure",
        summary="Owned account A could read owned account B object",
        evidence_refs=obs.evidence_refs,
        judge_result=judged,
        lineage_complete=True,
    )
    assert draft.submission_blocked is True
    assert draft.automatic_submission_allowed is False
