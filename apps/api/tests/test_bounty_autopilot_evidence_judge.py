"""Phase 8 evidence judge tests."""

from datetime import UTC, datetime

from app.bounty_autopilot.evidence_judge import (
    EvidenceJudgeVerdict,
    build_submission_blocked_report,
    judge_evidence,
)
from app.bounty_autopilot.gateway import GatewayOutcomeClass
from app.bounty_autopilot.observations import EndpointIdentity, ObservationGrade, ObservationSummaryCode, build_observation
from app.bounty_autopilot.recipes import default_recipe_registry
from app.bounty_autopilot.refutation import (
    REQUIRED_REFUTATION_CHECKS,
    RefutationCase,
    refute_candidate,
)


def test_l3_yields_retained_submission_blocked_candidate():
    recipe = default_recipe_registry().require("lab_two_account_authorization_differential", "1.0.0")
    obs = build_observation(
        observation_id="obs_1",
        campaign_id="c1",
        authorization_id="auth_1",
        authorization_digest="sha256:" + ("a" * 64),
        scope_snapshot_digest="sha256:" + ("b" * 64),
        asset_id="asset_1",
        asset_identity_digest="sha256:" + ("c" * 64),
        branch_id="b1",
        plan_id="plan_1",
        plan_digest="sha256:" + ("d" * 64),
        risk_decision_id="risk_1",
        risk_tier="R2",
        recipe_ref=recipe.ref,
        lease_id="lease_1",
        reservation_id="request_1",
        session_generation=1,
        tool_run_id="toolrun_1",
        endpoint=EndpointIdentity(method="GET", route_template="/objects/{owned_object}"),
        occurred_at=datetime.now(UTC),
        outcome_class=GatewayOutcomeClass.OK,
        summary_code=ObservationSummaryCode.OWNED_ACCOUNT_DIFFERENTIAL,
        grade=ObservationGrade.L3_ACTIONABLE,
        evidence_refs=("evidence_owned_diff",),
    )
    result = judge_evidence(
        hypothesis_id="h1",
        observations=[obs],
        refutation=refute_candidate(
            RefutationCase(
            case_id="case_1",
            hypothesis_id="h1",
            branch_id="b1",
            counter_questions=("ownership",),
            observations_cited=(obs.observation_id,),
            reproducible=True,
            completed_checks=REQUIRED_REFUTATION_CHECKS,
            )
        ),
    )
    assert result.verdict is EvidenceJudgeVerdict.RETAINED_CANDIDATE
    assert result.submission_blocked is True
    assert result.report_submission_allowed is False
    draft = build_submission_blocked_report(
        report_id="rep_1",
        hypothesis_id="h1",
        title="Object authz failure",
        summary="sanitized",
        evidence_refs=("evidence_owned_diff",),
        judge_result=result,
        lineage_complete=True,
    )
    assert draft.automatic_submission_allowed is False
