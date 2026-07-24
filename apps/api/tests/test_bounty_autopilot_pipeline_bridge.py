"""Phase 8 bridges into Candidate Hunter, evidence, and report review."""

from datetime import UTC, datetime

import pytest

from app import candidate_hunter_loop
from app import evidence as evidence_module
from app import mythos_report
from app.intelligence_benchmark.candidate_report_bridge import (
    build_submission_blocked_report_bundle,
)
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


def _digest(character: str) -> str:
    return "sha256:" + (character * 64)


def _retained_flow():
    recipe = default_recipe_registry().require(
        "lab_two_account_authorization_differential", "1.0.0"
    )
    observation = build_observation(
        observation_id="obs_bridge_1",
        campaign_id="campaign_bridge",
        authorization_id="auth_bridge_1",
        authorization_digest=_digest("a"),
        scope_snapshot_digest=_digest("b"),
        asset_id="asset_bridge_1",
        asset_identity_digest=_digest("c"),
        branch_id="branch_bridge_1",
        plan_id="plan_bridge_1",
        plan_digest=_digest("d"),
        risk_decision_id="risk_bridge_1",
        risk_tier="R2",
        recipe_ref=recipe.ref,
        lease_id="lease_bridge_1",
        reservation_id="request_bridge_1",
        session_generation=3,
        tool_run_id="toolrun_bridge_1",
        endpoint=EndpointIdentity(
            method="GET", route_template="/objects/{owned_object}"
        ),
        occurred_at=datetime.now(UTC),
        outcome_class=GatewayOutcomeClass.OK,
        summary_code=ObservationSummaryCode.OWNED_ACCOUNT_DIFFERENTIAL,
        grade=ObservationGrade.L3_ACTIONABLE,
        evidence_refs=("evidence_owned_diff",),
    )
    refutation = refute_candidate(
        RefutationCase(
            case_id="case_bridge_1",
            hypothesis_id="hypothesis_bridge_1",
            branch_id=observation.branch_id,
            counter_questions=("global_control", "ownership"),
            observations_cited=(observation.observation_id,),
            reproducible=True,
            completed_checks=REQUIRED_REFUTATION_CHECKS,
        )
    )
    judge = judge_evidence(
        hypothesis_id="hypothesis_bridge_1",
        observations=[observation],
        refutation=refutation,
    )
    assert refutation.verdict is RefutationVerdict.RETAINED
    assert judge.verdict is EvidenceJudgeVerdict.RETAINED_CANDIDATE
    return observation, refutation, judge


def test_candidate_hunter_accepts_only_typed_autopilot_observations():
    assert hasattr(candidate_hunter_loop, "build_autopilot_candidate_projection")
    observation, refutation, judge = _retained_flow()

    projection = candidate_hunter_loop.build_autopilot_candidate_projection(
        observation=observation,
        refutation=refutation,
        judge_result=judge,
    )

    assert projection["status"] == "review_ready"
    assert projection["evidence_grade"] == "L3_actionable"
    assert projection["submission_blocked"] is True
    assert projection["candidate_promotion_allowed"] is False
    assert projection["report_submission_allowed"] is False
    assert projection["lineage"]["reservation_id"] == "request_bridge_1"
    assert projection["vuln_type"] == "authorization"
    assert projection["root_cause_id"]
    assert projection["affected_trace_ref"] in projection["source_fact_refs"]
    assert projection["dispatch_allowed"] is False
    assert projection["raw_payload_processed"] is False
    with pytest.raises(TypeError, match="typed_autopilot_observation_required"):
        candidate_hunter_loop.build_autopilot_candidate_projection(
            observation=observation.model_dump(mode="json"),
            refutation=refutation,
            judge_result=judge,
        )


def test_autopilot_projection_survives_the_real_candidate_and_report_bridges():
    observation, refutation, judge = _retained_flow()
    projection = candidate_hunter_loop.build_autopilot_candidate_projection(
        observation=observation,
        refutation=refutation,
        judge_result=judge,
    )

    resumed = candidate_hunter_loop.advance_candidate_hunter_round(
        pipeline_run_id="autopilot_bridge_run",
        round_number=2,
        candidate_states=[],
        observations={
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
            "raw_payload_processed": False,
        },
        prior_decisions=[
            {
                "candidate_id": projection["candidate_id"],
                "root_cause_id": projection["root_cause_id"],
                "disposition": "retained",
                "evidence_refs": projection["source_fact_refs"],
                "candidate_projection": projection,
            }
        ],
    )

    assert len(resumed["final_candidates"]) == 1
    resumed_projection = resumed["final_candidates"][0]
    assert resumed_projection["candidate_id"] == projection["candidate_id"]
    assert resumed_projection["affected_trace_ref"] == projection["affected_trace_ref"]
    assert resumed_projection["lineage_digest"] == projection["lineage_digest"]
    report_bundle = build_submission_blocked_report_bundle(resumed_projection)
    assert report_bundle["submission_blocked"] is True
    assert report_bundle["report_submission_allowed"] is False


def test_cross_flow_lineage_is_rejected_by_candidate_evidence_and_report_bridges():
    observation, refutation, judge = _retained_flow()
    other_observation = observation.model_copy(
        update={
            "campaign_id": "campaign_other",
            "branch_id": "branch_other",
            "observation_id": "obs_other",
        }
    )

    with pytest.raises(ValueError, match="autopilot_lineage_mismatch"):
        candidate_hunter_loop.build_autopilot_candidate_projection(
            observation=other_observation,
            refutation=refutation,
            judge_result=judge,
        )

    with pytest.raises(ValueError, match="retained_sanitized_l3_autopilot_evidence_required"):
        evidence_module.build_autopilot_evidence_bundle(
            observation=other_observation,
            judge_result=judge,
        )

    evidence_bundle = evidence_module.build_autopilot_evidence_bundle(
        observation=observation,
        judge_result=judge,
    )
    draft = build_submission_blocked_report(
        report_id="report_cross_flow",
        hypothesis_id=judge.hypothesis_id,
        title="Owned-object authorization boundary",
        summary="Owned account A received the structural canary for account B.",
        evidence_refs=observation.evidence_refs,
        judge_result=judge,
    )
    with pytest.raises(ValueError, match="autopilot_lineage_mismatch"):
        mythos_report.build_autopilot_report_review_packet(
            draft=draft.model_copy(update={"campaign_id": "campaign_other"}),
            evidence_bundle=evidence_bundle,
        )

    with pytest.raises(ValueError, match="autopilot_report_copy_unsafe"):
        mythos_report.build_autopilot_report_review_packet(
            draft=draft.model_copy(
                update={"summary": "Observed real.user@example.test in the response."}
            ),
            evidence_bundle=evidence_bundle,
        )

    with pytest.raises(ValueError, match="judge_hypothesis_lineage_mismatch"):
        build_submission_blocked_report(
            report_id="report_wrong_hypothesis",
            hypothesis_id="hypothesis_other",
            title="Owned-object authorization boundary",
            summary="Owned account A received the structural canary for account B.",
            evidence_refs=observation.evidence_refs,
            judge_result=judge,
        )

    with pytest.raises(ValueError, match="safe_report_evidence_ref_required"):
        build_submission_blocked_report(
            report_id="report_unsafe_ref",
            hypothesis_id=judge.hypothesis_id,
            title="Owned-object authorization boundary",
            summary="Owned account A received the structural canary for account B.",
            evidence_refs=("real.user@example.test",),
            judge_result=judge,
        )


def test_autopilot_evidence_bundle_contains_only_complete_safe_lineage():
    assert hasattr(evidence_module, "build_autopilot_evidence_bundle")
    observation, _refutation, judge = _retained_flow()

    bundle = evidence_module.build_autopilot_evidence_bundle(
        observation=observation,
        judge_result=judge,
    )

    payload = bundle.model_dump(mode="json")
    assert payload["lineage_complete"] is True
    assert payload["evidence_grade"] == "L3_actionable"
    assert payload["authorization_id"] == "auth_bridge_1"
    assert payload["reservation_id"] == "request_bridge_1"
    assert payload["raw_content_retained"] is False
    serialized = str(payload).lower()
    for forbidden in ("response_body", "request_headers", "cookie", "bearer "):
        assert forbidden not in serialized


def test_autopilot_report_export_requires_matching_complete_lineage():
    assert hasattr(mythos_report, "build_autopilot_report_review_packet")
    observation, _refutation, judge = _retained_flow()
    evidence_bundle = evidence_module.build_autopilot_evidence_bundle(
        observation=observation,
        judge_result=judge,
    )
    draft = build_submission_blocked_report(
        report_id="report_bridge_1",
        hypothesis_id=judge.hypothesis_id,
        title="Owned-object authorization boundary",
        summary="Owned account A received the structural canary for account B.",
        evidence_refs=observation.evidence_refs,
        judge_result=judge,
        lineage_complete=True,
    )

    packet = mythos_report.build_autopilot_report_review_packet(
        draft=draft,
        evidence_bundle=evidence_bundle,
    )

    assert packet["submission_blocked"] is True
    assert packet["automatic_submission_allowed"] is False
    assert packet["human_review_required"] is True
    assert packet["lineage_complete"] is True
    with pytest.raises(ValueError, match="autopilot_lineage_mismatch"):
        mythos_report.build_autopilot_report_review_packet(
            draft=draft.model_copy(update={"hypothesis_id": "different_hypothesis"}),
            evidence_bundle=evidence_bundle,
        )
