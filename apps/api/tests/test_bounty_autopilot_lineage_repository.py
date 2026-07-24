"""Repository persistence for strict, sanitized Autopilot lineage."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.bounty_autopilot.evidence_judge import EvidenceJudgeVerdict
from app.bounty_autopilot.gateway import GatewayOutcomeClass
from app.bounty_autopilot.lineage import (
    AutopilotRiskDecisionRecord,
    AutopilotToolRunRecord,
    CandidateRevisionRecord,
    EvidenceClaimRecord,
    HumanEvidenceReviewRecord,
    RefutationDecisionRecord,
    ReportRevisionRecord,
)
from app.bounty_autopilot.observations import (
    EndpointIdentity,
    HumanEvidenceGrade,
    ObservationGrade,
    ObservationRecord,
    ObservationSummaryCode,
)
from app.bounty_autopilot.recipes import default_recipe_registry
from app.bounty_autopilot.refutation import RefutationVerdict
from app.db import Base
from app.repository import DatabaseRepository, seed_sample_data


def _digest(character: str) -> str:
    return "sha256:" + (character * 64)


def _repository() -> tuple[DatabaseRepository, object, str]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    session = sessionmaker(bind=engine)()
    Base.metadata.create_all(bind=engine)
    seed_sample_data(session)
    repository = DatabaseRepository(session)
    campaign = repository.create_campaign(
        program_id=repository.list_programs()[0].id,
        name="strict-lineage",
        autonomy_level="level_0_read_only",
        scope_status="in_scope",
        policy_text="local lab only",
        default_asset="127.0.0.1",
        created_by="operator_alpha",
        campaign_mode="bounty_autopilot",
    )
    return repository, session, campaign.id


def _records(campaign_id: str) -> dict[str, object]:
    occurred_at = datetime.now(UTC)
    recipe = default_recipe_registry().require("lab_browser_mapping", "1.0.0")
    risk = AutopilotRiskDecisionRecord(
        risk_decision_id="risk_1",
        campaign_id=campaign_id,
        authorization_id="campauth_1",
        authorization_digest=_digest("a"),
        scope_snapshot_digest=_digest("b"),
        asset_id="asset_1",
        branch_id="branch_1",
        recipe_ref=recipe.ref,
        risk_tier="R1",
        status="authorized",
        reason_code="server_classification",
        decided_at=occurred_at,
    )
    tool_run = AutopilotToolRunRecord(
        tool_run_id="toolrun_1",
        campaign_id=campaign_id,
        authorization_id="campauth_1",
        authorization_digest=_digest("a"),
        scope_snapshot_digest=_digest("b"),
        asset_id="asset_1",
        asset_identity_digest=_digest("c"),
        branch_id="branch_1",
        plan_id="plan_1",
        plan_digest=_digest("d"),
        risk_decision_id="risk_1",
        risk_tier="R1",
        recipe_ref=recipe.ref,
        lease_id="lease_1",
        reservation_id="request_1",
        session_generation=1,
        isolation_profile="docker",
        gateway_decision="allowed",
        request_sent=True,
        run_status="completed",
        outcome_class=GatewayOutcomeClass.OK,
        outcome_code="owned_response_projected",
        occurred_at=occurred_at,
    )
    observation = ObservationRecord(
        observation_id="observation_1",
        campaign_id=campaign_id,
        authorization_id="campauth_1",
        authorization_digest=_digest("a"),
        scope_snapshot_digest=_digest("b"),
        asset_id="asset_1",
        asset_identity_digest=_digest("c"),
        branch_id="branch_1",
        plan_id="plan_1",
        plan_digest=_digest("d"),
        risk_decision_id="risk_1",
        risk_tier="R1",
        recipe_ref=recipe.ref,
        lease_id="lease_1",
        reservation_id="request_1",
        session_generation=1,
        tool_run_id="toolrun_1",
        endpoint=EndpointIdentity(method="GET", route_template="/api/docs/{owned}"),
        occurred_at=occurred_at,
        outcome_class=GatewayOutcomeClass.OK,
        grade=ObservationGrade.L3_ACTIONABLE,
        summary_code=ObservationSummaryCode.OWNED_ACCOUNT_DIFFERENTIAL,
        evidence_refs=("sanitized_diff_1",),
    )
    claim = EvidenceClaimRecord(
        claim_id="claim_1",
        campaign_id=campaign_id,
        hypothesis_id="hypothesis_1",
        observation_ids=(observation.observation_id,),
        evidence_grade=ObservationGrade.L3_ACTIONABLE,
        lineage_digest=_digest("e"),
        summary_code="owned_account_differential",
        created_at=occurred_at,
    )
    refutation = RefutationDecisionRecord(
        decision_id="refutation_1",
        campaign_id=campaign_id,
        case_id="case_1",
        hypothesis_id="hypothesis_1",
        branch_id="branch_1",
        observation_ids=(observation.observation_id,),
        lineage_digest=_digest("f"),
        verdict=RefutationVerdict.RETAINED,
        created_at=occurred_at,
    )
    candidate = CandidateRevisionRecord(
        revision_id="candidate_revision_1",
        candidate_id="candidate_1",
        campaign_id=campaign_id,
        hypothesis_id="hypothesis_1",
        branch_id="branch_1",
        evidence_claim_ids=(claim.claim_id,),
        refutation_decision_id=refutation.decision_id,
        judge_verdict=EvidenceJudgeVerdict.RETAINED_CANDIDATE,
        lineage_digest=_digest("1"),
        created_at=occurred_at,
    )
    report = ReportRevisionRecord(
        revision_id="report_revision_1",
        report_id="report_1",
        candidate_id="candidate_1",
        campaign_id=campaign_id,
        evidence_claim_ids=(claim.claim_id,),
        lineage_digest=_digest("2"),
        evidence_grade=ObservationGrade.L3_ACTIONABLE,
        created_at=occurred_at,
    )
    review = HumanEvidenceReviewRecord(
        review_id="review_1",
        campaign_id=campaign_id,
        hypothesis_id="hypothesis_1",
        observation_ids=(observation.observation_id,),
        grade=HumanEvidenceGrade.L4_HUMAN_VERIFIED,
        decision_code="verified_sanitized_owned_account_evidence",
        reviewer_alias="reviewer_alpha",
        reviewed_at=occurred_at,
    )
    return {
        "risk": risk,
        "tool_run": tool_run,
        "observation": observation,
        "claim": claim,
        "refutation": refutation,
        "candidate": candidate,
        "report": report,
        "review": review,
    }


def test_repository_appends_and_lists_every_strict_lineage_contract():
    repository, session, campaign_id = _repository()
    try:
        records = _records(campaign_id)
        persisted = [
            repository.append_autopilot_risk_decision(records["risk"]),
            repository.append_autopilot_tool_run(records["tool_run"]),
            repository.create_autopilot_observation(records["observation"]),
            repository.append_autopilot_evidence_claim(records["claim"]),
            repository.append_autopilot_refutation_decision(records["refutation"]),
            repository.append_autopilot_candidate_revision(records["candidate"]),
            repository.append_autopilot_report_revision(records["report"]),
            repository.append_autopilot_human_evidence_review(records["review"]),
        ]

        assert all(row.campaign_id == campaign_id for row in persisted)
        assert len(repository.list_autopilot_risk_decisions(campaign_id)) == 1
        assert len(repository.list_autopilot_tool_runs(campaign_id)) == 1
        assert len(repository.list_autopilot_observations(campaign_id)) == 1
        assert len(repository.list_autopilot_evidence_claims(campaign_id)) == 1
        assert len(repository.list_autopilot_refutation_decisions(campaign_id)) == 1
        assert len(repository.list_autopilot_candidate_revisions(campaign_id)) == 1
        assert len(repository.list_autopilot_report_revisions(campaign_id)) == 1
        assert len(repository.list_autopilot_human_evidence_reviews(campaign_id)) == 1
        assert repository.append_autopilot_tool_run(records["tool_run"]).id == persisted[1].id
        assert repository.create_autopilot_observation(records["observation"]).id == persisted[2].id
    finally:
        session.close()


def test_repository_rejects_untyped_observations_and_conflicting_replays():
    repository, session, campaign_id = _repository()
    try:
        records = _records(campaign_id)
        repository.append_autopilot_evidence_claim(records["claim"])

        with pytest.raises(TypeError, match="ObservationRecord"):
            repository.create_autopilot_observation(  # type: ignore[arg-type]
                {"observation_id": "weak_dict"}
            )
        changed = records["claim"].model_copy(
            update={"summary_code": "different_summary"}
        )
        with pytest.raises(ValueError, match="lineage_record_conflict"):
            repository.append_autopilot_evidence_claim(changed)
    finally:
        session.close()
