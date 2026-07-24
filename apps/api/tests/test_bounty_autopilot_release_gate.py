"""Repository-derived Phase 10 release gate tests."""

from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from urllib.request import urlopen

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.bounty_autopilot.asset_admission import (
    AssetProvenance,
    NetworkIdentityObservation,
    ScopeMatcher,
    decide_admission,
    parse_asset_url,
)
from app.bounty_autopilot.authority import build_campaign_authorization
from app.bounty_autopilot.branches import BranchStatus, ResearchBranch
from app.bounty_autopilot.contracts import (
    ActiveHoursWindow,
    AutopilotBudgets,
    CampaignAuthorization,
    PolicyMode,
    RiskTier,
    campaign_authorization_payload,
)
from app.bounty_autopilot.evidence_judge import EvidenceJudgeVerdict
from app.bounty_autopilot.gateway import GatewayDecisionStatus, GatewayOutcomeClass
from app.bounty_autopilot.lineage import (
    AutopilotRiskDecisionRecord,
    AutopilotToolRunRecord,
    CandidateRevisionRecord,
    EvidenceClaimRecord,
    RefutationDecisionRecord,
    ReportRevisionRecord,
)
from app.bounty_autopilot.observations import (
    EndpointIdentity,
    ObservationGrade,
    ObservationRecord,
    ObservationSummaryCode,
)
from app.bounty_autopilot.plans import build_validation_plan
from app.bounty_autopilot.recipes import default_recipe_registry
from app.bounty_autopilot.refutation import RefutationVerdict
from app.bounty_autopilot.request_ledger import RequestReservationStatus
from app.bounty_autopilot.release_gate import (
    RELEASE_COUNTER_NAMES,
    ReleaseAuditSnapshot,
    derive_release_audit,
    derive_release_counters,
    evaluate_release_gate,
)
from app.db import Base
from app.repository import DatabaseRepository, seed_sample_data


def _repository():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    seed_sample_data(session)
    repo = DatabaseRepository(session)
    campaign = repo.create_campaign(
        program_id=repo.list_programs()[0].id,
        name="release-gate-lab",
        autonomy_level="level_0_read_only",
        scope_status="in_scope",
        policy_text="local lab only",
        default_asset="127.0.0.1",
        created_by="operator_alpha",
        campaign_mode="bounty_autopilot",
    )
    return session, repo, campaign


def _digest(value: str) -> str:
    return f"sha256:{sha256(value.encode('utf-8')).hexdigest()}"


def _load_lab_server():
    server_path = (
        Path(__file__).resolve().parent
        / "fixtures"
        / "bounty_autopilot_lab"
        / "server.py"
    )
    spec = importlib.util.spec_from_file_location(
        "bounty_autopilot_release_gate_server", server_path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _contains_forbidden_capture_key(value: object) -> bool:
    forbidden = {
        "authorization_header",
        "body",
        "cookie",
        "credentials",
        "headers",
        "password",
        "raw_body",
        "response_body",
        "token",
    }
    if isinstance(value, dict):
        return any(
            key.lower().replace("-", "_") in forbidden
            or _contains_forbidden_capture_key(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_forbidden_capture_key(item) for item in value)
    return False


def test_release_gate_fails_closed_when_repository_lineage_is_missing():
    session, repository, campaign = _repository()
    try:
        result = evaluate_release_gate(repository, campaign_id=campaign.id)
        assert result.passed is False
        assert "isolation_unverified" in result.blockers
        assert "missing_record:tool_runs" in result.blockers
        assert set(result.counters) == set(RELEASE_COUNTER_NAMES)
    finally:
        session.close()


def test_counter_helper_counts_untraced_runs_without_becoming_the_gate_input():
    snapshot = ReleaseAuditSnapshot(
        campaign_id="campaign_lab",
        isolation_verified=True,
        available_sources=(),
        source_record_counts={},
        scope_escape_request_ids=(),
        unauthorized_r3_lease_ids=(),
        allowed_r4_attempt_ids=(),
        retained_third_party_record_ids=(),
        raw_secret_leak_ids=(),
        automatic_submission_ids=(),
        approval_consumption_ids=(),
        mutation_idempotency_keys=(),
        gateway_bypass_ids=(),
        tool_run_ids=("toolrun_1",),
        traced_tool_run_ids=(),
        trace_failure_codes={"toolrun_1": ("plan_lineage_mismatch",)},
        source_digest="sha256:" + ("a" * 64),
    )
    counters = derive_release_counters(snapshot)
    assert counters.untraced_tool_runs == 1


def test_captured_release_artifacts_are_sanitized_and_submission_blocked():
    root = Path(__file__).resolve().parent / "fixtures" / "bounty_autopilot_lab" / "captured-output"
    artifacts = {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in root.glob("*.json")
    }

    assert set(artifacts) == {
        "emergency-stop-drill.json",
        "release-audit-projection.json",
        "third-party-discard-receipt.json",
    }
    projection = artifacts["release-audit-projection.json"]
    assert projection["release_counters"] == {
        name: 0 for name in RELEASE_COUNTER_NAMES
    }
    assert projection["submission_blocked"] is True
    assert artifacts["third-party-discard-receipt.json"]["discard_completed"] is True
    assert artifacts["emergency-stop-drill.json"]["all_leases_revoked"] is True
    assert not any(_contains_forbidden_capture_key(value) for value in artifacts.values())


def test_release_gate_passes_for_complete_persisted_loopback_run():
    """The release gate derives a passing result from real durable lab lineage."""

    lab_server = _load_lab_server().start_lab_target(port=0)
    session, repository, _ = _repository()
    try:
        now = datetime.now(UTC)
        source = repository.create_program_rule_source(
            program_alias="autopilot_lab",
            registered_url="https://autopilot-lab.example/rules",
            now=now,
        )
        normalized_sha256 = sha256(b"autopilot-release-gate-scope").hexdigest()
        snapshot = repository.save_program_rule_snapshot(
            source_id=source.id,
            raw_aggregate_sha256=sha256(b"autopilot-release-gate-raw").hexdigest(),
            normalized_sha256=normalized_sha256,
            fetched_at=now,
            fetch_mode="local_fixture",
            content_types=["application/json"],
            detected_language="en",
            extraction={"scope": "loopback_lab"},
            evidence=[],
            linked_documents=[],
            openapi_candidates=[],
            ai_status="not_requested",
            review_status="approved",
            review_digest=sha256(b"autopilot-release-gate-review").hexdigest(),
        )
        scope_digest = f"sha256:{normalized_sha256}"
        identity = parse_asset_url(
            f"{lab_server.base_url}/api",
            provenance=AssetProvenance.SEED,
        )
        admission = decide_admission(
            identity,
            ScopeMatcher(
                include_hosts=(lab_server.host,),
                include_path_prefixes=("/api",),
                scope_snapshot_digest=scope_digest,
            ),
            network=NetworkIdentityObservation(resolved_ips=("127.0.0.1",)),
            seen_at=now.isoformat(),
        )
        campaign = repository.create_campaign(
            program_id=source.program_id,
            name="release-gate-complete-loopback",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="authorized local lab only",
            default_asset=admission.asset_id,
            created_by="operator_alpha",
            campaign_mode="bounty_autopilot",
            payload={"source_snapshot_digest": scope_digest},
        )
        repository.upsert_campaign_asset_admission(
            campaign_id=campaign.id,
            admission=admission.model_dump(mode="json"),
            now=now,
        )

        recipe = default_recipe_registry().require(
            "lab_two_account_authorization_differential", "1.0.0"
        )
        authorization = build_campaign_authorization(
            CampaignAuthorization(
                campaign_id=campaign.id,
                scope_snapshot_id=snapshot.id,
                scope_review_state="approved",
                scope_snapshot_digest=scope_digest,
                policy_digest=_digest("autopilot-release-gate-policy"),
                asset_ids=(admission.asset_id,),
                account_aliases=("account_a", "account_b"),
                recipe_refs=(recipe.ref,),
                max_automatic_risk=RiskTier.R2,
                policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
                network_profile="authorized_local_lab",
                allowed_method_classes=("read_only",),
                active_hours_utc=(
                    ActiveHoursWindow(
                        days_utc=(0, 1, 2, 3, 4, 5, 6),
                        start_minute_utc=0,
                        end_minute_utc=1440,
                    ),
                ),
                budgets=AutopilotBudgets(
                    max_requests=2,
                    max_concurrency=1,
                    max_response_bytes=131_072,
                    max_duration_seconds=120,
                    max_account_operations=2,
                    max_cost_microusd=500_000,
                ),
                issued_at=now,
                expires_at=now + timedelta(hours=1),
                operator_identity="operator_alpha",
            )
        )
        authorization_record = repository.create_campaign_authorization(
            campaign_id=campaign.id,
            authorization_payload=campaign_authorization_payload(authorization),
        )
        branch = repository.create_research_branch(
            campaign_id=campaign.id,
            branch=ResearchBranch(
                branch_id="branch_release",
                campaign_id=campaign.id,
                asset_id=admission.asset_id,
                status=BranchStatus.QUEUED,
                priority=50,
                recipe_ref=recipe.ref,
                risk_tier=RiskTier.R2,
                account_aliases=("account_a", "account_b"),
            ).model_dump(mode="json"),
            now=now,
        )
        repository.append_autopilot_risk_decision(
            AutopilotRiskDecisionRecord(
                risk_decision_id="risk_release",
                campaign_id=campaign.id,
                authorization_id=authorization_record.id,
                authorization_digest=authorization.authorization_digest,
                scope_snapshot_digest=scope_digest,
                asset_id=admission.asset_id,
                branch_id=branch.branch_id,
                recipe_ref=recipe.ref,
                risk_tier=RiskTier.R2,
                status="authorized",
                reason_code="server_classification",
                decided_at=now,
            )
        )
        branch = repository.transition_research_branch(
            campaign_id=campaign.id,
            branch_id=branch.branch_id,
            new_status=BranchStatus.AWAITING_HUMAN.value,
            expected_version=branch.version,
            stop_reason="awaiting_plan",
            now=now,
        )
        handoff = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="autopilot_plan_materialization",
            agent_type="human_plan_reviewer",
            title="Materialize immutable plan for selected research branch",
            input_refs=[
                f"campaign_authorization:{authorization_record.id}",
                f"asset:{admission.asset_id}",
                f"research_branch:{branch.branch_id}",
            ],
            payload={
                "schema_version": "autopilot-plan-materialization/v1",
                "campaign_id": campaign.id,
                "branch_id": branch.branch_id,
                "branch_version": branch.version - 1,
                "authorization_id": authorization_record.id,
                "authorization_digest": authorization.authorization_digest,
                "scope_snapshot_digest": scope_digest,
                "asset_id": admission.asset_id,
                "recipe_ref": recipe.ref.model_dump(mode="json"),
                "risk_tier": RiskTier.R2,
                "hypothesis_id": None,
                "human_approval_required": True,
            },
        )
        repository.update_campaign_task_status(handoff.id, "awaiting_approval")
        plan = build_validation_plan(
            plan_id="plan_release",
            campaign_id=campaign.id,
            authorization_digest=authorization.authorization_digest,
            scope_snapshot_digest=scope_digest,
            asset_id=admission.asset_id,
            destination_scheme="http",
            destination_host=lab_server.host,
            destination_port=lab_server.port,
            destination_path="/api",
            branch_id=branch.branch_id,
            account_aliases=("account_a", "account_b"),
            risk_tier=RiskTier.R2,
            recipe_ref=recipe.ref,
            methods=("GET",),
            mutation_inventory=recipe.mutation_inventory,
            max_requests=2,
            max_response_bytes=131_072,
            max_duration_seconds=120,
            rollback_plan="close_context",
            stop_conditions=("waf", "third_party"),
            tool_profile="lab_browser_v1",
            container_profile="docker_readonly_v1",
        )
        repository.materialize_validation_plan_from_handoff(
            campaign_id=campaign.id,
            handoff_id=handoff.id,
            plan=plan,
            actor="operator_alpha",
            now=now,
        )
        issued, reason, lease = repository.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_release",
            authorization_digest=authorization.authorization_digest,
            scope_snapshot_digest=scope_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
            now=now,
        )
        assert issued is True, reason
        assert lease is not None

        observations: list[ObservationRecord] = []
        for index, object_id in enumerate(("1", "2"), start=1):
            reservation_id = f"reservation_release_{index}"
            reservation = repository.reserve_execution_request(
                campaign_id=campaign.id,
                lease_id=lease.lease_id,
                reservation_payload={
                    "reservation_id": reservation_id,
                    "lease_id": lease.lease_id,
                    "plan_id": plan.plan_id,
                    "plan_digest": plan.plan_digest,
                    "destination_host": lab_server.host,
                    "destination_port": lab_server.port,
                    "destination_path": f"/api/docs/{object_id}",
                    "method": "GET",
                    "mutation_class": "none",
                    "idempotency_key": f"idem_release_{index}",
                    "remaining_request_budget": 2 - index,
                },
                now=now,
            )
            gateway_decision = repository.authorize_execution_request(
                campaign_id=campaign.id,
                lease_id=lease.lease_id,
                reservation_id=reservation.reservation_id,
                method="GET",
                scheme="http",
                host=lab_server.host,
                port=lab_server.port,
                path=f"/api/docs/{object_id}",
                body_digest=None,
                mutation_class="none",
                resolved_ips=("127.0.0.1",),
                cname_chain=(),
            )
            assert gateway_decision.status is GatewayDecisionStatus.ALLOWED
            assert reservation.status == RequestReservationStatus.SENT.value
            with urlopen(f"{lab_server.base_url}/api/docs/{object_id}", timeout=2) as response:
                assert response.status == 200
                response.read()
            repository.complete_execution_request(
                campaign_id=campaign.id,
                reservation_id=reservation.reservation_id,
                outcome=RequestReservationStatus.COMPLETED.value,
                now=now,
            )
            tool_run_id = f"toolrun_release_{index}"
            repository.append_autopilot_tool_run(
                AutopilotToolRunRecord(
                    tool_run_id=tool_run_id,
                    campaign_id=campaign.id,
                    authorization_id=authorization_record.id,
                    authorization_digest=authorization.authorization_digest,
                    scope_snapshot_digest=scope_digest,
                    asset_id=admission.asset_id,
                    asset_identity_digest=admission.identity_digest,
                    branch_id=branch.branch_id,
                    plan_id=plan.plan_id,
                    plan_digest=plan.plan_digest,
                    risk_decision_id="risk_release",
                    risk_tier=RiskTier.R2,
                    recipe_ref=recipe.ref,
                    lease_id=lease.lease_id,
                    reservation_id=reservation.reservation_id,
                    session_generation=1,
                    isolation_profile="docker",
                    gateway_decision="allowed",
                    request_sent=True,
                    run_status="completed",
                    outcome_class=GatewayOutcomeClass.OK,
                    outcome_code="owned_response_projected",
                    occurred_at=now,
                )
            )
            observation = ObservationRecord(
                observation_id=f"observation_release_{index}",
                campaign_id=campaign.id,
                authorization_id=authorization_record.id,
                authorization_digest=authorization.authorization_digest,
                scope_snapshot_digest=scope_digest,
                asset_id=admission.asset_id,
                asset_identity_digest=admission.identity_digest,
                branch_id=branch.branch_id,
                plan_id=plan.plan_id,
                plan_digest=plan.plan_digest,
                risk_decision_id="risk_release",
                risk_tier=RiskTier.R2,
                recipe_ref=recipe.ref,
                lease_id=lease.lease_id,
                reservation_id=reservation.reservation_id,
                session_generation=1,
                tool_run_id=tool_run_id,
                endpoint=EndpointIdentity(
                    method="GET", route_template="/api/docs/{owned_object}"
                ),
                occurred_at=now,
                outcome_class=GatewayOutcomeClass.OK,
                grade=(
                    ObservationGrade.L3_ACTIONABLE
                    if index == 2
                    else ObservationGrade.L2_CORROBORATED
                ),
                summary_code=(
                    ObservationSummaryCode.OWNED_ACCOUNT_DIFFERENTIAL
                    if index == 2
                    else ObservationSummaryCode.ROUTE_MAPPED
                ),
                evidence_refs=("sanitized_owned_account_diff",) if index == 2 else (),
            )
            repository.create_autopilot_observation(observation)
            observations.append(observation)

        claim = EvidenceClaimRecord(
            claim_id="claim_release",
            campaign_id=campaign.id,
            hypothesis_id="hypothesis_release",
            observation_ids=(observations[1].observation_id,),
            evidence_grade=ObservationGrade.L3_ACTIONABLE,
            lineage_digest=_digest("claim_release"),
            summary_code="sanitized_owned_account_differential",
            created_at=now,
        )
        refutation = RefutationDecisionRecord(
            decision_id="refutation_release",
            campaign_id=campaign.id,
            case_id="case_release",
            hypothesis_id="hypothesis_release",
            branch_id=branch.branch_id,
            observation_ids=(observations[1].observation_id,),
            lineage_digest=_digest("refutation_release"),
            verdict=RefutationVerdict.RETAINED,
            created_at=now,
        )
        candidate = CandidateRevisionRecord(
            revision_id="candidate_revision_release",
            candidate_id="candidate_release",
            campaign_id=campaign.id,
            hypothesis_id="hypothesis_release",
            branch_id=branch.branch_id,
            evidence_claim_ids=(claim.claim_id,),
            refutation_decision_id=refutation.decision_id,
            judge_verdict=EvidenceJudgeVerdict.RETAINED_CANDIDATE,
            lineage_digest=_digest("candidate_release"),
            created_at=now,
        )
        report = ReportRevisionRecord(
            revision_id="report_revision_release",
            report_id="report_release",
            candidate_id=candidate.candidate_id,
            campaign_id=campaign.id,
            evidence_claim_ids=(claim.claim_id,),
            lineage_digest=_digest("report_release"),
            evidence_grade=ObservationGrade.L3_ACTIONABLE,
            created_at=now,
        )
        repository.append_autopilot_evidence_claim(claim)
        repository.append_autopilot_refutation_decision(refutation)
        repository.append_autopilot_candidate_revision(candidate)
        repository.append_autopilot_report_revision(report)

        audit = derive_release_audit(repository, campaign_id=campaign.id)
        result = evaluate_release_gate(repository, campaign_id=campaign.id)

        assert audit.trace_failure_codes == {}
        assert set(audit.traced_tool_run_ids) == {"toolrun_release_1", "toolrun_release_2"}
        assert result.passed is True
        assert result.failing_counters == ()
        assert result.blockers == ()
        assert result.counters == {name: 0 for name in RELEASE_COUNTER_NAMES}
    finally:
        lab_server.stop()
        session.close()
