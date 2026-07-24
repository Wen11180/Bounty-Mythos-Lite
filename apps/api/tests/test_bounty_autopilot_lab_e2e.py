"""Phase 10 lab golden-path pure e2e over Autopilot decision modules."""

from __future__ import annotations

from datetime import UTC, datetime

from app.bounty_autopilot.branches import BranchLimits, BranchStatus, ResearchBranch, select_next_branch
from app.bounty_autopilot.contracts import MutationInventory, PolicyMode, RecipeRef, RiskTier
from app.bounty_autopilot.evidence_judge import EvidenceJudgeVerdict, judge_evidence
from app.bounty_autopilot.gateway import (
    GatewayAuthorizeRequest,
    GatewayDecisionStatus,
    GatewayOutcomeClass,
    authorize_gateway_request,
)
from app.bounty_autopilot.leases import ApprovalStore, R3ApprovalToken, issue_execution_lease
from app.bounty_autopilot.observations import (
    EndpointIdentity,
    ObservationGrade,
    ObservationSummaryCode,
    build_observation,
)
from app.bounty_autopilot.plans import build_validation_plan
from app.bounty_autopilot.recipes import default_recipe_registry
from app.bounty_autopilot.refutation import (
    REQUIRED_REFUTATION_CHECKS,
    RefutationCase,
    RefutationVerdict,
    refute_candidate,
)
from app.bounty_autopilot.request_ledger import RequestLedger, RequestReservation, RequestReservationStatus


def _digest(n="a"):
    return "sha256:" + (n * 64)


def test_lab_golden_candidate_loop_retains_only_sanitized_l3_evidence():
    # Independent branches: WAF parked + productive R0/R1.
    branches = [
        ResearchBranch(
            branch_id="waf_branch",
            campaign_id="lab",
            asset_id="asset_waf",
            status=BranchStatus.PARKED,
            priority=90,
            risk_tier=RiskTier.R1,
        ),
        ResearchBranch(
            branch_id="authz_branch",
            campaign_id="lab",
            asset_id="asset_lab",
            status=BranchStatus.QUEUED,
            priority=50,
            risk_tier=RiskTier.R2,
        ),
    ]
    selection = select_next_branch(
        branches,
        limits=BranchLimits(
            campaign_max_requests=20,
            campaign_max_time_seconds=600,
            campaign_max_cost_units=20,
            per_asset_max_requests=10,
            per_account_max_requests=5,
            per_hypothesis_max_requests=5,
        ),
        admitted_asset_ids={"asset_waf", "asset_lab"},
    )
    assert selection.selected_branch_id == "authz_branch"

    plan = build_validation_plan(
        plan_id="plan_lab",
        campaign_id="lab",
        authorization_digest=_digest("a"),
        scope_snapshot_digest=_digest("b"),
        asset_id="asset_lab",
        destination_scheme="http",
        destination_host="127.0.0.1",
        destination_port=18080,
        destination_path="/api",
        branch_id="authz_branch",
        account_aliases=("account_a", "account_b"),
        risk_tier=RiskTier.R2,
        recipe_ref=default_recipe_registry().require(
            "lab_two_account_authorization_differential", "1.0.0"
        ).ref,
        methods=("GET",),
        mutation_inventory=default_recipe_registry().require(
            "lab_two_account_authorization_differential", "1.0.0"
        ).mutation_inventory,
        max_requests=3,
        max_response_bytes=10000,
        max_duration_seconds=60,
        rollback_plan="close_context",
        stop_conditions=("waf", "third_party"),
        tool_profile="lab_browser",
        container_profile="lab_pod",
    )
    lease_result = issue_execution_lease(
        plan=plan,
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        authorization_recipe_allowed=True,
        authorization_digest=plan.authorization_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        lease_id="lease_lab",
        now_iso="2026-07-24T00:00:00+00:00",
    )
    assert lease_result.allowed and lease_result.lease

    # R4 impossible; R3 single-use path checked separately in lease tests.
    auth = authorize_gateway_request(
        plan=plan,
        lease=lease_result.lease,
        request=GatewayAuthorizeRequest(
            url="http://127.0.0.1:18080/api/docs/1",
            method="GET",
            resolved_ips=("127.0.0.1",),
        ),
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        admitted_asset_id="asset_lab",
        current_scope_snapshot_digest=plan.scope_snapshot_digest,
        asset_identity_digest_current=True,
    )
    assert auth.status is GatewayDecisionStatus.ALLOWED

    ledger = RequestLedger()
    reservation = ledger.reserve(
        lease=lease_result.lease,
        reservation=RequestReservation(
            reservation_id="res_lab",
            lease_id=lease_result.lease.lease_id,
            plan_id=plan.plan_id,
            plan_digest=plan.plan_digest,
            destination_host="127.0.0.1",
            destination_port=18080,
            destination_path="/api/docs/1",
            method="GET",
            mutation_class="none",
            idempotency_key="idem_lab",
            remaining_request_budget=2,
        ),
    )
    ledger.complete(reservation.reservation_id, outcome=RequestReservationStatus.COMPLETED)

    # Public-by-design false positive is refuted.
    refuted = refute_candidate(
        RefutationCase(
            case_id="fp_public",
            hypothesis_id="h_public",
            branch_id="authz_branch",
            counter_questions=("public?",),
            public_by_design=True,
        )
    )
    assert refuted.verdict is RefutationVerdict.REFUTED

    # True candidate retained with L3 sanitized evidence.
    obs = build_observation(
        observation_id="obs_lab",
        campaign_id="lab",
        authorization_id="auth_lab",
        authorization_digest=plan.authorization_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        asset_id=plan.asset_id,
        asset_identity_digest=_digest("c"),
        branch_id="authz_branch",
        plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        risk_decision_id="risk_lab",
        risk_tier=plan.risk_tier,
        recipe_ref=plan.recipe_ref,
        lease_id=lease_result.lease.lease_id,
        reservation_id=reservation.reservation_id,
        session_generation=1,
        tool_run_id="toolrun_lab",
        endpoint=EndpointIdentity(
            method="GET", route_template="/api/docs/{owned_object}"
        ),
        occurred_at=datetime(2026, 7, 24, tzinfo=UTC),
        outcome_class=GatewayOutcomeClass.OK,
        summary_code=ObservationSummaryCode.OWNED_ACCOUNT_DIFFERENTIAL,
        grade=ObservationGrade.L3_ACTIONABLE,
        evidence_refs=("sanitized_cross_account_diff",),
    )
    retained = refute_candidate(
        RefutationCase(
            case_id="true_idor",
            hypothesis_id="h_idor",
            branch_id="authz_branch",
            counter_questions=("middleware?", "ownership?"),
            observations_cited=(obs.observation_id,),
            reproducible=True,
            completed_checks=REQUIRED_REFUTATION_CHECKS,
        )
    )
    judged = judge_evidence(
        hypothesis_id="h_idor",
        observations=[obs],
        refutation=retained,
    )
    assert judged.verdict is EvidenceJudgeVerdict.RETAINED_CANDIDATE
    assert judged.report_submission_allowed is False
    assert judged.submission_blocked is True

def test_lab_fixture_manifest_is_loopback_only():
    import json
    from pathlib import Path
    from urllib.parse import urlsplit

    root = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "bounty_autopilot_lab"
    manifest = json.loads((root / "lab_target.json").read_text(encoding="utf-8"))
    assert manifest["policy_mode"] == "authorized_local_lab"
    assert manifest["loopback_only"] is True
    base_url = manifest["base_url"]
    assert base_url.startswith("http://127.0.0.1")
    parsed = urlsplit(base_url)
    assert parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    for target in manifest["targets"]:
        # Targets inherit the loopback base_url; individual paths must stay relative.
        assert "base_url" not in target or str(target["base_url"]).startswith("http://127.0.0.1")
        for path in target.get("paths", []):
            assert str(path).startswith("/"), path


def test_lab_durable_crash_recovery_no_duplicate_reservation(tmp_path):
    """Crash after reserve + restart reconstructs from DB without duplicate mutation slot."""

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.db import Base
    from app.repository import DatabaseRepository, seed_sample_data

    database_path = tmp_path / "autopilot-crash-recovery.db"
    engine = create_engine(
        f"sqlite+pysqlite:///{database_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as session:
        seed_sample_data(session)
        repo = DatabaseRepository(session)
        program = repo.list_programs()[0]
        campaign = repo.create_campaign(
            program_id=program.id,
            name="lab-crash",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="policy",
            default_asset="127.0.0.1",
            created_by="operator_alice",
            campaign_mode="bounty_autopilot",
        )
        plan = build_validation_plan(
            plan_id="plan_crash",
            campaign_id=campaign.id,
            authorization_digest=_digest("a"),
            scope_snapshot_digest=_digest("b"),
            asset_id="asset_loopback",
            destination_scheme="http",
            destination_host="127.0.0.1",
            destination_port=18080,
            destination_path="/api/docs/1",
            branch_id="authz_branch",
            risk_tier=RiskTier.R1,
            recipe_ref=default_recipe_registry().require(
                "lab_browser_mapping", "1.0.0"
            ).ref,
            methods=("GET",),
            mutation_inventory=default_recipe_registry().require(
                "lab_browser_mapping", "1.0.0"
            ).mutation_inventory,
            max_requests=2,
            max_response_bytes=1000,
            max_duration_seconds=30,
            rollback_plan="noop",
            stop_conditions=("stop",),
            tool_profile="lab",
            container_profile="lab",
        )
        repo.create_validation_plan(
            campaign_id=campaign.id,
            plan_payload=plan.model_dump(mode="json"),
        )
        ok, reason, lease = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_crash",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        )
        assert ok is True, reason
        first = repo.reserve_execution_request(
            campaign_id=campaign.id,
            lease_id="lease_crash",
            reservation_payload={
                "reservation_id": "res_crash",
                "lease_id": "lease_crash",
                "plan_id": plan.plan_id,
                "plan_digest": plan.plan_digest,
                "destination_host": "127.0.0.1",
                "destination_port": 18080,
                "destination_path": "/api/docs/1",
                "method": "GET",
                "mutation_class": "none",
                "idempotency_key": "idem_crash",
                "remaining_request_budget": 1,
            },
        )

        campaign_id = campaign.id

    # Simulated restart after reserve and before send. The new repository session
    # must recover the same idempotency slot rather than allocate another request.
    with Session() as session:
        repo = DatabaseRepository(session)
        second = repo.reserve_execution_request(
            campaign_id=campaign_id,
            lease_id="lease_crash",
            reservation_payload={
                "reservation_id": "res_crash_retry",
                "lease_id": "lease_crash",
                "plan_id": plan.plan_id,
                "plan_digest": plan.plan_digest,
                "destination_host": "127.0.0.1",
                "destination_port": 18080,
                "destination_path": "/api/docs/1",
                "method": "GET",
                "mutation_class": "none",
                "idempotency_key": "idem_crash",
                "remaining_request_budget": 1,
            },
        )
        assert second.id == first.id
        completed = repo.complete_execution_request(
            campaign_id=campaign_id,
            reservation_id="res_crash",
            outcome=RequestReservationStatus.NO_SEND_FAILURE.value,
        )
        assert completed.status == RequestReservationStatus.NO_SEND_FAILURE.value

        # Emergency stop drill after recovery.
        stop = repo.emergency_stop_campaign(
            campaign_id=campaign_id,
            actor="operator_alice",
            reason="lab_drill",
            now=datetime.now(UTC),
        )
        assert stop["emergency_stopped"] is True
