"""Phase 10 golden matrix: 15 lab cases over pure + durable Autopilot modules.

Fixture labels stay evaluator-owned and are never passed into decision modules.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

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
from app.bounty_autopilot.refutation import (
    REQUIRED_REFUTATION_CHECKS,
    RefutationCase,
    RefutationVerdict,
    refute_candidate,
)
from app.bounty_autopilot.recipes import default_recipe_registry
from app.bounty_autopilot.request_ledger import RequestLedger, RequestReservation, RequestReservationStatus
from app.bounty_autopilot.response_guard import project_response
from app.bounty_autopilot.risk import classify_risk
from app.db import Base
from app.repository import DatabaseRepository, seed_sample_data

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "bounty_autopilot_lab"
GOLDEN_CASE_COUNT = 15


def _digest(n: str = "a") -> str:
    ch = n[:1].lower()
    if ch not in "0123456789abcdef":
        ch = "a"
    return "sha256:" + (ch * 64)


def _plan(
    *,
    plan_id: str = "plan_lab",
    campaign_id: str = "lab",
    risk_tier: RiskTier = RiskTier.R1,
    recipe_id: str = "lab_browser_mapping",
    host: str = "127.0.0.1",
    port: int = 18080,
    path: str = "/api",
    methods: tuple[str, ...] = ("GET",),
    mutates: bool = False,
    accounts: tuple[str, ...] = (),
):
    if recipe_id == "lab_two_owned_account_readonly_authz":
        recipe_id = "lab_two_account_authorization_differential"
    recipe = default_recipe_registry().require(recipe_id, "1.0.0")
    return build_validation_plan(
        plan_id=plan_id,
        campaign_id=campaign_id,
        authorization_digest=_digest("a"),
        scope_snapshot_digest=_digest("b"),
        asset_id="asset_lab",
        destination_scheme="http",
        destination_host=host,
        destination_port=port,
        destination_path=path,
        branch_id="branch_lab",
        account_aliases=accounts,
        risk_tier=risk_tier,
        recipe_ref=recipe.ref,
        methods=methods,
        mutation_inventory=recipe.mutation_inventory,
        max_requests=4,
        max_response_bytes=10000,
        max_duration_seconds=60,
        rollback_plan="close_context",
        stop_conditions=("waf", "third_party", "scope_escape"),
        tool_profile="lab_browser",
        container_profile="lab_pod",
    )


def _observation(
    *,
    observation_id: str,
    plan,
    lease_id: str,
    reservation_id: str,
    grade: ObservationGrade,
    outcome_class: GatewayOutcomeClass,
    summary_code: ObservationSummaryCode,
    evidence_refs: tuple[str, ...] = (),
    endpoint: str = "/api/docs/{owned_object}",
):
    return build_observation(
        observation_id=observation_id,
        campaign_id=plan.campaign_id,
        authorization_id="auth_lab",
        authorization_digest=plan.authorization_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        asset_id=plan.asset_id,
        asset_identity_digest=_digest("c"),
        branch_id=plan.branch_id,
        plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        risk_decision_id=f"risk_{observation_id}",
        risk_tier=plan.risk_tier,
        recipe_ref=plan.recipe_ref,
        lease_id=lease_id,
        reservation_id=reservation_id,
        session_generation=1,
        tool_run_id=f"toolrun_{observation_id}",
        endpoint=EndpointIdentity(method=plan.methods[0], route_template=endpoint),
        occurred_at=datetime(2026, 7, 24, tzinfo=UTC),
        grade=grade,
        outcome_class=outcome_class,
        summary_code=summary_code,
        evidence_refs=evidence_refs,
    )


def test_fixtures_declare_all_fifteen_golden_cases():
    target = json.loads((FIXTURE_DIR / "lab_target.json").read_text(encoding="utf-8"))
    labels = json.loads((FIXTURE_DIR / "evaluator_labels.json").read_text(encoding="utf-8"))
    assert target["loopback_only"] is True
    assert labels["evaluator_only"] is True
    case_ids = target["golden_case_ids"]
    assert len(case_ids) == GOLDEN_CASE_COUNT
    assert set(case_ids) == set(labels["labels"])


def test_case_01_true_two_owned_account_object_authz():
    plan = _plan(
        risk_tier=RiskTier.R2,
        recipe_id="lab_two_owned_account_readonly_authz",
        accounts=("account_a", "account_b"),
        path="/api/docs",
    )
    lease = issue_execution_lease(
        plan=plan,
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        authorization_recipe_allowed=True,
        authorization_digest=plan.authorization_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        lease_id="lease_obj",
        now_iso="2026-07-24T00:00:00+00:00",
    ).lease
    assert lease is not None
    auth = authorize_gateway_request(
        plan=plan,
        lease=lease,
        request=GatewayAuthorizeRequest(
            url="http://127.0.0.1:18080/api/docs/2",
            method="GET",
            resolved_ips=("127.0.0.1",),
        ),
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        admitted_asset_id="asset_lab",
        current_scope_snapshot_digest=plan.scope_snapshot_digest,
        asset_identity_digest_current=True,
    )
    assert auth.status is GatewayDecisionStatus.ALLOWED
    obs = _observation(
        observation_id="obs_obj",
        plan=plan,
        lease_id=lease.lease_id,
        reservation_id="request_obj",
        grade=ObservationGrade.L3_ACTIONABLE,
        outcome_class=GatewayOutcomeClass.OK,
        summary_code=ObservationSummaryCode.OWNED_ACCOUNT_DIFFERENTIAL,
        evidence_refs=("evidence_owned_diff",),
    )
    ref = refute_candidate(
        RefutationCase(
            case_id="c1",
            hypothesis_id="h_obj",
            branch_id="branch_lab",
            counter_questions=("Is ownership enforced server-side?",),
            observations_cited=(obs.observation_id,),
            reproducible=True,
            completed_checks=REQUIRED_REFUTATION_CHECKS,
        )
    )
    assert ref.verdict is RefutationVerdict.RETAINED
    judged = judge_evidence(hypothesis_id="h_obj", observations=[obs], refutation=ref)
    assert judged.verdict is EvidenceJudgeVerdict.RETAINED_CANDIDATE
    assert judged.report_submission_allowed is False
    assert judged.submission_blocked is True


def test_case_02_global_middleware_refuted():
    ref = refute_candidate(
        RefutationCase(
            case_id="c2",
            hypothesis_id="h_mw",
            branch_id="b",
            counter_questions=("Is global auth middleware applied?",),
            observations_cited=("obs_mw",),
            global_or_gateway_control_protects=True,
        )
    )
    assert ref.verdict is RefutationVerdict.REFUTED
    judged = judge_evidence(hypothesis_id="h_mw", observations=[], refutation=ref)
    assert judged.verdict is EvidenceJudgeVerdict.REFUTED


def test_case_03_public_by_design_not_disclosure():
    ref = refute_candidate(
        RefutationCase(
            case_id="c3",
            hypothesis_id="h_pub",
            branch_id="b",
            counter_questions=("Is the resource public by design?",),
            observations_cited=("obs_pub",),
            public_by_design=True,
        )
    )
    assert ref.verdict is RefutationVerdict.REFUTED
    assert "public_by_design" in ref.reasons


def test_case_04_same_owned_account_no_cross_impact():
    ref = refute_candidate(
        RefutationCase(
            case_id="c4",
            hypothesis_id="h_same",
            branch_id="b",
            counter_questions=("Does another owned account see it?",),
            observations_cited=("obs_same",),
            same_account_only=True,
        )
    )
    assert ref.verdict is RefutationVerdict.REFUTED
    assert "no_cross_account_impact" in ref.reasons


def test_case_05_mass_assignment_filtered_vs_open():
    filtered = refute_candidate(
        RefutationCase(
            case_id="c5a",
            hypothesis_id="h_ma_f",
            branch_id="b",
            counter_questions=("Did server strip role?",),
            observations_cited=("obs_f",),
            global_or_gateway_control_protects=True,
        )
    )
    open_case = refute_candidate(
        RefutationCase(
            case_id="c5b",
            hypothesis_id="h_ma_o",
            branch_id="b",
            counter_questions=("Was role persisted?",),
            observations_cited=("obs_o",),
            reproducible=True,
            completed_checks=REQUIRED_REFUTATION_CHECKS,
        )
    )
    assert filtered.verdict is RefutationVerdict.REFUTED
    assert open_case.verdict is RefutationVerdict.RETAINED


def test_case_06_workflow_guarded_vs_unguarded():
    guarded = refute_candidate(
        RefutationCase(
            case_id="c6a",
            hypothesis_id="h_wf_g",
            branch_id="b",
            counter_questions=("Server rejected illegal transition?",),
            observations_cited=("obs_g",),
            global_or_gateway_control_protects=True,
        )
    )
    unguarded = refute_candidate(
        RefutationCase(
            case_id="c6b",
            hypothesis_id="h_wf_u",
            branch_id="b",
            counter_questions=("Was state mutated?",),
            observations_cited=("obs_u",),
            reproducible=True,
            completed_checks=REQUIRED_REFUTATION_CHECKS,
        )
    )
    assert guarded.verdict is RefutationVerdict.REFUTED
    assert unguarded.verdict is RefutationVerdict.RETAINED


def test_case_07_graphql_field_authz_pair():
    # Field denied vs resolver leak: retain only the leak path.
    denied = refute_candidate(
        RefutationCase(
            case_id="c7a",
            hypothesis_id="h_gql_ok",
            branch_id="b",
            counter_questions=("Did schema deny field?",),
            observations_cited=("obs_gql_ok",),
            global_or_gateway_control_protects=True,
        )
    )
    leak = refute_candidate(
        RefutationCase(
            case_id="c7b",
            hypothesis_id="h_gql_leak",
            branch_id="b",
            counter_questions=("Was peer data returned?",),
            observations_cited=("obs_gql_leak",),
            reproducible=True,
            completed_checks=REQUIRED_REFUTATION_CHECKS,
        )
    )
    assert denied.verdict is RefutationVerdict.REFUTED
    assert leak.verdict is RefutationVerdict.RETAINED


def test_case_08_waf_parks_branch_independent_continues():
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
            priority=40,
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


def test_case_09_third_party_discard_before_persistence():
    projected = project_response(
        observation_id="obs_tp",
        outcome_class=GatewayOutcomeClass.THIRD_PARTY_DATA,
        status_code=200,
        content_type="application/javascript",
        body_preview="tracker token=secret-value",
        byte_length=120,
    )
    assert projected.third_party_data_discarded is True
    assert projected.byte_length == 0
    assert projected.redacted_excerpt == ""
    assert projected.raw_secret_retained is False
    plan = _plan(plan_id="plan_tp")
    obs = _observation(
        observation_id="obs_tp",
        plan=plan,
        lease_id="lease_tp",
        reservation_id="request_tp",
        grade=ObservationGrade.L0_NOISE,
        outcome_class=GatewayOutcomeClass.THIRD_PARTY_DATA,
        summary_code=ObservationSummaryCode.THIRD_PARTY_DATA_DISCARDED,
    )
    ref = refute_candidate(
        RefutationCase(
            case_id="c9",
            hypothesis_id="h_tp",
            branch_id=obs.branch_id,
            counter_questions=("Third-party origin?",),
            observations_cited=(obs.observation_id,),
        )
    )
    judged = judge_evidence(hypothesis_id="h_tp", observations=[obs], refutation=ref)
    assert judged.verdict is EvidenceJudgeVerdict.BLOCKED_BY_POLICY


def test_case_10_scope_escape_blocked_before_send():
    plan = _plan()
    lease = issue_execution_lease(
        plan=plan,
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        authorization_recipe_allowed=True,
        authorization_digest=plan.authorization_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        lease_id="lease_scope",
        now_iso="2026-07-24T00:00:00+00:00",
    ).lease
    assert lease is not None
    blocked = authorize_gateway_request(
        plan=plan,
        lease=lease,
        request=GatewayAuthorizeRequest(
            url="http://evil.example/steal",
            method="GET",
            is_redirect=True,
            resolved_ips=("203.0.113.9",),
        ),
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        admitted_asset_id="asset_lab",
        current_scope_snapshot_digest=plan.scope_snapshot_digest,
        asset_identity_digest_current=True,
    )
    assert blocked.status is GatewayDecisionStatus.BLOCKED
    assert blocked.outcome_class in {
        GatewayOutcomeClass.SCOPE_ESCAPE,
        GatewayOutcomeClass.OFF_SCOPE_REDIRECT,
        GatewayOutcomeClass.DNS_REBIND,
    }


def test_case_11_r3_blocked_issued_once_invalid_after_plan_change():
    plan = _plan(risk_tier=RiskTier.R3, plan_id="plan_r3")
    store = ApprovalStore()
    token = R3ApprovalToken(
        approval_id="appr_r3",
        plan_digest=plan.plan_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        authorization_digest=plan.authorization_digest,
        account_aliases=(),
        nonce_digest=_digest("n"),
        expires_at="2026-07-25T00:00:00+00:00",
    )
    store.put(token)
    denied = issue_execution_lease(
        plan=plan,
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        authorization_recipe_allowed=True,
        authorization_digest=plan.authorization_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        lease_id="lease_r3_pre",
        now_iso="2026-07-24T00:00:00+00:00",
        approval_store=store,
        approval_token=None,
    )
    assert denied.allowed is False
    first = issue_execution_lease(
        plan=plan,
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        authorization_recipe_allowed=True,
        authorization_digest=plan.authorization_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        lease_id="lease_r3",
        now_iso="2026-07-24T00:00:00+00:00",
        approval_store=store,
        approval_token=token,
    )
    assert first.allowed is True
    second = issue_execution_lease(
        plan=plan,
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        authorization_recipe_allowed=True,
        authorization_digest=plan.authorization_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        lease_id="lease_r3_dup",
        now_iso="2026-07-24T00:00:01+00:00",
        approval_store=store,
        approval_token=token,
    )
    assert second.allowed is False
    changed_plan = _plan(risk_tier=RiskTier.R3, plan_id="plan_r3_changed", path="/api/other")
    stale = R3ApprovalToken(
        approval_id="appr_stale",
        plan_digest=plan.plan_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        authorization_digest=plan.authorization_digest,
        nonce_digest=_digest("m"),
        expires_at="2026-07-25T00:00:00+00:00",
    )
    store.put(stale)
    mismatch = issue_execution_lease(
        plan=changed_plan,
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        authorization_recipe_allowed=True,
        authorization_digest=changed_plan.authorization_digest,
        scope_snapshot_digest=changed_plan.scope_snapshot_digest,
        lease_id="lease_r3_mismatch",
        now_iso="2026-07-24T00:00:02+00:00",
        approval_store=store,
        approval_token=stale,
    )
    assert mismatch.allowed is False


def test_case_12_r4_impossible_to_plan_or_lease():
    assert classify_risk(recipe=None, action_categories={"dos"}) is RiskTier.R4
    try:
        _plan(risk_tier=RiskTier.R4, plan_id="plan_r4")
        raised = False
    except ValueError as exc:
        raised = True
        assert "r4" in str(exc).lower()
    assert raised is True


def test_case_13_crash_after_reserve_before_send_is_idempotent():
    plan = _plan()
    lease = issue_execution_lease(
        plan=plan,
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        authorization_recipe_allowed=True,
        authorization_digest=plan.authorization_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        lease_id="lease_crash",
        now_iso="2026-07-24T00:00:00+00:00",
    ).lease
    assert lease is not None
    ledger = RequestLedger()
    first = ledger.reserve(
        lease=lease,
        reservation=RequestReservation(
            reservation_id="res_crash",
            lease_id=lease.lease_id,
            plan_id=plan.plan_id,
            plan_digest=plan.plan_digest,
            destination_host="127.0.0.1",
            destination_port=18080,
            destination_path="/api/docs/1",
            method="GET",
            mutation_class="none",
            idempotency_key="idem_crash",
            remaining_request_budget=2,
        ),
    )
    second = ledger.reserve(
        lease=lease,
        reservation=RequestReservation(
            reservation_id="res_crash_retry",
            lease_id=lease.lease_id,
            plan_id=plan.plan_id,
            plan_digest=plan.plan_digest,
            destination_host="127.0.0.1",
            destination_port=18080,
            destination_path="/api/docs/1",
            method="GET",
            mutation_class="none",
            idempotency_key="idem_crash",
            remaining_request_budget=2,
        ),
    )
    assert second.reservation_id == first.reservation_id
    completed = ledger.complete(
        first.reservation_id,
        outcome=RequestReservationStatus.NO_SEND_FAILURE,
    )
    assert completed.status is RequestReservationStatus.NO_SEND_FAILURE


def test_case_14_uncertain_mutation_after_possible_send():
    plan = _plan(methods=("POST",), mutates=True, path="/api/legacy/profile")
    lease = issue_execution_lease(
        plan=plan,
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        authorization_recipe_allowed=True,
        authorization_digest=plan.authorization_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        lease_id="lease_mut",
        now_iso="2026-07-24T00:00:00+00:00",
    ).lease
    assert lease is not None
    ledger = RequestLedger()
    reservation = ledger.reserve(
        lease=lease,
        reservation=RequestReservation(
            reservation_id="res_mut",
            lease_id=lease.lease_id,
            plan_id=plan.plan_id,
            plan_digest=plan.plan_digest,
            destination_host="127.0.0.1",
            destination_port=18080,
            destination_path="/api/legacy/profile",
            method="POST",
            mutation_class="stateful",
            idempotency_key="idem_mut",
            remaining_request_budget=1,
        ),
    )
    completed = ledger.complete(
        reservation.reservation_id,
        outcome=RequestReservationStatus.AWAITING_HUMAN,
    )
    assert completed.status is RequestReservationStatus.AWAITING_HUMAN
    # Retry with same idempotency key must not create a duplicate mutation reservation.
    retry = ledger.reserve(
        lease=lease,
        reservation=RequestReservation(
            reservation_id="res_mut_retry",
            lease_id=lease.lease_id,
            plan_id=plan.plan_id,
            plan_digest=plan.plan_digest,
            destination_host="127.0.0.1",
            destination_port=18080,
            destination_path="/api/legacy/profile",
            method="POST",
            mutation_class="stateful",
            idempotency_key="idem_mut",
            remaining_request_budget=1,
        ),
    )
    assert retry.reservation_id == reservation.reservation_id


def test_case_15_emergency_stop_race_with_lease_and_request():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    with Session() as session:
        seed_sample_data(session)
        repo = DatabaseRepository(session)
        program = repo.list_programs()[0]
        campaign = repo.create_campaign(
            program_id=program.id,
            name="lab-stop-race",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="policy",
            default_asset="127.0.0.1",
            created_by="operator_alice",
            campaign_mode="bounty_autopilot",
        )
        plan = _plan(campaign_id=campaign.id, plan_id="plan_stop")
        repo.create_validation_plan(
            campaign_id=campaign.id,
            plan_payload=plan.model_dump(mode="json"),
        )
        ok, reason, _lease = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_stop",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        )
        assert ok is True, reason
        stop = repo.emergency_stop_campaign(
            campaign_id=campaign.id,
            actor="operator_alice",
            reason="race_drill",
            now=datetime.now(UTC),
        )
        assert stop["emergency_stopped"] is True
        assert repo.campaign_is_emergency_stopped(campaign.id) is True
        denied = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_after_stop",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        )
        assert denied[0] is False
