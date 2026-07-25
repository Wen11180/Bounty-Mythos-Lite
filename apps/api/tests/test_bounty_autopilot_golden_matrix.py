"""Phase 10 golden matrix: 15 lab cases over pure + durable Autopilot modules.

Fixture labels stay evaluator-owned and are never passed into decision modules.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.bounty_autopilot.branches import BranchLimits, BranchStatus, ResearchBranch, select_next_branch
from app.bounty_autopilot.authority import build_campaign_authorization
from app.bounty_autopilot.asset_admission import (
    AssetIdentity,
    AssetProvenance,
    ScopeMatcher,
    compute_asset_id,
    decide_admission,
)
from app.bounty_autopilot.contracts import (
    AuthorizationBudget,
    CampaignAuthorizationCreate,
    MutationInventory,
    PolicyMode,
    RecipeRef,
    RiskTier,
)
from app.bounty_autopilot.evidence_judge import EvidenceJudgeVerdict, judge_evidence
from app.bounty_autopilot.gateway import (
    GatewayAuthorizeRequest,
    GatewayDecisionStatus,
    GatewayOutcomeClass,
    authorize_gateway_request,
)
from app.bounty_autopilot.leases import ApprovalStore, R3ApprovalToken, issue_execution_lease
from app.bounty_autopilot.observations import ObservationGrade, build_observation
from app.bounty_autopilot.plans import build_validation_plan
from app.bounty_autopilot.refutation import RefutationCase, RefutationVerdict, refute_candidate
from app.bounty_autopilot.release_gate import RELEASE_COUNTER_NAMES, ReleaseCounters, evaluate_release_gate
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
    asset_id: str = "asset_lab",
    authorization_digest: str | None = None,
    scope_snapshot_digest: str | None = None,
):
    return build_validation_plan(
        plan_id=plan_id,
        campaign_id=campaign_id,
        authorization_digest=authorization_digest or _digest("a"),
        scope_snapshot_digest=scope_snapshot_digest or _digest("b"),
        asset_id=asset_id,
        destination_scheme="http",
        destination_host=host,
        destination_port=port,
        destination_path=path,
        branch_id="branch_lab",
        account_aliases=accounts,
        risk_tier=risk_tier,
        recipe_ref=RecipeRef(recipe_id=recipe_id, version="1.0"),
        methods=methods,
        mutation_inventory=MutationInventory(
            methods=methods,
            mutates_state=mutates,
            reversible=not mutates,
            requires_owned_accounts=bool(accounts),
        ),
        max_requests=4,
        max_response_bytes=10000,
        max_duration_seconds=60,
        rollback_plan="close_context",
        stop_conditions=("waf", "third_party", "scope_escape"),
        tool_profile="lab_browser",
        container_profile="lab_pod",
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
            account_alias="account_a",
        ),
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        admitted_asset_id="asset_lab",
        current_scope_snapshot_digest=plan.scope_snapshot_digest,
        asset_identity_digest_current=True,
    )
    assert auth.status is GatewayDecisionStatus.ALLOWED
    obs = build_observation(
        observation_id="obs_obj",
        campaign_id="lab",
        branch_id="branch_lab",
        plan_digest=plan.plan_digest,
        lease_id=lease.lease_id,
        grade=ObservationGrade.L3_ACTIONABLE,
        outcome_class=GatewayOutcomeClass.OK,
        summary="account_a can read account_b document",
        evidence_refs=("path:/api/docs/2",),
    )
    ref = refute_candidate(
        RefutationCase(
            case_id="c1",
            hypothesis_id="h_obj",
            branch_id="branch_lab",
            claim_summary="cross-account object access",
            counter_questions=("Is ownership enforced server-side?",),
            observations_cited=(obs.observation_id,),
        )
    )
    assert ref.verdict is RefutationVerdict.RETAINED
    judged = judge_evidence(hypothesis_id="h_obj", observations=[obs], refutation=ref)
    assert judged.verdict in {
        EvidenceJudgeVerdict.RETAIN_CANDIDATE,
        EvidenceJudgeVerdict.REPORT_DRAFT_READY,
    }
    assert judged.report_submission_allowed is False
    assert judged.submission_blocked is True


def test_case_02_global_middleware_refuted():
    ref = refute_candidate(
        RefutationCase(
            case_id="c2",
            hypothesis_id="h_mw",
            branch_id="b",
            claim_summary="admin status exposed",
            counter_questions=("Is global auth middleware applied?",),
            observations_cited=("obs_mw",),
            global_middleware_protects=True,
        )
    )
    assert ref.verdict is RefutationVerdict.REFUTED
    judged = judge_evidence(hypothesis_id="h_mw", observations=[], refutation=ref)
    assert judged.verdict is EvidenceJudgeVerdict.DISCARD


def test_case_03_public_by_design_not_disclosure():
    ref = refute_candidate(
        RefutationCase(
            case_id="c3",
            hypothesis_id="h_pub",
            branch_id="b",
            claim_summary="health endpoint discloses status",
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
            claim_summary="profile readable by owner",
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
            claim_summary="role field ignored by filter",
            counter_questions=("Did server strip role?",),
            observations_cited=("obs_f",),
            global_middleware_protects=True,
        )
    )
    open_case = refute_candidate(
        RefutationCase(
            case_id="c5b",
            hypothesis_id="h_ma_o",
            branch_id="b",
            claim_summary="role accepted on legacy endpoint",
            counter_questions=("Was role persisted?",),
            observations_cited=("obs_o",),
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
            claim_summary="transition rejected by guard",
            counter_questions=("Server rejected illegal transition?",),
            observations_cited=("obs_g",),
            global_middleware_protects=True,
        )
    )
    unguarded = refute_candidate(
        RefutationCase(
            case_id="c6b",
            hypothesis_id="h_wf_u",
            branch_id="b",
            claim_summary="illegal transition accepted",
            counter_questions=("Was state mutated?",),
            observations_cited=("obs_u",),
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
            claim_summary="field blocked by schema auth",
            counter_questions=("Did schema deny field?",),
            observations_cited=("obs_gql_ok",),
            global_middleware_protects=True,
        )
    )
    leak = refute_candidate(
        RefutationCase(
            case_id="c7b",
            hypothesis_id="h_gql_leak",
            branch_id="b",
            claim_summary="resolver returns peer private field",
            counter_questions=("Was peer data returned?",),
            observations_cited=("obs_gql_leak",),
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
    obs = build_observation(
        observation_id="obs_tp",
        campaign_id="lab",
        branch_id="b",
        plan_digest=_digest("p"),
        lease_id="lease_tp",
        grade=ObservationGrade.L0_NOISE,
        outcome_class=GatewayOutcomeClass.THIRD_PARTY_DATA,
        summary="third party discarded",
        third_party_data_discarded=True,
    )
    ref = refute_candidate(
        RefutationCase(
            case_id="c9",
            hypothesis_id="h_tp",
            branch_id="b",
            claim_summary="cdn script disclosure",
            counter_questions=("Third-party origin?",),
            observations_cited=(obs.observation_id,),
        )
    )
    judged = judge_evidence(hypothesis_id="h_tp", observations=[obs], refutation=ref)
    assert judged.verdict is EvidenceJudgeVerdict.DISCARD


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
        identity = AssetIdentity(
            scheme="http",
            host="127.0.0.1",
            port=18080,
            path_authority="/api",
            provenance=AssetProvenance.SEED,
        )
        asset_id = compute_asset_id(identity)
        scope_digest = _digest("b")
        authorization = build_campaign_authorization(
            CampaignAuthorizationCreate(
                campaign_id=campaign.id,
                scope_snapshot_id="scope_lab_stop",
                scope_snapshot_digest=scope_digest,
                policy_digest=f"sha256:{campaign.policy_text_hash.removeprefix('sha256:')}",
                asset_ids=(asset_id,),
                recipe_refs=(RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),),
                risk_ceiling=RiskTier.R1,
                active_hours_utc=tuple(range(24)),
                budget=AuthorizationBudget(
                    max_requests=20,
                    max_concurrent_requests=1,
                    max_response_bytes=10_000,
                    max_duration_seconds=300,
                    max_accounts=0,
                    max_cost_units=20,
                ),
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                operator_id="operator_alice",
                policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
            )
        )
        repo.create_campaign_authorization(
            campaign_id=campaign.id,
            authorization_payload=authorization.model_dump(mode="json"),
        )
        admission = decide_admission(
            identity,
            ScopeMatcher(
                include_hosts=("127.0.0.1",),
                include_path_prefixes=("/api",),
                scope_snapshot_digest=scope_digest,
            ),
        )
        repo.upsert_campaign_asset_admission(
            campaign_id=campaign.id,
            admission=admission.model_dump(mode="json"),
        )
        plan = _plan(
            campaign_id=campaign.id,
            plan_id="plan_stop",
            asset_id=asset_id,
            authorization_digest=authorization.authorization_digest,
            scope_snapshot_digest=authorization.scope_snapshot_digest,
        )
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
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
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
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
        )
        assert denied[0] is False


def test_release_gate_rejects_matrix_scaffold_without_runtime_evidence():
    result = evaluate_release_gate(ReleaseCounters())
    assert result.passed is False
    assert result.failing_counters == ()
    assert result.evidence_complete is False
    assert set(result.counters) == set(RELEASE_COUNTER_NAMES)
    dirty = evaluate_release_gate(
        ReleaseCounters(
            scope_escape_requests=0,
            unauthorized_r3_executions=0,
            r4_execution_attempts_allowed=0,
            retained_third_party_content=0,
            raw_secret_leaks=0,
            automatic_report_submissions=0,
            duplicate_approval_consumptions=0,
            duplicate_mutations=0,
            gateway_bypass_attempts_allowed=0,
            untraced_tool_runs=1,
        )
    )
    assert dirty.passed is False
    assert "untraced_tool_runs" in dirty.failing_counters
