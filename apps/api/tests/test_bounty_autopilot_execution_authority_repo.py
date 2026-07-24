"""Durable Autopilot plan/lease/ledger/emergency-stop repository tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from threading import Barrier, Event, Thread
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.bounty_autopilot.authority import authorization_from_payload
from app.bounty_autopilot.contracts import (
    ActiveHoursWindow,
    AutopilotBudgets,
    CampaignAuthorization,
    MutationInventory,
    PolicyMode,
    RecipeRef,
    RiskTier,
    campaign_authorization_payload,
)
from app.bounty_autopilot.plans import build_validation_plan
from app.bounty_autopilot.gateway import GatewayOutcomeClass
from app.bounty_autopilot.observations import (
    EndpointIdentity,
    ObservationGrade,
    ObservationRecord,
    ObservationSummaryCode,
)
from app.bounty_autopilot.recipes import default_recipe_registry
from app.db import Base
from app.db_models import (
    ApprovalRecord,
    ExecutionLeaseRecord,
    ExecutionRequestLedgerRecord,
)
from app.repository import DatabaseRepository, seed_sample_data


def _digest(n: str = "a") -> str:
    return "sha256:" + (n * 64)


def _session_repo():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    seed_sample_data(session)
    repo = DatabaseRepository(session)
    program = repo.list_programs()[0]
    campaign = repo.create_campaign(
        program_id=program.id,
        name="exec-authority",
        autonomy_level="level_0_read_only",
        scope_status="in_scope",
        policy_text="policy",
        default_asset="127.0.0.1",
        created_by="operator_alice",
        campaign_mode="bounty_autopilot",
    )
    return session, repo, campaign


def _plan_dict(
    campaign_id: str,
    *,
    risk_tier: RiskTier = RiskTier.R1,
    plan_id: str = "plan_1",
    authorization_digest: str | None = None,
    max_requests: int = 3,
):
    plan = build_validation_plan(
        plan_id=plan_id,
        campaign_id=campaign_id,
        authorization_digest=authorization_digest or _digest("a"),
        scope_snapshot_digest=_digest("b"),
        asset_id="asset_loopback",
        destination_scheme="http",
        destination_host="127.0.0.1",
        destination_port=8080,
        destination_path="/api",
        branch_id="branch_1",
        risk_tier=risk_tier,
        recipe_ref=default_recipe_registry().require(
            "lab_browser_mapping", "1.0.0"
        ).ref,
        methods=("GET",),
        mutation_inventory=default_recipe_registry().require(
            "lab_browser_mapping", "1.0.0"
        ).mutation_inventory,
        max_requests=max_requests,
        max_response_bytes=1000,
        max_duration_seconds=30,
        rollback_plan="noop",
        stop_conditions=("stop",),
        tool_profile="lab",
        container_profile="lab",
    )
    return plan.model_dump(mode="json"), plan


def _authorization(campaign_id: str, *, policy_digest: str) -> CampaignAuthorization:
    now = datetime.now(UTC)
    recipe = default_recipe_registry().require("lab_browser_mapping", "1.0.0")
    return CampaignAuthorization(
        campaign_id=campaign_id,
        scope_snapshot_id="scope_snapshot_1",
        scope_review_state="approved",
        scope_snapshot_digest=_digest("b"),
        policy_digest=policy_digest,
        asset_ids=("asset_loopback",),
        account_aliases=("account_a", "account_b"),
        recipe_refs=(recipe.ref,),
        max_automatic_risk=RiskTier.R2,
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        network_profile="authorized_local_lab",
        allowed_method_classes=("passive", "read_only"),
        active_hours_utc=(
            ActiveHoursWindow(
                days_utc=(0, 1, 2, 3, 4, 5, 6),
                start_minute_utc=0,
                end_minute_utc=1440,
            ),
        ),
        budgets=AutopilotBudgets(
            max_requests=10,
            max_concurrency=1,
            max_response_bytes=1_000,
            max_duration_seconds=30,
            max_account_operations=1,
            max_cost_microusd=1_000,
        ),
        issued_at=now,
        expires_at=now + timedelta(hours=1),
        operator_identity="operator_alice",
    )


def test_repository_persists_plan_lease_request_and_idempotency():
    session, repo, campaign = _session_repo()
    try:
        plan_payload, plan = _plan_dict(campaign.id)
        plan_row = repo.create_validation_plan(
            campaign_id=campaign.id,
            plan_payload=plan_payload,
        )
        assert plan_row.plan_digest == plan.plan_digest
        # Immutable re-create is idempotent.
        again = repo.create_validation_plan(
            campaign_id=campaign.id,
            plan_payload=plan_payload,
        )
        assert again.id == plan_row.id

        ok, reason, lease = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_1",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        )
        assert ok is True
        assert reason == "issued"
        assert lease is not None
        assert lease.payload.get("report_submission_allowed") is False
        assert lease.payload.get("candidate_promotion_allowed") is False

        res = repo.reserve_execution_request(
            campaign_id=campaign.id,
            lease_id="lease_1",
            reservation_payload={
                "reservation_id": "res_1",
                "lease_id": "lease_1",
                "plan_id": plan.plan_id,
                "plan_digest": plan.plan_digest,
                "destination_host": "127.0.0.1",
                "destination_port": 8080,
                "destination_path": "/api",
                "method": "GET",
                "mutation_class": "none",
                "idempotency_key": "idem_1",
                "remaining_request_budget": 2,
            },
        )
        again_res = repo.reserve_execution_request(
            campaign_id=campaign.id,
            lease_id="lease_1",
            reservation_payload={
                "reservation_id": "res_other",
                "lease_id": "lease_1",
                "plan_id": plan.plan_id,
                "plan_digest": plan.plan_digest,
                "destination_host": "127.0.0.1",
                "destination_port": 8080,
                "destination_path": "/api",
                "method": "GET",
                "mutation_class": "none",
                "idempotency_key": "idem_1",
                "remaining_request_budget": 2,
            },
        )
        assert again_res.id == res.id
        completed = repo.complete_execution_request(
            campaign_id=campaign.id,
            reservation_id="res_1",
            outcome="completed",
        )
        assert completed.status == "completed"
        # Completion is idempotent.
        completed2 = repo.complete_execution_request(
            campaign_id=campaign.id,
            reservation_id="res_1",
            outcome="completed",
        )
        assert completed2.id == completed.id
    finally:
        session.close()


def test_concurrent_request_reservations_cannot_overrun_lease_budget(
    tmp_path,
    monkeypatch,
):
    database_path = tmp_path / "autopilot-request-budget-race.db"
    engine = create_engine(
        f"sqlite+pysqlite:///{database_path.as_posix()}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as session:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        program = repository.list_programs()[0]
        campaign = repository.create_campaign(
            program_id=program.id,
            name="request-budget-race",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="policy",
            default_asset="127.0.0.1",
            created_by="operator_alice",
            campaign_mode="bounty_autopilot",
        )
        plan_payload, plan = _plan_dict(
            campaign.id,
            plan_id="plan_budget_race",
            max_requests=1,
        )
        repository.create_validation_plan(
            campaign_id=campaign.id,
            plan_payload=plan_payload,
        )
        issued, reason, lease = repository.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_budget_race",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        )
        assert issued is True, reason
        assert lease is not None
        campaign_id = campaign.id

    claims_ready = Barrier(2)
    original_claim = DatabaseRepository._claim_autopilot_execution_authority

    def synchronize_claim(self, claimed_campaign_id):
        claims_ready.wait(timeout=5)
        return original_claim(self, claimed_campaign_id)

    monkeypatch.setattr(
        DatabaseRepository,
        "_claim_autopilot_execution_authority",
        synchronize_claim,
    )
    successes: list[str] = []
    failures: list[Exception] = []

    def reserve(index: int) -> None:
        try:
            with Session() as session:
                reservation = DatabaseRepository(session).reserve_execution_request(
                    campaign_id=campaign_id,
                    lease_id="lease_budget_race",
                    reservation_payload={
                        "reservation_id": f"reservation_budget_{index}",
                        "lease_id": "lease_budget_race",
                        "plan_id": plan.plan_id,
                        "plan_digest": plan.plan_digest,
                        "destination_host": "127.0.0.1",
                        "destination_port": 8080,
                        "destination_path": "/api",
                        "method": "GET",
                        "mutation_class": "none",
                        "idempotency_key": f"idem_budget_{index}",
                        "remaining_request_budget": 0,
                    },
                )
                successes.append(reservation.reservation_id)
        except Exception as exc:  # noqa: BLE001 - assert the stable loser below
            failures.append(exc)

    workers = [Thread(target=reserve, args=(index,)) for index in (1, 2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=15)
        assert worker.is_alive() is False

    assert len(successes) == 1
    assert [str(failure) for failure in failures] == ["request_budget_exhausted"]
    with Session() as session:
        rows = session.scalars(
            select(ExecutionRequestLedgerRecord).where(
                ExecutionRequestLedgerRecord.campaign_id == campaign_id,
                ExecutionRequestLedgerRecord.status == "reserved",
            )
        ).all()
        assert len(rows) == 1


def test_repository_r3_approval_single_use_cas(monkeypatch):
    session, repo, campaign = _session_repo()
    try:
        plan_payload, plan = _plan_dict(campaign.id, risk_tier=RiskTier.R3, plan_id="plan_r3")
        repo.create_validation_plan(campaign_id=campaign.id, plan_payload=plan_payload)
        nonce = _digest("c")
        approval = repo.create_approval_record(
            approval_id="appr_r3",
            campaign_id=campaign.id,
            approval_type="r3_exact_plan",
            actor="operator_alice",
            reason="exact plan",
            plan_digest=plan.plan_digest,
            status="approved",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            payload={
                "scope_snapshot_digest": plan.scope_snapshot_digest,
                "authorization_digest": plan.authorization_digest,
                "nonce_digest": nonce,
            },
            single_use_nonce_digest=nonce,
        )
        # create_approval may force pending; force approved for CAS test.
        approval.status = "approved"
        approval.decided_at = datetime.now(UTC)
        session.commit()

        ok, reason, lease = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_r3",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
            approval_id="appr_r3",
        )
        assert ok is True, reason
        assert lease is not None
        assert lease.r3_approval_id == "appr_r3"

        replay_ok, replay_reason, replayed = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_r3",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
            approval_id="appr_r3",
        )
        assert replay_ok is True, replay_reason
        assert replay_reason == "already_issued"
        assert replayed is not None
        assert replayed.id == lease.id

        approval.status = "approved"
        approval.consumed_at = None
        approval.consumed_by_lease_id = None
        session.commit()
        original_scalar = session.scalar
        original_execute = session.execute
        hidden_existing_lease = False

        def hide_existing_lease_once(statement, *args, **kwargs):
            nonlocal hidden_existing_lease
            entities = {
                item.get("entity")
                for item in getattr(statement, "column_descriptions", ())
            }
            if ExecutionLeaseRecord in entities and not hidden_existing_lease:
                hidden_existing_lease = True
                return None
            return original_scalar(statement, *args, **kwargs)

        def lose_approval_cas_to_competing_replay(statement, *args, **kwargs):
            statement_table = getattr(statement, "table", None)
            if getattr(statement_table, "name", None) == ApprovalRecord.__tablename__:
                approval.status = "used"
                approval.consumed_at = datetime.now(UTC)
                approval.consumed_by_lease_id = "lease_r3"
                session.commit()
                return SimpleNamespace(rowcount=0)
            return original_execute(statement, *args, **kwargs)

        monkeypatch.setattr(session, "scalar", hide_existing_lease_once)
        monkeypatch.setattr(session, "execute", lose_approval_cas_to_competing_replay)
        raced_ok, raced_reason, raced_lease = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_r3",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
            approval_id="appr_r3",
        )
        assert raced_ok is True, raced_reason
        assert raced_reason == "already_issued"
        assert raced_lease is not None
        assert raced_lease.id == lease.id

        ok2, reason2, lease2 = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_r3_b",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
            approval_id="appr_r3",
        )
        assert ok2 is False
        assert reason2 == "approval_already_consumed"
        assert lease2 is None

        refreshed = session.get(type(approval), "appr_r3")
        assert refreshed.consumed_at is not None
        assert refreshed.consumed_by_lease_id == "lease_r3"
    finally:
        session.close()


def test_r3_approval_consumption_survives_repository_restart(tmp_path):
    database_path = tmp_path / "autopilot-r3-restart.db"
    engine = create_engine(
        f"sqlite+pysqlite:///{database_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as session:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        program = repository.list_programs()[0]
        campaign = repository.create_campaign(
            program_id=program.id,
            name="r3-restart",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="policy",
            default_asset="127.0.0.1",
            created_by="operator_alice",
            campaign_mode="bounty_autopilot",
        )
        plan_payload, plan = _plan_dict(
            campaign.id,
            risk_tier=RiskTier.R3,
            plan_id="plan_r3_restart",
        )
        repository.create_validation_plan(
            campaign_id=campaign.id,
            plan_payload=plan_payload,
        )
        nonce = "sha256:" + sha256(b"r3-restart-nonce").hexdigest()
        approval = repository.create_approval_record(
            approval_id="approval_r3_restart",
            campaign_id=campaign.id,
            approval_type="r3_exact_plan",
            actor="operator_alice",
            reason="exact plan",
            plan_digest=plan.plan_digest,
            status="approved",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            payload={"account_aliases": [], "nonce_digest": nonce},
            single_use_nonce_digest=nonce,
        )
        approval.status = "approved"
        approval.decided_at = datetime.now(UTC)
        session.commit()
        campaign_id = campaign.id

    with Session() as session:
        issued, reason, lease = DatabaseRepository(session).issue_execution_lease(
            campaign_id=campaign_id,
            plan_id=plan.plan_id,
            lease_id="lease_r3_restart",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
            approval_id="approval_r3_restart",
        )
        assert issued is True, reason
        assert lease is not None

    with Session() as session:
        repository = DatabaseRepository(session)
        replayed, replay_reason, replay_lease = repository.issue_execution_lease(
            campaign_id=campaign_id,
            plan_id=plan.plan_id,
            lease_id="lease_r3_restart",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
            approval_id="approval_r3_restart",
        )
        blocked, blocked_reason, second_lease = repository.issue_execution_lease(
            campaign_id=campaign_id,
            plan_id=plan.plan_id,
            lease_id="lease_r3_restart_second",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
            approval_id="approval_r3_restart",
        )

        assert replayed is True, replay_reason
        assert replay_reason == "already_issued"
        assert replay_lease is not None
        assert blocked is False
        assert blocked_reason == "approval_already_consumed"
        assert second_lease is None
        assert len(repository.list_execution_leases(campaign_id)) == 1


def test_repository_rejects_existing_lease_after_authorization_rotation():
    session, repo, campaign = _session_repo()
    try:
        first = _authorization(campaign.id, policy_digest=_digest("c"))
        repo.create_campaign_authorization(
            campaign_id=campaign.id,
            authorization_payload=campaign_authorization_payload(first),
        )
        plan_payload, plan = _plan_dict(
            campaign.id,
            plan_id="plan_rotation",
            authorization_digest=first.authorization_digest,
        )
        repo.create_validation_plan(campaign_id=campaign.id, plan_payload=plan_payload)
        ok, reason, lease = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_rotation",
            authorization_digest=first.authorization_digest,
            scope_snapshot_digest=first.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=first.policy_mode,
        )
        assert ok is True, reason
        assert lease is not None

        rotated = _authorization(campaign.id, policy_digest=_digest("d"))
        repo.create_campaign_authorization(
            campaign_id=campaign.id,
            authorization_payload=campaign_authorization_payload(rotated),
        )
        current = repo.get_current_campaign_authorization(campaign.id)
        assert current is not None
        resolved = authorization_from_payload(current.payload)

        replay_ok, replay_reason, replayed = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_rotation",
            authorization_digest=resolved.authorization_digest,
            scope_snapshot_digest=resolved.scope_snapshot_digest,
            authorization_recipe_allowed=plan.recipe_ref in resolved.recipe_refs,
            policy_mode=resolved.policy_mode,
        )

        assert replay_ok is False
        assert replay_reason == "authorization_digest_mismatch"
        assert replayed is None
    finally:
        session.close()


def test_repository_emergency_stop_revokes_leases_and_blocks_new():
    session, repo, campaign = _session_repo()
    try:
        plan_payload, plan = _plan_dict(campaign.id, plan_id="plan_stop")
        repo.create_validation_plan(campaign_id=campaign.id, plan_payload=plan_payload)
        ok, _, lease = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_stop",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        )
        assert ok is True
        assert lease is not None
        repo.reserve_execution_request(
            campaign_id=campaign.id,
            lease_id="lease_stop",
            reservation_payload={
                "reservation_id": "res_stop",
                "lease_id": "lease_stop",
                "plan_id": plan.plan_id,
                "plan_digest": plan.plan_digest,
                "destination_host": "127.0.0.1",
                "destination_port": 8080,
                "destination_path": "/api",
                "method": "GET",
                "mutation_class": "none",
                "idempotency_key": "idem_stop",
                "remaining_request_budget": 2,
            },
        )
        result = repo.emergency_stop_campaign(
            campaign_id=campaign.id,
            actor="operator_alice",
            reason="drill",
        )
        assert result["emergency_stopped"] is True
        assert result["revoked_leases"] >= 1
        assert result["released_reservations"] >= 1

        stopped_lease = repo.get_execution_lease(
            campaign_id=campaign.id,
            lease_id="lease_stop",
        )
        assert stopped_lease is not None
        assert stopped_lease.status == "revoked"

        ok2, reason2, _ = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_after_stop",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        )
        assert ok2 is False
        assert reason2 == "emergency_stopped"
    finally:
        session.close()


@pytest.mark.parametrize("operation", ("lease", "request"))
def test_emergency_stop_race_cannot_commit_new_execution_authority(
    tmp_path,
    monkeypatch,
    operation,
):
    """A stop that wins after the first read still blocks the pending write."""

    database_path = tmp_path / f"autopilot-{operation}-stop-race.db"
    engine = create_engine(
        f"sqlite+pysqlite:///{database_path.as_posix()}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as session:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        program = repository.list_programs()[0]
        campaign = repository.create_campaign(
            program_id=program.id,
            name=f"stop-race-{operation}",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="policy",
            default_asset="127.0.0.1",
            created_by="operator_alice",
            campaign_mode="bounty_autopilot",
        )
        plan_payload, plan = _plan_dict(campaign.id, plan_id=f"plan_stop_{operation}")
        repository.create_validation_plan(
            campaign_id=campaign.id,
            plan_payload=plan_payload,
        )
        if operation == "request":
            issued, reason, lease = repository.issue_execution_lease(
                campaign_id=campaign.id,
                plan_id=plan.plan_id,
                lease_id="lease_before_stop",
                authorization_digest=plan.authorization_digest,
                scope_snapshot_digest=plan.scope_snapshot_digest,
                authorization_recipe_allowed=True,
                policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
            )
            assert issued is True, reason
            assert lease is not None
        campaign_id = campaign.id

    checked = Event()
    resume = Event()
    original_stopped = DatabaseRepository.campaign_is_emergency_stopped

    def pause_after_initial_stop_check(self, campaign_id):
        stopped = original_stopped(self, campaign_id)
        if checked.is_set() is False:
            checked.set()
            assert resume.wait(timeout=5)
        return stopped

    monkeypatch.setattr(
        DatabaseRepository,
        "campaign_is_emergency_stopped",
        pause_after_initial_stop_check,
    )
    result: dict[str, object] = {}

    def attempt_execution_authority() -> None:
        try:
            with Session() as session:
                repository = DatabaseRepository(session)
                if operation == "lease":
                    result["lease"] = repository.issue_execution_lease(
                        campaign_id=campaign_id,
                        plan_id=plan.plan_id,
                        lease_id="lease_after_stop",
                        authorization_digest=plan.authorization_digest,
                        scope_snapshot_digest=plan.scope_snapshot_digest,
                        authorization_recipe_allowed=True,
                        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
                    )
                else:
                    result["request"] = repository.reserve_execution_request(
                        campaign_id=campaign_id,
                        lease_id="lease_before_stop",
                        reservation_payload={
                            "reservation_id": "reservation_after_stop",
                            "lease_id": "lease_before_stop",
                            "plan_id": plan.plan_id,
                            "plan_digest": plan.plan_digest,
                            "destination_host": "127.0.0.1",
                            "destination_port": 8080,
                            "destination_path": "/api",
                            "method": "GET",
                            "mutation_class": "none",
                            "idempotency_key": "idem_after_stop",
                            "remaining_request_budget": 1,
                        },
                    )
        except Exception as exc:  # noqa: BLE001 - assert durable stop reason below
            result["error"] = exc

    worker = Thread(target=attempt_execution_authority)
    worker.start()
    assert checked.wait(timeout=5)
    with Session() as session:
        stopped = DatabaseRepository(session).emergency_stop_campaign(
            campaign_id=campaign_id,
            actor="operator_alice",
            reason="race_drill",
        )
        assert stopped["emergency_stopped"] is True
    resume.set()
    worker.join(timeout=10)
    assert worker.is_alive() is False

    if operation == "lease":
        issued, reason, lease = result["lease"]
        assert issued is False
        assert reason == "emergency_stopped"
        assert lease is None
    else:
        assert isinstance(result.get("error"), ValueError)
        assert str(result["error"]) in {"emergency_stopped", "lease_not_active"}

    with Session() as session:
        repository = DatabaseRepository(session)
        assert all(
            lease.status != "active"
            for lease in repository.list_execution_leases(campaign_id)
        )
        assert session.scalars(
            select(ExecutionRequestLedgerRecord).where(
                ExecutionRequestLedgerRecord.campaign_id == campaign_id,
                ExecutionRequestLedgerRecord.status == "reserved",
            )
        ).all() == []


def test_repository_persists_sanitized_observation():
    session, repo, campaign = _session_repo()
    try:
        recipe = default_recipe_registry().require("lab_browser_mapping", "1.0.0")
        row = repo.create_autopilot_observation(
            ObservationRecord(
                observation_id="obs_1",
                campaign_id=campaign.id,
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
                reservation_id="reservation_1",
                session_generation=1,
                tool_run_id="toolrun_1",
                endpoint=EndpointIdentity(method="GET", route_template="/api/{owned}"),
                occurred_at=datetime.now(UTC),
                outcome_class=GatewayOutcomeClass.OK,
                grade=ObservationGrade.L2_CORROBORATED,
                summary_code=ObservationSummaryCode.ROUTE_MAPPED,
            )
        )
        assert row.observation_id == "obs_1"
        assert row.payload["raw_content_retained"] is False
        assert "raw_body" not in row.payload
        assert "authorization" not in row.payload
    finally:
        session.close()
