"""Durable Autopilot plan/lease/ledger/emergency-stop repository tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.bounty_autopilot.asset_admission import (
    AssetIdentity,
    AssetProvenance,
    ScopeMatcher,
    compute_asset_id,
    decide_admission,
)
from app.bounty_autopilot.authority import build_campaign_authorization
from app.bounty_autopilot.contracts import (
    AuthorizationBudget,
    CampaignAuthorizationCreate,
    MutationInventory,
    PolicyMode,
    RecipeRef,
    RiskTier,
)
from app.bounty_autopilot.plans import build_validation_plan
from app.bounty_autopilot.transport import TransportReceipt, sign_transport_receipt
from app.db import Base
from app.repository import DatabaseRepository, seed_sample_data


def _digest(n: str = "a") -> str:
    return "sha256:" + (n * 64)


LAB_ASSET_ID = compute_asset_id(
    AssetIdentity(
        scheme="http",
        host="127.0.0.1",
        port=8080,
        path_authority="/api",
        provenance=AssetProvenance.SEED,
    )
)


def _authorize_lab_campaign(
    repo: DatabaseRepository,
    campaign,
    *,
    max_requests: int = 20,
    max_concurrent_requests: int = 1,
    max_duration_seconds: int = 300,
    max_cost_units: int = 20,
    expires_at: datetime | None = None,
) -> object:
    authorization = build_campaign_authorization(
        CampaignAuthorizationCreate(
            campaign_id=campaign.id,
            scope_snapshot_id="scope_lab",
            scope_snapshot_digest=_digest("b"),
            policy_digest=f"sha256:{sha256(b'policy').hexdigest()}",
            asset_ids=(LAB_ASSET_ID,),
            recipe_refs=(RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),),
            risk_ceiling=RiskTier.R3,
            active_hours_utc=tuple(range(24)),
            budget=AuthorizationBudget(
                max_requests=max_requests,
                max_concurrent_requests=max_concurrent_requests,
                max_response_bytes=10_000,
                max_duration_seconds=max_duration_seconds,
                max_accounts=0,
                max_cost_units=max_cost_units,
            ),
            expires_at=expires_at or datetime.now(UTC) + timedelta(hours=1),
            operator_id="operator_alice",
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        )
    )
    record = repo.create_campaign_authorization(
        campaign_id=campaign.id,
        authorization_payload=authorization.model_dump(mode="json"),
    )
    admission = decide_admission(
        AssetIdentity(
            scheme="http",
            host="127.0.0.1",
            port=8080,
            path_authority="/api",
            provenance=AssetProvenance.SEED,
        ),
        ScopeMatcher(
            include_hosts=("127.0.0.1",),
            include_path_prefixes=("/api",),
            scope_snapshot_digest=record.scope_snapshot_digest,
        ),
    )
    repo.upsert_campaign_asset_admission(
        campaign_id=campaign.id,
        admission=admission.model_dump(mode="json"),
    )
    return record


def _session_repo(**authorization_overrides):
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
    authorization = _authorize_lab_campaign(
        repo,
        campaign,
        **authorization_overrides,
    )
    return session, repo, campaign, authorization


def _plan_dict(
    campaign_id: str,
    *,
    authorization_digest: str,
    scope_snapshot_digest: str,
    risk_tier: RiskTier = RiskTier.R1,
    plan_id: str = "plan_1",
    max_requests: int = 3,
    max_duration_seconds: int = 30,
):
    plan = build_validation_plan(
        plan_id=plan_id,
        campaign_id=campaign_id,
        authorization_digest=authorization_digest,
        scope_snapshot_digest=scope_snapshot_digest,
        asset_id=LAB_ASSET_ID,
        destination_scheme="http",
        destination_host="127.0.0.1",
        destination_port=8080,
        destination_path="/api",
        branch_id="branch_1",
        risk_tier=risk_tier,
        recipe_ref=RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),
        methods=("GET",),
        mutation_inventory=MutationInventory(
            methods=("GET",),
            mutates_state=False,
            reversible=True,
            requires_owned_accounts=False,
        ),
        max_requests=max_requests,
        max_response_bytes=1000,
        max_duration_seconds=max_duration_seconds,
        rollback_plan="noop",
        stop_conditions=("stop",),
        tool_profile="lab",
        container_profile="lab",
    )
    return plan.model_dump(mode="json"), plan


def test_repository_persists_plan_lease_request_and_idempotency():
    session, repo, campaign, authorization = _session_repo()
    try:
        plan_payload, plan = _plan_dict(
            campaign.id,
            authorization_digest=authorization.authorization_digest,
            scope_snapshot_digest=authorization.scope_snapshot_digest,
        )
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
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
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
        with pytest.raises(ValueError, match="transport_receipt_required"):
            repo.mark_execution_request_sent(
                campaign_id=campaign.id,
                lease_id="lease_1",
                reservation_id=res.reservation_id,
                destination_host="127.0.0.1",
                destination_port=8080,
                destination_path="/api",
                method="GET",
                gateway_authorized=True,
            )
        authorized, _challenge = repo.authorize_execution_request(
            campaign_id=campaign.id,
            lease_id="lease_1",
            reservation_id=res.reservation_id,
            destination_host="127.0.0.1",
            destination_port=8080,
            destination_path="/api",
            method="GET",
        )
        assert authorized.status == "reserved"
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
        assert again_res.status == "reserved"
        with pytest.raises(ValueError, match="idempotency_key_conflict"):
            repo.reserve_execution_request(
                campaign_id=campaign.id,
                lease_id="lease_1",
                reservation_payload={
                    "reservation_id": "res_other",
                    "lease_id": "lease_1",
                    "plan_id": plan.plan_id,
                    "plan_digest": plan.plan_digest,
                    "destination_host": "127.0.0.1",
                    "destination_port": 8080,
                    "destination_path": "/api/other",
                    "method": "GET",
                    "mutation_class": "none",
                    "idempotency_key": "idem_1",
                    "remaining_request_budget": 2,
                },
            )
        completed = repo.complete_execution_request(
            campaign_id=campaign.id,
            reservation_id="res_1",
            outcome="awaiting_human",
        )
        assert completed.status == "awaiting_human"
        # Terminal outcome is idempotent.
        completed2 = repo.complete_execution_request(
            campaign_id=campaign.id,
            reservation_id="res_1",
            outcome="awaiting_human",
        )
        assert completed2.id == completed.id
    finally:
        session.close()


def test_repository_rejects_receipt_after_lease_expiry():
    session, repo, campaign, authorization = _session_repo()
    try:
        issued_at = datetime.now(UTC).replace(microsecond=0)
        plan_payload, plan = _plan_dict(
            campaign.id,
            authorization_digest=authorization.authorization_digest,
            scope_snapshot_digest=authorization.scope_snapshot_digest,
            max_duration_seconds=10,
        )
        repo.create_validation_plan(campaign_id=campaign.id, plan_payload=plan_payload)
        issued, reason, lease = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_expiring_receipt",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
            now=issued_at,
        )
        assert issued is True, reason
        assert lease is not None

        reservation = repo.reserve_execution_request(
            campaign_id=campaign.id,
            lease_id=lease.lease_id,
            reservation_payload={
                "reservation_id": "res_expiring_receipt",
                "lease_id": lease.lease_id,
                "plan_id": plan.plan_id,
                "plan_digest": plan.plan_digest,
                "destination_host": "127.0.0.1",
                "destination_port": 8080,
                "destination_path": "/api",
                "method": "GET",
                "mutation_class": "none",
                "idempotency_key": "idem_expiring_receipt",
                "remaining_request_budget": 2,
            },
            now=issued_at + timedelta(seconds=1),
        )
        _record, challenge = repo.authorize_execution_request(
            campaign_id=campaign.id,
            lease_id=lease.lease_id,
            reservation_id=reservation.reservation_id,
            destination_host="127.0.0.1",
            destination_port=8080,
            destination_path="/api",
            method="GET",
            now=issued_at + timedelta(seconds=2),
        )
        receipt = TransportReceipt(
            receipt_id="receipt_expiring",
            campaign_id=campaign.id,
            lease_id=lease.lease_id,
            reservation_id=reservation.reservation_id,
            plan_id=plan.plan_id,
            plan_digest=plan.plan_digest,
            branch_id=plan.branch_id,
            method="GET",
            scheme="http",
            host="127.0.0.1",
            port=8080,
            path="/api",
            status_code=200,
            byte_length=42,
            sent_at=issued_at + timedelta(seconds=11),
            challenge=challenge,
        )

        with pytest.raises(ValueError, match="lease_expired"):
            repo.record_transport_receipt(
                campaign_id=campaign.id,
                receipt=receipt,
                signature=sign_transport_receipt(receipt, "x" * 43),
                capability="x" * 43,
                now=issued_at + timedelta(seconds=11),
            )

        expired_lease = repo.get_execution_lease(
            campaign_id=campaign.id,
            lease_id=lease.lease_id,
        )
        assert expired_lease is not None
        assert expired_lease.status == "expired"
        assert repo.list_execution_request_ledger(campaign.id)[0].status == "expired"
    finally:
        session.close()


def test_repository_r3_approval_single_use_cas():
    session, repo, campaign, authorization = _session_repo()
    try:
        plan_payload, plan = _plan_dict(
            campaign.id,
            authorization_digest=authorization.authorization_digest,
            scope_snapshot_digest=authorization.scope_snapshot_digest,
            risk_tier=RiskTier.R3,
            plan_id="plan_r3",
        )
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
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
            payload={
                "scope_snapshot_digest": plan.scope_snapshot_digest,
                "authorization_digest": plan.authorization_digest,
                "plan_digest": plan.plan_digest,
                "account_aliases": [],
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
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
            approval_id="appr_r3",
        )
        assert ok is True, reason
        assert lease is not None
        assert lease.r3_approval_id == "appr_r3"

        ok2, reason2, lease2 = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_r3_b",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
            approval_id="appr_r3",
        )
        assert ok2 is False
        assert reason2 == "approval_already_consumed"
        assert lease2 is None

        refreshed = session.get(type(approval), "appr_r3")
        assert refreshed.consumed_at is not None
        assert refreshed.consumed_by_lease_id == "lease_r3"

        long_lived = repo.create_approval_record(
            approval_id="appr_r3_long_lived",
            campaign_id=campaign.id,
            approval_type="r3_exact_plan",
            actor="operator_alice",
            reason="exact plan",
            plan_digest=plan.plan_digest,
            status="approved",
            expires_at=datetime.now(UTC) + timedelta(minutes=31),
            payload={
                "scope_snapshot_digest": plan.scope_snapshot_digest,
                "authorization_digest": plan.authorization_digest,
                "plan_digest": plan.plan_digest,
                "account_aliases": [],
                "nonce_digest": nonce,
            },
            single_use_nonce_digest=nonce,
        )
        long_lived.status = "approved"
        long_lived.decided_at = datetime.now(UTC)
        session.commit()
        ok3, reason3, lease3 = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_r3_long_lived",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
            approval_id=long_lived.id,
        )
        assert ok3 is False
        assert reason3 == "approval_expiry_exceeds_max_ttl"
        assert lease3 is None
    finally:
        session.close()


def test_repository_replays_same_lease_after_r3_cas_loss(monkeypatch):
    session, repo, campaign, authorization = _session_repo()
    try:
        plan_payload, plan = _plan_dict(
            campaign.id,
            authorization_digest=authorization.authorization_digest,
            scope_snapshot_digest=authorization.scope_snapshot_digest,
            risk_tier=RiskTier.R3,
            plan_id="plan_r3_replay",
        )
        repo.create_validation_plan(campaign_id=campaign.id, plan_payload=plan_payload)
        nonce = _digest("f")
        approval = repo.create_approval_record(
            approval_id="appr_r3_replay",
            campaign_id=campaign.id,
            approval_type="r3_exact_plan",
            actor="operator_alice",
            reason="exact plan",
            plan_digest=plan.plan_digest,
            status="approved",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
            payload={
                "scope_snapshot_digest": plan.scope_snapshot_digest,
                "authorization_digest": plan.authorization_digest,
                "plan_digest": plan.plan_digest,
                "account_aliases": [],
                "nonce_digest": nonce,
            },
            single_use_nonce_digest=nonce,
        )
        approval.status = "approved"
        approval.decided_at = datetime.now(UTC)
        session.commit()

        issued, reason, existing = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_r3_replay",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
            approval_id=approval.id,
        )
        assert issued is True, reason
        assert existing is not None

        # Simulate the competing transaction being committed after our initial
        # lookup but before this transaction's approval CAS.
        approval.status = "approved"
        approval.consumed_at = None
        approval.consumed_by_lease_id = None
        session.commit()
        original_scalar = session.scalar
        skipped_lease_lookups = 0

        def hide_competing_lease(statement, *args, **kwargs):
            nonlocal skipped_lease_lookups
            if "execution_leases" in str(statement) and skipped_lease_lookups < 2:
                skipped_lease_lookups += 1
                return None
            return original_scalar(statement, *args, **kwargs)

        original_execute = session.execute
        cas_lost = False

        def lose_approval_cas(statement, *args, **kwargs):
            nonlocal cas_lost
            if getattr(getattr(statement, "table", None), "name", None) == "approval_records":
                cas_lost = True
                approval.status = "used"
                approval.consumed_at = datetime.now(UTC)
                approval.consumed_by_lease_id = existing.lease_id
                session.commit()
                return SimpleNamespace(rowcount=0)
            return original_execute(statement, *args, **kwargs)

        monkeypatch.setattr(session, "scalar", hide_competing_lease)
        monkeypatch.setattr(session, "execute", lose_approval_cas)

        replayed, replay_reason, lease = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id=existing.lease_id,
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
            approval_id=approval.id,
        )
        assert cas_lost is True
        assert skipped_lease_lookups == 2
        assert replayed is True, replay_reason
        assert replay_reason == "already_issued"
        assert lease is not None
        assert lease.id == existing.id
        assert len(repo.list_execution_leases(campaign.id)) == 1
    finally:
        session.close()


def test_repository_r3_approval_requires_an_expiry():
    session, repo, campaign, authorization = _session_repo()
    try:
        plan_payload, plan = _plan_dict(
            campaign.id,
            authorization_digest=authorization.authorization_digest,
            scope_snapshot_digest=authorization.scope_snapshot_digest,
            risk_tier=RiskTier.R3,
            plan_id="plan_r3_no_expiry",
        )
        repo.create_validation_plan(campaign_id=campaign.id, plan_payload=plan_payload)
        nonce = _digest("d")
        approval = repo.create_approval_record(
            approval_id="appr_r3_no_expiry",
            campaign_id=campaign.id,
            approval_type="r3_exact_plan",
            actor="operator_alice",
            reason="exact plan",
            plan_digest=plan.plan_digest,
            status="approved",
            payload={
                "scope_snapshot_digest": plan.scope_snapshot_digest,
                "authorization_digest": plan.authorization_digest,
                "plan_digest": plan.plan_digest,
                "account_aliases": [],
                "nonce_digest": nonce,
            },
            single_use_nonce_digest=nonce,
        )
        approval.status = "approved"
        approval.decided_at = datetime.now(UTC)
        session.commit()

        issued, reason, lease = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_r3_no_expiry",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
            approval_id=approval.id,
        )
        assert issued is False
        assert reason == "approval_expiry_required"
        assert lease is None
    finally:
        session.close()


def test_repository_emergency_stop_revokes_leases_and_blocks_new():
    session, repo, campaign, authorization = _session_repo()
    try:
        plan_payload, plan = _plan_dict(
            campaign.id,
            authorization_digest=authorization.authorization_digest,
            scope_snapshot_digest=authorization.scope_snapshot_digest,
            plan_id="plan_stop",
        )
        repo.create_validation_plan(campaign_id=campaign.id, plan_payload=plan_payload)
        ok, _, lease = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_stop",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
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
        assert result["local_stop_confirmation"] == "pending"
        assert repo.get_autopilot_local_stop_status(campaign.id) == {
            "campaign_id": campaign.id,
            "emergency_stopped": True,
            "local_stop_confirmed": False,
        }
        acknowledged = repo.acknowledge_autopilot_local_stop(campaign_id=campaign.id)
        assert acknowledged["local_stop_confirmed"] is True
        assert repo.acknowledge_autopilot_local_stop(campaign_id=campaign.id) == acknowledged

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
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
        )
        assert ok2 is False
        assert reason2 == "emergency_stopped"
        with pytest.raises(ValueError, match="emergency_stopped"):
            repo.reserve_execution_request(
                campaign_id=campaign.id,
                lease_id="lease_stop",
                reservation_payload={
                    "reservation_id": "res_after_stop",
                    "lease_id": "lease_stop",
                    "plan_id": plan.plan_id,
                    "plan_digest": plan.plan_digest,
                    "destination_host": "127.0.0.1",
                    "destination_port": 8080,
                    "destination_path": "/api",
                    "method": "GET",
                    "mutation_class": "none",
                    "idempotency_key": "idem_after_stop",
                    "remaining_request_budget": 2,
                },
            )
    finally:
        session.close()


def test_repository_reservation_budget_and_ids_are_bounded():
    session, repo, campaign, authorization = _session_repo()
    try:
        plan_payload, plan = _plan_dict(
            campaign.id,
            authorization_digest=authorization.authorization_digest,
            scope_snapshot_digest=authorization.scope_snapshot_digest,
            plan_id="plan_budget_one",
            max_requests=1,
        )
        repo.create_validation_plan(campaign_id=campaign.id, plan_payload=plan_payload)
        ok, reason, lease = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_budget_one",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
        )
        assert ok is True, reason
        assert lease is not None
        reservation = {
            "reservation_id": "res_budget_one",
            "lease_id": lease.lease_id,
            "plan_id": plan.plan_id,
            "plan_digest": plan.plan_digest,
            "destination_host": "127.0.0.1",
            "destination_port": 8080,
            "destination_path": "/api",
            "method": "GET",
            "mutation_class": "none",
            "idempotency_key": "idem_budget_one",
            "remaining_request_budget": 0,
        }
        repo.reserve_execution_request(
            campaign_id=campaign.id,
            lease_id=lease.lease_id,
            reservation_payload=reservation,
        )
        with pytest.raises(ValueError, match="request_budget_exhausted"):
            repo.reserve_execution_request(
                campaign_id=campaign.id,
                lease_id=lease.lease_id,
                reservation_payload={
                    **reservation,
                    "reservation_id": "res_budget_two",
                    "idempotency_key": "idem_budget_two",
                },
            )
        with pytest.raises(ValueError, match="reservation_id_conflict"):
            repo.reserve_execution_request(
                campaign_id=campaign.id,
                lease_id=lease.lease_id,
                reservation_payload={
                    **reservation,
                    "idempotency_key": "idem_budget_conflict",
                },
            )
    finally:
        session.close()


def test_repository_binds_reservations_to_authorization_generation_budget():
    session, repo, campaign, authorization = _session_repo(max_requests=3)
    try:
        first_payload, first_plan = _plan_dict(
            campaign.id,
            authorization_digest=authorization.authorization_digest,
            scope_snapshot_digest=authorization.scope_snapshot_digest,
            plan_id="plan_generation_first",
            max_requests=2,
        )
        second_payload, second_plan = _plan_dict(
            campaign.id,
            authorization_digest=authorization.authorization_digest,
            scope_snapshot_digest=authorization.scope_snapshot_digest,
            plan_id="plan_generation_second",
            max_requests=2,
        )
        repo.create_validation_plan(campaign_id=campaign.id, plan_payload=first_payload)
        repo.create_validation_plan(campaign_id=campaign.id, plan_payload=second_payload)
        for plan, lease_id in ((first_plan, "lease_generation_first"), (second_plan, "lease_generation_second")):
            issued, reason, lease = repo.issue_execution_lease(
                campaign_id=campaign.id,
                plan_id=plan.plan_id,
                lease_id=lease_id,
                authorization_digest=plan.authorization_digest,
                scope_snapshot_digest=plan.scope_snapshot_digest,
                authorization_recipe_allowed=True,
                policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
            )
            assert issued is True, reason
            assert lease is not None

        def reserve(plan, lease_id: str, suffix: str, remaining: int) -> None:
            repo.reserve_execution_request(
                campaign_id=campaign.id,
                lease_id=lease_id,
                reservation_payload={
                    "reservation_id": f"res_generation_{suffix}",
                    "lease_id": lease_id,
                    "plan_id": plan.plan_id,
                    "plan_digest": plan.plan_digest,
                    "destination_host": "127.0.0.1",
                    "destination_port": 8080,
                    "destination_path": "/api",
                    "method": "GET",
                    "mutation_class": "none",
                    "idempotency_key": f"idem_generation_{suffix}",
                    "remaining_request_budget": remaining,
                },
            )

        reserve(first_plan, "lease_generation_first", "one", 1)
        reserve(first_plan, "lease_generation_first", "two", 0)
        reserve(second_plan, "lease_generation_second", "three", 1)
        with pytest.raises(ValueError, match="authorization_request_budget_exhausted"):
            reserve(second_plan, "lease_generation_second", "four", 0)
    finally:
        session.close()


def test_repository_expires_lease_and_unsent_reservations_without_revival():
    now = datetime.now(UTC).replace(microsecond=0)
    session, repo, campaign, authorization = _session_repo(
        expires_at=now + timedelta(minutes=5)
    )
    try:
        plan_payload, plan = _plan_dict(
            campaign.id,
            authorization_digest=authorization.authorization_digest,
            scope_snapshot_digest=authorization.scope_snapshot_digest,
            plan_id="plan_short_lease",
            max_requests=2,
            max_duration_seconds=1,
        )
        repo.create_validation_plan(campaign_id=campaign.id, plan_payload=plan_payload)
        issued, reason, lease = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_short",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
            now=now,
        )
        assert issued is True, reason
        assert lease is not None
        reservation = {
            "reservation_id": "res_short_one",
            "lease_id": "lease_short",
            "plan_id": plan.plan_id,
            "plan_digest": plan.plan_digest,
            "destination_host": "127.0.0.1",
            "destination_port": 8080,
            "destination_path": "/api",
            "method": "GET",
            "mutation_class": "none",
            "idempotency_key": "idem_short_one",
            "remaining_request_budget": 1,
        }
        repo.reserve_execution_request(
            campaign_id=campaign.id,
            lease_id="lease_short",
            reservation_payload=reservation,
            now=now,
        )
        with pytest.raises(ValueError, match="lease_expired"):
            repo.reserve_execution_request(
                campaign_id=campaign.id,
                lease_id="lease_short",
                reservation_payload={
                    **reservation,
                    "reservation_id": "res_short_two",
                    "idempotency_key": "idem_short_two",
                    "remaining_request_budget": 0,
                },
                now=now + timedelta(seconds=2),
            )
        durable_lease = repo.get_execution_lease(
            campaign_id=campaign.id,
            lease_id="lease_short",
        )
        assert durable_lease is not None
        assert durable_lease.status == "expired"
        ledger = repo.list_execution_request_ledger(campaign.id)
        assert [(row.reservation_id, row.status) for row in ledger] == [
            ("res_short_one", "expired")
        ]
        with pytest.raises(ValueError, match="lease_not_active"):
            repo.reserve_execution_request(
                campaign_id=campaign.id,
                lease_id="lease_short",
                reservation_payload=reservation,
                now=now + timedelta(seconds=3),
            )
    finally:
        session.close()


def test_gateway_authorization_counts_pending_receipts_against_concurrency():
    session, repo, campaign, authorization = _session_repo(max_concurrent_requests=1)
    try:
        plan_payload, plan = _plan_dict(
            campaign.id,
            authorization_digest=authorization.authorization_digest,
            scope_snapshot_digest=authorization.scope_snapshot_digest,
            plan_id="plan_gateway_concurrency",
            max_requests=2,
        )
        repo.create_validation_plan(campaign_id=campaign.id, plan_payload=plan_payload)
        issued, reason, lease = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_gateway_concurrency",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
        )
        assert issued is True, reason
        assert lease is not None
        for suffix, remaining in (("one", 1), ("two", 0)):
            repo.reserve_execution_request(
                campaign_id=campaign.id,
                lease_id="lease_gateway_concurrency",
                reservation_payload={
                    "reservation_id": f"res_gateway_concurrency_{suffix}",
                    "lease_id": "lease_gateway_concurrency",
                    "plan_id": plan.plan_id,
                    "plan_digest": plan.plan_digest,
                    "destination_host": "127.0.0.1",
                    "destination_port": 8080,
                    "destination_path": "/api",
                    "method": "GET",
                    "mutation_class": "none",
                    "idempotency_key": f"idem_gateway_concurrency_{suffix}",
                    "remaining_request_budget": remaining,
                },
            )

        def authorize(reservation_id: str):
            return repo.authorize_execution_request(
                campaign_id=campaign.id,
                lease_id="lease_gateway_concurrency",
                reservation_id=reservation_id,
                destination_host="127.0.0.1",
                destination_port=8080,
                destination_path="/api",
                method="GET",
            )

        first, challenge = authorize("res_gateway_concurrency_one")
        assert first.status == "reserved"
        repeated, repeated_challenge = authorize("res_gateway_concurrency_one")
        assert repeated.id == first.id
        assert repeated_challenge == challenge
        with pytest.raises(ValueError, match="authorization_concurrency_exhausted"):
            authorize("res_gateway_concurrency_two")
        repo.complete_execution_request(
            campaign_id=campaign.id,
            reservation_id="res_gateway_concurrency_one",
            outcome="no_send_failure",
        )
        second, _challenge = authorize("res_gateway_concurrency_two")
        assert second.status == "reserved"
    finally:
        session.close()


def test_repository_rejects_query_fragment_and_encoded_reservation_paths():
    session, repo, campaign, authorization = _session_repo()
    try:
        plan_payload, plan = _plan_dict(
            campaign.id,
            authorization_digest=authorization.authorization_digest,
            scope_snapshot_digest=authorization.scope_snapshot_digest,
            plan_id="plan_canonical_path",
        )
        repo.create_validation_plan(campaign_id=campaign.id, plan_payload=plan_payload)
        issued, reason, lease = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_canonical_path",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
        )
        assert issued is True, reason
        assert lease is not None
        for suffix, destination_path in (
            ("query", "/api?op=delete"),
            ("fragment", "/api#hidden"),
            ("encoded", "/api%2Fother"),
            ("traversal", "/api/../other"),
        ):
            with pytest.raises(ValueError, match="request_destination_mismatch"):
                repo.reserve_execution_request(
                    campaign_id=campaign.id,
                    lease_id="lease_canonical_path",
                    reservation_payload={
                        "reservation_id": f"res_path_{suffix}",
                        "lease_id": "lease_canonical_path",
                        "plan_id": plan.plan_id,
                        "plan_digest": plan.plan_digest,
                        "destination_host": "127.0.0.1",
                        "destination_port": 8080,
                        "destination_path": destination_path,
                        "method": "GET",
                        "mutation_class": "none",
                        "idempotency_key": f"idem_path_{suffix}",
                        "remaining_request_budget": 2,
                    },
                )
    finally:
        session.close()


def test_repository_persists_sanitized_observation():
    session, repo, campaign, _authorization = _session_repo()
    try:
        with pytest.raises(ValueError, match="observation_contract_invalid"):
            repo.create_autopilot_observation(
                campaign_id=campaign.id,
                observation_payload={
                    "observation_id": "obs_1",
                    "branch_id": "branch_1",
                    "plan_digest": _digest("b"),
                    "grade": "L3_ACTIONABLE",
                    "outcome_class": "ok",
                    "summary": "sanitized",
                    "raw_body": "SECRET_SHOULD_NOT_PERSIST",
                    "authorization": "Bearer secret",
                },
            )
    finally:
        session.close()


def test_repository_reserves_duration_across_plans_and_reopened_sessions():
    session, repo, campaign, authorization = _session_repo(max_duration_seconds=35)
    reopened_session = None
    try:
        campaign_id = campaign.id
        authorization_id = authorization.id
        authorization_digest = authorization.authorization_digest
        scope_snapshot_digest = authorization.scope_snapshot_digest
        first_payload, first_plan = _plan_dict(
            campaign_id,
            authorization_digest=authorization_digest,
            scope_snapshot_digest=scope_snapshot_digest,
            plan_id="plan_duration_first",
            max_requests=1,
            max_duration_seconds=20,
        )
        second_payload, second_plan = _plan_dict(
            campaign_id,
            authorization_digest=authorization_digest,
            scope_snapshot_digest=scope_snapshot_digest,
            plan_id="plan_duration_second",
            max_requests=1,
            max_duration_seconds=20,
        )
        repo.create_validation_plan(campaign_id=campaign_id, plan_payload=first_payload)
        repo.create_validation_plan(campaign_id=campaign_id, plan_payload=second_payload)
        issued, reason, lease = repo.issue_execution_lease(
            campaign_id=campaign_id,
            plan_id=first_plan.plan_id,
            lease_id="lease_duration_first",
            authorization_digest=authorization_digest,
            scope_snapshot_digest=scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
        )
        assert issued is True, reason
        assert lease is not None
        assert lease.duration_reserved_seconds == 20

        engine = session.get_bind()
        session.close()
        reopened_session = sessionmaker(bind=engine)()
        reopened = DatabaseRepository(reopened_session)
        usage = reopened.get_autopilot_authorization_budget_usage(
            campaign_id=campaign_id,
            authorization_id=authorization_id,
        )
        assert usage == {
            "requests_reserved": 0,
            "duration_reserved_seconds": 20,
            "cost_units_reserved": 1,
        }
        issued, reason, lease = reopened.issue_execution_lease(
            campaign_id=campaign_id,
            plan_id=second_plan.plan_id,
            lease_id="lease_duration_second",
            authorization_digest=authorization_digest,
            scope_snapshot_digest=scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
        )
        assert issued is False
        assert reason == "authorization_duration_budget_exhausted"
        assert lease is None
    finally:
        if reopened_session is not None:
            reopened_session.close()
        session.close()


def test_repository_reserves_cost_across_plans():
    session, repo, campaign, authorization = _session_repo(
        max_duration_seconds=100,
        max_cost_units=3,
    )
    try:
        first_payload, first_plan = _plan_dict(
            campaign.id,
            authorization_digest=authorization.authorization_digest,
            scope_snapshot_digest=authorization.scope_snapshot_digest,
            plan_id="plan_cost_first",
            max_requests=2,
            max_duration_seconds=10,
        )
        second_payload, second_plan = _plan_dict(
            campaign.id,
            authorization_digest=authorization.authorization_digest,
            scope_snapshot_digest=authorization.scope_snapshot_digest,
            plan_id="plan_cost_second",
            max_requests=2,
            max_duration_seconds=10,
        )
        repo.create_validation_plan(campaign_id=campaign.id, plan_payload=first_payload)
        repo.create_validation_plan(campaign_id=campaign.id, plan_payload=second_payload)
        issued, reason, lease = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=first_plan.plan_id,
            lease_id="lease_cost_first",
            authorization_digest=first_plan.authorization_digest,
            scope_snapshot_digest=first_plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
        )
        assert issued is True, reason
        assert lease is not None
        assert lease.cost_units_reserved == 2

        issued, reason, lease = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=second_plan.plan_id,
            lease_id="lease_cost_second",
            authorization_digest=second_plan.authorization_digest,
            scope_snapshot_digest=second_plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
        )
        assert issued is False
        assert reason == "authorization_cost_budget_exhausted"
        assert lease is None
    finally:
        session.close()


def test_repository_rejects_legacy_lease_without_budget_ledger():
    session, repo, campaign, authorization = _session_repo()
    try:
        plan_payload, plan = _plan_dict(
            campaign.id,
            authorization_digest=authorization.authorization_digest,
            scope_snapshot_digest=authorization.scope_snapshot_digest,
            plan_id="plan_legacy_budget_ledger",
            max_requests=2,
        )
        repo.create_validation_plan(campaign_id=campaign.id, plan_payload=plan_payload)
        issued, reason, lease = repo.issue_execution_lease(
            campaign_id=campaign.id,
            plan_id=plan.plan_id,
            lease_id="lease_legacy_budget_ledger",
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            authorization_recipe_allowed=True,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
        )
        assert issued is True, reason
        assert lease is not None
        reserved = repo.reserve_execution_request(
            campaign_id=campaign.id,
            lease_id=lease.lease_id,
            reservation_payload={
                "reservation_id": "reservation_legacy_budget_ledger",
                "lease_id": lease.lease_id,
                "plan_id": plan.plan_id,
                "plan_digest": plan.plan_digest,
                "destination_host": "127.0.0.1",
                "destination_port": 8080,
                "destination_path": "/api",
                "method": "GET",
                "mutation_class": "none",
                "idempotency_key": "legacy-budget-ledger",
                "remaining_request_budget": 1,
            },
        )
        lease_record = repo.get_execution_lease(
            campaign_id=campaign.id,
            lease_id=lease.lease_id,
        )
        assert lease_record is not None
        legacy_payload = dict(lease_record.payload)
        legacy_payload.pop("duration_reserved_seconds", None)
        legacy_payload.pop("cost_units_reserved", None)
        lease_record.payload = legacy_payload
        lease_record.duration_reserved_seconds = None
        lease_record.cost_units_reserved = None
        session.commit()

        with pytest.raises(ValueError, match="authorization_budget_ledger_invalid"):
            repo.reserve_execution_request(
                campaign_id=campaign.id,
                lease_id=lease.lease_id,
                reservation_payload={
                    "reservation_id": "reservation_legacy_budget_ledger_second",
                    "lease_id": lease.lease_id,
                    "plan_id": plan.plan_id,
                    "plan_digest": plan.plan_digest,
                    "destination_host": "127.0.0.1",
                    "destination_port": 8080,
                    "destination_path": "/api",
                    "method": "GET",
                    "mutation_class": "none",
                    "idempotency_key": "legacy-budget-ledger-second",
                    "remaining_request_budget": 0,
                },
            )
        with pytest.raises(ValueError, match="authorization_budget_ledger_invalid"):
            repo.authorize_execution_request(
                campaign_id=campaign.id,
                lease_id=lease.lease_id,
                reservation_id=reserved.reservation_id,
                destination_host="127.0.0.1",
                destination_port=8080,
                destination_path="/api",
                method="GET",
            )
    finally:
        session.close()
