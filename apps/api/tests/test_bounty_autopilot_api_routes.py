"""HTTP API tests for Bounty Autopilot durable routes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
import os

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.bounty_autopilot.authority import build_campaign_authorization
from app.bounty_autopilot.asset_admission import (
    AssetIdentity,
    AssetProvenance,
    ScopeMatcher,
    compute_asset_id,
    decide_admission,
)
from app.bounty_autopilot.branches import BranchStatus, ResearchBranch
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
from app import autonomous_research_runtime
from app.candidate_hunter_loop import run_candidate_hunter_loop
from app.db import Base, get_session
from app.config import get_settings
from app.main import (
    _autopilot_candidate_queue,
    _materialize_autopilot_source_snapshot,
    _wait_for_autopilot_local_stop_confirmation,
    app,
)
from app.repository import DatabaseRepository, seed_sample_data


def _digest(n: str = "a") -> str:
    return "sha256:" + (n * 64)


def _hash_digest(value: str) -> str:
    return f"sha256:{sha256(value.encode('utf-8')).hexdigest()}"


LAB_ASSET_ID = compute_asset_id(
    AssetIdentity(
        scheme="http",
        host="127.0.0.1",
        port=18080,
        path_authority="/api",
        provenance=AssetProvenance.SEED,
    )
)
RUNNER_CAPABILITY = "a" * 43


def _admit_lab_asset(repository: DatabaseRepository, campaign_id: str, scope_digest: str):
    admission = decide_admission(
        AssetIdentity(
            scheme="http",
            host="127.0.0.1",
            port=18080,
            path_authority="/api",
            provenance=AssetProvenance.SEED,
        ),
        ScopeMatcher(
            include_hosts=("127.0.0.1",),
            include_path_prefixes=("/api",),
            scope_snapshot_digest=scope_digest,
        ),
    )
    assert admission.asset_id == LAB_ASSET_ID
    return repository.upsert_campaign_asset_admission(
        campaign_id=campaign_id,
        admission=admission.model_dump(mode="json"),
    )


def _client_and_campaign():
    os.environ["AUTOPILOT_RUNNER_CAPABILITY"] = RUNNER_CAPABILITY
    get_settings.cache_clear()
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine)

    def override_get_session():
        with TestingSession() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestingSession() as session:
        seed_sample_data(session)
        repo = DatabaseRepository(session)
        program = repo.list_programs()[0]
        campaign = repo.create_campaign(
            program_id=program.id,
            name="autopilot-api",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="policy",
            default_asset="127.0.0.1",
            created_by="operator_alice",
            campaign_mode="bounty_autopilot",
        )
        campaign_id = campaign.id
    client = TestClient(
        app,
        headers={"X-Mythos-Autopilot-Runner-Capability": RUNNER_CAPABILITY},
    )
    return client, campaign_id, TestingSession


def test_local_stop_confirmation_waiter_uses_durable_acknowledgement():
    class Repository:
        def __init__(self):
            self.calls = 0

        def get_autopilot_local_stop_status(self, campaign_id: str):
            self.calls += 1
            return {
                "campaign_id": campaign_id,
                "emergency_stopped": True,
                "local_stop_confirmed": self.calls >= 2,
            }

    class Session:
        def __init__(self):
            self.expired = 0
            self.rolled_back = 0

        def expire_all(self):
            self.expired += 1

        def rollback(self):
            self.rolled_back += 1

    repository = Repository()
    session = Session()
    assert _wait_for_autopilot_local_stop_confirmation(
        repository,
        session,
        "campaign_lab",
        timeout_seconds=0.1,
    )
    assert repository.calls >= 2
    assert session.expired >= 2
    assert session.rolled_back >= 1


def test_local_stop_confirmation_waiter_reports_missing_acknowledgement():
    class Repository:
        def get_autopilot_local_stop_status(self, campaign_id: str):
            return {
                "campaign_id": campaign_id,
                "emergency_stopped": True,
                "local_stop_confirmed": False,
            }

    class Session:
        def expire_all(self):
            return None

        def rollback(self):
            return None

    assert not _wait_for_autopilot_local_stop_confirmation(
        Repository(),
        Session(),
        "campaign_lab",
        timeout_seconds=0,
    )


def _plan_payload(
    campaign_id: str,
    *,
    authorization_digest: str = _digest("a"),
    scope_snapshot_digest: str = _digest("b"),
):
    plan = build_validation_plan(
        plan_id="plan_api",
        campaign_id=campaign_id,
        authorization_digest=authorization_digest,
        scope_snapshot_digest=scope_snapshot_digest,
        asset_id=LAB_ASSET_ID,
        destination_scheme="http",
        destination_host="127.0.0.1",
        destination_port=18080,
        destination_path="/api",
        branch_id="branch_api",
        risk_tier=RiskTier.R1,
        recipe_ref=RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),
        methods=("GET",),
        mutation_inventory=MutationInventory(
            methods=("GET",),
            mutates_state=False,
            reversible=True,
            requires_owned_accounts=False,
        ),
        max_requests=3,
        max_response_bytes=1000,
        max_duration_seconds=30,
        rollback_plan="noop",
        stop_conditions=("stop",),
        tool_profile="lab",
        container_profile="lab",
    )
    return plan.model_dump(mode="json"), plan


def _persist_authorization(
    repository: DatabaseRepository,
    campaign_id: str,
    *,
    risk_ceiling: RiskTier = RiskTier.R3,
    max_concurrent_requests: int = 1,
    recipe_refs: tuple[RecipeRef, ...] | None = None,
):
    authorization = build_campaign_authorization(
        CampaignAuthorizationCreate(
            campaign_id=campaign_id,
            scope_snapshot_id="scope_autopilot",
            scope_snapshot_digest=_digest("b"),
            policy_digest=_hash_digest("policy"),
            asset_ids=(LAB_ASSET_ID,),
            account_aliases=("account_a", "account_b"),
            recipe_refs=recipe_refs
            or (RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),),
            risk_ceiling=risk_ceiling,
            active_hours_utc=tuple(range(24)),
            budget=AuthorizationBudget(
                max_requests=20,
                max_concurrent_requests=max_concurrent_requests,
                max_response_bytes=100_000,
                max_duration_seconds=1_800,
                max_accounts=2,
                max_cost_units=20,
            ),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            operator_id="operator_alice",
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        )
    )
    record = repository.create_campaign_authorization(
        campaign_id=campaign_id,
        authorization_payload=authorization.model_dump(mode="json"),
    )
    _admit_lab_asset(repository, campaign_id, record.scope_snapshot_digest)
    return record


def test_autopilot_plan_lease_request_observation_and_stop_flow():
    client, campaign_id, testing_session = _client_and_campaign()
    try:
        with testing_session() as session:
            authorization = _persist_authorization(DatabaseRepository(session), campaign_id)
            authorization_digest = authorization.authorization_digest
            scope_snapshot_digest = authorization.scope_snapshot_digest
        plan_payload, plan = _plan_payload(
            campaign_id,
            authorization_digest=authorization_digest,
            scope_snapshot_digest=scope_snapshot_digest,
        )
        created = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/plans",
            json={"plan": plan_payload},
        )
        assert created.status_code == 200, created.text
        assert created.json()["plan_digest"] == plan.plan_digest
        listed = client.get(f"/mythos/campaigns/{campaign_id}/autopilot/plans")
        assert listed.status_code == 200
        assert len(listed.json()) >= 1

        lease = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/leases",
            json={
                "plan_id": plan.plan_id,
                "lease_id": "lease_api",
                "authorization_digest": authorization_digest,
                "scope_snapshot_digest": scope_snapshot_digest,
                "authorization_recipe_allowed": True,
                "policy_mode": PolicyMode.AUTHORIZED_LOCAL_LAB.value,
            },
        )
        assert lease.status_code == 200, lease.text
        assert lease.json()["allowed"] is True

        reserve = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/requests/reserve",
            json={
                "lease_id": "lease_api",
                "reservation": {
                    "reservation_id": "res_api",
                    "lease_id": "lease_api",
                    "plan_id": plan.plan_id,
                    "plan_digest": plan.plan_digest,
                    "destination_host": "127.0.0.1",
                    "destination_port": 18080,
                    "destination_path": "/api/docs/1",
                    "method": "GET",
                    "mutation_class": "none",
                    "idempotency_key": "idem_api",
                    "remaining_request_budget": 2,
                },
            },
        )
        assert reserve.status_code == 200, reserve.text
        assert reserve.json()["reservation_id"] == "res_api"

        auth = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/gateway/authorize",
            json={
                "lease_id": "lease_api",
                "method": "GET",
                "scheme": "http",
                "host": "127.0.0.1",
                "port": 18080,
                "path": "/api/docs/1",
            },
        )
        assert auth.status_code == 200, auth.text
        assert auth.json()["status"] == "allowed"
        assert auth.json()["report_submission_allowed"] is False

        receipt = TransportReceipt(
            receipt_id="receipt_api",
            campaign_id=campaign_id,
            lease_id="lease_api",
            reservation_id="res_api",
            plan_id=plan.plan_id,
            plan_digest=plan.plan_digest,
            branch_id=plan.branch_id,
            method="GET",
            scheme="http",
            host="127.0.0.1",
            port=18080,
            path="/api/docs/1",
            body_digest=None,
            status_code=200,
            content_type_class="json",
            byte_length=42,
            sent_at=datetime.now(UTC),
            challenge=auth.json()["transport_challenge"],
        )
        receipt_response = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/requests/receipt",
            json={
                "receipt": receipt.model_dump(mode="json"),
                "signature": sign_transport_receipt(receipt, RUNNER_CAPABILITY),
            },
        )
        assert receipt_response.status_code == 200, receipt_response.text
        receipt_digest = receipt_response.json()["receipt_digest"]

        complete = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/requests/complete",
            json={"reservation_id": "res_api", "outcome": "completed"},
        )
        assert complete.status_code == 200, complete.text

        mismatched_obs = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/observations",
            json={
                "observation": {
                    "observation_id": "obs_api",
                    "branch_id": "branch_api",
                    "plan_digest": plan.plan_digest,
                    "lease_id": "lease_api",
                    "reservation_id": "res_api",
                    "receipt_digest": receipt_digest,
                    "grade": "L2_corroborated",
                    "outcome_class": "ok",
                    "summary": "tampered receipt metadata",
                    "evidence_refs": ["safe_ref"],
                    "status_class": "5xx",
                    "content_type_class": "html",
                    "byte_length": 43,
                }
            },
        )
        assert mismatched_obs.status_code == 400
        assert mismatched_obs.json()["detail"] == "observation_metadata_mismatch"

        rejected_obs = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/observations",
            json={
                "observation": {
                    "observation_id": "obs_api",
                    "branch_id": "branch_api",
                    "plan_digest": plan.plan_digest,
                    "lease_id": "lease_api",
                    "reservation_id": "res_api",
                    "receipt_digest": receipt_digest,
                    "grade": "L2_corroborated",
                    "outcome_class": "ok",
                    "summary": "Authorization: Bearer nested-secret",
                    "evidence_refs": ["safe_ref", "Bearer nested-secret"],
                    "status_class": "2xx",
                    "content_type_class": "json",
                    "byte_length": 42,
                    "raw_body": "should-be-stripped",
                    "authorization": "Bearer secret",
                    "metadata": {
                        "Authorization": "Bearer nested-secret",
                        "Set-Cookie": "session=nested-secret",
                        "token": "nested-secret",
                    },
                }
            },
        )
        assert rejected_obs.status_code == 422
        valid_observation = {
            "observation_id": "obs_api",
            "branch_id": "branch_api",
            "plan_digest": plan.plan_digest,
            "lease_id": "lease_api",
            "reservation_id": "res_api",
            "receipt_digest": receipt_digest,
            "grade": "L2_corroborated",
            "outcome_class": "ok",
            "summary": "owned account document read",
            "evidence_refs": ["safe_ref"],
            "status_class": "2xx",
            "content_type_class": "json",
            "byte_length": 42,
        }
        obs = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/observations",
            json={"observation": valid_observation},
        )
        assert obs.status_code == 200, obs.text
        duplicate_obs = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/observations",
            json={"observation": valid_observation},
        )
        assert duplicate_obs.status_code == 200, duplicate_obs.text
        conflicting_obs = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/observations",
            json={
                "observation": {
                    **valid_observation,
                    "summary": "conflicting duplicate delivery",
                }
            },
        )
        assert conflicting_obs.status_code == 400
        assert conflicting_obs.json()["detail"] == "observation_idempotency_conflict"
        listed_obs = client.get(
            f"/mythos/campaigns/{campaign_id}/autopilot/observations"
        )
        assert listed_obs.status_code == 200
        item = listed_obs.json()["items"][0]
        assert item["observation_id"] == "obs_api"
        assert "raw_body" not in item["payload"]
        assert "authorization" not in item["payload"]
        assert "metadata" not in item["payload"]
        assert "nested-secret" not in str(item["payload"])
        assert item["payload"]["summary"] == "owned account document read"
        assert item["payload"]["status_class"] == "2xx"
        assert item["payload"]["content_type_class"] == "json"
        assert item["payload"]["byte_length"] == 42
        release_gate = client.get(
            f"/mythos/campaigns/{campaign_id}/autopilot/release-gate"
        )
        assert release_gate.status_code == 200, release_gate.text
        assert release_gate.json()["passed"] is True
        assert release_gate.json()["evidence_complete"] is True
        assert release_gate.json()["trace_count"] == 1
        assert all(value == 0 for value in release_gate.json()["counters"].values())
        with testing_session() as session:
            repository = DatabaseRepository(session)
            repository.create_research_branch(
                campaign_id=campaign_id,
                branch=ResearchBranch(
                    branch_id="branch_api_completed_duplicate",
                    campaign_id=campaign_id,
                    asset_id=LAB_ASSET_ID,
                    status=BranchStatus.COMPLETED,
                    priority=10,
                    hypothesis_id="hypothesis_api_duplicate",
                    risk_tier=RiskTier.R1,
                ).model_dump(mode="json"),
            )
            repository.create_research_branch(
                campaign_id=campaign_id,
                branch=ResearchBranch(
                    branch_id="branch_api_duplicate",
                    campaign_id=campaign_id,
                    asset_id=LAB_ASSET_ID,
                    status=BranchStatus.QUEUED,
                    priority=99,
                    hypothesis_id="hypothesis_api_duplicate",
                    risk_tier=RiskTier.R1,
                ).model_dump(mode="json"),
            )
            repository.create_research_branch(
                campaign_id=campaign_id,
                branch=ResearchBranch(
                    branch_id="branch_api",
                    campaign_id=campaign_id,
                    asset_id=LAB_ASSET_ID,
                    status=BranchStatus.QUEUED,
                    priority=50,
                    risk_tier=RiskTier.R1,
                ).model_dump(mode="json"),
            )
            repository.create_research_branch(
                campaign_id=campaign_id,
                branch=ResearchBranch(
                    branch_id="branch_api_unauthorized_alias",
                    campaign_id=campaign_id,
                    asset_id=LAB_ASSET_ID,
                    status=BranchStatus.QUEUED,
                    priority=90,
                    account_aliases=("account_not_authorized",),
                    risk_tier=RiskTier.R1,
                ).model_dump(mode="json"),
            )

        tick = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/scheduler/tick",
            json={
                "directive": "continue",
                "reason": "lab_tick",
                "admitted_asset_ids": [LAB_ASSET_ID],
                "branches": [
                    {
                        "branch_id": "branch_api",
                        "asset_id": LAB_ASSET_ID,
                        "status": "queued",
                        "priority": 50,
                        "risk_tier": "R1",
                    }
                ],
            },
        )
        assert tick.status_code == 200, tick.text
        assert tick.json()["selected_branch_id"] == "branch_api"
        assert tick.json()["suppressed_duplicate_branch_ids"] == [
            "branch_api_duplicate"
        ]
        assert tick.json()["report_submission_allowed"] is False

        prepared = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/emergency-stop/prepare",
            json={"actor": "operator_alice", "reason": "api_drill"},
        )
        assert prepared.status_code == 200, prepared.text
        with testing_session() as session:
            campaign = DatabaseRepository(session).get_campaign(campaign_id)
            assert campaign is not None
            confirmation = campaign.payload["emergency_stop_confirmation"]
            assert prepared.json()["confirmation_nonce"] not in str(confirmation)
            assert confirmation["nonce_digest"].startswith("sha256:")
        stop = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/emergency-stop",
            json={
                "actor": "operator_alice",
                "reason": "api_drill",
                "confirmation_nonce": prepared.json()["confirmation_nonce"],
            },
        )
        assert stop.status_code == 200, stop.text
        assert stop.json()["emergency_stopped"] is True
        assert stop.json()["local_stop_confirmation"] == "unconfirmed"

        untrusted = TestClient(app)
        blocked_local_status = untrusted.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/emergency-stop/local-status",
            json={},
        )
        assert blocked_local_status.status_code == 403

        local_status = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/emergency-stop/local-status",
            json={},
        )
        assert local_status.status_code == 200, local_status.text
        assert local_status.json() == {
            "campaign_id": campaign_id,
            "emergency_stopped": True,
            "local_stop_confirmed": False,
        }

        local_ack = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/emergency-stop/local-ack",
            json={},
        )
        assert local_ack.status_code == 200, local_ack.text
        assert local_ack.json()["local_stop_confirmed"] is True
        with testing_session() as session:
            campaign = DatabaseRepository(session).get_campaign(campaign_id)
            assert campaign is not None
            local_confirmation = campaign.payload["emergency_stop_local_confirmation"]
            assert local_confirmation["status"] == "confirmed"
            assert RUNNER_CAPABILITY not in str(local_confirmation)

        blocked_tick = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/scheduler/tick",
            json={
                "directive": "continue",
                "reason": "after_stop",
                "admitted_asset_ids": [LAB_ASSET_ID],
                "branches": [
                    {
                        "branch_id": "branch_api",
                        "asset_id": LAB_ASSET_ID,
                        "status": "queued",
                        "priority": 50,
                        "risk_tier": "R1",
                    }
                ],
            },
        )
        assert blocked_tick.status_code == 200
        assert blocked_tick.json()["emergency_stopped"] is True
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_transport_receipt_rejects_missing_tampered_and_replayed_provenance():
    client, campaign_id, testing_session = _client_and_campaign()
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            authorization = _persist_authorization(
                repository,
                campaign_id,
                max_concurrent_requests=2,
            )
            plan_payload, plan = _plan_payload(
                campaign_id,
                authorization_digest=authorization.authorization_digest,
                scope_snapshot_digest=authorization.scope_snapshot_digest,
            )
            repository.create_validation_plan(
                campaign_id=campaign_id,
                plan_payload=plan_payload,
            )
            issued, reason, lease = repository.issue_execution_lease(
                campaign_id=campaign_id,
                plan_id=plan.plan_id,
                lease_id="lease_receipt",
                authorization_digest=authorization.authorization_digest,
                scope_snapshot_digest=authorization.scope_snapshot_digest,
                authorization_recipe_allowed=True,
                policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
            )
            assert issued is True, reason
            assert lease is not None
            for reservation_id, idempotency_key, remaining_budget in (
                ("res_transport_primary", "idem_transport_primary", 2),
                ("res_transport_secondary", "idem_transport_secondary", 1),
            ):
                repository.reserve_execution_request(
                    campaign_id=campaign_id,
                    lease_id="lease_receipt",
                    reservation_payload={
                        "reservation_id": reservation_id,
                        "lease_id": "lease_receipt",
                        "plan_id": plan.plan_id,
                        "plan_digest": plan.plan_digest,
                        "destination_host": "127.0.0.1",
                        "destination_port": 18080,
                        "destination_path": "/api/docs/1",
                        "method": "GET",
                        "mutation_class": "none",
                        "idempotency_key": idempotency_key,
                        "remaining_request_budget": remaining_budget,
                    },
                )

        def authorize(reservation_id: str):
            response = client.post(
                f"/mythos/campaigns/{campaign_id}/autopilot/gateway/authorize",
                json={
                    "lease_id": "lease_receipt",
                    "reservation_id": reservation_id,
                    "method": "GET",
                    "scheme": "http",
                    "host": "127.0.0.1",
                    "port": 18080,
                    "path": "/api/docs/1",
                },
            )
            assert response.status_code == 200, response.text
            assert response.json()["status"] == "allowed"
            return response.json()

        primary = authorize("res_transport_primary")
        secondary = authorize("res_transport_secondary")
        receipt = TransportReceipt(
            receipt_id="receipt_transport",
            campaign_id=campaign_id,
            lease_id="lease_receipt",
            reservation_id="res_transport_primary",
            plan_id=plan.plan_id,
            plan_digest=plan.plan_digest,
            branch_id=plan.branch_id,
            method="GET",
            scheme="http",
            host="127.0.0.1",
            port=18080,
            path="/api/docs/1",
            body_digest=None,
            status_code=200,
            byte_length=42,
            sent_at=datetime.now(UTC),
            challenge=primary["execution_binding"]["transport_challenge"],
        )

        missing_receipt = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/requests/complete",
            json={"reservation_id": "res_transport_primary", "outcome": "completed"},
        )
        assert missing_receipt.status_code == 409
        assert missing_receipt.json()["detail"] == "transport_receipt_required"

        def submit(value: TransportReceipt, signature: str | None = None):
            return client.post(
                f"/mythos/campaigns/{campaign_id}/autopilot/requests/receipt",
                json={
                    "receipt": value.model_dump(mode="json"),
                    "signature": signature or sign_transport_receipt(value, RUNNER_CAPABILITY),
                },
            )

        invalid_signature = submit(receipt, "0" * 64)
        assert invalid_signature.status_code == 409
        assert invalid_signature.json()["detail"] == "transport_receipt_signature_invalid"

        invalid_challenge = submit(receipt.model_copy(update={"challenge": "z" * 32}))
        assert invalid_challenge.status_code == 409
        assert invalid_challenge.json()["detail"] == "transport_receipt_binding_mismatch"

        invalid_path = submit(receipt.model_copy(update={"path": "/api/docs/2"}))
        assert invalid_path.status_code == 409
        assert invalid_path.json()["detail"] == "transport_receipt_request_mismatch"

        cross_reservation = submit(
            receipt.model_copy(update={"reservation_id": "res_transport_secondary"})
        )
        assert cross_reservation.status_code == 409
        assert cross_reservation.json()["detail"] == "transport_receipt_binding_mismatch"
        assert secondary["transport_challenge"] != primary["transport_challenge"]

        accepted = submit(receipt)
        assert accepted.status_code == 200, accepted.text
        replay = submit(receipt.model_copy(update={"byte_length": 43}))
        assert replay.status_code == 409
        assert replay.json()["detail"] == "transport_receipt_replay"
    finally:
        app.dependency_overrides.pop(get_session, None)
def test_autopilot_projection_endpoints_are_safe():
    client, campaign_id, _testing_session = _client_and_campaign()
    try:
        resp = client.get(f"/mythos/campaigns/{campaign_id}/autopilot")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["campaign_id"] == campaign_id
        assert body["report_submission_allowed"] is False
        assert body["candidate_promotion_allowed"] is False
        assert body["submission_blocked"] is True
        assert body["projection_generated_at"]
        assert "budgets" in body
        assert client.get(f"/mythos/campaigns/{campaign_id}/autopilot/assets").status_code == 200
        assert client.get(f"/mythos/campaigns/{campaign_id}/autopilot/branches").status_code == 200
        assert client.get(f"/mythos/campaigns/{campaign_id}/autopilot/budgets").status_code == 200
        assert client.get(f"/mythos/campaigns/{campaign_id}/autopilot/approvals").status_code == 200
        assert client.get(f"/mythos/campaigns/{campaign_id}/autopilot/events").status_code == 200
        release_gate = client.get(f"/mythos/campaigns/{campaign_id}/autopilot/release-gate")
        assert release_gate.status_code == 200
        assert release_gate.json()["passed"] is False
        assert release_gate.json()["evidence_complete"] is False
    finally:
        app.dependency_overrides.pop(get_session, None)

def test_autopilot_projection_reads_only_its_owned_candidate_hunter_queue():
    client, unrelated_campaign_id, testing_session = _client_and_campaign()
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            unrelated_campaign = repository.get_campaign(unrelated_campaign_id)
            assert unrelated_campaign is not None
            pipeline_run = repository.save_pipeline_run(
                program_id=unrelated_campaign.program_id,
                asset=unrelated_campaign.default_asset,
                policy_text="policy",
                scope_status="in_scope",
                hypothesis_count=1,
                blocked_count=0,
                report_title=None,
                payload={"hypotheses": []},
            )
            pipeline_run_id = pipeline_run.id
            candidate_state = {
                "candidate_id": "H-001",
                "candidate_key": f"{pipeline_run_id}:H-001",
                "vuln_type": "authorization",
                "root_cause_id": "missing_object_ownership_check:read_record",
                "route": {"method": "GET", "path": "/records/{record_id}"},
                "source_fact_refs": [
                    "scope:scope_context",
                    "policy:policy_context",
                    "code:routes.py:read_record",
                    "api:GET:/records/{record_id}",
                    "har:har_context",
                ],
                "observed_artifact_kinds": ["scope", "policy", "code", "api", "har"],
                "required_artifact_kinds": ["scope", "policy", "code", "api", "har"],
                "evidence_trace_status": "traceable",
                "priority_score": 80,
                "gap_evidence_ref": "code:routes.py:read_record",
                "shared_root": "read_record",
                "shared_root_evidence_ref": "code:routes.py:read_record",
            }
            result = run_candidate_hunter_loop(
                repository=repository,
                record=pipeline_run,
                policy_text="policy",
                candidates=[],
                observations={
                    "candidate_states": [candidate_state],
                    "execution_allowed": False,
                    "dispatch_allowed": False,
                    "validation_allowed": False,
                    "candidate_promotion_allowed": False,
                    "report_submission_allowed": False,
                    "raw_payload_processed": False,
                },
            )
            candidate_campaign_id = result["campaign_id"]
            unrelated_payload = dict(unrelated_campaign.payload)
            unrelated_payload["pipeline_run_id"] = pipeline_run_id
            unrelated_campaign.payload = unrelated_payload
            session.commit()

        owned = client.get(f"/mythos/campaigns/{candidate_campaign_id}/autopilot")
        assert owned.status_code == 200, owned.text
        owned_queue = owned.json()["candidate_queue"]
        assert owned_queue["status"] == "ready"
        assert owned_queue["pipeline_run_id"] == pipeline_run_id
        assert len(owned_queue["source_stage_ids"]) == 4
        candidate = owned_queue["candidates"][0]
        assert candidate["candidate_id"] == "H-001"
        assert candidate["rank"] == 1
        assert candidate["vuln_type"] == "authorization"
        assert candidate["affected_endpoint"] == "GET /records/{record_id}"
        assert candidate["affected_code_path"] == "code:routes.py:read_record"
        assert candidate["evidence_trace_status"] == "traceable"
        assert candidate["human_validation_readiness"] == "ready"
        assert candidate["refutation_status"] == "retained"
        assert candidate["validation_allowed"] is False
        assert candidate["validation_requires_human_approval"] is True
        assert candidate["candidate_promotion_allowed"] is False
        assert candidate["report_submission_allowed"] is False
        assert candidate["submission_blocked"] is True

        unrelated = client.get(
            f"/mythos/campaigns/{unrelated_campaign_id}/autopilot"
        )
        assert unrelated.status_code == 200, unrelated.text
        assert unrelated.json()["candidate_queue"]["status"] == "invalid"
        assert unrelated.json()["candidate_queue"]["pipeline_run_id"] == pipeline_run_id
        assert unrelated.json()["candidate_queue"]["candidates"] == []
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_autopilot_candidate_queue_rejects_malformed_loader_projection(monkeypatch):
    _client, campaign_id, testing_session = _client_and_campaign()
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.get_campaign(campaign_id)
            assert campaign is not None
            pipeline_run = repository.save_pipeline_run(
                program_id=campaign.program_id,
                asset=campaign.default_asset,
                policy_text="policy",
                scope_status="in_scope",
                hypothesis_count=0,
                blocked_count=0,
                report_title=None,
                payload={"hypotheses": []},
            )
            campaign.payload = {**dict(campaign.payload or {}), "pipeline_run_id": pipeline_run.id}
            session.commit()

            malformed_projections = (
                None,
                [],
                {
                    "status": "ready",
                    "pipeline_run_id": pipeline_run.id,
                    "audit": {
                        "campaign_id": campaign.id,
                        "round_count": 1,
                        "stage_refs": [],
                    },
                    "final_candidates": [],
                },
                {
                    "status": "ready",
                    "pipeline_run_id": pipeline_run.id,
                    "audit": {
                        "campaign_id": campaign.id,
                        "round_count": 1,
                        "stage_refs": [
                            {
                                "stage_id": "stage_1",
                                "stage_key": "candidate_hunter_snapshot",
                                "round": 1,
                            },
                            {
                                "stage_id": "stage_1",
                                "stage_key": "candidate_hunter_evidence_request",
                                "round": 1,
                            },
                            {
                                "stage_id": "stage_3",
                                "stage_key": "candidate_hunter_decision",
                                "round": 1,
                            },
                            {
                                "stage_id": "stage_4",
                                "stage_key": "candidate_hunter_rerank",
                                "round": 1,
                            },
                        ],
                    },
                    "final_candidates": [],
                },
                {
                    "status": "ready",
                    "pipeline_run_id": pipeline_run.id,
                    "audit": {
                        "campaign_id": campaign.id,
                        "round_count": 1,
                        "stage_refs": [
                            {
                                "stage_id": "stage_1",
                                "stage_key": "candidate_hunter_snapshot",
                                "round": True,
                            },
                            {
                                "stage_id": "stage_2",
                                "stage_key": "candidate_hunter_evidence_request",
                                "round": 1,
                            },
                            {
                                "stage_id": "stage_3",
                                "stage_key": "candidate_hunter_decision",
                                "round": 1,
                            },
                            {
                                "stage_id": "stage_4",
                                "stage_key": "candidate_hunter_rerank",
                                "round": 1,
                            },
                        ],
                    },
                    "final_candidates": [],
                },
                {
                    "status": "ready",
                    "pipeline_run_id": pipeline_run.id,
                    "audit": {
                        "campaign_id": campaign.id,
                        "round_count": 1,
                        "stage_refs": [
                            {
                                "stage_id": "stage_1",
                                "stage_key": "candidate_hunter_snapshot",
                                "round": 1,
                            },
                            {
                                "stage_id": "stage_2",
                                "stage_key": "candidate_hunter_rerank",
                                "round": 1,
                            },
                            {
                                "stage_id": "stage_3",
                                "stage_key": "candidate_hunter_decision",
                                "round": 1,
                            },
                            {
                                "stage_id": "stage_4",
                                "stage_key": "candidate_hunter_rerank",
                                "round": 1,
                            },
                        ],
                    },
                    "final_candidates": [],
                },
            )
            for malformed_projection in malformed_projections:
                monkeypatch.setattr(
                    "app.main.load_candidate_hunter_projection",
                    lambda **_kwargs: malformed_projection,
                )

                queue = _autopilot_candidate_queue(
                    campaign=campaign,
                    repository=repository,
                )

                assert queue == {
                    "status": "invalid",
                    "pipeline_run_id": pipeline_run.id,
                }
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_gateway_blocks_when_current_dns_identity_cannot_be_resolved(monkeypatch):
    client, campaign_id, testing_session = _client_and_campaign()
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            authorization = _persist_authorization(repository, campaign_id)
            plan_payload, plan = _plan_payload(
                campaign_id,
                authorization_digest=authorization.authorization_digest,
                scope_snapshot_digest=authorization.scope_snapshot_digest,
            )
            repository.create_validation_plan(
                campaign_id=campaign_id,
                plan_payload=plan_payload,
            )
            issued, reason, lease = repository.issue_execution_lease(
                campaign_id=campaign_id,
                plan_id=plan.plan_id,
                lease_id="lease_dns_unavailable",
                authorization_digest=plan.authorization_digest,
                scope_snapshot_digest=plan.scope_snapshot_digest,
                authorization_recipe_allowed=True,
                policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
            )
            assert issued is True, reason
            assert lease is not None

        monkeypatch.setattr("app.main._current_autopilot_asset_ips", lambda _host: None)
        response = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/gateway/authorize",
            json={
                "lease_id": "lease_dns_unavailable",
                "method": "GET",
                "scheme": "http",
                "host": "127.0.0.1",
                "port": 18080,
                "path": "/api",
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "blocked"
        assert response.json()["reason"] == "identity_stale"
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_gateway_returns_only_server_derived_execution_binding():
    client, campaign_id, testing_session = _client_and_campaign()
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            authorization = _persist_authorization(repository, campaign_id)
            plan_payload, plan = _plan_payload(
                campaign_id,
                authorization_digest=authorization.authorization_digest,
                scope_snapshot_digest=authorization.scope_snapshot_digest,
            )
            repository.create_validation_plan(
                campaign_id=campaign_id,
                plan_payload=plan_payload,
            )
            issued, reason, lease = repository.issue_execution_lease(
                campaign_id=campaign_id,
                plan_id=plan.plan_id,
                lease_id="lease_binding",
                authorization_digest=authorization.authorization_digest,
                scope_snapshot_digest=authorization.scope_snapshot_digest,
                authorization_recipe_allowed=True,
                policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
            )
            assert issued is True, reason
            assert lease is not None
            repository.reserve_execution_request(
                campaign_id=campaign_id,
                lease_id="lease_binding",
                reservation_payload={
                    "reservation_id": "res_binding",
                    "lease_id": "lease_binding",
                    "plan_id": plan.plan_id,
                    "plan_digest": plan.plan_digest,
                    "destination_host": "127.0.0.1",
                    "destination_port": 18080,
                    "destination_path": "/api/docs/1",
                    "method": "GET",
                    "mutation_class": "none",
                    "idempotency_key": "idem_binding",
                    "remaining_request_budget": 2,
                },
            )

        response = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/gateway/authorize",
            json={
                "lease_id": "lease_binding",
                "reservation_id": "res_binding",
                "method": "GET",
                "scheme": "http",
                "host": "127.0.0.1",
                "port": 18080,
                "path": "/api/docs/1",
            },
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["status"] == "allowed"
        binding = payload["execution_binding"]
        assert binding == {
            "campaign_id": campaign_id,
            "lease_id": "lease_binding",
            "reservation_id": "res_binding",
            "plan_id": plan.plan_id,
            "plan_digest": plan.plan_digest,
            "branch_id": "branch_api",
            "recipe_id": "lab_browser_mapping",
            "recipe_version": "1.0",
            "policy_mode": "authorized_local_lab",
            "scheme": "http",
            "host": "127.0.0.1",
            "port": 18080,
            "path": "/api/docs/1",
            "method": "GET",
            "account_alias": None,
            "max_response_bytes": 1000,
            "max_duration_seconds": 30,
            "admitted_ips": ["127.0.0.1"],
            "transport_challenge": payload["transport_challenge"],
        }
        assert "authorization_digest" not in binding
        assert "account_aliases" not in binding
        assert "url" not in binding
        assert "plan" not in binding
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_gateway_binds_owned_account_alias_to_its_reservation():
    client, campaign_id, testing_session = _client_and_campaign()
    try:
        recipe_ref = RecipeRef(
            recipe_id="lab_two_owned_account_readonly_authz",
            version="1.0",
        )
        with testing_session() as session:
            repository = DatabaseRepository(session)
            authorization = _persist_authorization(
                repository,
                campaign_id,
                recipe_refs=(recipe_ref,),
            )
            plan = build_validation_plan(
                plan_id="plan_r2_binding",
                campaign_id=campaign_id,
                authorization_digest=authorization.authorization_digest,
                scope_snapshot_digest=authorization.scope_snapshot_digest,
                asset_id=LAB_ASSET_ID,
                destination_scheme="http",
                destination_host="127.0.0.1",
                destination_port=18080,
                destination_path="/api",
                branch_id="branch_r2_binding",
                account_aliases=("account_a", "account_b"),
                risk_tier=RiskTier.R2,
                recipe_ref=recipe_ref,
                methods=("GET",),
                mutation_inventory=MutationInventory(
                    methods=("GET",),
                    mutates_state=False,
                    reversible=True,
                    requires_owned_accounts=True,
                ),
                max_requests=2,
                max_response_bytes=1000,
                max_duration_seconds=30,
                rollback_plan="noop",
                stop_conditions=("stop",),
                tool_profile="lab",
                container_profile="lab",
            )
            repository.create_validation_plan(
                campaign_id=campaign_id,
                plan_payload=plan.model_dump(mode="json"),
            )
            issued, reason, lease = repository.issue_execution_lease(
                campaign_id=campaign_id,
                plan_id=plan.plan_id,
                lease_id="lease_r2_binding",
                authorization_digest=authorization.authorization_digest,
                scope_snapshot_digest=authorization.scope_snapshot_digest,
                authorization_recipe_allowed=True,
                policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
            )
            assert issued is True, reason
            assert lease is not None

        reservation = {
            "reservation_id": "res_r2_binding",
            "lease_id": "lease_r2_binding",
            "plan_id": plan.plan_id,
            "plan_digest": plan.plan_digest,
            "destination_host": "127.0.0.1",
            "destination_port": 18080,
            "destination_path": "/api/docs/1",
            "method": "GET",
            "mutation_class": "none",
            "idempotency_key": "idem_r2_binding",
            "remaining_request_budget": 1,
        }
        missing_alias = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/requests/reserve",
            json={"lease_id": "lease_r2_binding", "reservation": reservation},
        )
        assert missing_alias.status_code == 409
        assert missing_alias.json()["detail"] == "request_account_alias_required"

        reserved = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/requests/reserve",
            json={
                "lease_id": "lease_r2_binding",
                "reservation": {**reservation, "account_alias": "account_a"},
            },
        )
        assert reserved.status_code == 200, reserved.text

        payload = {
            "lease_id": "lease_r2_binding",
            "reservation_id": "res_r2_binding",
            "method": "GET",
            "scheme": "http",
            "host": "127.0.0.1",
            "port": 18080,
            "path": "/api/docs/1",
        }
        mismatched = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/gateway/authorize",
            json={**payload, "account_alias": "account_b"},
        )
        assert mismatched.status_code == 200, mismatched.text
        assert mismatched.json()["status"] == "blocked"
        assert mismatched.json()["reason"] == "request_reservation_mismatch"

        allowed = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/gateway/authorize",
            json={**payload, "account_alias": "account_a"},
        )
        assert allowed.status_code == 200, allowed.text
        assert allowed.json()["status"] == "allowed"
        assert allowed.json()["execution_binding"]["account_alias"] == "account_a"
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_r2_api_observation_traces_both_owned_accounts_through_release_gate():
    client, campaign_id, testing_session = _client_and_campaign()
    try:
        recipe_ref = RecipeRef(
            recipe_id="lab_two_owned_account_readonly_authz",
            version="1.0",
        )
        with testing_session() as session:
            repository = DatabaseRepository(session)
            authorization = _persist_authorization(
                repository,
                campaign_id,
                recipe_refs=(recipe_ref,),
            )
            plan = build_validation_plan(
                plan_id="plan_r2_observation",
                campaign_id=campaign_id,
                authorization_digest=authorization.authorization_digest,
                scope_snapshot_digest=authorization.scope_snapshot_digest,
                asset_id=LAB_ASSET_ID,
                destination_scheme="http",
                destination_host="127.0.0.1",
                destination_port=18080,
                destination_path="/api",
                branch_id="branch_r2_observation",
                account_aliases=("account_a", "account_b"),
                risk_tier=RiskTier.R2,
                recipe_ref=recipe_ref,
                methods=("GET",),
                mutation_inventory=MutationInventory(
                    methods=("GET",),
                    mutates_state=False,
                    reversible=True,
                    requires_owned_accounts=True,
                ),
                max_requests=2,
                max_response_bytes=1000,
                max_duration_seconds=30,
                rollback_plan="close_context",
                stop_conditions=("third_party", "waf"),
                tool_profile="lab",
                container_profile="lab",
            )
            repository.create_validation_plan(
                campaign_id=campaign_id,
                plan_payload=plan.model_dump(mode="json"),
            )
            issued, reason, lease = repository.issue_execution_lease(
                campaign_id=campaign_id,
                plan_id=plan.plan_id,
                lease_id="lease_r2_observation",
                authorization_digest=authorization.authorization_digest,
                scope_snapshot_digest=authorization.scope_snapshot_digest,
                authorization_recipe_allowed=True,
                policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB.value,
            )
            assert issued is True, reason
            assert lease is not None

        receipt_digests: dict[str, str] = {}
        receipt_metadata = {
            "account_a": ("res_r2_account_a", 200, "json", 42, 1),
            "account_b": ("res_r2_account_b", 403, "html", 17, 0),
        }
        for account_alias, (
            reservation_id,
            status_code,
            content_type_class,
            byte_length,
            remaining_request_budget,
        ) in receipt_metadata.items():
            reservation = {
                "reservation_id": reservation_id,
                "lease_id": "lease_r2_observation",
                "plan_id": plan.plan_id,
                "plan_digest": plan.plan_digest,
                "destination_host": "127.0.0.1",
                "destination_port": 18080,
                "destination_path": "/api/docs/1",
                "method": "GET",
                "mutation_class": "none",
                "idempotency_key": f"idem_r2_{account_alias}",
                "remaining_request_budget": remaining_request_budget,
                "account_alias": account_alias,
            }
            reserved = client.post(
                f"/mythos/campaigns/{campaign_id}/autopilot/requests/reserve",
                json={"lease_id": "lease_r2_observation", "reservation": reservation},
            )
            assert reserved.status_code == 200, reserved.text

            gateway = client.post(
                f"/mythos/campaigns/{campaign_id}/autopilot/gateway/authorize",
                json={
                    "lease_id": "lease_r2_observation",
                    "reservation_id": reservation_id,
                    "method": "GET",
                    "scheme": "http",
                    "host": "127.0.0.1",
                    "port": 18080,
                    "path": "/api/docs/1",
                    "account_alias": account_alias,
                },
            )
            assert gateway.status_code == 200, gateway.text
            assert gateway.json()["status"] == "allowed"
            assert gateway.json()["execution_binding"]["account_alias"] == account_alias

            receipt = TransportReceipt(
                receipt_id=f"receipt_r2_{account_alias}",
                campaign_id=campaign_id,
                lease_id="lease_r2_observation",
                reservation_id=reservation_id,
                plan_id=plan.plan_id,
                plan_digest=plan.plan_digest,
                branch_id=plan.branch_id,
                method="GET",
                scheme="http",
                host="127.0.0.1",
                port=18080,
                path="/api/docs/1",
                body_digest=None,
                status_code=status_code,
                content_type_class=content_type_class,
                byte_length=byte_length,
                sent_at=datetime.now(UTC),
                challenge=gateway.json()["transport_challenge"],
            )
            receipt_response = client.post(
                f"/mythos/campaigns/{campaign_id}/autopilot/requests/receipt",
                json={
                    "receipt": receipt.model_dump(mode="json"),
                    "signature": sign_transport_receipt(receipt, RUNNER_CAPABILITY),
                },
            )
            assert receipt_response.status_code == 200, receipt_response.text
            receipt_digests[account_alias] = receipt_response.json()["receipt_digest"]

            complete = client.post(
                f"/mythos/campaigns/{campaign_id}/autopilot/requests/complete",
                json={"reservation_id": reservation_id, "outcome": "completed"},
            )
            assert complete.status_code == 200, complete.text

        observation = {
            "observation_id": "obs_r2_accounts",
            "branch_id": plan.branch_id,
            "plan_digest": plan.plan_digest,
            "lease_id": "lease_r2_observation",
            "reservation_id": "res_r2_account_a",
            "comparison_reservation_id": "res_r2_account_b",
            "receipt_digest": receipt_digests["account_a"],
            "comparison_receipt_digest": receipt_digests["account_b"],
            "grade": "L1_hint",
            "outcome_class": "ok",
            "summary": "owned_account_differential_metadata_only",
            "evidence_refs": ["metadata_only_response"],
            "status_class": "2xx",
            "content_type_class": "json",
            "byte_length": 42,
            "comparison_status_class": "4xx",
            "comparison_content_type_class": "html",
            "comparison_byte_length": 17,
            "difference_labels": [
                "status_class_different",
                "content_type_class_different",
                "byte_length_different",
            ],
        }
        invalid = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/observations",
            json={
                "observation": {
                    **observation,
                    "comparison_receipt_digest": _digest("f"),
                }
            },
        )
        assert invalid.status_code == 400
        assert invalid.json()["detail"] == "r2_comparison_receipt_mismatch"

        created = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/observations",
            json={"observation": observation},
        )
        assert created.status_code == 200, created.text

        with testing_session() as session:
            repository = DatabaseRepository(session)
            stored = repository.list_autopilot_observations(campaign_id)
            assert len(stored) == 1
            assert stored[0].comparison_reservation_id == "res_r2_account_b"
            stored[0].payload = {
                key: value
                for key, value in stored[0].payload.items()
                if key != "comparison_reservation_id"
            }
            session.commit()
            gate = repository.evaluate_autopilot_release_gate(campaign_id)

        assert gate.passed is True
        assert gate.trace_count == 2
        assert gate.counters["untraced_tool_runs"] == 0
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_autopilot_r3_approval_decision_is_exact_and_single_use():
    client, campaign_id, testing_session = _client_and_campaign()
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            authorization = _persist_authorization(repository, campaign_id)
            plan = build_validation_plan(
                plan_id="plan_r3_api",
                campaign_id=campaign_id,
                authorization_digest=authorization.authorization_digest,
                scope_snapshot_digest=authorization.scope_snapshot_digest,
                asset_id=LAB_ASSET_ID,
                destination_scheme="http",
                destination_host="127.0.0.1",
                destination_port=18080,
                destination_path="/api/reversible",
                branch_id="branch_r3_api",
                risk_tier=RiskTier.R3,
                recipe_ref=RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),
                methods=("GET",),
                mutation_inventory=MutationInventory(
                    methods=("GET",),
                    mutates_state=False,
                    reversible=True,
                    requires_owned_accounts=False,
                ),
                max_requests=1,
                max_response_bytes=1_000,
                max_duration_seconds=30,
                rollback_plan="noop",
                stop_conditions=("stop",),
                tool_profile="lab",
                container_profile="lab",
            )
            repository.create_validation_plan(
                campaign_id=campaign_id,
                plan_payload=plan.model_dump(mode="json"),
            )
            approval = repository.create_approval_record(
                campaign_id=campaign_id,
                approval_type="r3_exact_plan",
                actor="operator_alice",
                reason="review R3 plan",
                plan_digest=plan.plan_digest,
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
                payload={
                    "authorization_digest": authorization.authorization_digest,
                    "scope_snapshot_digest": authorization.scope_snapshot_digest,
                },
            )
            approval_id = approval.id

        approved = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/approvals/{approval_id}/decision",
            json={
                "decision": "approved",
                "actor": "operator_alice",
                "reason": "exact plan reviewed",
            },
        )
        assert approved.status_code == 200, approved.text
        body = approved.json()
        assert body["status"] == "approved"
        assert body["approval_diff"]["plan_digest"] == plan.plan_digest
        assert "rollback_plan" not in body["approval_diff"]
        projection = client.get(f"/mythos/campaigns/{campaign_id}/autopilot")
        assert projection.status_code == 200
        assert projection.json()["approvals"][0]["approval_diff"]["plan_digest"] == (
            plan.plan_digest
        )

        lease = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/leases",
            json={
                "plan_id": plan.plan_id,
                "lease_id": "lease_r3_api",
                "authorization_digest": plan.authorization_digest,
                "scope_snapshot_digest": plan.scope_snapshot_digest,
                "authorization_recipe_allowed": True,
                "policy_mode": PolicyMode.AUTHORIZED_LOCAL_LAB.value,
                "approval_id": approval_id,
            },
        )
        assert lease.status_code == 200, lease.text
        assert lease.json()["r3_approval_id"] == approval_id

        repeat = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/approvals/{approval_id}/decision",
            json={
                "decision": "approved",
                "actor": "operator_alice",
                "reason": "repeat",
            },
        )
        assert repeat.status_code == 409
        assert repeat.json()["detail"] == "approval_already_consumed"

        with testing_session() as session:
            no_expiry = DatabaseRepository(session).create_approval_record(
                campaign_id=campaign_id,
                approval_type="r3_exact_plan",
                actor="operator_alice",
                reason="missing expiry",
                plan_digest=plan.plan_digest,
            )
            no_expiry_id = no_expiry.id
        no_expiry_decision = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/approvals/{no_expiry_id}/decision",
            json={
                "decision": "approved",
                "actor": "operator_alice",
                "reason": "should require expiry",
            },
        )
        assert no_expiry_decision.status_code == 409
        assert no_expiry_decision.json()["detail"] == "approval_expiry_required"

        with testing_session() as session:
            long_lived = DatabaseRepository(session).create_approval_record(
                campaign_id=campaign_id,
                approval_type="r3_exact_plan",
                actor="operator_alice",
                reason="long-lived approval",
                plan_digest=plan.plan_digest,
                expires_at=datetime.now(UTC) + timedelta(minutes=31),
            )
            long_lived_id = long_lived.id
        long_lived_decision = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/approvals/{long_lived_id}/decision",
            json={
                "decision": "approved",
                "actor": "operator_alice",
                "reason": "should require short expiry",
            },
        )
        assert long_lived_decision.status_code == 409
        assert long_lived_decision.json()["detail"] == "approval_expiry_exceeds_max_ttl"
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_autopilot_resume_selection_uses_current_scope_digest_for_admitted_assets():
    client, campaign_id, testing_session = _client_and_campaign()
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            authorization = _persist_authorization(
                repository,
                campaign_id,
                risk_ceiling=RiskTier.R1,
            )
            campaign = repository.get_campaign(campaign_id)
            assert campaign is not None
            campaign = _materialize_autopilot_source_snapshot(campaign, repository)
            assert campaign.payload["scope_snapshot_digest"] == (
                authorization.scope_snapshot_digest
            )
            repository.create_research_branch(
                campaign_id=campaign_id,
                branch=ResearchBranch(
                    branch_id="branch_scope_resume",
                    campaign_id=campaign_id,
                    asset_id=LAB_ASSET_ID,
                    status=BranchStatus.QUEUED,
                    priority=10,
                    risk_tier=RiskTier.R1,
                ).model_dump(mode="json"),
            )
            unapproved_identity = AssetIdentity(
                scheme="http",
                host="127.0.0.1",
                port=18081,
                path_authority="/api",
                provenance=AssetProvenance.SEED,
            )
            unapproved_admission = decide_admission(
                unapproved_identity,
                ScopeMatcher(
                    include_hosts=("127.0.0.1",),
                    include_path_prefixes=("/api",),
                    scope_snapshot_digest=authorization.scope_snapshot_digest,
                ),
            )
            repository.upsert_campaign_asset_admission(
                campaign_id=campaign_id,
                admission=unapproved_admission.model_dump(mode="json"),
            )
            for branch in (
                ResearchBranch(
                    branch_id="branch_scope_unapproved_asset",
                    campaign_id=campaign_id,
                    asset_id=unapproved_admission.asset_id,
                    status=BranchStatus.QUEUED,
                    priority=90,
                    risk_tier=RiskTier.R1,
                ),
                ResearchBranch(
                    branch_id="branch_scope_unapproved_recipe",
                    campaign_id=campaign_id,
                    asset_id=LAB_ASSET_ID,
                    status=BranchStatus.QUEUED,
                    priority=80,
                    recipe_ref=RecipeRef(
                        recipe_id="passive_rule_snapshot_analysis",
                        version="1.0",
                    ),
                    risk_tier=RiskTier.R1,
                ),
                ResearchBranch(
                    branch_id="branch_scope_unapproved_risk",
                    campaign_id=campaign_id,
                    asset_id=LAB_ASSET_ID,
                    status=BranchStatus.QUEUED,
                    priority=70,
                    risk_tier=RiskTier.R2,
                ),
                ResearchBranch(
                    branch_id="branch_scope_unapproved_alias",
                    campaign_id=campaign_id,
                    asset_id=LAB_ASSET_ID,
                    status=BranchStatus.QUEUED,
                    priority=60,
                    account_aliases=("account_not_authorized",),
                    risk_tier=RiskTier.R1,
                ),
            ):
                repository.create_research_branch(
                    campaign_id=campaign_id,
                    branch=branch.model_dump(mode="json"),
                )
            selection = autonomous_research_runtime._select_autopilot_branch_work(
                campaign=campaign,
                repository=repository,
            )
            assert selection is not None
            assert selection["branch_id"] == "branch_scope_resume"

            campaign_payload = dict(campaign.payload)
            campaign_payload["scope_snapshot_digest"] = campaign_payload[
                "source_snapshot_digest"
            ]
            campaign.payload = campaign_payload
            session.commit()
            session.refresh(campaign)
            stale_selection = autonomous_research_runtime._select_autopilot_branch_work(
                campaign=campaign,
                repository=repository,
            )
            assert stale_selection["status"] == "blocked"
            assert stale_selection["stop_reason"] == "authorization_scope_stale"
            assert stale_selection["task_type"] is None
            assert stale_selection["source_snapshot_digest"] is None
            assert stale_selection["execution_allowed"] is False
            assert stale_selection["dispatch_allowed"] is False
            assert stale_selection["validation_allowed"] is False
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_autopilot_rejects_expired_r3_approval_and_unbounded_steering():
    client, campaign_id, testing_session = _client_and_campaign()
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            authorization = _persist_authorization(repository, campaign_id)
            plan = build_validation_plan(
                plan_id="plan_expired_api",
                campaign_id=campaign_id,
                authorization_digest=authorization.authorization_digest,
                scope_snapshot_digest=authorization.scope_snapshot_digest,
                asset_id=LAB_ASSET_ID,
                destination_scheme="http",
                destination_host="127.0.0.1",
                destination_port=18080,
                destination_path="/api/reversible",
                branch_id="branch_steer_api",
                risk_tier=RiskTier.R3,
                recipe_ref=RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),
                methods=("GET",),
                mutation_inventory=MutationInventory(
                    methods=("GET",),
                    mutates_state=False,
                    reversible=True,
                    requires_owned_accounts=False,
                ),
                max_requests=1,
                max_response_bytes=1_000,
                max_duration_seconds=30,
                rollback_plan="noop",
                stop_conditions=("stop",),
                tool_profile="lab",
                container_profile="lab",
            )
            repository.create_validation_plan(
                campaign_id=campaign_id,
                plan_payload=plan.model_dump(mode="json"),
            )
            expired = repository.create_approval_record(
                campaign_id=campaign_id,
                approval_type="r3_exact_plan",
                actor="operator_alice",
                reason="expired R3 plan",
                plan_digest=plan.plan_digest,
                expires_at=datetime.now(UTC) - timedelta(seconds=1),
            )
            expired_id = expired.id
            repository.create_research_branch(
                campaign_id=campaign_id,
                branch=ResearchBranch(
                    branch_id="branch_steer_api",
                    campaign_id=campaign_id,
                    asset_id=LAB_ASSET_ID,
                    status=BranchStatus.QUEUED,
                    priority=10,
                    risk_tier=RiskTier.R1,
                ).model_dump(mode="json"),
            )

        expired_decision = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/approvals/{expired_id}/decision",
            json={
                "decision": "approved",
                "actor": "operator_alice",
                "reason": "should fail",
            },
        )
        assert expired_decision.status_code == 409
        assert expired_decision.json()["detail"] == "approval_expired"

        hostile_steer = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/steering",
            json={
                "branch_id": "branch_steer_api",
                "priority": 80,
                "risk_tier": "R0",
                "reason": "attempt risk downgrade",
            },
        )
        assert hostile_steer.status_code == 422

        steer = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/steering",
            json={
                "branch_id": "branch_steer_api",
                "priority": 80,
                "hypothesis_guidance": "verify ownership boundary",
                "actor": "operator_alice",
                "reason": "prioritize safe refutation",
            },
        )
        assert steer.status_code == 200, steer.text
        assert steer.json()["steering"] == {
            "branch_id": "branch_steer_api",
            "priority": 80,
            "version": 2,
        }
        with testing_session() as session:
            branch = DatabaseRepository(session).list_research_branches(campaign_id)[0]
            assert branch.priority == 80
            assert branch.risk_tier == "R1"
            assert branch.payload["hypothesis_guidance"] == "verify ownership boundary"
    finally:
        app.dependency_overrides.pop(get_session, None)
