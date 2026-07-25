"""Loopback lab HTTP fixture server integration."""

from __future__ import annotations

import importlib.util
import json
import os
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from urllib.request import Request, urlopen

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
from app.bounty_autopilot.contracts import (
    AuthorizationBudget,
    CampaignAuthorizationCreate,
    MutationInventory,
    PolicyMode,
    RecipeRef,
    RiskTier,
)
from app.bounty_autopilot.gateway import (
    GatewayAuthorizeRequest,
    GatewayDecisionStatus,
    authorize_gateway_request,
)
from app.bounty_autopilot.leases import issue_execution_lease
from app.bounty_autopilot.plans import build_validation_plan
from app.bounty_autopilot.request_ledger import (
    RequestLedger,
    RequestReservation,
    RequestReservationStatus,
)
from app.bounty_autopilot.transport import TransportReceipt, sign_transport_receipt
from app.db import Base, get_session
from app.config import get_settings
from app.main import app
from app.repository import DatabaseRepository, seed_sample_data


def _digest(n: str = "a") -> str:
    return "sha256:" + (n * 64)


def _load_lab_server():
    server_path = (
        Path(__file__).resolve().parent / "fixtures" / "bounty_autopilot_lab" / "server.py"
    )
    spec = importlib.util.spec_from_file_location("bounty_autopilot_lab_server", server_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RUNNER_CAPABILITY = "a" * 43


def test_lab_server_is_loopback_and_serves_matrix_behaviors():
    mod = _load_lab_server()
    manifest = mod.load_lab_manifest()
    assert manifest["loopback_only"] is True
    server = mod.start_lab_target(port=0)
    try:
        assert server.host in {"127.0.0.1", "localhost"}
        with urlopen(f"{server.base_url}/public/health", timeout=2) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        assert payload["ok"] is True
        with urlopen(f"{server.base_url}/api/docs/1", timeout=2) as resp:
            doc = json.loads(resp.read().decode("utf-8"))
        assert doc["owner"] == "account_a"
    finally:
        server.stop()


def test_lab_server_document_matrix_uses_owned_account_session_cookie():
    mod = _load_lab_server()
    server = mod.start_lab_target(port=0)
    try:
        def read_doc(path: str, session_alias: str) -> dict[str, object]:
            request = Request(
                f"{server.base_url}{path}",
                headers={"Cookie": f"session={session_alias}"},
            )
            with urlopen(request, timeout=2) as resp:
                assert resp.status == 200
                return json.loads(resp.read().decode("utf-8"))

        own_doc = read_doc("/api/docs/1", "account_a")
        cross_doc = read_doc("/api/docs/1", "account_b")
        account_b_doc = read_doc("/api/docs/2", "account_b")

        assert own_doc == {
            "doc_id": "1",
            "owner": "account_a",
            "viewer": "account_a",
            "cross_account": False,
        }
        assert cross_doc == {
            "doc_id": "1",
            "owner": "account_a",
            "viewer": "account_b",
            "cross_account": True,
        }
        assert account_b_doc == {
            "doc_id": "2",
            "owner": "account_b",
            "viewer": "account_b",
            "cross_account": False,
        }
    finally:
        server.stop()


def test_gateway_allows_only_plan_bound_loopback_against_live_lab_server():
    mod = _load_lab_server()
    server = mod.start_lab_target(port=0)
    try:
        plan = build_validation_plan(
            plan_id="plan_live",
            campaign_id="lab",
            authorization_digest=_digest("a"),
            scope_snapshot_digest=_digest("b"),
            asset_id="asset_lab",
            destination_scheme="http",
            destination_host="127.0.0.1",
            destination_port=server.port,
            destination_path="/api/docs/1",
            branch_id="branch_lab",
            account_aliases=("account_a", "account_b"),
            risk_tier=RiskTier.R1,
            recipe_ref=RecipeRef(
                recipe_id="lab_two_owned_account_readonly_authz",
                version="1.0",
            ),
            methods=("GET",),
            mutation_inventory=MutationInventory(
                methods=("GET",),
                mutates_state=False,
                reversible=True,
                requires_owned_accounts=True,
            ),
            max_requests=2,
            max_response_bytes=10000,
            max_duration_seconds=30,
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
            lease_id="lease_live",
            now_iso="2026-07-24T00:00:00+00:00",
        )
        assert lease_result.allowed and lease_result.lease is not None
        lease = lease_result.lease
        ledger = RequestLedger()
        reservation = ledger.reserve(
            lease=lease,
            reservation=RequestReservation(
                reservation_id="res_live",
                lease_id=lease.lease_id,
                plan_id=plan.plan_id,
                plan_digest=plan.plan_digest,
                destination_host="127.0.0.1",
                destination_port=server.port,
                destination_path="/api/docs/1",
                method="GET",
                mutation_class="none",
                idempotency_key="idem_live",
                remaining_request_budget=1,
            ),
        )
        decision = authorize_gateway_request(
            plan=plan,
            lease=lease,
            request=GatewayAuthorizeRequest(
                url=f"http://127.0.0.1:{server.port}/api/docs/1",
                method="GET",
                resolved_ips=("127.0.0.1",),
            ),
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
            admitted_asset_id="asset_lab",
            current_scope_snapshot_digest=plan.scope_snapshot_digest,
            asset_identity_digest_current=True,
        )
        assert decision.status is GatewayDecisionStatus.ALLOWED
        with urlopen(f"{server.base_url}/api/docs/1", timeout=2) as resp:
            assert resp.status == 200
        ledger.complete(reservation.reservation_id, outcome=RequestReservationStatus.COMPLETED)

        blocked = authorize_gateway_request(
            plan=plan,
            lease=lease,
            request=GatewayAuthorizeRequest(
                url="http://evil.example/api/docs/1",
                method="GET",
                resolved_ips=("93.184.216.34",),
            ),
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
            admitted_asset_id="asset_lab",
            current_scope_snapshot_digest=plan.scope_snapshot_digest,
            asset_identity_digest_current=True,
        )
        assert blocked.status is GatewayDecisionStatus.BLOCKED
    finally:
        server.stop()


def test_live_api_trace_recovers_after_restart_without_duplicate_loopback_send():
    mod = _load_lab_server()
    server = mod.start_lab_target(port=0)
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)

    def override_get_session():
        with Session() as session:
            yield session

    os.environ["AUTOPILOT_RUNNER_CAPABILITY"] = RUNNER_CAPABILITY
    get_settings.cache_clear()
    app.dependency_overrides[get_session] = override_get_session
    try:
        identity = AssetIdentity(
            scheme="http",
            host="127.0.0.1",
            port=server.port,
            path_authority="/api",
            provenance=AssetProvenance.SEED,
        )
        asset_id = compute_asset_id(identity)
        scope_digest = _digest("b")
        with Session() as session:
            seed_sample_data(session)
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id=repository.list_programs()[0].id,
                name="live-loopback-release-trace",
                autonomy_level="level_0_read_only",
                scope_status="in_scope",
                policy_text="policy",
                default_asset="127.0.0.1",
                created_by="operator_alice",
                campaign_mode="bounty_autopilot",
            )
            campaign_id = campaign.id
            authorization = build_campaign_authorization(
                CampaignAuthorizationCreate(
                    campaign_id=campaign_id,
                    scope_snapshot_id="scope_live_loopback",
                    scope_snapshot_digest=scope_digest,
                    policy_digest=f"sha256:{sha256(b'policy').hexdigest()}",
                    asset_ids=(asset_id,),
                    recipe_refs=(RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),),
                    risk_ceiling=RiskTier.R1,
                    active_hours_utc=tuple(range(24)),
                    budget=AuthorizationBudget(
                        max_requests=2,
                        max_concurrent_requests=1,
                        max_response_bytes=10_000,
                        max_duration_seconds=60,
                        max_accounts=0,
                        max_cost_units=2,
                    ),
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                    operator_id="operator_alice",
                    policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
                )
            )
            authorization_digest = authorization.authorization_digest
            repository.create_campaign_authorization(
                campaign_id=campaign_id,
                authorization_payload=authorization.model_dump(mode="json"),
            )
            repository.upsert_campaign_asset_admission(
                campaign_id=campaign_id,
                admission=decide_admission(
                    identity,
                    ScopeMatcher(
                        include_hosts=("127.0.0.1",),
                        include_path_prefixes=("/api",),
                        scope_snapshot_digest=scope_digest,
                    ),
                ).model_dump(mode="json"),
            )

        plan = build_validation_plan(
            plan_id="plan_live_loopback",
            campaign_id=campaign_id,
            authorization_digest=authorization_digest,
            scope_snapshot_digest=scope_digest,
            asset_id=asset_id,
            destination_scheme="http",
            destination_host="127.0.0.1",
            destination_port=server.port,
            destination_path="/api",
            branch_id="branch_live_loopback",
            risk_tier=RiskTier.R1,
            recipe_ref=RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),
            methods=("GET",),
            mutation_inventory=MutationInventory(
                methods=("GET",),
                mutates_state=False,
                reversible=True,
                requires_owned_accounts=False,
            ),
            max_requests=1,
            max_response_bytes=10_000,
            max_duration_seconds=30,
            rollback_plan="close_context",
            stop_conditions=("waf", "third_party"),
            tool_profile="lab_browser",
            container_profile="lab_pod",
        )
        reservation = {
            "reservation_id": "res_live_loopback",
            "lease_id": "lease_live_loopback",
            "plan_id": plan.plan_id,
            "plan_digest": plan.plan_digest,
            "destination_host": "127.0.0.1",
            "destination_port": server.port,
            "destination_path": "/api/docs/1",
            "method": "GET",
            "mutation_class": "none",
            "idempotency_key": "idem_live_loopback",
            "remaining_request_budget": 0,
        }

        with TestClient(
            app,
            headers={"X-Mythos-Autopilot-Runner-Capability": RUNNER_CAPABILITY},
        ) as client:
            created = client.post(
                f"/mythos/campaigns/{campaign_id}/autopilot/plans",
                json={"plan": plan.model_dump(mode="json")},
            )
            assert created.status_code == 200, created.text
            lease = client.post(
                f"/mythos/campaigns/{campaign_id}/autopilot/leases",
                json={
                    "plan_id": plan.plan_id,
                    "lease_id": "lease_live_loopback",
                    "authorization_digest": authorization_digest,
                    "scope_snapshot_digest": scope_digest,
                    "authorization_recipe_allowed": True,
                    "policy_mode": PolicyMode.AUTHORIZED_LOCAL_LAB.value,
                },
            )
            assert lease.status_code == 200, lease.text
            reserved = client.post(
                f"/mythos/campaigns/{campaign_id}/autopilot/requests/reserve",
                json={"lease_id": "lease_live_loopback", "reservation": reservation},
            )
            assert reserved.status_code == 200, reserved.text
            authorized = client.post(
                f"/mythos/campaigns/{campaign_id}/autopilot/gateway/authorize",
                json={
                    "lease_id": "lease_live_loopback",
                    "reservation_id": "res_live_loopback",
                    "method": "GET",
                    "scheme": "http",
                    "host": "127.0.0.1",
                    "port": server.port,
                    "path": "/api/docs/1",
                },
            )
            assert authorized.status_code == 200, authorized.text
            assert authorized.json()["status"] == "allowed"
            assert (
                authorized.json()["execution_binding"]["transport_challenge"]
                == authorized.json()["transport_challenge"]
            )
            with urlopen(f"{server.base_url}/api/docs/1", timeout=2) as response:
                response_body = response.read().decode("utf-8")
                assert json.loads(response_body)["owner"] == "account_a"
            assert server.request_count("/api/docs/1") == 1
            receipt = TransportReceipt(
                receipt_id="receipt_live_loopback",
                campaign_id=campaign_id,
                lease_id="lease_live_loopback",
                reservation_id="res_live_loopback",
                plan_id=plan.plan_id,
                plan_digest=plan.plan_digest,
                branch_id=plan.branch_id,
                method="GET",
                scheme="http",
                host="127.0.0.1",
                port=server.port,
                path="/api/docs/1",
                status_code=200,
                byte_length=len(response_body.encode("utf-8")),
                sent_at=datetime.now(UTC),
                challenge=authorized.json()["transport_challenge"],
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

        # A fresh client represents a restarted local control plane. The
        # idempotency key recovers the existing sent reservation and never
        # replays the network send.
        with TestClient(
            app,
            headers={"X-Mythos-Autopilot-Runner-Capability": RUNNER_CAPABILITY},
        ) as recovered_client:
            recovered = recovered_client.post(
                f"/mythos/campaigns/{campaign_id}/autopilot/requests/reserve",
                json={"lease_id": "lease_live_loopback", "reservation": reservation},
            )
            assert recovered.status_code == 200, recovered.text
            assert recovered.json()["status"] == "sent"
            incomplete_gate = recovered_client.get(
                f"/mythos/campaigns/{campaign_id}/autopilot/release-gate"
            )
            assert incomplete_gate.status_code == 200
            assert incomplete_gate.json()["passed"] is False
            assert incomplete_gate.json()["counters"]["untraced_tool_runs"] == 1

            completed = recovered_client.post(
                f"/mythos/campaigns/{campaign_id}/autopilot/requests/complete",
                json={"reservation_id": "res_live_loopback", "outcome": "completed"},
            )
            assert completed.status_code == 200, completed.text
            observation = recovered_client.post(
                f"/mythos/campaigns/{campaign_id}/autopilot/observations",
                json={
                    "observation": {
                        "observation_id": "obs_live_loopback",
                        "branch_id": "branch_live_loopback",
                        "plan_digest": plan.plan_digest,
                        "lease_id": "lease_live_loopback",
                        "reservation_id": "res_live_loopback",
                        "receipt_digest": receipt_digest,
                        "outcome_class": "ok",
                        "grade": "L2_corroborated",
                        "summary": "owned account document read",
                        "evidence_refs": ["sanitized_document_owner"],
                    }
                },
            )
            assert observation.status_code == 200, observation.text
            release_gate = recovered_client.get(
                f"/mythos/campaigns/{campaign_id}/autopilot/release-gate"
            )
            assert release_gate.status_code == 200, release_gate.text
            assert release_gate.json()["passed"] is True
            assert release_gate.json()["trace_count"] == 1
            assert all(value == 0 for value in release_gate.json()["counters"].values())
            assert server.request_count("/api/docs/1") == 1
    finally:
        app.dependency_overrides.pop(get_session, None)
        engine.dispose()
        server.stop()
