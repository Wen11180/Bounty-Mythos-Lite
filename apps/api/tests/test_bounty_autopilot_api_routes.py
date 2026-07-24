"""HTTP API tests for Bounty Autopilot durable routes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.bounty_autopilot.authority import build_campaign_authorization
from app.bounty_autopilot.asset_admission import (
    AssetProvenance,
    NetworkIdentityObservation,
    ScopeMatcher,
    decide_admission,
    parse_asset_url,
)
from app.bounty_autopilot.branches import BranchStatus, ResearchBranch
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
from app.bounty_autopilot.gateway import GatewayOutcomeClass
from app.bounty_autopilot.lineage import AutopilotRiskDecisionRecord
from app.bounty_autopilot.observations import (
    EndpointIdentity,
    ObservationGrade,
    ObservationRecord,
    ObservationSummaryCode,
)
from app.bounty_autopilot.plans import build_validation_plan
from app.bounty_autopilot.recipes import default_recipe_registry
from app.db import Base, get_session
from app.db_models import ExecutionRequestLedgerRecord
from app.main import app
from app.main import AutopilotGatewayAuthorizeRequest, AutopilotLeaseIssueRequest
from app.repository import DatabaseRepository, seed_sample_data


def _digest(n: str = "a") -> str:
    return "sha256:" + (n * 64)


def _client_and_campaign():
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
        scope_digest = _digest("b")
        identity = parse_asset_url(
            "http://127.0.0.1:18080/api",
            provenance=AssetProvenance.SEED,
        )
        admission = decide_admission(
            identity,
            ScopeMatcher(
                include_hosts=("127.0.0.1",),
                include_path_prefixes=("/api",),
                scope_snapshot_digest=scope_digest,
            ),
            network=NetworkIdentityObservation(resolved_ips=("127.0.0.1",)),
            seen_at=datetime.now(UTC).isoformat(),
        )
        campaign = repo.create_campaign(
            program_id=program.id,
            name="autopilot-api",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="policy",
            default_asset=admission.asset_id,
            created_by="operator_alice",
            campaign_mode="bounty_autopilot",
        )
        recipe = default_recipe_registry().require("lab_browser_mapping", "1.0.0")
        now = datetime.now(UTC)
        authorization = build_campaign_authorization(
            CampaignAuthorization(
                campaign_id=campaign.id,
                scope_snapshot_id="scope_snap_1",
                scope_review_state="approved",
                scope_snapshot_digest=scope_digest,
                policy_digest=_digest("c"),
                asset_ids=(admission.asset_id,),
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
        )
        authorization_record = repo.create_campaign_authorization(
            campaign_id=campaign.id,
            authorization_payload=campaign_authorization_payload(authorization),
        )
        repo.upsert_campaign_asset_admission(
            campaign_id=campaign.id,
            admission=admission.model_dump(mode="json"),
        )
        branch = repo.create_research_branch(
            campaign_id=campaign.id,
            branch=ResearchBranch(
                branch_id="branch_api",
                campaign_id=campaign.id,
                asset_id=admission.asset_id,
                status=BranchStatus.QUEUED,
                priority=50,
                recipe_ref=recipe.ref,
                risk_tier=RiskTier.R1,
            ).model_dump(mode="json"),
        )
        repo.append_autopilot_risk_decision(
            AutopilotRiskDecisionRecord(
                risk_decision_id="risk_api",
                campaign_id=campaign.id,
                authorization_id=authorization_record.id,
                authorization_digest=authorization.authorization_digest,
                scope_snapshot_digest=scope_digest,
                asset_id=admission.asset_id,
                branch_id=branch.branch_id,
                recipe_ref=recipe.ref,
                risk_tier=RiskTier.R1,
                status="authorized",
                reason_code="server_classification",
                decided_at=now,
            )
        )
        branch = repo.transition_research_branch(
            campaign_id=campaign.id,
            branch_id=branch.branch_id,
            new_status=BranchStatus.AWAITING_HUMAN.value,
            expected_version=branch.version,
            stop_reason="awaiting_plan",
        )
        handoff = repo.create_campaign_task(
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
                "risk_tier": RiskTier.R1,
                "hypothesis_id": None,
                "human_approval_required": True,
            },
        )
        repo.update_campaign_task_status(handoff.id, "awaiting_approval")
        context = {
            "campaign_id": campaign.id,
            "authorization": authorization,
            "authorization_id": authorization_record.id,
            "asset_id": admission.asset_id,
            "asset_identity_digest": admission.identity_digest,
            "handoff_id": handoff.id,
            "risk_decision_id": "risk_api",
        }
    client = TestClient(app)
    return client, TestingSession, context


def test_lease_issue_request_accepts_only_server_resolved_identifiers():
    assert set(AutopilotLeaseIssueRequest.model_fields) == {
        "plan_id",
        "lease_id",
        "approval_id",
    }


def test_gateway_authorize_request_requires_durable_reservation_and_network_identity():
    assert set(AutopilotGatewayAuthorizeRequest.model_fields) == {
        "lease_id",
        "reservation_id",
        "method",
        "scheme",
        "host",
        "port",
        "path",
        "body_digest",
        "mutation_class",
        "resolved_ips",
        "cname_chain",
        "is_redirect",
        "is_subresource",
    }


def test_client_supplied_scheduler_state_endpoint_is_not_exposed():
    paths = {route.path for route in app.routes}
    assert "/mythos/campaigns/{campaign_id}/autopilot/scheduler/tick" not in paths


def _plan_payload(
    campaign_id: str,
    *,
    asset_id: str,
    authorization_digest: str,
    branch_id: str = "branch_api",
    plan_id: str = "plan_api",
    risk_tier: RiskTier = RiskTier.R1,
    r3_approval_id: str | None = None,
):
    plan = build_validation_plan(
        plan_id=plan_id,
        campaign_id=campaign_id,
        authorization_digest=authorization_digest,
        scope_snapshot_digest=_digest("b"),
        asset_id=asset_id,
        destination_scheme="http",
        destination_host="127.0.0.1",
        destination_port=18080,
        destination_path="/api",
        branch_id=branch_id,
        risk_tier=risk_tier,
        recipe_ref=default_recipe_registry().require(
            "lab_browser_mapping", "1.0.0"
        ).ref,
        methods=("GET",),
        mutation_inventory=default_recipe_registry().require(
            "lab_browser_mapping", "1.0.0"
        ).mutation_inventory,
        max_requests=3,
        max_response_bytes=1000,
        max_duration_seconds=30,
        rollback_plan="noop",
        stop_conditions=("stop",),
        tool_profile="lab_browser_v1",
        container_profile="docker_readonly_v1",
        r3_approval_id=r3_approval_id,
    )
    return plan.model_dump(mode="json"), plan


def test_autopilot_plan_lease_request_observation_and_stop_flow():
    client, TestingSession, context = _client_and_campaign()
    campaign_id = context["campaign_id"]
    authorization = context["authorization"]
    try:
        plan_payload, plan = _plan_payload(
            campaign_id,
            asset_id=context["asset_id"],
            authorization_digest=authorization.authorization_digest,
        )
        bypass = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/plans",
            json={"handoff_id": "campaign_task_missing", "plan": plan_payload},
        )
        assert bypass.status_code == 409
        assert bypass.json()["detail"] == "plan_handoff_not_found"
        created = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/plans",
            json={"handoff_id": context["handoff_id"], "plan": plan_payload},
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

        unreserved = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/gateway/authorize",
            json={
                "lease_id": "lease_api",
                "reservation_id": "res_missing",
                "method": "GET",
                "scheme": "http",
                "host": "127.0.0.1",
                "port": 18080,
                "path": "/api/docs/1",
                "resolved_ips": ["127.0.0.1"],
            },
        )
        assert unreserved.status_code == 409
        assert unreserved.json()["detail"] == "reservation_not_found"

        for reservation_id, destination_path, cname_chain, reason in (
            (
                "res_cname_mismatch",
                "/api/docs/2",
                ["unexpected.lab"],
                "network_identity_mismatch",
            ),
            ("res_path_mismatch", "/api2", [], "path_not_authorized"),
        ):
            reserved = client.post(
                f"/mythos/campaigns/{campaign_id}/autopilot/requests/reserve",
                json={
                    "lease_id": "lease_api",
                    "reservation": {
                        "reservation_id": reservation_id,
                        "lease_id": "lease_api",
                        "plan_id": plan.plan_id,
                        "plan_digest": plan.plan_digest,
                        "destination_host": "127.0.0.1",
                        "destination_port": 18080,
                        "destination_path": destination_path,
                        "method": "GET",
                        "mutation_class": "none",
                        "idempotency_key": f"idem_{reservation_id}",
                        "remaining_request_budget": 2,
                    },
                },
            )
            assert reserved.status_code == 200, reserved.text
            blocked = client.post(
                f"/mythos/campaigns/{campaign_id}/autopilot/gateway/authorize",
                json={
                    "lease_id": "lease_api",
                    "reservation_id": reservation_id,
                    "method": "GET",
                    "scheme": "http",
                    "host": "127.0.0.1",
                    "port": 18080,
                    "path": destination_path,
                    "resolved_ips": ["127.0.0.1"],
                    "cname_chain": cname_chain,
                },
            )
            assert blocked.status_code == 200, blocked.text
            assert blocked.json()["status"] == "blocked"
            assert blocked.json()["reason"] == reason
            with TestingSession() as session:
                reservation_row = session.scalar(
                    select(ExecutionRequestLedgerRecord).where(
                        ExecutionRequestLedgerRecord.campaign_id == campaign_id,
                        ExecutionRequestLedgerRecord.reservation_id == reservation_id,
                    )
                )
                assert reservation_row is not None
                assert reservation_row.status == "reserved"

        auth = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/gateway/authorize",
            json={
                "lease_id": "lease_api",
                "reservation_id": "res_api",
                "method": "GET",
                "scheme": "http",
                "host": "127.0.0.1",
                "port": 18080,
                "path": "/api/docs/1",
                "resolved_ips": ["127.0.0.1"],
            },
        )
        assert auth.status_code == 200, auth.text
        assert auth.json()["status"] == "allowed"
        assert auth.json()["report_submission_allowed"] is False
        with TestingSession() as session:
            reservation_row = session.scalar(
                select(ExecutionRequestLedgerRecord).where(
                    ExecutionRequestLedgerRecord.campaign_id == campaign_id,
                    ExecutionRequestLedgerRecord.reservation_id == "res_api",
                )
            )
            assert reservation_row is not None
            assert reservation_row.status == "sent"

        replay_authorize = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/gateway/authorize",
            json={
                "lease_id": "lease_api",
                "reservation_id": "res_api",
                "method": "GET",
                "scheme": "http",
                "host": "127.0.0.1",
                "port": 18080,
                "path": "/api/docs/1",
                "resolved_ips": ["127.0.0.1"],
            },
        )
        assert replay_authorize.status_code == 409
        assert replay_authorize.json()["detail"] == "reservation_not_reserved"

        complete = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/requests/complete",
            json={"reservation_id": "res_api", "outcome": "completed"},
        )
        assert complete.status_code == 200, complete.text

        obs = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/observations",
            json={
                "observation": {
                    "observation_id": "obs_api",
                    "campaign_id": campaign_id,
                    "authorization_id": context["authorization_id"],
                    "authorization_digest": authorization.authorization_digest,
                    "scope_snapshot_digest": authorization.scope_snapshot_digest,
                    "asset_id": context["asset_id"],
                    "asset_identity_digest": context["asset_identity_digest"],
                    "branch_id": plan.branch_id,
                    "plan_id": plan.plan_id,
                    "plan_digest": plan.plan_digest,
                    "risk_decision_id": context["risk_decision_id"],
                    "risk_tier": plan.risk_tier,
                    "recipe_ref": plan.recipe_ref.model_dump(mode="json"),
                    "lease_id": "lease_api",
                    "reservation_id": "res_api",
                    "session_generation": 1,
                    "tool_run_id": "toolrun_api",
                    "endpoint": {
                        "method": "GET",
                        "route_template": "/api/docs/{owned}",
                    },
                    "occurred_at": datetime.now(UTC).isoformat(),
                    "grade": "L2_corroborated",
                    "outcome_class": "ok",
                    "summary_code": "route_mapped",
                    "evidence_refs": [],
                }
            },
        )
        assert obs.status_code == 200, obs.text
        listed_obs = client.get(
            f"/mythos/campaigns/{campaign_id}/autopilot/observations"
        )
        assert listed_obs.status_code == 200
        item = listed_obs.json()["items"][0]
        assert item["observation_id"] == "obs_api"
        rejected_raw = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/observations",
            json={"observation": {**item["payload"], "raw_body": "must-not-enter"}},
        )
        assert rejected_raw.status_code == 400

        grant = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/pods/grant",
            json={"lease_id": "lease_api", "pod_id": "pod_api"},
        )
        assert grant.status_code == 200, grant.text
        assert grant.json()["lease_id"] == "lease_api"
        assert grant.json()["network_profile"] == "gateway_only_v1"
        assert grant.json()["report_submission_allowed"] is False

        prepared = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/emergency-stop/prepare",
            json={"actor": "operator_alice", "reason": "api_drill"},
        )
        assert prepared.status_code == 200, prepared.text
        nonce = prepared.json()["confirmation_nonce"]
        assert nonce

        wrong_stop = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/emergency-stop",
            json={
                "actor": "operator_alice",
                "reason": "api_drill",
                "confirmation_nonce": "wrong-nonce-xxxxxxxx",
            },
        )
        assert wrong_stop.status_code == 409

        stop = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/emergency-stop",
            json={
                "actor": "operator_alice",
                "reason": "api_drill",
                "confirmation_nonce": nonce,
            },
        )
        assert stop.status_code == 200, stop.text
        assert stop.json()["emergency_stopped"] is True

        replay = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/emergency-stop",
            json={
                "actor": "operator_alice",
                "reason": "api_drill",
                "confirmation_nonce": nonce,
            },
        )
        assert replay.status_code == 409
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_autopilot_projection_endpoints_are_safe():
    client, TestingSession, context = _client_and_campaign()
    campaign_id = context["campaign_id"]
    try:
        resp = client.get(f"/mythos/campaigns/{campaign_id}/autopilot")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["campaign_id"] == campaign_id
        assert body["report_submission_allowed"] is False
        assert body["candidate_promotion_allowed"] is False
        assert body["submission_blocked"] is True
        assert "budgets" in body
        assert client.get(f"/mythos/campaigns/{campaign_id}/autopilot/assets").status_code == 200
        assert client.get(f"/mythos/campaigns/{campaign_id}/autopilot/branches").status_code == 200
        assert client.get(f"/mythos/campaigns/{campaign_id}/autopilot/budgets").status_code == 200
        assert client.get(f"/mythos/campaigns/{campaign_id}/autopilot/approvals").status_code == 200
        assert client.get(f"/mythos/campaigns/{campaign_id}/autopilot/events").status_code == 200
        steer = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/steering",
            json={
                "directive": "set_priority",
                "branch_id": "branch_api",
                "priority": 70,
                "reason": "projection_steer",
            },
        )
        assert steer.status_code == 200, steer.text
        assert steer.json()["priority"] == 70
        assert steer.json()["report_submission_allowed"] is False
        guidance = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/steering",
            json={
                "directive": "add_hypothesis_guidance",
                "branch_id": "branch_api",
                "hypothesis_guidance": "Compare only the two owned account paths.",
                "reason": "operator_guidance",
            },
        )
        assert guidance.status_code == 200, guidance.text
        injected_state = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/steering",
            json={
                "directive": "set_priority",
                "branch_id": "branch_api",
                "priority": 80,
                "branches": [],
                "campaign_max_requests": 9999,
            },
        )
        assert injected_state.status_code == 422
        with TestingSession() as session:
            branch = DatabaseRepository(session).get_research_branch(
                campaign_id=campaign_id,
                branch_id="branch_api",
            )
            assert branch is not None
            assert branch.priority == 70
            assert branch.payload["hypothesis_guidance"][-1]["guidance"] == (
                "Compare only the two owned account paths."
            )
    finally:
        app.dependency_overrides.pop(get_session, None)

def test_autopilot_r3_decision_is_exact_and_single_use():
    client, TestingSession, context = _client_and_campaign()
    campaign_id = context["campaign_id"]
    authorization = context["authorization"]
    recipe = default_recipe_registry().require("lab_browser_mapping", "1.0.0")
    plan_payload, plan = _plan_payload(
        campaign_id,
        asset_id=context["asset_id"],
        authorization_digest=authorization.authorization_digest,
        branch_id="branch_r3",
        plan_id="plan_r3_api",
        risk_tier=RiskTier.R3,
        r3_approval_id="approval_r3_api",
    )
    try:
        with TestingSession() as session:
            repository = DatabaseRepository(session)
            branch = repository.create_research_branch(
                campaign_id=campaign_id,
                branch=ResearchBranch(
                    branch_id="branch_r3",
                    campaign_id=campaign_id,
                    asset_id=context["asset_id"],
                    status=BranchStatus.QUEUED,
                    priority=40,
                    recipe_ref=recipe.ref,
                    risk_tier=RiskTier.R3,
                ).model_dump(mode="json"),
            )
            repository.append_autopilot_risk_decision(
                AutopilotRiskDecisionRecord(
                    risk_decision_id="risk_r3_api",
                    campaign_id=campaign_id,
                    authorization_id=context["authorization_id"],
                    authorization_digest=authorization.authorization_digest,
                    scope_snapshot_digest=authorization.scope_snapshot_digest,
                    asset_id=context["asset_id"],
                    branch_id=branch.branch_id,
                    recipe_ref=recipe.ref,
                    risk_tier=RiskTier.R3,
                    status="awaiting_exact_approval",
                    reason_code="exact_plan_required",
                    decided_at=datetime.now(UTC),
                )
            )
            branch = repository.transition_research_branch(
                campaign_id=campaign_id,
                branch_id=branch.branch_id,
                new_status=BranchStatus.AWAITING_HUMAN.value,
                expected_version=branch.version,
                stop_reason="awaiting_plan",
            )
            handoff = repository.create_campaign_task(
                campaign_id=campaign_id,
                task_type="autopilot_plan_materialization",
                agent_type="human_plan_reviewer",
                title="Materialize immutable plan for selected research branch",
                payload={
                    "schema_version": "autopilot-plan-materialization/v1",
                    "campaign_id": campaign_id,
                    "branch_id": branch.branch_id,
                    "branch_version": branch.version - 1,
                    "authorization_id": context["authorization_id"],
                    "authorization_digest": authorization.authorization_digest,
                    "scope_snapshot_digest": authorization.scope_snapshot_digest,
                    "asset_id": context["asset_id"],
                    "recipe_ref": recipe.ref.model_dump(mode="json"),
                    "risk_tier": RiskTier.R3,
                    "hypothesis_id": None,
                    "human_approval_required": True,
                },
            )
            repository.update_campaign_task_status(handoff.id, "awaiting_approval")
            handoff_id = handoff.id
            nonce_digest = _digest("e")
            repository.create_approval_record(
                approval_id="approval_r3_api",
                campaign_id=campaign_id,
                approval_type="r3_exact_plan",
                actor="operator_alice",
                reason="exact r3 plan",
                scope_reference=authorization.scope_snapshot_digest,
                requested_action="autopilot_r3_exact_plan",
                asset=context["asset_id"],
                validation_mode=recipe.ref.recipe_id,
                plan_digest=plan.plan_digest,
                status="pending",
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
                payload={
                    "account_aliases": [],
                    "exact_diff": [
                        {"field": "risk_tier", "before": "R2", "after": "R3"}
                    ],
                },
                single_use_nonce_digest=nonce_digest,
            )

        materialized = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/plans",
            json={"handoff_id": handoff_id, "plan": plan_payload},
        )
        assert materialized.status_code == 200, materialized.text
        decision = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/approvals/approval_r3_api/decision",
            json={
                "decision": "approved",
                "actor": "operator_alice",
                "reason": "exact_r3_approval",
            },
        )
        assert decision.status_code == 200, decision.text
        assert decision.json()["status"] == "approved"
        replay = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/approvals/approval_r3_api/decision",
            json={
                "decision": "approved",
                "actor": "operator_alice",
                "reason": "exact_r3_approval",
            },
        )
        assert replay.status_code == 409
        lease = client.post(
            f"/mythos/campaigns/{campaign_id}/autopilot/leases",
            json={
                "plan_id": plan.plan_id,
                "lease_id": "lease_r3_api",
                "approval_id": "approval_r3_api",
            },
        )
        assert lease.status_code == 200, lease.text
        assert lease.json()["r3_approval_id"] == "approval_r3_api"
    finally:
        app.dependency_overrides.pop(get_session, None)
