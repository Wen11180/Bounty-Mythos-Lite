from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_session
import app.main as main_module
from app.main import app
from app.repository import DatabaseRepository, seed_sample_data


client = TestClient(app)


def build_testing_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine)
    with testing_session() as session:
        seed_sample_data(session)
    return testing_session


def test_campaign_api_creates_lists_and_controls_campaign_lifecycle(monkeypatch):
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    monkeypatch.setattr(
        main_module,
        "dispatch_agent_task",
        lambda *, campaign_task_id: {"campaign_task_id": campaign_task_id, "queue": "fake"},
    )
    app.dependency_overrides[get_session] = override_get_session
    try:
        create_response = client.post(
            "/mythos/campaigns",
            json={
                "program_id": "program_example",
                "name": "Authorized autonomous research",
                "autonomy_level": "level_1_local_validation",
                "scope_status": "in_scope",
                "policy_text": "Testing allowed. Authorization: Bearer secret-token",
                "default_asset": "api.example.com",
                "target_classes": ["idor"],
                "allowed_tools": ["static_analyzer"],
                "created_by": "operator@example.com",
                "budget": {
                    "time_budget_minutes": 60,
                    "token_budget": 10000,
                    "tool_call_budget": 50,
                    "validation_budget": 3,
                },
            },
        )
        assert create_response.status_code == 200
        created = create_response.json()
        assert created["id"].startswith("campaign_")
        assert created["status"] == "draft"
        assert created["policy_text_hash"]
        assert "policy_text" not in created
        assert created["budget"]["status"] == "active"

        list_response = client.get("/mythos/campaigns")
        assert list_response.status_code == 200
        assert list_response.json()[0]["id"] == created["id"]

        start_response = client.post(f"/mythos/campaigns/{created['id']}/start")
        assert start_response.status_code == 200
        assert start_response.json()["status"] == "running"

        pause_response = client.post(f"/mythos/campaigns/{created['id']}/pause")
        assert pause_response.status_code == 200
        assert pause_response.json()["status"] == "paused"

        resume_response = client.post(f"/mythos/campaigns/{created['id']}/resume")
        assert resume_response.status_code == 200
        assert resume_response.json()["status"] == "running"
    finally:
        app.dependency_overrides.clear()


def test_campaign_api_start_runs_first_safe_orchestrator_tick(monkeypatch):
    testing_session = build_testing_session()
    dispatched_task_ids: list[str] = []

    def override_get_session():
        with testing_session() as session:
            yield session

    def fake_dispatcher(*, campaign_task_id: str):
        dispatched_task_ids.append(campaign_task_id)
        return {"campaign_task_id": campaign_task_id, "queue": "fake"}

    monkeypatch.setattr(main_module, "dispatch_agent_task", fake_dispatcher)
    app.dependency_overrides[get_session] = override_get_session
    try:
        create_response = client.post(
            "/mythos/campaigns",
            json={
                "program_id": "program_example",
                "name": "Start orchestrator campaign",
                "autonomy_level": "level_0_read_only",
                "scope_status": "in_scope",
                "policy_text": "Testing allowed. Authorization: Bearer secret-token",
                "default_asset": "api.example.com",
                "created_by": "operator",
                "budget": {
                    "time_budget_minutes": 30,
                    "token_budget": 1000,
                    "tool_call_budget": 10,
                    "validation_budget": 1,
                },
            },
        )
        assert create_response.status_code == 200
        campaign_id = create_response.json()["id"]

        start_response = client.post(f"/mythos/campaigns/{campaign_id}/start")

        assert start_response.status_code == 200
        assert start_response.json()["status"] == "running"

        tasks_response = client.get(f"/mythos/campaigns/{campaign_id}/tasks")
        agent_runs_response = client.get(f"/mythos/campaigns/{campaign_id}/agent-runs")
        stages_response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")

        assert tasks_response.status_code == 200
        assert agent_runs_response.status_code == 200
        assert stages_response.status_code == 200
        tasks = tasks_response.json()
        agent_runs = agent_runs_response.json()
        stages = stages_response.json()
        assert {task["task_type"] for task in tasks} == {
            "campaign_observation",
            "attack_surface_mapping",
            "hypothesis_generation",
            "report_chain_review",
        }
        assert {run["agent_type"] for run in agent_runs} == {
            "orchestrator_agent",
            "target_model_agent",
            "hypothesis_agent",
            "report_agent",
        }
        assert all(run["safety_gate_state"] == "allowed" for run in agent_runs)
        assert {stage["stage_key"] for stage in stages} == {
            "campaign_observation",
            "attack_surface_mapping",
            "hypothesis_generation",
            "report_chain_review",
        }
        assert all(stage["status"] == "dispatched" for stage in stages)
        assert sorted(dispatched_task_ids) == sorted(task["id"] for task in tasks)
        assert "secret-token" not in str(tasks + agent_runs + stages)
        assert "Authorization" not in str(tasks + agent_runs + stages)
    finally:
        app.dependency_overrides.clear()


def test_campaign_api_start_blocks_out_of_scope_without_dispatch():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        create_response = client.post(
            "/mythos/campaigns",
            json={
                "program_id": "program_example",
                "name": "Out of scope start",
                "autonomy_level": "level_0_read_only",
                "scope_status": "out_of_scope",
                "policy_text": "Testing is not allowed",
                "default_asset": "api.example.com",
                "created_by": "operator",
            },
        )
        assert create_response.status_code == 200
        campaign_id = create_response.json()["id"]

        start_response = client.post(f"/mythos/campaigns/{campaign_id}/start")

        assert start_response.status_code == 200
        assert start_response.json()["status"] == "blocked"
        assert client.get(f"/mythos/campaigns/{campaign_id}/tasks").json() == []
        stages = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages").json()
        assert stages[0]["stage_key"] == "campaign_tick"
        assert stages[0]["status"] == "blocked"
        assert stages[0]["stop_reason"] == "scope_not_in_scope"
    finally:
        app.dependency_overrides.clear()


def test_campaign_api_rejects_missing_program():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        response = client.post(
            "/mythos/campaigns",
            json={
                "program_id": "missing",
                "name": "Invalid campaign",
                "autonomy_level": "level_0_read_only",
                "scope_status": "in_scope",
                "policy_text": "Testing allowed",
                "default_asset": "api.example.com",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 404
    assert response.json()["detail"] == "Program not found"


def test_campaign_api_lists_tasks_agent_runs_and_approvals_without_payload_leaks():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        create_response = client.post(
            "/mythos/campaigns",
            json={
                "program_id": "program_example",
                "name": "Audited campaign",
                "autonomy_level": "level_0_read_only",
                "scope_status": "in_scope",
                "policy_text": "Testing allowed",
                "default_asset": "api.example.com",
            },
        )
        assert create_response.status_code == 200
        campaign_id = create_response.json()["id"]

        with testing_session() as session:
            repository = DatabaseRepository(session)
            task = repository.create_campaign_task(
                campaign_id=campaign_id,
                task_type="campaign_observation",
                agent_type="orchestrator_agent",
                title="Observe authorized campaign state",
                input_refs=["campaign"],
                payload={"authorization": "Bearer secret-token"},
            )
            repository.save_agent_run(
                campaign_id=campaign_id,
                task_id=task.id,
                agent_type="orchestrator_agent",
                status="dispatched",
                input_refs=[f"campaign_task:{task.id}"],
                output_refs=[],
                tool_calls=[{"tool": "queue", "token": "secret"}],
                safety_gate_state="allowed",
                stop_reason=None,
                payload={"cookie": "session=secret"},
            )
            repository.create_approval_record(
                campaign_id=campaign_id,
                task_id=task.id,
                approval_type="validation_batch",
                actor="operator",
                reason="Approve test-account validation; cookie: session=secret",
                requested_action="two_account_authorization_check",
                safety_gate_state="awaiting_approval",
                payload={"authorization": "Bearer secret-token"},
            )

        tasks_response = client.get(f"/mythos/campaigns/{campaign_id}/tasks")
        agent_runs_response = client.get(f"/mythos/campaigns/{campaign_id}/agent-runs")
        approvals_response = client.get(f"/mythos/campaigns/{campaign_id}/approvals")

        assert tasks_response.status_code == 200
        assert tasks_response.json()[0]["task_type"] == "campaign_observation"
        assert "secret-token" not in str(tasks_response.json())

        assert agent_runs_response.status_code == 200
        assert agent_runs_response.json()[0]["safety_gate_state"] == "allowed"
        assert "secret" not in str(agent_runs_response.json())

        assert approvals_response.status_code == 200
        assert approvals_response.json()[0]["status"] == "pending"
        assert approvals_response.json()[0]["reason"] == "[REDACTED]"
        assert "session=secret" not in str(approvals_response.json())
    finally:
        app.dependency_overrides.clear()


def test_campaign_api_lists_pipeline_stages_without_payload_leaks():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        create_response = client.post(
            "/mythos/campaigns",
            json={
                "program_id": "program_example",
                "name": "Stage audit campaign",
                "autonomy_level": "level_0_read_only",
                "scope_status": "in_scope",
                "policy_text": "Testing allowed",
                "default_asset": "api.example.com",
            },
        )
        assert create_response.status_code == 200
        campaign_id = create_response.json()["id"]

        with testing_session() as session:
            repository = DatabaseRepository(session)
            task = repository.create_campaign_task(
                campaign_id=campaign_id,
                task_type="campaign_observation",
                agent_type="orchestrator_agent",
                title="Observe campaign",
                input_refs=[f"campaign:{campaign_id}"],
                payload={},
            )
            repository.save_pipeline_stage(
                pipeline_run_id=None,
                campaign_id=campaign_id,
                task_id=task.id,
                stage_key="campaign_tick",
                stage_order=0,
                status="blocked",
                input_refs=[f"campaign:{campaign_id}", "artifact:token=secret-token"],
                output_refs=["evidence:session=secret"],
                safety_gate_state="blocked",
                stop_reason="approval_required",
                payload={"authorization": "Bearer secret-token"},
            )

        response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")

        assert response.status_code == 200
        stages = response.json()
        assert stages[0]["stage_key"] == "campaign_tick"
        assert stages[0]["stop_reason"] == "approval_required"
        assert "secret-token" not in str(stages)
        assert "session=secret" not in str(stages)
        assert "authorization" not in str(stages).lower()
    finally:
        app.dependency_overrides.clear()


def test_campaign_api_returns_codebase_map_without_raw_scanner_or_secret_payloads():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        create_response = client.post(
            "/mythos/campaigns",
            json={
                "program_id": "program_example",
                "name": "Codebase map campaign",
                "autonomy_level": "level_0_read_only",
                "scope_status": "in_scope",
                "policy_text": "Testing allowed",
                "default_asset": "api.example.com",
            },
        )
        assert create_response.status_code == 200
        campaign_id = create_response.json()["id"]

        with testing_session() as session:
            repository = DatabaseRepository(session)
            codebase_map = repository.save_codebase_map(
                campaign_id=campaign_id,
                source_ref="artifact:repo_snapshot",
                repository="authorized/service",
                commit_ref="abc123",
                status="mapped",
                route_count=1,
                handler_count=1,
                model_count=1,
                authz_check_count=1,
                sensitive_sink_count=0,
                provenance_refs=["artifact:repo_snapshot"],
                safety_gate_state="allowed",
                payload={"authorization": "Bearer secret-token"},
            )
            repository.save_codebase_fact(
                codebase_map_id=codebase_map.id,
                campaign_id=campaign_id,
                fact_type="route_handler",
                source_path="apps/api/users.py?token=secret-token",
                symbol_name="get_user",
                route_method="GET",
                route_path="/users/{id}",
                authz_hint="owner_or_admin",
                sensitivity_label="low",
                provenance_refs=["codebase_map:route:1"],
                payload={"cookie": "session=secret"},
            )
            repository.save_scanner_run(
                campaign_id=campaign_id,
                codebase_map_id=codebase_map.id,
                tool_name="semgrep",
                command_hash="sha256:scanner-command",
                status="candidate_findings",
                finding_count=1,
                candidate_count=1,
                summary="Static candidates only; Authorization: Bearer secret-token",
                safety_gate_state="allowed",
                payload={"raw_stdout": "token=secret-token"},
            )

        response = client.get(f"/mythos/campaigns/{campaign_id}/codebase-map")

        assert response.status_code == 200
        body = response.json()
        assert body["maps"][0]["route_count"] == 1
        assert body["facts"][0]["source_path"] == "apps/api/users.py"
        assert body["facts"][0]["authz_hint"] == "owner_or_admin"
        assert body["scanner_runs"][0]["tool_name"] == "semgrep"
        assert body["scanner_runs"][0]["summary"] == "[REDACTED]"
        response_text = str(body)
        assert "raw_stdout" not in response_text
        assert "secret-token" not in response_text
        assert "session=secret" not in response_text
        assert "authorization" not in response_text.lower()
    finally:
        app.dependency_overrides.clear()


def test_campaign_api_lists_validation_runs_without_execution_or_payload_leaks():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        create_response = client.post(
            "/mythos/campaigns",
            json={
                "program_id": "program_example",
                "name": "Validation runs campaign",
                "autonomy_level": "level_1_local_validation",
                "scope_status": "in_scope",
                "policy_text": "Testing allowed",
                "default_asset": "api.example.com",
            },
        )
        assert create_response.status_code == 200
        campaign_id = create_response.json()["id"]

        with testing_session() as session:
            repository = DatabaseRepository(session)
            task = repository.create_campaign_task(
                campaign_id=campaign_id,
                task_type="validation_planning",
                agent_type="validation_harness_agent",
                title="Plan validation",
                input_refs=["hypothesis:1"],
                payload={},
            )
            repository.save_validation_run(
                campaign_id=campaign_id,
                task_id=task.id,
                approval_id=None,
                validation_mode="two_account_authorization_check",
                target_ref="candidate:idor?token=secret-token",
                status="ready",
                safety_gate_state="allowed",
                plan_digest="plan_digest_1",
                approval_required=True,
                allowed_to_execute=True,
                evidence_ref_count=0,
                summary="Needs approval; Authorization: Bearer secret-token",
                payload={"raw_request": "Cookie: session=secret"},
            )

        response = client.get(f"/mythos/campaigns/{campaign_id}/validation-runs")

        assert response.status_code == 200
        runs = response.json()
        assert runs[0]["validation_mode"] == "two_account_authorization_check"
        assert runs[0]["status"] == "awaiting_approval"
        assert runs[0]["allowed_to_execute"] is False
        assert runs[0]["approval_required"] is True
        assert runs[0]["target_ref"] == "candidate:idor"
        assert "payload" not in runs[0]
        assert "raw_request" not in str(runs)
        assert "secret-token" not in str(runs)
        assert "session=secret" not in str(runs)
        assert "authorization:" not in str(runs).lower()
        assert "bearer" not in str(runs).lower()
    finally:
        app.dependency_overrides.clear()


def test_campaign_approval_decision_unlocks_matching_validation_run_without_execution():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id="program_example",
                name="Approval unlock campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                created_by="operator",
            )
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="report_chain_review",
                agent_type="report_agent",
                title="Review validation gate",
                input_refs=[f"campaign:{campaign.id}"],
                payload={},
            )
            approval = repository.create_approval_record(
                campaign_id=campaign.id,
                task_id=task.id,
                program_id=campaign.program_id,
                approval_type="validation_batch",
                actor="operator",
                reason="Approve test-account validation; Authorization: Bearer secret-token",
                requested_action="two_account_authorization_check",
                asset=campaign.default_asset,
                validation_mode="two_account_authorization_check",
                plan_digest="plan_digest_1",
                autonomy_level=campaign.autonomy_level,
                safety_gate_state="awaiting_approval",
            )
            validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="planned",
                safety_gate_state="awaiting_approval",
                plan_digest="plan_digest_1",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Awaiting approval; Cookie: session=secret",
                payload={},
            )
            campaign_id = campaign.id
            approval_id = approval.id
            validation_id = validation.id

        decision_response = client.post(
            f"/mythos/approvals/{approval_id}/decisions",
            json={
                "decision": "approved",
                "actor": "lead_reviewer",
                "reason": "Approved for test accounts only.",
            },
        )
        assert decision_response.status_code == 200

        runs_response = client.get(f"/mythos/campaigns/{campaign_id}/validation-runs")
        assert runs_response.status_code == 200
        runs = runs_response.json()
        assert runs[0]["id"] == validation_id
        assert runs[0]["approval_id"] == approval_id
        assert runs[0]["status"] == "ready"
        assert runs[0]["safety_gate_state"] == "approved_validation_record"
        assert runs[0]["allowed_to_execute"] is True
        assert runs[0]["approval_required"] is True
        assert "secret-token" not in str(runs)
        assert "session=secret" not in str(runs)

        revoke_response = client.post(
            f"/mythos/approvals/{approval_id}/decisions",
            json={
                "decision": "revoked",
                "actor": "lead_reviewer",
                "reason": "Revoked before execution.",
            },
        )
        assert revoke_response.status_code == 200

        revoked_runs_response = client.get(f"/mythos/campaigns/{campaign_id}/validation-runs")
        assert revoked_runs_response.status_code == 200
        revoked_run = revoked_runs_response.json()[0]
        assert revoked_run["approval_id"] == approval_id
        assert revoked_run["status"] == "blocked"
        assert revoked_run["safety_gate_state"] == "blocked"
        assert revoked_run["allowed_to_execute"] is False
    finally:
        app.dependency_overrides.clear()


def test_validation_run_preflight_requires_scope_guard_after_approval():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id="program_example",
                name="Runtime preflight campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
            )
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="report_chain_review",
                agent_type="report_agent",
                title="Review validation gate",
                input_refs=[f"campaign:{campaign.id}"],
                payload={},
            )
            approval = repository.create_approval_record(
                campaign_id=campaign.id,
                task_id=task.id,
                program_id=campaign.program_id,
                approval_type="validation_batch",
                actor="operator",
                reason="Approve test-account validation; Authorization: Bearer secret-token",
                requested_action="two_account_authorization_check",
                asset=campaign.default_asset,
                validation_mode="two_account_authorization_check",
                plan_digest="plan_digest_preflight",
                autonomy_level=campaign.autonomy_level,
                safety_gate_state="awaiting_approval",
            )
            validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="planned",
                safety_gate_state="awaiting_approval",
                plan_digest="plan_digest_preflight",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Awaiting approval; Cookie: session=secret",
                payload={},
            )
            approval_id = approval.id
            validation_id = validation.id

        decision_response = client.post(
            f"/mythos/approvals/{approval_id}/decisions",
            json={
                "decision": "approved",
                "actor": "lead_reviewer",
                "reason": "Approved for test accounts only.",
            },
        )
        assert decision_response.status_code == 200

        preflight_response = client.post(
            f"/mythos/validation-runs/{validation_id}/preflight"
        )

        assert preflight_response.status_code == 200
        body = preflight_response.json()
        assert body["decision"] == {
            "allowed": True,
            "reason": "approved_validation_record",
        }
        assert body["validation_run"]["id"] == validation_id
        assert body["validation_run"]["status"] == "preflight_passed"
        assert body["validation_run"]["safety_gate_state"] == "scope_guard_preflight_passed"
        assert body["validation_run"]["allowed_to_execute"] is True
        assert body["execution_started"] is False
        assert "secret-token" not in str(body)
        assert "session=secret" not in str(body)
    finally:
        app.dependency_overrides.clear()


def test_validation_run_preflight_blocks_modes_missing_from_campaign_allowlist():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id="program_example",
                name="Preflight allowlist campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                allowed_tools=["static_local_check"],
                created_by="operator",
            )
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="report_chain_review",
                agent_type="report_agent",
                title="Review validation gate",
                input_refs=[f"campaign:{campaign.id}"],
                payload={},
            )
            approval = repository.create_approval_record(
                campaign_id=campaign.id,
                task_id=task.id,
                program_id=campaign.program_id,
                approval_type="validation_batch",
                actor="operator",
                reason="Approve test-account validation.",
                requested_action="two_account_authorization_check",
                asset=campaign.default_asset,
                validation_mode="two_account_authorization_check",
                plan_digest="plan_digest_preflight_blocked",
                autonomy_level=campaign.autonomy_level,
                safety_gate_state="awaiting_approval",
            )
            validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="planned",
                safety_gate_state="awaiting_approval",
                plan_digest="plan_digest_preflight_blocked",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Awaiting approval",
                payload={},
            )
            approval_id = approval.id
            validation_id = validation.id

        decision_response = client.post(
            f"/mythos/approvals/{approval_id}/decisions",
            json={
                "decision": "approved",
                "actor": "lead_reviewer",
                "reason": "Approved for test accounts only.",
            },
        )
        assert decision_response.status_code == 200

        preflight_response = client.post(
            f"/mythos/validation-runs/{validation_id}/preflight"
        )

        assert preflight_response.status_code == 200
        body = preflight_response.json()
        assert body["decision"] == {
            "allowed": False,
            "reason": "validation_not_allowed",
        }
        assert body["validation_run"]["status"] == "blocked"
        assert body["validation_run"]["safety_gate_state"] == "blocked"
        assert body["validation_run"]["allowed_to_execute"] is False
        assert body["execution_started"] is False
    finally:
        app.dependency_overrides.clear()


def test_validation_run_preflight_blocks_empty_campaign_allowlist():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id="program_example",
                name="Empty allowlist preflight campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                created_by="operator",
            )
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="report_chain_review",
                agent_type="report_agent",
                title="Review validation gate",
                input_refs=[f"campaign:{campaign.id}"],
                payload={},
            )
            approval = repository.create_approval_record(
                campaign_id=campaign.id,
                task_id=task.id,
                program_id=campaign.program_id,
                approval_type="validation_batch",
                actor="operator",
                reason="Approve test-account validation.",
                requested_action="two_account_authorization_check",
                asset=campaign.default_asset,
                validation_mode="two_account_authorization_check",
                plan_digest="plan_digest_empty_allowlist",
                autonomy_level=campaign.autonomy_level,
                safety_gate_state="awaiting_approval",
            )
            validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="planned",
                safety_gate_state="awaiting_approval",
                plan_digest="plan_digest_empty_allowlist",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Awaiting approval",
                payload={},
            )
            approval_id = approval.id
            validation_id = validation.id

        decision_response = client.post(
            f"/mythos/approvals/{approval_id}/decisions",
            json={
                "decision": "approved",
                "actor": "lead_reviewer",
                "reason": "Approved for test accounts only.",
            },
        )
        assert decision_response.status_code == 200

        preflight_response = client.post(
            f"/mythos/validation-runs/{validation_id}/preflight"
        )

        assert preflight_response.status_code == 200
        body = preflight_response.json()
        assert body["decision"] == {
            "allowed": False,
            "reason": "validation_not_allowed",
        }
        assert body["validation_run"]["status"] == "blocked"
        assert body["validation_run"]["allowed_to_execute"] is False
        assert body["execution_started"] is False
    finally:
        app.dependency_overrides.clear()


def test_validation_run_preflight_rejects_unbound_cross_campaign_approval_record():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            approved_campaign = repository.create_campaign(
                program_id="program_example",
                name="Approved source campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
            )
            approved_task = repository.create_campaign_task(
                campaign_id=approved_campaign.id,
                task_type="report_chain_review",
                agent_type="report_agent",
                title="Approved validation gate",
                input_refs=[f"campaign:{approved_campaign.id}"],
                payload={},
            )
            approval = repository.create_approval_record(
                campaign_id=approved_campaign.id,
                task_id=approved_task.id,
                program_id=approved_campaign.program_id,
                approval_type="validation_batch",
                actor="operator",
                reason="Approved for the source campaign only.",
                requested_action="two_account_authorization_check",
                asset=approved_campaign.default_asset,
                validation_mode="two_account_authorization_check",
                plan_digest="shared_plan_digest",
                autonomy_level=approved_campaign.autonomy_level,
                safety_gate_state="awaiting_approval",
            )
            repository.decide_approval_record(
                approval_id=approval.id,
                decision="approved",
                actor="lead_reviewer",
                reason="Approved source campaign.",
            )

            target_campaign = repository.create_campaign(
                program_id="program_example",
                name="Unbound target campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
            )
            target_task = repository.create_campaign_task(
                campaign_id=target_campaign.id,
                task_type="report_chain_review",
                agent_type="report_agent",
                title="Target validation gate",
                input_refs=[f"campaign:{target_campaign.id}"],
                payload={},
            )
            validation = repository.save_validation_run(
                campaign_id=target_campaign.id,
                task_id=target_task.id,
                approval_id=approval.id,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{target_campaign.id}",
                status="ready",
                safety_gate_state="approved_validation_record",
                plan_digest="shared_plan_digest",
                approval_required=True,
                allowed_to_execute=True,
                evidence_ref_count=0,
                summary="Incorrectly bound approval should not pass preflight",
                payload={},
            )
            validation_id = validation.id

        preflight_response = client.post(
            f"/mythos/validation-runs/{validation_id}/preflight"
        )

        assert preflight_response.status_code == 200
        body = preflight_response.json()
        assert body["decision"] == {
            "allowed": False,
            "reason": "approval_record_required",
        }
        assert body["validation_run"]["status"] == "blocked"
        assert body["validation_run"]["allowed_to_execute"] is False
        assert body["execution_started"] is False
    finally:
        app.dependency_overrides.clear()


def test_campaign_denied_approval_blocks_matching_validation_run():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id="program_example",
                name="Denied approval campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                created_by="operator",
            )
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="report_chain_review",
                agent_type="report_agent",
                title="Review validation gate",
                input_refs=[f"campaign:{campaign.id}"],
                payload={},
            )
            approval = repository.create_approval_record(
                campaign_id=campaign.id,
                task_id=task.id,
                program_id=campaign.program_id,
                approval_type="validation_batch",
                actor="operator",
                reason="Approval request",
                requested_action="two_account_authorization_check",
                asset=campaign.default_asset,
                validation_mode="two_account_authorization_check",
                plan_digest="plan_digest_2",
                autonomy_level=campaign.autonomy_level,
                safety_gate_state="awaiting_approval",
            )
            repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="planned",
                safety_gate_state="awaiting_approval",
                plan_digest="plan_digest_2",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Awaiting approval",
                payload={},
            )
            campaign_id = campaign.id
            approval_id = approval.id

        decision_response = client.post(
            f"/mythos/approvals/{approval_id}/decisions",
            json={
                "decision": "denied",
                "actor": "lead_reviewer",
                "reason": "Not approved for this batch.",
            },
        )
        assert decision_response.status_code == 200

        runs_response = client.get(f"/mythos/campaigns/{campaign_id}/validation-runs")
        assert runs_response.status_code == 200
        run = runs_response.json()[0]
        assert run["approval_id"] == approval_id
        assert run["status"] == "blocked"
        assert run["safety_gate_state"] == "blocked"
        assert run["allowed_to_execute"] is False
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_returns_audited_read_only_summary():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        create_response = client.post(
            "/mythos/campaigns",
            json={
                "program_id": "program_example",
                "name": "Control center campaign",
                "autonomy_level": "level_0_read_only",
                "scope_status": "in_scope",
                "policy_text": "Testing allowed. Authorization: Bearer secret-token",
                "default_asset": "api.example.com",
                "budget": {
                    "time_budget_minutes": 30,
                    "token_budget": 5000,
                    "tool_call_budget": 10,
                    "validation_budget": 1,
                },
            },
        )
        assert create_response.status_code == 200
        campaign_id = create_response.json()["id"]

        with testing_session() as session:
            repository = DatabaseRepository(session)
            task = repository.create_campaign_task(
                campaign_id=campaign_id,
                task_type="campaign_observation",
                agent_type="orchestrator_agent",
                title="Observe campaign",
                input_refs=[f"campaign:{campaign_id}"],
                payload={"authorization": "Bearer secret-token"},
            )
            task_id = task.id
            repository.save_agent_run(
                campaign_id=campaign_id,
                task_id=task_id,
                agent_type="orchestrator_agent",
                status="dispatched",
                input_refs=[f"campaign_task:{task_id}"],
                output_refs=[],
                tool_calls=[],
                safety_gate_state="allowed",
                stop_reason=None,
                payload={"mode": "read_only"},
            )
            repository.create_approval_record(
                campaign_id=campaign_id,
                task_id=task_id,
                approval_type="validation_batch",
                actor="operator",
                reason="Needs approval; cookie: session=secret",
                requested_action="two_account_authorization_check",
                safety_gate_state="awaiting_approval",
                payload={"authorization": "Bearer secret-token"},
            )
            repository.save_pipeline_stage(
                pipeline_run_id=None,
                campaign_id=campaign_id,
                task_id=task_id,
                stage_key="campaign_tick",
                stage_order=0,
                status="blocked",
                input_refs=[f"campaign:{campaign_id}"],
                output_refs=[],
                safety_gate_state="blocked",
                stop_reason="approval_required",
                payload={"authorization": "Bearer secret-token"},
            )

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["campaign"]["id"] == campaign_id
        assert control_center["budget"]["status"] == "active"
        assert control_center["tasks"][0]["id"] == task_id
        assert control_center["agent_runs"][0]["safety_gate_state"] == "allowed"
        assert control_center["approvals"][0]["status"] == "pending"
        assert control_center["pipeline_stages"][0]["stop_reason"] == "approval_required"
        assert control_center["safe_next_action"] == "review_approval_queue"
        assert control_center["blocked_reasons"] == ["approval_required"]
        assert control_center["execution_allowed"] is False
        assert "policy_text" not in str(control_center)
        assert "secret-token" not in str(control_center)
        assert "session=secret" not in str(control_center)
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_redacts_secret_like_display_fields():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id="program_example",
                name="Control campaign token=secret-token",
                autonomy_level="level_0_read_only",
                scope_status="in_scope",
                policy_text="Testing allowed. Authorization: Bearer secret-token",
                default_asset="https://api.example.com/path?session=secret",
                target_classes=["idor"],
                allowed_tools=["static_analyzer"],
                created_by="operator",
            )
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="campaign_observation",
                agent_type="orchestrator_agent",
                title="Observe campaign secret=abc",
                input_refs=["campaign:campaign_1", "token=secret-token"],
                payload={},
            )
            repository.save_agent_run(
                campaign_id=campaign.id,
                task_id=task.id,
                agent_type="orchestrator_agent",
                status="blocked",
                input_refs=["campaign_task:task_1"],
                output_refs=[],
                tool_calls=[],
                safety_gate_state="blocked",
                stop_reason="api_key=abc",
                payload={},
            )
            repository.save_pipeline_stage(
                pipeline_run_id=None,
                campaign_id=campaign.id,
                task_id=task.id,
                stage_key="campaign_tick",
                stage_order=0,
                status="blocked",
                input_refs=["secret=abc"],
                output_refs=[],
                safety_gate_state="blocked",
                stop_reason="api_key=abc",
                payload={},
            )
            campaign_id = campaign.id

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        response_text = str(response.json())
        assert "[REDACTED]" in response_text
        assert "secret-token" not in response_text
        assert "session=secret" not in response_text
        assert "secret=abc" not in response_text
        assert "api_key=abc" not in response_text
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_points_to_validation_queue_when_validation_run_awaits_approval():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id="program_example",
                name="Validation queue campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                created_by="operator",
            )
            repository.update_campaign_status(campaign.id, "running")
            repository.upsert_campaign_budget(
                campaign_id=campaign.id,
                time_budget_minutes=30,
                token_budget=1000,
                tool_call_budget=10,
                validation_budget=1,
            )
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="report_chain_review",
                agent_type="report_agent",
                title="Review validation gate",
                input_refs=[f"campaign:{campaign.id}"],
                payload={},
            )
            repository.update_campaign_task_status(
                task.id,
                "completed",
                output_refs=["validation_run:pending"],
            )
            repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="awaiting_approval",
                safety_gate_state="awaiting_approval",
                plan_digest="validation_plan_1",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Awaiting approval; Authorization: Bearer secret-token",
                payload={"raw_request": "Cookie: session=secret"},
            )
            campaign_id = campaign.id

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["safe_next_action"] == "review_validation_queue"
        assert control_center["execution_allowed"] is False
        assert "secret-token" not in str(control_center)
        assert "session=secret" not in str(control_center)
    finally:
        app.dependency_overrides.clear()
