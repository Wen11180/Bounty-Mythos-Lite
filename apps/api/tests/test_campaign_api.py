from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_session
from app.db_models import ApprovalRecord, CampaignRecord, ValidationRunRecord
import app.main as main_module
from app.main import app
from app.repository import DatabaseRepository, seed_sample_data
from app.worker.tasks import run_agent_task


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


def validation_scope_guard_payload(
    *,
    asset: str = "api.example.com",
    allowed_validation: list[str] | None = None,
) -> dict:
    return {
        "scope_guard_rule": {
            "asset": asset,
            "scope_status": "in_scope",
            "automation": "limited",
            "allowed_validation": allowed_validation
            if allowed_validation is not None
            else ["two_account_authorization_check"],
            "forbidden": [],
            "human_approval_required": True,
        }
    }


def test_campaign_api_derives_scope_from_policy_and_persists_parsed_rule():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        response = client.post(
            "/mythos/campaigns",
            json={
                "program_id": "program_example",
                "name": "Caller supplied scope must not grant authority",
                "autonomy_level": "level_0_read_only",
                "scope_status": "in_scope",
                "policy_text": "api.example.com is out of scope. No automation.",
                "default_asset": "api.example.com",
                "allowed_tools": ["two_account_authorization_check"],
            },
        )

        assert response.status_code == 200
        assert response.json()["scope_status"] == "out_of_scope"

        with testing_session() as session:
            campaign = DatabaseRepository(session).get_campaign(response.json()["id"])
            assert campaign is not None
            assert campaign.payload["scope_guard_rule"] == {
                "asset": "api.example.com",
                "scope_status": "out_of_scope",
                "automation": "none",
                "allowed_validation": [],
                "forbidden": [],
                "human_approval_required": True,
            }
            assert "policy_text" not in campaign.payload
    finally:
        app.dependency_overrides.clear()


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
                "policy_text": "api.example.com is in scope. No automation. Authorization: Bearer secret-token",
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
                "policy_text": "api.example.com is in scope. No automation. Authorization: Bearer secret-token",
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


def test_campaign_launch_with_authorized_code_auto_materializes_hunt_queue(monkeypatch):
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    def inline_dispatcher(*, campaign_task_id: str):
        with testing_session() as session:
            return run_agent_task(
                campaign_task_id,
                repository=DatabaseRepository(session),
            )

    monkeypatch.setattr(main_module, "dispatch_agent_task", inline_dispatcher)
    app.dependency_overrides[get_session] = override_get_session
    try:
        create_response = client.post(
            "/mythos/campaigns",
            json={
                "program_id": "program_example",
                "name": "Authorized code-backed candidate hunt",
                "autonomy_level": "level_0_read_only",
                "scope_status": "in_scope",
                "policy_text": "authorized/service is in scope. No automation. Authorization: Bearer secret-token",
                "default_asset": "authorized/service",
                "target_classes": ["idor"],
                "allowed_tools": ["static_analyzer"],
                "created_by": "operator",
                "authorized_code_files": [
                    {
                        "path": "apps/api/routes/files.py",
                        "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    return send_file(file_id)
""",
                    }
                ],
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
        control_response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")
        maps_response = client.get(f"/mythos/campaigns/{campaign_id}/codebase-map")

        assert tasks_response.status_code == 200
        assert control_response.status_code == 200
        assert maps_response.status_code == 200

        tasks = tasks_response.json()
        assert {task["task_type"]: task["status"] for task in tasks} == {
            "report_chain_review": "completed",
            "hypothesis_generation": "completed",
            "attack_surface_mapping": "completed",
            "campaign_observation": "completed",
        }

        codebase_map = maps_response.json()
        assert codebase_map["maps"][0]["status"] == "mapped"
        assert any(
            fact["fact_type"] == "authorization_gap_candidate"
            and fact["route_path"] == "/files/{file_id}/export"
            for fact in codebase_map["facts"]
        )

        control_center = control_response.json()
        hunt_suggestions = [
            suggestion
            for suggestion in control_center["research_queue_suggestions"]
            if suggestion["source"] == "mythos_pipeline_autonomous_hunt_queue"
        ]
        assert len(hunt_suggestions) == 1
        suggestion = hunt_suggestions[0]
        assert suggestion["title"] == "Review autonomous hunt candidate codebase_fact_hypothesis_1"
        assert suggestion["playbook_id"] == "bola_idor"
        assert suggestion["candidate_status"] == "awaiting_human_approval"
        assert suggestion["human_approval_required"] is True
        assert suggestion["execution_allowed"] is False
        assert suggestion["safety_gate"] == "awaiting_evidence_review"
        assert suggestion["blocked_action_count"] == 4
        assert suggestion["priority_score"] < suggestion["raw_priority_score"]
        assert suggestion["required_evidence"] == ["independent_refutation_or_static_rule"]
        assert suggestion["quality_gate_reasons"] == ["required_evidence_missing"]
        assert "secret-token" not in str(control_center)
        assert "Authorization" not in str(control_center)
    finally:
        app.dependency_overrides.clear()


def test_campaign_launch_with_authorized_api_artifact_auto_materializes_gated_hunt_queue(
    monkeypatch,
):
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    def inline_dispatcher(*, campaign_task_id: str):
        with testing_session() as session:
            return run_agent_task(
                campaign_task_id,
                repository=DatabaseRepository(session),
            )

    monkeypatch.setattr(main_module, "dispatch_agent_task", inline_dispatcher)
    app.dependency_overrides[get_session] = override_get_session
    try:
        create_response = client.post(
            "/mythos/campaigns",
            json={
                "program_id": "program_example",
                "name": "Authorized API-backed candidate hunt",
                "autonomy_level": "level_0_read_only",
                "scope_status": "in_scope",
                "policy_text": "authorized/service is in scope. No automation. Authorization: Bearer secret-token",
                "default_asset": "authorized/service",
                "target_classes": ["idor"],
                "allowed_tools": ["static_analyzer"],
                "created_by": "operator",
                "authorized_api_artifacts": [
                    {
                        "kind": "openapi",
                        "source_name": "openapi.json",
                        "payload": {
                            "paths": {
                                "/teams/{team_id}/invite": {
                                    "post": {"operationId": "inviteTeamMember"}
                                }
                            }
                        },
                    }
                ],
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
        maps_response = client.get(f"/mythos/campaigns/{campaign_id}/codebase-map")
        control_response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert maps_response.status_code == 200
        assert control_response.status_code == 200

        codebase_map = maps_response.json()
        assert codebase_map["maps"][0]["route_count"] == 1
        assert codebase_map["facts"][0]["source_path"] == "openapi.json"
        assert codebase_map["facts"][0]["route_method"] == "POST"
        assert codebase_map["facts"][0]["route_path"] == "/teams/{team_id}/invite"

        control_center = control_response.json()
        hunt_suggestion = next(
            suggestion
            for suggestion in control_center["research_queue_suggestions"]
            if suggestion["source"] == "mythos_pipeline_autonomous_hunt_queue"
        )
        assert hunt_suggestion["playbook_id"] == "role_boundary"
        assert hunt_suggestion["safety_gate"] == "awaiting_evidence_review"
        assert hunt_suggestion["next_allowed_action"] == "Review validation plan before any execution."
        assert hunt_suggestion["execution_allowed"] is False
        assert hunt_suggestion["required_evidence"] == ["local_code_or_har_correlation"]
        assert hunt_suggestion["quality_gate_reasons"] == ["required_evidence_missing"]
        assert hunt_suggestion["priority_score"] < hunt_suggestion["raw_priority_score"]
        assert "secret-token" not in str(control_center)
        assert "Authorization" not in str(control_center)
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_reports_tool_call_budget_usage_after_partial_dispatch(monkeypatch):
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
                "name": "Partial dispatch budget campaign",
                "autonomy_level": "level_0_read_only",
                "scope_status": "in_scope",
                "policy_text": "api.example.com is in scope. No automation.",
                "default_asset": "api.example.com",
                "created_by": "operator",
                "budget": {
                    "time_budget_minutes": 30,
                    "token_budget": 1000,
                    "tool_call_budget": 2,
                    "validation_budget": 1,
                },
            },
        )
        assert create_response.status_code == 200
        campaign_id = create_response.json()["id"]

        start_response = client.post(f"/mythos/campaigns/{campaign_id}/start")
        control_response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert start_response.status_code == 200
        assert control_response.status_code == 200
        control_center = control_response.json()
        assert len(dispatched_task_ids) == 2
        assert control_center["budget"]["tool_call_budget"] == 2
        assert control_center["budget"]["tool_call_used"] == 2
        assert control_center["budget"]["tool_call_remaining"] == 0
        assert control_center["blocked_reasons"] == ["budget_exhausted"]
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_blocks_when_tool_call_budget_is_consumed_without_tick_stage():
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
                name="Consumed tool-call budget campaign",
                autonomy_level="level_0_read_only",
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
                tool_call_budget=1,
                validation_budget=1,
            )
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="campaign_observation",
                agent_type="orchestrator_agent",
                title="Observe campaign",
                input_refs=[f"campaign:{campaign.id}"],
                payload={},
            )
            repository.save_agent_run(
                campaign_id=campaign.id,
                task_id=task.id,
                agent_type=task.agent_type,
                status="completed",
                input_refs=[f"campaign_task:{task.id}"],
                output_refs=[],
                tool_calls=[],
                safety_gate_state="allowed",
                stop_reason=None,
                payload={"raw_payload_processed": False},
            )
            campaign_id = campaign.id

        control_response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert control_response.status_code == 200
        control_center = control_response.json()
        assert control_center["budget"]["tool_call_budget"] == 1
        assert control_center["budget"]["tool_call_used"] == 1
        assert control_center["budget"]["tool_call_remaining"] == 0
        assert "budget_exhausted" in control_center["blocked_reasons"]
        assert control_center["safe_next_action"] == "resolve_blockers"
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
                "policy_text": "api.example.com is out of scope. No automation.",
                "default_asset": "api.example.com",
                "created_by": "operator",
            },
        )
        assert create_response.status_code == 200
        campaign_id = create_response.json()["id"]

        start_response = client.post(f"/mythos/campaigns/{campaign_id}/start")

        assert start_response.status_code == 409
        assert start_response.json()["detail"] == "scope_not_in_scope"
        assert client.get(f"/mythos/campaigns/{campaign_id}/tasks").json() == []
        stages = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages").json()
        assert stages == []
    finally:
        app.dependency_overrides.clear()


def test_campaign_api_resume_blocks_out_of_scope_without_running_window():
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
                name="Out of scope resume",
                autonomy_level="level_0_read_only",
                scope_status="out_of_scope",
                policy_text="Testing is not allowed",
                default_asset="api.example.com",
                created_by="operator",
            )
            repository.update_campaign_status(campaign.id, "paused")
            campaign_id = campaign.id

        response = client.post(f"/mythos/campaigns/{campaign_id}/resume")

        assert response.status_code == 409
        assert response.json()["detail"] == "scope_not_in_scope"
        campaign_response = client.get(f"/mythos/campaigns/{campaign_id}")
        assert campaign_response.status_code == 200
        assert campaign_response.json()["status"] == "paused"
        assert client.get(f"/mythos/campaigns/{campaign_id}/tasks").json() == []
    finally:
        app.dependency_overrides.clear()


def test_campaign_api_resume_blocks_budget_exhausted_without_running_window():
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
                name="Budget exhausted resume",
                autonomy_level="level_0_read_only",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                created_by="operator",
            )
            repository.update_campaign_status(campaign.id, "paused")
            repository.upsert_campaign_budget(
                campaign_id=campaign.id,
                time_budget_minutes=30,
                token_budget=1000,
                tool_call_budget=10,
                validation_budget=0,
            )
            campaign_id = campaign.id

        response = client.post(f"/mythos/campaigns/{campaign_id}/resume")

        assert response.status_code == 409
        assert response.json()["detail"] == "budget_exhausted"
        campaign_response = client.get(f"/mythos/campaigns/{campaign_id}")
        assert campaign_response.status_code == 200
        assert campaign_response.json()["status"] == "paused"
        assert client.get(f"/mythos/campaigns/{campaign_id}/tasks").json() == []
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


def test_campaign_api_completes_cycle_review_without_dispatch_or_payload_leaks():
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
                name="Complete cycle review campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed. Authorization: Bearer secret-token",
                default_asset="api.example.com",
                created_by="operator",
            )
            repository.update_campaign_status(campaign.id, "running")
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="hypothesis_generation",
                agent_type="hypothesis_agent",
                title="Generate hypotheses",
                input_refs=[f"campaign:{campaign.id}"],
                payload={},
            )
            review_stage = repository.save_pipeline_stage(
                pipeline_run_id=None,
                campaign_id=campaign.id,
                task_id=None,
                stage_key="campaign_cycle_review",
                stage_order=4,
                status="awaiting_review",
                input_refs=[f"campaign:{campaign.id}"],
                output_refs=[
                    f"campaign_task:{task.id}",
                    "pipeline_run:run_with_token=secret",
                ],
                safety_gate_state="allowed",
                stop_reason="campaign_cycle_review_required",
                payload={
                    "review_gate": "human_review_required",
                    "notes": "Authorization: Bearer secret-token",
                },
            )
            campaign_id = campaign.id
            task_id = task.id
            review_stage_id = review_stage.id

        response = client.post(
            f"/mythos/campaigns/{campaign_id}/cycle-reviews/{review_stage_id}/complete",
            json={
                "actor": "lead_reviewer",
                "reason": "Reviewed sanitized state; Authorization: Bearer secret-token",
            },
        )

        assert response.status_code == 200
        completed = response.json()
        assert completed["stage_key"] == "campaign_cycle_review"
        assert completed["status"] == "completed"
        assert completed["safety_gate_state"] == "allowed"
        assert completed["input_refs"] == [f"campaign:{campaign_id}"]
        assert completed["output_refs"] == [
            f"campaign_task:{task_id}",
            "[REDACTED]",
        ]
        assert "secret-token" not in str(completed)
        assert "Authorization" not in str(completed)

        tasks_response = client.get(f"/mythos/campaigns/{campaign_id}/tasks")
        assert tasks_response.status_code == 200
        assert len(tasks_response.json()) == 1

        control_response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")
        assert control_response.status_code == 200
        control_center = control_response.json()
        assert control_center["safe_next_action"] != "complete_cycle_review"
        assert "secret-token" not in str(control_center)
        assert "Authorization" not in str(control_center)

        replay_response = client.post(
            f"/mythos/campaigns/{campaign_id}/cycle-reviews/{review_stage_id}/complete",
            json={
                "actor": "lead_reviewer",
                "reason": "Second click; Authorization: Bearer secret-token",
            },
        )
        assert replay_response.status_code == 409
        assert "secret-token" not in replay_response.text
        assert "Authorization" not in replay_response.text

        stages_response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")
        assert stages_response.status_code == 200
        completed_reviews = [
            stage for stage in stages_response.json()
            if stage["stage_key"] == "campaign_cycle_review"
            and stage["status"] == "completed"
        ]
        assert len(completed_reviews) == 1
    finally:
        app.dependency_overrides.clear()


def test_campaign_api_rejects_cycle_review_completion_with_unresolved_gates():
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
                name="Unresolved cycle review campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed.",
                default_asset="api.example.com",
                created_by="operator",
            )
            repository.update_campaign_status(campaign.id, "running")
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="validation_planning",
                agent_type="validation_agent",
                title="Plan validation",
                input_refs=[f"campaign:{campaign.id}"],
                payload={},
            )
            approval = repository.create_approval_record(
                campaign_id=campaign.id,
                task_id=task.id,
                reason="Approval required before validation.",
                requested_action="manual validation",
                asset="api.example.com",
                validation_mode="http_probe",
                plan_digest="digest_unresolved_gate",
            )
            validation_run = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="http_probe",
                target_ref="asset:api.example.com",
                status="ready",
                safety_gate_state="awaiting_approval",
                plan_digest="digest_unresolved_gate",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Awaiting human approval.",
            )
            review_stage = repository.save_pipeline_stage(
                pipeline_run_id=None,
                campaign_id=campaign.id,
                task_id=None,
                stage_key="campaign_cycle_review",
                stage_order=4,
                status="awaiting_review",
                input_refs=[f"campaign:{campaign.id}"],
                output_refs=[
                    f"approval:{approval.id}",
                    f"validation_run:{validation_run.id}",
                ],
                safety_gate_state="awaiting_approval",
                stop_reason="validation_approval_required",
                payload={"review_gate": "human_review_required"},
            )
            campaign_id = campaign.id
            review_stage_id = review_stage.id

        response = client.post(
            f"/mythos/campaigns/{campaign_id}/cycle-reviews/{review_stage_id}/complete",
            json={
                "actor": "lead_reviewer",
                "reason": "Reviewed queue, but gates remain unresolved.",
            },
        )

        assert response.status_code == 409
        assert response.json()["detail"] == "Cycle review has unresolved gates"

        stages_response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")
        assert stages_response.status_code == 200
        completed_reviews = [
            stage for stage in stages_response.json()
            if stage["stage_key"] == "campaign_cycle_review"
            and stage["status"] == "completed"
        ]
        assert completed_reviews == []
    finally:
        app.dependency_overrides.clear()


def test_campaign_api_blocks_cycle_review_completion_when_out_of_scope():
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
                name="Out-of-scope cycle review campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="out_of_scope",
                policy_text="Testing is not currently authorized.",
                default_asset="api.example.com",
                created_by="operator",
            )
            review_stage = repository.save_pipeline_stage(
                pipeline_run_id=None,
                campaign_id=campaign.id,
                task_id=None,
                stage_key="campaign_cycle_review",
                stage_order=1,
                status="awaiting_review",
                input_refs=[f"campaign:{campaign.id}"],
                output_refs=[],
                safety_gate_state="manual_review_required",
                stop_reason="campaign_cycle_review_required",
                payload={"review_gate": "human_review_required"},
            )
            campaign_id = campaign.id
            review_stage_id = review_stage.id

        response = client.post(
            f"/mythos/campaigns/{campaign_id}/cycle-reviews/{review_stage_id}/complete",
            json={
                "actor": "lead_reviewer",
                "reason": "Scope must be restored before closing autonomous review gates.",
            },
        )

        assert response.status_code == 409
        assert response.json()["detail"] == "scope_not_in_scope"

        stages_response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")
        assert stages_response.status_code == 200
        completed_reviews = [
            stage for stage in stages_response.json()
            if stage["stage_key"] == "campaign_cycle_review"
            and stage["status"] == "completed"
        ]
        assert completed_reviews == []
    finally:
        app.dependency_overrides.clear()


def test_autonomous_priority_reason_count_counts_fixed_authz_gap_reasons():
    assert main_module._autonomous_priority_reason_count(
        [
            "authorization_gap_candidate",
            "sensitive_sink_present",
            "Authorization: Bearer secret-token",
        ],
        [
            "same_handler_authorization_evidence",
            "token=secret-token",
        ],
        [
            "sensitive_sink",
        ],
    ) == 3


def test_campaign_api_allows_cycle_review_completion_with_expired_approval_ref():
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
                name="Expired approval review completion campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed.",
                default_asset="api.example.com",
                created_by="operator",
            )
            repository.update_campaign_status(campaign.id, "running")
            approval = repository.create_approval_record(
                campaign_id=campaign.id,
                reason="Approval expired before review completion.",
                requested_action="manual validation",
                asset="api.example.com",
                validation_mode="http_probe",
                plan_digest="digest_expired_gate",
                expires_at=datetime.now(UTC) - timedelta(minutes=1),
            )
            review_stage = repository.save_pipeline_stage(
                pipeline_run_id=None,
                campaign_id=campaign.id,
                task_id=None,
                stage_key="campaign_cycle_review",
                stage_order=4,
                status="awaiting_review",
                input_refs=[f"campaign:{campaign.id}"],
                output_refs=[f"approval:{approval.id}"],
                safety_gate_state="awaiting_approval",
                stop_reason="validation_approval_required",
                payload={"review_gate": "human_review_required"},
            )
            campaign_id = campaign.id
            review_stage_id = review_stage.id

        response = client.post(
            f"/mythos/campaigns/{campaign_id}/cycle-reviews/{review_stage_id}/complete",
            json={
                "actor": "lead_reviewer",
                "reason": "Expired approval is no longer an active gate.",
            },
        )

        assert response.status_code == 200
        completed = response.json()
        assert completed["stage_key"] == "campaign_cycle_review"
        assert completed["status"] == "completed"
        assert completed["safety_gate_state"] == "allowed"
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_points_to_cycle_review_completion_gate():
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
                name="Cycle review gate campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed. Authorization: Bearer secret-token",
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
            repository.save_pipeline_stage(
                pipeline_run_id=None,
                campaign_id=campaign.id,
                task_id=None,
                stage_key="campaign_cycle_review",
                stage_order=4,
                status="awaiting_review",
                input_refs=[f"campaign:{campaign.id}"],
                output_refs=[
                    "pipeline_run:hypothesis_summary",
                    "codebase_fact:authorization_boundary",
                ],
                safety_gate_state="allowed",
                stop_reason="campaign_cycle_review_required",
                payload={
                    "review_gate": "human_review_required",
                    "notes": "Authorization: Bearer secret-token",
                },
            )
            campaign_id = campaign.id

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["safe_next_action"] == "complete_cycle_review"
        assert control_center["execution_allowed"] is False
        assert "secret-token" not in str(control_center)
        assert "Authorization" not in str(control_center)
    finally:
        app.dependency_overrides.clear()


def test_campaign_pipeline_stages_expose_report_preview_run_links_without_payload_leaks():
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
                name="Report preview link campaign",
                autonomy_level="level_0_read_only",
                scope_status="in_scope",
                policy_text="Testing allowed. Authorization: Bearer secret-token",
                default_asset="api.example.com",
                created_by="operator",
            )
            repository.update_campaign_status(campaign.id, "running")
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="hypothesis_generation",
                agent_type="hypothesis_agent",
                title="Generate hypotheses",
                payload={"cookie": "session=secret"},
            )
            run_agent_task(task.id, repository=repository)
            campaign_id = campaign.id
            pipeline_run_id = next(
                ref.removeprefix("pipeline_run:")
                for ref in repository.list_campaign_tasks(campaign.id)[0].output_refs
                if ref.startswith("pipeline_run:")
            )

        response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")

        assert response.status_code == 200
        stages = response.json()
        linked_stages = [
            stage for stage in stages
            if stage["pipeline_run_id"] == pipeline_run_id
        ]
        assert len(linked_stages) == 1
        assert linked_stages[0]["stage_key"] == "campaign_report_preview"
        assert linked_stages[0]["status"] == "awaiting_review"
        assert linked_stages[0]["safety_gate_state"] == "awaiting_review"
        assert "secret-token" not in str(stages)
        assert "session=secret" not in str(stages)
        assert "authorization" not in str(stages).lower()
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_moves_to_learning_after_finding_candidate():
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
                name="Finding candidate campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed. Authorization: Bearer secret-token",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
                payload=validation_scope_guard_payload(),
            )
            repository.update_campaign_status(campaign.id, "running")
            repository.upsert_campaign_budget(
                campaign_id=campaign.id,
                time_budget_minutes=30,
                token_budget=1000,
                tool_call_budget=10,
                validation_budget=1,
            )
            campaign_id = campaign.id

        dry_run_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert dry_run_response.status_code == 200
        run_id = dry_run_response.json()["run_id"]

        with testing_session() as session:
            repository = DatabaseRepository(session)
            repository.save_pipeline_stage(
                pipeline_run_id=run_id,
                campaign_id=campaign_id,
                task_id=None,
                stage_key="campaign_report_preview",
                stage_order=20,
                status="awaiting_review",
                input_refs=[f"campaign:{campaign_id}"],
                output_refs=[f"pipeline_run:{run_id}"],
                safety_gate_state="awaiting_review",
                stop_reason=None,
                payload={
                    "review_gate": "human_review_required",
                    "submission_allowed": False,
                    "raw_payload_processed": False,
                },
            )

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        claim_id = next(
            claim["claim_id"]
            for claim in preview_response.json()["claim_ledger"]
            if claim["claim_type"] == "observed_fact"
        )

        observation_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/manual-observations",
            json={
                "claim_id": claim_id,
                "observation_type": "request_response_diff",
                "observer": "lead_reviewer",
                "observation": "Safe test-account diff showed an authorization boundary.",
                "evidence_refs": ["sanitized_request_response"],
                "safety_notes": ["test_accounts_only", "no_real_user_data"],
            },
        )
        assert observation_response.status_code == 200

        decision_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/claim-review-decisions",
            json={
                "claim_id": claim_id,
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Confirmed with sanitized fixture.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )
        assert decision_response.status_code == 200

        candidate_response = client.post(f"/mythos/pipeline/runs/{run_id}/finding-candidates")
        assert candidate_response.status_code == 200
        candidate = candidate_response.json()
        assert candidate["submission_recommendation"] == "promote_to_finding_candidate"

        promotion_stages_response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")
        assert promotion_stages_response.status_code == 200
        promotion_stages = [
            stage for stage in promotion_stages_response.json()
            if stage["stage_key"] == "finding_promotion"
        ]
        assert len(promotion_stages) == 1
        assert promotion_stages[0]["pipeline_run_id"] == run_id
        assert promotion_stages[0]["status"] == "candidate_created"
        assert promotion_stages[0]["safety_gate_state"] == "manual_review_required"
        assert promotion_stages[0]["output_refs"] == [f"finding_candidate:{candidate['id']}"]
        assert promotion_stages[0]["payload"] == {
            "claim_provenance_ref_count": 5,
            "candidate_ref_count": 1,
            "finding_promotion_allowed": False,
            "report_submission_allowed": False,
            "review_evidence_ref_count": 1,
        }
        assert "claim_provenance_refs" not in str(promotion_stages)
        assert "candidate_refs" not in str(promotion_stages)
        assert "review_evidence_refs" not in str(promotion_stages)
        with testing_session() as session:
            repository = DatabaseRepository(session)
            promotion_stage = next(
                stage for stage in repository.list_campaign_pipeline_stages(campaign_id)
                if stage.stage_key == "finding_promotion"
            )
            assert promotion_stage.payload["finding_promotion_allowed"] is False
            assert promotion_stage.payload["report_submission_allowed"] is False

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["safe_next_action"] == "record_learning_outcome"
        assert control_center["execution_allowed"] is False
        assert "report_ready" not in str(control_center)
        assert "secret-token" not in str(control_center)
        assert "SECRET POLICY" not in str(control_center)

        outcome_response = client.post(
            "/mythos/brain/outcomes",
            json={
                "run_id": run_id,
                "outcome": "accepted",
                "notes": "Accepted safe fixture; Authorization: Bearer secret-token",
                "evidence_quality": "strong",
            },
        )
        assert outcome_response.status_code == 200
        signal_id = outcome_response.json()["recent_learning_signals"][0]["id"]

        stages_response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")
        assert stages_response.status_code == 200
        learning_stages = [
            stage for stage in stages_response.json()
            if stage["stage_key"] == "learning_outcome_recorded"
        ]
        assert len(learning_stages) == 1
        assert learning_stages[0]["status"] == "recorded"
        assert learning_stages[0]["safety_gate_state"] == "advisory_memory_only"
        assert learning_stages[0]["input_refs"] == [f"pipeline_run:{run_id}"]
        assert learning_stages[0]["output_refs"] == [f"learning_signal:{signal_id}"]
        assert "Accepted safe fixture" not in str(learning_stages)
        assert "secret-token" not in str(learning_stages)

        review_response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert review_response.status_code == 200
        review_control_center = review_response.json()
        assert review_control_center["safe_next_action"] == "review_learning_outcome"
        assert review_control_center["execution_allowed"] is False
        reasoning_suggestion = next(
            suggestion
            for suggestion in review_control_center["research_queue_suggestions"]
            if suggestion["queue_key"] == "reasoning_memory:bola_idor"
        )
        assert {
            "queue_key": "reasoning_memory:bola_idor",
            "title": "Review bola_idor reasoning memory",
            "source": "mythos_brain_reasoning_memory",
            "playbook_id": "bola_idor",
            "surface_key": "file_id:export",
            "priority_score": 69,
            "safety_gate": "advisory_memory_only",
            "next_allowed_action": "Review hypothesis board and plan non-destructive evidence work.",
            "execution_allowed": False,
        }.items() <= reasoning_suggestion.items()
        assert all(
            suggestion["execution_allowed"] is False
            for suggestion in review_control_center["research_queue_suggestions"]
        )
        assert "Accepted safe fixture" not in str(review_control_center)
        assert "secret-token" not in str(review_control_center)
        assert "Authorization" not in str(review_control_center)
        assert "execution_allowed: True" not in str(review_control_center)

        with testing_session() as session:
            repository = DatabaseRepository(session)
            repository.upsert_campaign_budget(
                campaign_id=campaign_id,
                time_budget_minutes=0,
                token_budget=1000,
                tool_call_budget=10,
                validation_budget=1,
            )
        budget_block_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks",
            json={
                "queue_key": "reasoning_memory:bola_idor",
                "requester": "lead_reviewer",
                "reason": "Budget gate should stop new research work.",
            },
        )
        assert budget_block_response.status_code == 409
        assert budget_block_response.json()["detail"] == "budget_exhausted"

        with testing_session() as session:
            repository = DatabaseRepository(session)
            repository.upsert_campaign_budget(
                campaign_id=campaign_id,
                time_budget_minutes=30,
                token_budget=1000,
                tool_call_budget=10,
                validation_budget=1,
            )

        materialize_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks",
            json={
                "queue_key": "reasoning_memory:bola_idor",
                "requester": "lead_reviewer",
                "reason": "Plan only non-destructive evidence work.",
            },
        )
        assert materialize_response.status_code == 200
        task = materialize_response.json()
        assert task["task_type"] == "research_queue_review"
        assert task["agent_type"] == "human_research_reviewer"
        assert task["title"] == "Review bola_idor reasoning memory"
        assert task["status"] == "queued_review"
        assert task["input_refs"] == [
            f"campaign:{campaign_id}",
            "research_queue:reasoning_memory:bola_idor",
            "playbook:bola_idor",
            "surface:file_id:export",
        ]
        assert task["output_refs"] == []
        assert "Accepted safe fixture" not in str(task)
        assert "secret-token" not in str(task)
        assert "Authorization" not in str(task)

        duplicate_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks",
            json={
                "queue_key": "reasoning_memory:bola_idor",
                "requester": "lead_reviewer",
                "reason": "Retry should not create another task.",
            },
        )
        assert duplicate_response.status_code == 200
        assert duplicate_response.json()["id"] == task["id"]

        tasks_response = client.get(f"/mythos/campaigns/{campaign_id}/tasks")
        assert tasks_response.status_code == 200
        research_tasks = [
            record for record in tasks_response.json()
            if record["task_type"] == "research_queue_review"
        ]
        assert len(research_tasks) == 1

        review_workspace_response = client.get(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review"
        )
        assert review_workspace_response.status_code == 200
        review_workspace = review_workspace_response.json()
        assert review_workspace == {
            "task_id": task["id"],
            "campaign_id": campaign_id,
            "queue_key": "reasoning_memory:bola_idor",
            "title": "Review bola_idor reasoning memory",
            "status": "queued_review",
            "source": "mythos_brain_reasoning_memory",
            "playbook_id": "bola_idor",
            "surface_key": "file_id:export",
            "priority_score": 69,
            "safety_gate": "advisory_memory_only",
            "next_allowed_action": "Review hypothesis board and plan non-destructive evidence work.",
            "non_destructive_plan": [
                "Review existing hypothesis board entries for this playbook and surface.",
                "Collect only redacted artifact summaries and provenance counts.",
                "Draft refutation questions before any validation request.",
                "Prepare a human-approved validation plan without executing it.",
            ],
            "required_human_gates": [
                "scope_guard_review",
                "redaction_review",
                "approval_required_before_validation",
            ],
            "execution_allowed": False,
            "dispatch_allowed": False,
            "report_submission_allowed": False,
            "latest_review_plan": None,
            "latest_refutation_decision": None,
            "latest_validation_feedback": None,
            "suggested_refutation_decision": None,
            "autonomous_candidate_context": None,
        }
        assert "Accepted safe fixture" not in str(review_workspace)
        assert "secret-token" not in str(review_workspace)
        assert "Authorization" not in str(review_workspace)

        review_plan_payload = {
            "reviewer": "lead_reviewer",
            "rationale": "Plan only from redacted summaries; Authorization: Bearer secret-token",
            "hypothesis": "BOLA/IDOR may affect file export authorization boundaries.",
            "refutation_questions": [
                "Is the export route reachable only through authorized test-account roles?",
                "Can existing redacted artifacts show object ownership checks?",
            ],
            "evidence_plan": [
                "Compare hypothesis board entries for file export.",
                "Collect redacted artifact summaries and provenance counts only.",
            ],
        }
        plan_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review-plans",
            json=review_plan_payload,
        )
        assert plan_response.status_code == 200
        plan = plan_response.json()
        assert plan["plan_id"].startswith("research_plan_")
        plan_id = plan["plan_id"]
        assert plan == {
            "plan_id": plan_id,
            "task_id": task["id"],
            "campaign_id": campaign_id,
            "status": "drafted",
            "hypothesis": "BOLA/IDOR may affect file export authorization boundaries.",
            "refutation_questions": [
                "Is the export route reachable only through authorized test-account roles?",
                "Can existing redacted artifacts show object ownership checks?",
            ],
            "evidence_plan": [
                "Compare hypothesis board entries for file export.",
                "Collect redacted artifact summaries and provenance counts only.",
            ],
            "required_human_gates": [
                "scope_guard_review",
                "redaction_review",
                "approval_required_before_validation",
            ],
            "safety_gate": "advisory_plan_only",
            "next_allowed_action": "Review hypothesis board and request approval before validation.",
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        }
        assert "Authorization" not in str(plan)
        assert "secret-token" not in str(plan)

        stages_response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")
        assert stages_response.status_code == 200
        plan_stages = [
            stage for stage in stages_response.json()
            if stage["stage_key"] == "research_task_review_plan"
        ]
        assert len(plan_stages) == 1
        assert plan_stages[0]["status"] == "drafted"
        assert plan_stages[0]["task_id"] == task["id"]
        assert plan_stages[0]["input_refs"] == [
            f"campaign:{campaign_id}",
            f"campaign_task:{task['id']}",
            "research_queue:reasoning_memory:bola_idor",
        ]
        assert plan_stages[0]["output_refs"] == [f"research_plan:{plan_id}"]
        assert plan_stages[0]["safety_gate_state"] == "advisory_plan_only"
        assert "Authorization" not in str(plan_stages)
        assert "secret-token" not in str(plan_stages)

        repeated_plan_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review-plans",
            json=review_plan_payload,
        )
        assert repeated_plan_response.status_code == 200
        assert repeated_plan_response.json() == plan

        repeated_plan_stages_response = client.get(
            f"/mythos/campaigns/{campaign_id}/pipeline-stages"
        )
        assert repeated_plan_stages_response.status_code == 200
        repeated_plan_stages = [
            stage for stage in repeated_plan_stages_response.json()
            if stage["stage_key"] == "research_task_review_plan"
        ]
        assert len(repeated_plan_stages) == 1

        updated_review_response = client.get(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review"
        )
        assert updated_review_response.status_code == 200
        assert updated_review_response.json()["latest_review_plan"] == plan

        plan_control_center_response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")
        assert plan_control_center_response.status_code == 200
        assert plan_control_center_response.json()["research_review_plans"] == [plan]
        assert "Authorization" not in str(plan_control_center_response.json()["research_review_plans"])
        assert "secret-token" not in str(plan_control_center_response.json()["research_review_plans"])

        updated_plan_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review-plans",
            json={
                "reviewer": "lead_reviewer",
                "rationale": "Refined plan from redacted summaries only; Authorization: Bearer secret-token",
                "hypothesis": "Updated BOLA/IDOR hypothesis for export ownership checks.",
                "refutation_questions": [
                    "Can current artifact summaries refute missing ownership checks?",
                ],
                "evidence_plan": [
                    "Compare redacted route summaries with object ownership invariants.",
                ],
            },
        )
        assert updated_plan_response.status_code == 200
        updated_plan = updated_plan_response.json()

        latest_review_response = client.get(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review"
        )
        assert latest_review_response.status_code == 200
        assert latest_review_response.json()["latest_review_plan"] == updated_plan
        assert latest_review_response.json()["latest_refutation_decision"] is None

        latest_control_center_response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")
        assert latest_control_center_response.status_code == 200
        assert latest_control_center_response.json()["research_review_plans"] == [updated_plan]
        assert "Authorization" not in str(latest_control_center_response.json()["research_review_plans"])
        assert "secret-token" not in str(latest_control_center_response.json()["research_review_plans"])

        needs_evidence_payload = {
            "plan_id": updated_plan["plan_id"],
            "reviewer": "lead_reviewer",
            "decision": "needs_evidence",
            "rationale": "Need redacted proof before validation; Authorization: Bearer secret-token",
            "refutation_answers": [
                "Current summaries do not yet prove missing ownership checks.",
            ],
        }
        decision_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review-decisions",
            json=needs_evidence_payload,
        )
        assert decision_response.status_code == 200
        decision = decision_response.json()
        assert decision["decision_id"].startswith("refutation_decision_")
        assert decision.get("validation_run_id") is None
        assert {
            key: value
            for key, value in decision.items()
            if key != "validation_run_id"
        } == {
            "decision_id": decision["decision_id"],
            "task_id": task["id"],
            "campaign_id": campaign_id,
            "plan_id": updated_plan["plan_id"],
            "decision": "needs_evidence",
            "rationale": "[REDACTED]",
            "refutation_answers": [
                "Current summaries do not yet prove missing ownership checks.",
            ],
            "next_allowed_action": "Collect redacted evidence or refine the hypothesis before validation.",
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        }
        assert "Authorization: Bearer" not in str(decision)
        assert "secret-token" not in str(decision)

        decision_stages_response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")
        assert decision_stages_response.status_code == 200
        decision_stages = [
            stage for stage in decision_stages_response.json()
            if stage["stage_key"] == "research_task_refutation_decision"
        ]
        assert len(decision_stages) == 1
        assert decision_stages[0]["status"] == "needs_evidence"
        assert decision_stages[0]["task_id"] == task["id"]
        assert decision_stages[0]["input_refs"] == [
            f"campaign:{campaign_id}",
            f"campaign_task:{task['id']}",
            f"research_plan:{updated_plan['plan_id']}",
        ]
        assert decision_stages[0]["output_refs"] == [f"refutation_decision:{decision['decision_id']}"]
        assert decision_stages[0]["safety_gate_state"] == "advisory_refutation_only"

        decided_review_response = client.get(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review"
        )
        assert decided_review_response.status_code == 200
        assert decided_review_response.json()["latest_review_plan"] == updated_plan
        assert decided_review_response.json()["latest_refutation_decision"] == decision
        assert "Authorization: Bearer" not in str(decided_review_response.json())
        assert "secret-token" not in str(decided_review_response.json())

        evidence_control_center_response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")
        assert evidence_control_center_response.status_code == 200
        assert evidence_control_center_response.json()["validation_runs"] == []

        validation_decision_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review-decisions",
            json={
                "plan_id": updated_plan["plan_id"],
                "reviewer": "lead_reviewer",
                "decision": "needs_validation_review",
                "rationale": "Ready for human-approved validation; Authorization: Bearer secret-token",
                "refutation_answers": [
                    "Refutation did not disprove missing ownership checks.",
                ],
                "validation_mode": "two_account_authorization_check",
                "target_ref": f"campaign:{campaign_id}",
            },
        )
        assert validation_decision_response.status_code == 200
        validation_decision = validation_decision_response.json()
        assert validation_decision["decision"] == "needs_validation_review"
        assert validation_decision["validation_run_id"].startswith("validation_run_")
        assert validation_decision["approval_id"].startswith("approval_")
        assert validation_decision["validation_allowed"] is False
        assert validation_decision["execution_allowed"] is False

        validation_control_center_response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")
        assert validation_control_center_response.status_code == 200
        validation_control_center = validation_control_center_response.json()
        assert validation_control_center["safe_next_action"] == "review_approval_queue"
        assert len(validation_control_center["approvals"]) == 1
        approval = validation_control_center["approvals"][0]
        assert approval["id"] == validation_decision["approval_id"]
        assert approval["campaign_id"] == campaign_id
        assert approval["task_id"] == task["id"]
        assert approval["approval_type"] == "validation_batch"
        assert approval["status"] == "pending"
        assert approval["requested_action"] == "validation_preflight_review"
        assert approval["asset"] == "api.example.com"
        assert approval["validation_mode"] == "two_account_authorization_check"
        assert approval["plan_digest"] == f"research_plan:{updated_plan['plan_id']}"
        assert approval["safety_gate_state"] == "awaiting_approval"
        assert "Authorization" not in str(validation_control_center["approvals"])
        assert "secret-token" not in str(validation_control_center["approvals"])
        assert len(validation_control_center["validation_runs"]) == 1
        validation_run = validation_control_center["validation_runs"][0]
        assert validation_run["id"] == validation_decision["validation_run_id"]
        assert validation_run["task_id"] == task["id"]
        assert validation_run["approval_id"] == validation_decision["approval_id"]
        assert validation_run["approval_required"] is True
        assert validation_run["allowed_to_execute"] is False
        assert validation_run["preflight_passed"] is False
        assert validation_run["status"] == "awaiting_approval"
        assert validation_run["safety_gate_state"] == "awaiting_approval"
        assert validation_run["validation_mode"] == "two_account_authorization_check"
        assert validation_run["target_ref"] == f"campaign:{campaign_id}"
        assert validation_run["plan_digest"] == f"research_plan:{updated_plan['plan_id']}"
        assert "Authorization" not in str(validation_control_center["validation_runs"])
        assert "secret-token" not in str(validation_control_center["validation_runs"])

        stale_needs_evidence_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review-decisions",
            json=needs_evidence_payload,
        )
        assert stale_needs_evidence_response.status_code == 409
        assert stale_needs_evidence_response.json()["detail"] == "research_decision_not_current"

        stale_review_response = client.get(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review"
        )
        assert stale_review_response.status_code == 200
        assert stale_review_response.json()["latest_refutation_decision"] == validation_decision

        stale_stages_response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")
        assert stale_stages_response.status_code == 200
        stale_decision_stages = [
            stage for stage in stale_stages_response.json()
            if stage["stage_key"] == "research_task_refutation_decision"
        ]
        assert len(stale_decision_stages) == 2

        stale_control_center_response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")
        assert stale_control_center_response.status_code == 200
        stale_control_center = stale_control_center_response.json()
        assert len(stale_control_center["approvals"]) == 1
        assert stale_control_center["approvals"][0]["id"] == validation_decision["approval_id"]
        assert len(stale_control_center["validation_runs"]) == 1
        assert (
            stale_control_center["validation_runs"][0]["id"]
            == validation_decision["validation_run_id"]
        )

        approval_response = client.post(
            f"/mythos/approvals/{validation_decision['approval_id']}/decisions",
            json={
                "decision": "approved",
                "actor": "lead_reviewer",
                "reason": "Approved for test accounts and preflight only.",
            },
        )
        assert approval_response.status_code == 200
        preflight_response = client.post(
            f"/mythos/validation-runs/{validation_decision['validation_run_id']}/preflight"
        )
        assert preflight_response.status_code == 200
        assert preflight_response.json()["decision"]["allowed"] is True

        manual_result_response = client.post(
            f"/mythos/validation-runs/{validation_decision['validation_run_id']}/manual-results",
            json={
                "outcome": "observed",
                "reviewer": "lead_reviewer",
                "summary": "Observed with test accounts only; Authorization: Bearer secret-token",
                "evidence_refs": ["sanitized_request_response"],
            },
        )
        assert manual_result_response.status_code == 200
        manual_result = manual_result_response.json()
        assert manual_result["status"] == "evidence_recorded"
        assert manual_result["allowed_to_execute"] is False

        feedback_stages_response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")
        assert feedback_stages_response.status_code == 200
        feedback_stages = [
            stage for stage in feedback_stages_response.json()
            if stage["stage_key"] == "research_task_validation_feedback"
        ]
        assert len(feedback_stages) == 1
        feedback_stage = feedback_stages[0]
        assert feedback_stage["status"] == "evidence_recorded"
        assert feedback_stage["task_id"] == task["id"]
        assert feedback_stage["input_refs"] == [
            f"campaign:{campaign_id}",
            f"campaign_task:{task['id']}",
            f"research_plan:{updated_plan['plan_id']}",
            f"refutation_decision:{validation_decision['decision_id']}",
            f"approval:{validation_decision['approval_id']}",
            f"validation_run:{validation_decision['validation_run_id']}",
        ]
        assert feedback_stage["output_refs"] == [
            f"validation_run:{validation_decision['validation_run_id']}",
        ]
        assert feedback_stage["safety_gate_state"] == "advisory_validation_feedback_only"
        assert "Authorization" not in str(feedback_stages)
        assert "secret-token" not in str(feedback_stages)

        feedback_review_response = client.get(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review"
        )
        assert feedback_review_response.status_code == 200
        feedback_review = feedback_review_response.json()
        assert feedback_review["latest_validation_feedback"] == {
            "campaign_id": campaign_id,
            "task_id": task["id"],
            "plan_id": updated_plan["plan_id"],
            "decision_id": validation_decision["decision_id"],
            "approval_id": validation_decision["approval_id"],
            "validation_run_id": validation_decision["validation_run_id"],
            "feedback_stage_id": feedback_stage["id"],
            "status": "evidence_recorded",
            "outcome": "observed",
            "evidence_ref_count": 1,
            "safety_gate": "advisory_validation_feedback_only",
            "next_allowed_action": "Review validation evidence before finding promotion.",
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "finding_confirmation_allowed": False,
            "report_submission_allowed": False,
            "promotion_gate": {
                "status": "manual_review_required",
                "reason": "research_validation_feedback_is_advisory",
                "provenance_refs": [
                    f"campaign:{campaign_id}",
                    f"campaign_task:{task['id']}",
                    f"research_plan:{updated_plan['plan_id']}",
                    f"refutation_decision:{validation_decision['decision_id']}",
                    f"approval:{validation_decision['approval_id']}",
                    f"validation_run:{validation_decision['validation_run_id']}",
                ],
                "evidence_ref_count": 1,
                "finding_promotion_allowed": False,
                "report_submission_allowed": False,
                "next_allowed_action": "Review validation evidence before finding promotion.",
            },
        }
        assert "Authorization" not in str(feedback_review)
        assert "secret-token" not in str(feedback_review)

        feedback_allow_response = client.post(
            f"/mythos/campaigns/{campaign_id}/pipeline-stages/{feedback_stage['id']}/validation-feedback-review",
            json={
                "reviewer": "lead_reviewer",
                "decision": "allow_finding_promotion",
                "rationale": "Safe validation evidence reviewed. Authorization: Bearer secret-token",
            },
        )
        assert feedback_allow_response.status_code == 200

        reviewed_feedback_response = client.get(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review"
        )
        assert reviewed_feedback_response.status_code == 200
        reviewed_feedback = reviewed_feedback_response.json()["latest_validation_feedback"]
        assert reviewed_feedback["feedback_stage_id"] == feedback_stage["id"]
        assert reviewed_feedback["finding_confirmation_allowed"] is True
        assert reviewed_feedback["execution_allowed"] is False
        assert reviewed_feedback["dispatch_allowed"] is False
        assert reviewed_feedback["validation_allowed"] is False
        assert reviewed_feedback["report_submission_allowed"] is False
        assert reviewed_feedback["promotion_gate"] == {
            "status": "manual_review_completed",
            "reason": "validation_feedback_review_allowed_finding_promotion",
            "provenance_refs": [
                f"campaign:{campaign_id}",
                f"campaign_task:{task['id']}",
                f"research_plan:{updated_plan['plan_id']}",
                f"refutation_decision:{validation_decision['decision_id']}",
                f"approval:{validation_decision['approval_id']}",
                f"validation_run:{validation_decision['validation_run_id']}",
            ],
            "evidence_ref_count": 1,
            "finding_promotion_allowed": True,
            "report_submission_allowed": False,
            "next_allowed_action": "Promote to finding candidate only after explicit human action.",
        }
        assert "Authorization" not in str(reviewed_feedback_response.json())
        assert "secret-token" not in str(reviewed_feedback_response.json())

    finally:
        app.dependency_overrides.clear()


def test_learning_outcome_blocks_for_out_of_scope_campaign_linked_run():
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
                name="Out of scope learning campaign",
                autonomy_level="level_1_suggest_only",
                scope_status="in_scope",
                policy_text="Testing allowed. Authorization: Bearer secret-token",
                default_asset="api.example.com",
                allowed_tools=[],
                created_by="operator",
            )
            campaign_id = campaign.id

        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        with testing_session() as session:
            repository = DatabaseRepository(session)
            repository.save_pipeline_stage(
                pipeline_run_id=run_id,
                campaign_id=campaign_id,
                task_id=None,
                stage_key="campaign_report_preview",
                stage_order=1,
                status="awaiting_review",
                input_refs=[f"campaign:{campaign_id}"],
                output_refs=[f"pipeline_run:{run_id}"],
                safety_gate_state="awaiting_review",
                stop_reason=None,
                payload={"submission_allowed": False, "raw_payload_processed": False},
            )

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        claim_id = next(
            claim["claim_id"]
            for claim in preview_response.json()["claim_ledger"]
            if claim["claim_type"] == "observed_fact"
        )

        observation_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/manual-observations",
            json={
                "claim_id": claim_id,
                "observation_type": "request_response_diff",
                "observer": "lead_reviewer",
                "observation": "Safe test-account diff showed an authorization boundary.",
                "evidence_refs": ["sanitized_request_response"],
                "safety_notes": ["test_accounts_only", "no_real_user_data"],
            },
        )
        assert observation_response.status_code == 200

        decision_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/claim-review-decisions",
            json={
                "claim_id": claim_id,
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Confirmed with sanitized fixture.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )
        assert decision_response.status_code == 200

        candidate_response = client.post(f"/mythos/pipeline/runs/{run_id}/finding-candidates")
        assert candidate_response.status_code == 200

        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.get_campaign(campaign_id)
            campaign.scope_status = "out_of_scope"
            session.add(campaign)
            session.commit()

        outcome_response = client.post(
            "/mythos/brain/outcomes",
            json={
                "run_id": run_id,
                "outcome": "accepted",
                "notes": "Should not train memory after scope changed.",
                "evidence_quality": "strong",
            },
        )
        assert outcome_response.status_code == 409
        assert outcome_response.json()["detail"] == "scope_not_in_scope"

        with testing_session() as session:
            repository = DatabaseRepository(session)
            assert repository.list_learning_signals("program_example") == []
            learning_stages = [
                stage
                for stage in repository.list_campaign_pipeline_stages(campaign_id)
                if stage.stage_key == "learning_outcome_recorded"
            ]
            assert learning_stages == []
    finally:
        app.dependency_overrides.clear()


def test_campaign_research_queue_materializes_autonomous_hunt_candidates():
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
                name="Autonomous hunt queue campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed. Authorization: Bearer secret-token",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
                payload=validation_scope_guard_payload(),
            )
            repository.upsert_campaign_budget(
                campaign_id=campaign.id,
                time_budget_minutes=30,
                token_budget=1000,
                tool_call_budget=10,
                validation_budget=1,
            )
            campaign_id = campaign.id

        dry_run_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert dry_run_response.status_code == 200
        dry_run = dry_run_response.json()
        run_id = dry_run["run_id"]
        queue_item = dry_run["autonomous_hunt_queue"][0]
        with testing_session() as session:
            repository = DatabaseRepository(session)
            run = repository.get_pipeline_run(run_id)
            assert run is not None
            payload = dict(run.payload)
            queue = [dict(item) for item in payload["autonomous_hunt_queue"]]
            queue[0]["required_evidence"] = [
                "independent_refutation_or_static_rule",
                "policy",
            ]
            queue[0]["top_candidate_rank"] = 1
            queue[0]["evidence_trace_summary"] = {
                "trace_status": "traceable",
                "source_fact_count": 1,
                "traceable_source_fact_count": 1,
                "route_fact_count": 1,
                "artifact_kinds": ["api"],
                "source_fact_types": ["route_handler"],
                "report_submission_allowed": False,
            }
            queue[0]["report_readiness"] = {
                "status": "blocked_by_required_evidence",
                "submission_blocked": True,
                "report_submission_allowed": False,
                "required_evidence_count": 2,
                "safe_validation_step_count": len(
                    dry_run["hypothesis_assessments"][0]["validation_plan"]["steps"]
                ),
                "trace_status": "traceable",
                "next_allowed_action": "Resolve required evidence gaps before report drafting.",
            }
            queue_item["evidence_trace_summary"] = queue[0]["evidence_trace_summary"]
            queue_item["report_readiness"] = queue[0]["report_readiness"]
            payload["autonomous_hunt_queue"] = queue
            run.payload = payload
            session.add(run)
            session.commit()
        queue_item["required_evidence"] = [
            "independent_refutation_or_static_rule",
            "policy",
        ]
        queue_item["top_candidate_rank"] = 1

        control_center_response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")
        assert control_center_response.status_code == 200
        control_center = control_center_response.json()
        hunt_suggestions = [
            suggestion
            for suggestion in control_center["research_queue_suggestions"]
            if suggestion["source"] == "mythos_pipeline_autonomous_hunt_queue"
        ]
        assert len(hunt_suggestions) == 1
        suggestion = hunt_suggestions[0]
        assert suggestion["queue_key"] == f"autonomous_hunt:{run_id}:{queue_item['queue_id']}"
        assert suggestion["title"] == f"Review autonomous hunt candidate {queue_item['candidate_id']}"
        assert suggestion["playbook_id"] == queue_item["playbook_id"]
        assert suggestion["priority_score"] == queue_item["priority_score"]
        assert suggestion["top_candidate_rank"] == queue_item.get("top_candidate_rank")
        assert suggestion["safety_gate"] == "awaiting_human_approval"
        assert suggestion["next_allowed_action"] == "Review validation plan before any execution."
        assert suggestion["execution_allowed"] is False
        assert suggestion["evidence_needed"] == queue_item.get("evidence_needed", [])
        assert suggestion["evidence_trace_summary"] == queue_item["evidence_trace_summary"]
        assert suggestion["report_readiness"] == queue_item["report_readiness"]
        assert suggestion["required_evidence"] == queue_item["required_evidence"]
        matching_assessment = next(
            assessment
            for assessment in dry_run["hypothesis_assessments"]
            if assessment["candidate_id"] == queue_item["candidate_id"]
        )
        matching_hunter = matching_assessment["hunter_assessment"]
        matching_source_fact_types = [
            fact["fact_type"]
            for fact in matching_assessment["hypothesis"].get("source_facts", [])
        ]
        assert suggestion["candidate_status"] == matching_assessment["candidate_status"]
        assert suggestion["human_approval_required"] is True
        assert suggestion["refutation_question_count"] == len(
            matching_assessment["refutation"]["questions"]
        )
        assert suggestion["validation_step_count"] == len(
            matching_assessment["validation_plan"]["steps"]
        )
        assert suggestion["blocked_action_count"] == len(queue_item["blocked_actions"])
        assert matching_assessment["hypothesis"]["hypothesis"] not in str(suggestion)
        assert str(matching_assessment["refutation"]["questions"]) not in str(suggestion)
        assert str(matching_assessment["validation_plan"]["steps"]) not in str(suggestion)
        assert "secret-token" not in str(control_center)
        assert "Authorization" not in str(control_center)

        materialize_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks",
            json={
                "queue_key": suggestion["queue_key"],
                "requester": "lead_reviewer",
                "reason": "Review autonomous hypothesis without executing validation.",
            },
        )
        assert materialize_response.status_code == 200
        task = materialize_response.json()
        assert task["task_type"] == "research_queue_review"
        assert task["agent_type"] == "human_research_reviewer"
        assert task["status"] == "queued_review"
        assert task["input_refs"] == [
            f"campaign:{campaign_id}",
            f"research_queue:{suggestion['queue_key']}",
            f"pipeline_run:{run_id}",
            f"candidate:{queue_item['candidate_id']}",
            f"playbook:{queue_item['playbook_id']}",
        ]
        assert task["output_refs"] == []
        assert "secret-token" not in str(task)
        assert "Authorization" not in str(task)

        materialized_stages_response = client.get(
            f"/mythos/campaigns/{campaign_id}/pipeline-stages"
        )
        assert materialized_stages_response.status_code == 200
        materialized_stages = [
            stage for stage in materialized_stages_response.json()
            if stage["stage_key"] == "research_queue_materialized"
        ]
        assert materialized_stages == [
            {
                "campaign_id": campaign_id,
                "created_at": materialized_stages[0]["created_at"],
                "id": materialized_stages[0]["id"],
                "input_refs": [
                    f"campaign:{campaign_id}",
                    f"research_queue:{suggestion['queue_key']}",
                    f"pipeline_run:{run_id}",
                    f"candidate:{queue_item['candidate_id']}",
                    f"playbook:{queue_item['playbook_id']}",
                ],
                "output_refs": [f"campaign_task:{task['id']}"],
                "payload": {
                    "blocked_action_count": len(queue_item["blocked_actions"]),
                    "candidate_id": queue_item["candidate_id"],
                    "candidate_status": matching_assessment["candidate_status"],
                    "evidence_needed": queue_item.get("evidence_needed", []),
                    "evidence_trace_summary": queue_item["evidence_trace_summary"],
                    "execution_allowed": False,
                    "dispatch_allowed": False,
                    "human_approval_required": True,
                    "playbook_id": queue_item["playbook_id"],
                    "priority_score": queue_item["priority_score"],
                    "queue_key": suggestion["queue_key"],
                    "raw_payload_processed": False,
                    "refutation_question_count": len(
                        matching_assessment["refutation"]["questions"]
                    ),
                    "report_readiness": queue_item["report_readiness"],
                    "report_submission_allowed": False,
                    "required_evidence": queue_item["required_evidence"],
                    "satisfied_evidence": [],
                    "source": "mythos_pipeline_autonomous_hunt_queue",
                    "top_candidate_rank": queue_item.get("top_candidate_rank"),
                    "validation_allowed": False,
                    "validation_step_count": len(
                        matching_assessment["validation_plan"]["steps"]
                    ),
                },
                "pipeline_run_id": run_id,
                "safety_gate_state": "manual_review_required",
                "stage_key": "research_queue_materialized",
                "stage_order": materialized_stages[0]["stage_order"],
                "status": "queued_review",
                "stop_reason": None,
                "task_id": task["id"],
            }
        ]
        assert matching_assessment["hypothesis"]["hypothesis"] not in str(materialized_stages)
        assert str(matching_assessment["refutation"]["questions"]) not in str(materialized_stages)
        assert str(matching_assessment["validation_plan"]["steps"]) not in str(materialized_stages)
        assert "secret-token" not in str(materialized_stages)
        assert "Authorization" not in str(materialized_stages)

        review_response = client.get(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review"
        )
        assert review_response.status_code == 200
        review = review_response.json()
        candidate_context = review["autonomous_candidate_context"]
        expected_priority_reason_count = main_module._autonomous_priority_reason_count(
            candidate_context["triage_signals"],
            candidate_context["evidence_focus"],
            candidate_context["source_fact_types"],
        )
        assert candidate_context == {
            "pipeline_run_id": run_id,
            "candidate_id": queue_item["candidate_id"],
            "candidate_status": matching_assessment["candidate_status"],
            "triage_signals": matching_hunter["reasons"],
            "evidence_focus": matching_hunter["evidence_focus"],
            "source_fact_types": matching_source_fact_types,
            "hypothesis": matching_assessment["hypothesis"]["hypothesis"],
            "refutation_status": matching_assessment["refutation"]["status"],
            "refutation_questions": matching_assessment["refutation"]["questions"],
            "validation_plan_status": matching_assessment["validation_plan"]["status"],
            "validation_steps": matching_assessment["validation_plan"]["steps"],
            "human_approval_required": True,
            "blocked_actions": queue_item["blocked_actions"],
            "safety_notes": queue_item["safety_notes"],
            "evidence_needed": suggestion["evidence_needed"],
            "required_evidence": queue_item["required_evidence"],
            "satisfied_evidence": [],
            "evidence_trace_summary": queue_item["evidence_trace_summary"],
            "report_readiness": queue_item["report_readiness"],
            "raw_priority_score": None,
            "quality_gate_reasons": [],
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        }
        assert review["execution_allowed"] is False
        assert review["dispatch_allowed"] is False
        assert review["report_submission_allowed"] is False
        assert review["latest_refutation_decision"] is None
        assert review["suggested_refutation_decision"] == {
            "decision": "needs_validation_review",
            "plan_id": f"auto_research_plan_{task['id']}",
            "rationale": "Autonomous candidate still has unanswered refutation questions and a human-gated validation plan.",
            "refutation_answer_count": 0,
            "refutation_question_count": len(candidate_context["refutation_questions"]),
            "next_allowed_action": "Prepare a human-approved validation plan without executing it.",
            "validation_mode": matching_assessment["hypothesis"]["validation_mode"],
            "target_ref": f"campaign:{campaign_id}",
            "human_review_required": True,
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        }
        auto_plan = review["latest_review_plan"]
        assert auto_plan == {
            "campaign_id": campaign_id,
            "dispatch_allowed": False,
            "evidence_plan": candidate_context["validation_steps"],
            "execution_allowed": False,
            "hypothesis": candidate_context["hypothesis"],
            "next_allowed_action": "Review hypothesis board and request approval before validation.",
            "plan_id": f"auto_research_plan_{task['id']}",
            "refutation_questions": candidate_context["refutation_questions"],
            "report_submission_allowed": False,
            "required_human_gates": [
                "scope_guard_review",
                "redaction_review",
                "approval_required_before_validation",
            ],
            "safety_gate": "advisory_plan_only",
            "status": "auto_drafted",
            "task_id": task["id"],
            "validation_allowed": False,
        }
        assert "secret-token" not in str(review)
        assert "Authorization" not in str(review)

        with testing_session() as session:
            repository = DatabaseRepository(session)
            blocked_campaign = repository.create_campaign(
                program_id="program_example",
                name="Autonomous hunt blocked tool campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed.",
                default_asset="api.example.com",
                allowed_tools=["static_analyzer"],
                created_by="operator",
            )
            repository.upsert_campaign_budget(
                campaign_id=blocked_campaign.id,
                time_budget_minutes=30,
                token_budget=1000,
                tool_call_budget=10,
                validation_budget=1,
            )
            blocked_campaign_id = blocked_campaign.id

        blocked_materialize_response = client.post(
            f"/mythos/campaigns/{blocked_campaign_id}/research-queue/tasks",
            json={
                "queue_key": suggestion["queue_key"],
                "requester": "lead_reviewer",
                "reason": "Review autonomous hypothesis without executing validation.",
            },
        )
        assert blocked_materialize_response.status_code == 200
        blocked_task = blocked_materialize_response.json()
        blocked_review_response = client.get(
            f"/mythos/campaigns/{blocked_campaign_id}/research-queue/tasks/{blocked_task['id']}/review"
        )
        assert blocked_review_response.status_code == 200
        blocked_suggestion = blocked_review_response.json()["suggested_refutation_decision"]
        assert blocked_suggestion["decision"] == "needs_validation_review"
        assert blocked_suggestion["validation_mode"] is None
        assert blocked_suggestion["target_ref"] is None

        plan_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review-plans",
            json={
                "reviewer": "lead_reviewer",
                "rationale": "Use candidate context only; Authorization: Bearer secret-token",
                "hypothesis": candidate_context["hypothesis"],
                "refutation_questions": candidate_context["refutation_questions"],
                "evidence_plan": candidate_context["validation_steps"],
            },
        )
        assert plan_response.status_code == 200
        plan = plan_response.json()
        assert plan["execution_allowed"] is False
        assert plan["dispatch_allowed"] is False
        assert plan["validation_allowed"] is False
        assert plan["report_submission_allowed"] is False
        assert "secret-token" not in str(plan)
        assert "Authorization" not in str(plan)

        stages_response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")
        assert stages_response.status_code == 200
        plan_stages = [
            stage for stage in stages_response.json()
            if stage["stage_key"] == "research_task_review_plan"
        ]
        assert len(plan_stages) == 2
        manual_plan_stage = max(
            plan_stages,
            key=lambda stage: stage["stage_order"],
        )
        auto_plan_stage = min(
            plan_stages,
            key=lambda stage: stage["stage_order"],
        )
        assert auto_plan_stage["status"] == "auto_drafted"
        assert auto_plan_stage["safety_gate_state"] == "advisory_plan_only"
        assert auto_plan_stage["payload"] == {
            "blocked_action_count": len(queue_item["blocked_actions"]),
            "candidate_id": queue_item["candidate_id"],
            "dispatch_allowed": False,
            "evidence_focus_count": len(candidate_context["evidence_focus"]),
            "evidence_step_count": len(candidate_context["validation_steps"]),
            "execution_allowed": False,
            "has_authorization_gap_candidate": (
                "authorization_gap_candidate" in candidate_context["source_fact_types"]
                or "authorization_gap_candidate" in candidate_context["triage_signals"]
            ),
            "human_approval_required": True,
            "pipeline_run_id": run_id,
            "priority_reason_count": expected_priority_reason_count,
            "raw_payload_processed": False,
            "refutation_question_count": len(candidate_context["refutation_questions"]),
                "required_evidence": queue_item["required_evidence"],
                "report_submission_allowed": False,
                "satisfied_evidence": [],
                "source_fact_type_count": len(candidate_context["source_fact_types"]),
            "triage_signal_count": len(candidate_context["triage_signals"]),
            "validation_allowed": False,
        }
        assert manual_plan_stage["input_refs"] == [
            f"campaign:{campaign_id}",
            f"campaign_task:{task['id']}",
            f"research_queue:{suggestion['queue_key']}",
            f"pipeline_run:{run_id}",
            f"candidate:{queue_item['candidate_id']}",
            f"playbook:{queue_item['playbook_id']}",
        ]
        assert manual_plan_stage["output_refs"] == [f"research_plan:{plan['plan_id']}"]
        assert manual_plan_stage["safety_gate_state"] == "advisory_plan_only"
        assert manual_plan_stage["payload"] == {
            "blocked_action_count": len(queue_item["blocked_actions"]),
            "candidate_id": queue_item["candidate_id"],
            "dispatch_allowed": False,
            "evidence_focus_count": len(candidate_context["evidence_focus"]),
            "evidence_step_count": len(candidate_context["validation_steps"]),
            "execution_allowed": False,
            "has_authorization_gap_candidate": (
                "authorization_gap_candidate" in candidate_context["source_fact_types"]
                or "authorization_gap_candidate" in candidate_context["triage_signals"]
            ),
            "human_approval_required": True,
            "pipeline_run_id": run_id,
            "priority_reason_count": expected_priority_reason_count,
            "raw_payload_processed": False,
            "refutation_question_count": len(candidate_context["refutation_questions"]),
            "required_evidence": queue_item["required_evidence"],
            "report_submission_allowed": False,
            "satisfied_evidence": [],
            "source_fact_type_count": len(candidate_context["source_fact_types"]),
            "triage_signal_count": len(candidate_context["triage_signals"]),
            "validation_allowed": False,
        }
        assert candidate_context["hypothesis"] not in str(plan_stages)
        assert str(candidate_context["refutation_questions"]) not in str(plan_stages)
        assert str(candidate_context["validation_steps"]) not in str(plan_stages)
        assert "secret-token" not in str(plan_stages)
        assert "Authorization" not in str(plan_stages)

        with testing_session() as session:
            scoped_campaign = session.get(main_module.CampaignRecord, campaign_id)
            assert scoped_campaign is not None
            scoped_campaign.scope_status = "out_of_scope"
            session.add(scoped_campaign)
            session.commit()

        scope_block_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review-decisions",
            json={
                "plan_id": plan["plan_id"],
                "reviewer": "lead_reviewer",
                "decision": "needs_validation_review",
                "rationale": "Scope changed after planning; validation gate must not be created.",
                "refutation_answers": [
                    "Refutation did not disprove the autonomous candidate.",
                ],
                "validation_mode": "two_account_authorization_check",
                "target_ref": f"campaign:{campaign_id}",
            },
        )
        assert scope_block_response.status_code == 409
        assert scope_block_response.json()["detail"] == "scope_not_in_scope"

        with testing_session() as session:
            repository = DatabaseRepository(session)
            assert repository.list_campaign_approval_records(campaign_id) == []
            assert repository.list_campaign_validation_runs(campaign_id) == []
            assert [
                stage for stage in repository.list_campaign_pipeline_stages(campaign_id)
                if stage.stage_key == "research_task_refutation_decision"
            ] == []
            scoped_campaign = session.get(main_module.CampaignRecord, campaign_id)
            assert scoped_campaign is not None
            scoped_campaign.scope_status = "in_scope"
            session.add(scoped_campaign)
            session.commit()

        with testing_session() as session:
            repository = DatabaseRepository(session)
            repository.upsert_campaign_budget(
                campaign_id=campaign_id,
                time_budget_minutes=30,
                token_budget=1000,
                tool_call_budget=10,
                validation_budget=0,
            )

        budget_block_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review-decisions",
            json={
                "plan_id": plan["plan_id"],
                "reviewer": "lead_reviewer",
                "decision": "needs_validation_review",
                "rationale": "Validation budget is exhausted; validation gate must not be created.",
                "refutation_answers": [
                    "Refutation did not disprove the autonomous candidate.",
                ],
                "validation_mode": "two_account_authorization_check",
                "target_ref": f"campaign:{campaign_id}",
            },
        )
        assert budget_block_response.status_code == 409
        assert budget_block_response.json()["detail"] == "budget_exhausted"

        with testing_session() as session:
            repository = DatabaseRepository(session)
            assert repository.list_campaign_approval_records(campaign_id) == []
            assert repository.list_campaign_validation_runs(campaign_id) == []
            assert [
                stage for stage in repository.list_campaign_pipeline_stages(campaign_id)
                if stage.stage_key == "research_task_refutation_decision"
            ] == []
            repository.upsert_campaign_budget(
                campaign_id=campaign_id,
                time_budget_minutes=30,
                token_budget=1000,
                tool_call_budget=10,
                validation_budget=1,
            )

        with testing_session() as session:
            repository = DatabaseRepository(session)
            other_campaign = repository.create_campaign(
                program_id="program_example",
                name="Other target campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed.",
                default_asset="other-api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
            )
            other_campaign_id = other_campaign.id

        cross_campaign_target_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review-decisions",
            json={
                "plan_id": plan["plan_id"],
                "reviewer": "lead_reviewer",
                "decision": "needs_validation_review",
                "rationale": "Cross-campaign target refs must not bind this validation gate.",
                "refutation_answers": [
                    "Refutation did not disprove the autonomous candidate.",
                ],
                "validation_mode": "two_account_authorization_check",
                "target_ref": f"campaign:{other_campaign_id}",
            },
        )
        assert cross_campaign_target_response.status_code == 409
        assert cross_campaign_target_response.json()["detail"] == "target_ref_campaign_mismatch"

        with testing_session() as session:
            repository = DatabaseRepository(session)
            assert repository.list_campaign_approval_records(campaign_id) == []
            assert repository.list_campaign_validation_runs(campaign_id) == []
            assert [
                stage for stage in repository.list_campaign_pipeline_stages(campaign_id)
                if stage.stage_key == "research_task_refutation_decision"
            ] == []

        missing_refutation_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review-decisions",
            json={
                "plan_id": plan["plan_id"],
                "reviewer": "lead_reviewer",
                "decision": "needs_validation_review",
                "rationale": "Do not queue validation until refutation questions are answered.",
                "validation_mode": "two_account_authorization_check",
                "target_ref": f"campaign:{campaign_id}",
            },
        )
        assert missing_refutation_response.status_code == 422
        assert missing_refutation_response.json()["detail"] == "refutation_answers_required"

        with testing_session() as session:
            repository = DatabaseRepository(session)
            assert repository.list_campaign_approval_records(campaign_id) == []
            assert repository.list_campaign_validation_runs(campaign_id) == []
            assert [
                stage for stage in repository.list_campaign_pipeline_stages(campaign_id)
                if stage.stage_key == "research_task_refutation_decision"
            ] == []

        decision_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review-decisions",
            json={
                "plan_id": plan["plan_id"],
                "reviewer": "lead_reviewer",
                "decision": "needs_validation_review",
                "rationale": "Request approval for preflight only; Authorization: Bearer secret-token",
                "refutation_answers": [
                    "Refutation did not disprove the autonomous candidate.",
                ],
                "validation_mode": "two_account_authorization_check",
                "target_ref": f"campaign:{campaign_id}",
            },
        )
        assert decision_response.status_code == 200
        decision = decision_response.json()
        assert decision["decision"] == "needs_validation_review"
        assert decision["approval_id"].startswith("approval_")
        assert decision["validation_run_id"].startswith("validation_run_")
        assert decision["execution_allowed"] is False
        assert decision["dispatch_allowed"] is False
        assert decision["validation_allowed"] is False
        assert decision["report_submission_allowed"] is False
        assert "secret-token" not in str(decision)
        assert "Authorization" not in str(decision)

        duplicate_decision_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review-decisions",
            json={
                "plan_id": plan["plan_id"],
                "reviewer": "lead_reviewer",
                "decision": "needs_validation_review",
                "rationale": "Duplicate retry should not create another gate.",
                "refutation_answers": [
                    "Refutation did not disprove the autonomous candidate.",
                ],
                "validation_mode": "two_account_authorization_check",
                "target_ref": f"campaign:{campaign_id}",
            },
        )
        assert duplicate_decision_response.status_code == 200
        duplicate_decision = duplicate_decision_response.json()
        assert duplicate_decision["decision_id"] == decision["decision_id"]
        assert duplicate_decision["approval_id"] == decision["approval_id"]
        assert duplicate_decision["validation_run_id"] == decision["validation_run_id"]
        assert duplicate_decision["execution_allowed"] is False
        assert duplicate_decision["dispatch_allowed"] is False
        assert duplicate_decision["validation_allowed"] is False
        assert duplicate_decision["report_submission_allowed"] is False

        mismatched_gate_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review-decisions",
            json={
                "plan_id": plan["plan_id"],
                "reviewer": "lead_reviewer",
                "decision": "needs_validation_review",
                "rationale": "A retry with a different validation mode must not reuse the gate.",
                "refutation_answers": [
                    "Refutation did not disprove the autonomous candidate.",
                ],
                "validation_mode": "static_analyzer",
                "target_ref": f"campaign:{campaign_id}",
            },
        )
        assert mismatched_gate_response.status_code == 409
        assert mismatched_gate_response.json()["detail"] == "validation_review_gate_mismatch"

        validation_control_center_response = client.get(
            f"/mythos/campaigns/{campaign_id}/control-center"
        )
        assert validation_control_center_response.status_code == 200
        validation_control_center = validation_control_center_response.json()
        assert validation_control_center["safe_next_action"] == "review_approval_queue"
        assert len(validation_control_center["approvals"]) == 1
        assert len(validation_control_center["validation_runs"]) == 1
        approval = validation_control_center["approvals"][0]
        assert approval["id"] == decision["approval_id"]
        assert approval["task_id"] == task["id"]
        assert approval["status"] == "pending"
        assert approval["requested_action"] == "validation_preflight_review"
        assert approval["safety_gate_state"] == "awaiting_approval"
        validation_run = validation_control_center["validation_runs"][0]
        assert validation_run["id"] == decision["validation_run_id"]
        assert validation_run["approval_id"] == decision["approval_id"]
        assert validation_run["approval_required"] is True
        assert validation_run["allowed_to_execute"] is False
        assert validation_run["preflight_passed"] is False
        assert validation_run["status"] == "awaiting_approval"
        assert validation_run["safety_gate_state"] == "awaiting_approval"
        assert "secret-token" not in str(validation_control_center)
        assert "Authorization" not in str(validation_control_center)

        decision_stages_response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")
        assert decision_stages_response.status_code == 200
        decision_stages = [
            stage for stage in decision_stages_response.json()
            if stage["stage_key"] == "research_task_refutation_decision"
        ]
        assert len(decision_stages) == 1
        assert decision_stages[0]["input_refs"] == [
            f"campaign:{campaign_id}",
            f"campaign_task:{task['id']}",
            f"research_plan:{plan['plan_id']}",
            f"pipeline_run:{run_id}",
            f"candidate:{queue_item['candidate_id']}",
            f"playbook:{queue_item['playbook_id']}",
        ]
        assert decision_stages[0]["output_refs"] == [
            f"refutation_decision:{decision['decision_id']}",
            f"approval:{decision['approval_id']}",
            f"validation_run:{decision['validation_run_id']}",
        ]
        assert decision_stages[0]["safety_gate_state"] == "advisory_refutation_only"
        assert decision_stages[0]["payload"] == {
            "approval_created": True,
            "approval_id": decision["approval_id"],
            "blocked_action_count": len(queue_item["blocked_actions"]),
            "candidate_id": queue_item["candidate_id"],
            "decision": "needs_validation_review",
            "dispatch_allowed": False,
            "evidence_focus_count": len(candidate_context["evidence_focus"]),
            "execution_allowed": False,
            "has_authorization_gap_candidate": (
                "authorization_gap_candidate" in candidate_context["source_fact_types"]
                or "authorization_gap_candidate" in candidate_context["triage_signals"]
            ),
            "human_approval_required": True,
            "pipeline_run_id": run_id,
            "priority_reason_count": expected_priority_reason_count,
            "raw_payload_processed": False,
            "refutation_answer_count": 1,
            "report_submission_allowed": False,
            "source_fact_type_count": len(candidate_context["source_fact_types"]),
            "triage_signal_count": len(candidate_context["triage_signals"]),
            "validation_allowed": False,
            "validation_run_created": True,
            "validation_run_id": decision["validation_run_id"],
        }
        assert "Refutation did not disprove" not in str(decision_stages)
        assert "secret-token" not in str(decision_stages)
        assert "Authorization" not in str(decision_stages)

        approval_response = client.post(
            f"/mythos/approvals/{decision['approval_id']}/decisions",
            json={
                "decision": "approved",
                "actor": "lead_reviewer",
                "reason": "Approve test-account validation only.",
            },
        )
        assert approval_response.status_code == 200
        preflight_response = client.post(
            f"/mythos/validation-runs/{decision['validation_run_id']}/preflight"
        )
        assert preflight_response.status_code == 200
        assert preflight_response.json()["decision"]["allowed"] is True

        manual_result_response = client.post(
            f"/mythos/validation-runs/{decision['validation_run_id']}/manual-results",
            json={
                "outcome": "observed",
                "reviewer": "lead_reviewer",
                "summary": "Observed with test accounts only; Authorization: Bearer secret-token",
                "evidence_refs": ["sanitized_request_response"],
            },
        )
        assert manual_result_response.status_code == 200
        assert manual_result_response.json()["status"] == "evidence_recorded"

        with testing_session() as session:
            repository = DatabaseRepository(session)
            pipeline_run = repository.get_pipeline_run(run_id)
            assert pipeline_run is not None
            artifact_id = pipeline_run.payload["artifact"]["artifact_id"]
        artifact_response = client.get(f"/mythos/artifacts/{artifact_id}")
        assert artifact_response.status_code == 200
        validation_feedback_usage = [
            usage
            for usage in artifact_response.json()["usage_records"]
            if usage["usage_type"] == "validation_feedback"
        ]
        assert validation_feedback_usage == [
            {
                "usage_type": "validation_feedback",
                "ref": f"validation_run:{decision['validation_run_id']}",
                "run_id": run_id,
                "stage": "research_validation_feedback",
                "candidate_id": queue_item["candidate_id"],
                "task_id": task["id"],
                "plan_id": plan["plan_id"],
                "decision_id": decision["decision_id"],
                "approval_id": decision["approval_id"],
                "validation_run_id": decision["validation_run_id"],
                "outcome": "observed",
                "evidence_refs": ["sanitized_request_response"],
                "evidence_ref_count": 1,
                "finding_confirmation_allowed": False,
                "report_submission_allowed": False,
            }
        ]
        assert "Observed with test accounts only" not in str(validation_feedback_usage)
        assert "Authorization" not in str(validation_feedback_usage)
        assert "secret-token" not in str(validation_feedback_usage)

        feedback_stages_response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")
        assert feedback_stages_response.status_code == 200
        feedback_stage = next(
            stage
            for stage in feedback_stages_response.json()
            if stage["stage_key"] == "research_task_validation_feedback"
        )
        feedback_review_response = client.post(
            f"/mythos/campaigns/{campaign_id}/pipeline-stages/{feedback_stage['id']}/validation-feedback-review",
            json={
                "reviewer": "lead_reviewer",
                "decision": "allow_finding_promotion",
                "rationale": "Review sanitized validation feedback only. Authorization: Bearer secret-token",
            },
        )
        assert feedback_review_response.status_code == 200
        duplicate_feedback_review_response = client.post(
            f"/mythos/campaigns/{campaign_id}/pipeline-stages/{feedback_stage['id']}/validation-feedback-review",
            json={
                "reviewer": "lead_reviewer",
                "decision": "allow_finding_promotion",
                "rationale": "Duplicate click should not duplicate usage. Authorization: Bearer second-token",
            },
        )
        assert duplicate_feedback_review_response.status_code == 200
        assert duplicate_feedback_review_response.json()["id"] == feedback_review_response.json()["id"]

        reviewed_artifact_response = client.get(f"/mythos/artifacts/{artifact_id}")
        assert reviewed_artifact_response.status_code == 200
        validation_feedback_review_usage = [
            usage
            for usage in reviewed_artifact_response.json()["usage_records"]
            if usage["usage_type"] == "validation_feedback_review"
        ]
        assert validation_feedback_review_usage == [
            {
                "usage_type": "validation_feedback_review",
                "ref": f"pipeline_stage:{feedback_review_response.json()['id']}",
                "run_id": run_id,
                "stage": "research_validation_feedback_review",
                "candidate_id": queue_item["candidate_id"],
                "task_id": task["id"],
                "plan_id": plan["plan_id"],
                "decision_id": decision["decision_id"],
                "approval_id": decision["approval_id"],
                "validation_run_id": decision["validation_run_id"],
                "reviewed_stage_ref": f"pipeline_stage:{feedback_stage['id']}",
                "finding_confirmation_allowed": True,
                "report_submission_allowed": False,
            }
        ]
        assert "Review sanitized validation feedback" not in str(validation_feedback_review_usage)
        assert "Authorization" not in str(validation_feedback_review_usage)
        assert "secret-token" not in str(validation_feedback_review_usage)

        detail_response = client.get(f"/mythos/pipeline/runs/{run_id}")
        assert detail_response.status_code == 200
        closed_loop_summary = detail_response.json()["payload"]["closed_loop_summary"]
        assert closed_loop_summary["validation_feedback_count"] == 1
        assert closed_loop_summary["validation_feedback_review_count"] == 1
        assert "Review sanitized validation feedback" not in str(closed_loop_summary)
        assert "Authorization" not in str(closed_loop_summary)
        assert "secret-token" not in str(closed_loop_summary)

        with testing_session() as session:
            repository = DatabaseRepository(session)
            stored_task = repository.session.get(main_module.CampaignTaskRecord, task["id"])
            assert stored_task is not None
            assert stored_task.payload["source"] == "mythos_pipeline_autonomous_hunt_queue"
            assert stored_task.payload["candidate_id"] == queue_item["candidate_id"]
            assert stored_task.payload["pipeline_run_id"] == run_id
            assert stored_task.payload["human_approval_required"] is True
            assert stored_task.payload["blocked_actions"] == queue_item["blocked_actions"]
            assert stored_task.payload["execution_allowed"] is False
            assert stored_task.payload["dispatch_allowed"] is False
            stored_validation_runs = repository.list_campaign_validation_runs(campaign_id)
            assert len(stored_validation_runs) == 1
            assert stored_validation_runs[0].id == decision["validation_run_id"]
            plan_stage = next(
                stage for stage in repository.list_campaign_pipeline_stages(campaign_id)
                if stage.stage_key == "research_task_review_plan"
            )
            assert plan_stage.payload["pipeline_run_id"] == run_id
            assert plan_stage.payload["candidate_id"] == queue_item["candidate_id"]
            assert plan_stage.payload["human_approval_required"] is True
            assert plan_stage.payload["blocked_actions"] == queue_item["blocked_actions"]
            assert plan_stage.payload["execution_allowed"] is False
            assert plan_stage.payload["dispatch_allowed"] is False
            assert plan_stage.payload["validation_allowed"] is False
            approval_record = session.get(main_module.ApprovalRecord, decision["approval_id"])
            assert approval_record is not None
            assert approval_record.payload["pipeline_run_id"] == run_id
            assert approval_record.payload["candidate_id"] == queue_item["candidate_id"]
            assert approval_record.payload["human_approval_required"] is True
            assert approval_record.payload["blocked_actions"] == queue_item["blocked_actions"]
            assert approval_record.payload["execution_allowed"] is False
            validation_record = repository.get_validation_run(decision["validation_run_id"])
            assert validation_record is not None
            assert validation_record.payload["pipeline_run_id"] == run_id
            assert validation_record.payload["candidate_id"] == queue_item["candidate_id"]
            assert validation_record.payload["human_approval_required"] is True
            assert validation_record.payload["blocked_actions"] == queue_item["blocked_actions"]
            assert validation_record.payload["execution_allowed"] is False
            decision_stage = next(
                stage for stage in repository.list_campaign_pipeline_stages(campaign_id)
                if stage.stage_key == "research_task_refutation_decision"
            )
            assert decision_stage.payload["pipeline_run_id"] == run_id
            assert decision_stage.payload["candidate_id"] == queue_item["candidate_id"]
            assert decision_stage.payload["approval_id"] == decision["approval_id"]
            assert decision_stage.payload["validation_run_id"] == decision["validation_run_id"]
            assert decision_stage.payload["validation_allowed"] is False
            assert "secret-token" not in str(stored_task.payload)
            assert "Authorization" not in str(stored_task.payload)
            assert "secret-token" not in str(plan_stage.payload)
            assert "Authorization" not in str(plan_stage.payload)
            assert "secret-token" not in str(approval_record.payload)
            assert "Authorization" not in str(approval_record.payload)
            assert "secret-token" not in str(validation_record.payload)
            assert "Authorization" not in str(validation_record.payload)
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_surfaces_learned_evidence_required_from_worker_queue():
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
                name="Learned evidence queue campaign",
                autonomy_level="level_0_read_only",
                scope_status="in_scope",
                policy_text="Testing allowed. Authorization: Bearer secret-token",
                default_asset="authorized/service",
                target_classes=["idor"],
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
            map_task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="attack_surface_mapping",
                agent_type="target_model_agent",
                title="Map authorized local code",
                input_refs=[f"campaign:{campaign.id}"],
                payload={
                    "authorized_code_files": [
                        {
                            "path": "apps/api/routes/files.py",
                            "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    authorize_owner_or_admin(file_id)
    return send_file(file_id)
""",
                        }
                    ],
                },
            )
            hypothesis_task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="hypothesis_generation",
                agent_type="hypothesis_agent",
                title="Generate evidence-aware hypotheses",
                input_refs=[f"campaign:{campaign.id}"],
                payload={},
            )
            campaign_id = campaign.id
            map_task_id = map_task.id
            hypothesis_task_id = hypothesis_task.id

        learning_response = client.post(
            "/mythos/brain/learning-signals",
            json={
                "program_id": "program_example",
                "playbook_id": "bola_idor",
                "outcome": "informative",
                "surface_key": "file_id:export",
                "notes": "Candidate needed more evidence before ranking boost.",
                "evidence_quality": "weak",
                "target_relationships": [
                    "candidate:H-001",
                    "evidence_ready:false",
                    "trace_status:needs_evidence",
                    "missing_evidence:independent_cross_check",
                    "missing_required_artifact:policy",
                    "learned_evidence:lesson_evidence_needed_missing_evidence_independent_cross_check",
                ],
            },
        )
        assert learning_response.status_code == 200

        with testing_session() as session:
            repository = DatabaseRepository(session)
            assert run_agent_task(map_task_id, repository=repository)["status"] == "completed"
            assert (
                run_agent_task(hypothesis_task_id, repository=repository)["status"]
                == "completed"
            )
            run = repository.list_pipeline_runs_for_program("program_example")[0]
            queue_item = run.payload["autonomous_hunt_queue"][0]
            expected_required_evidence = [
                "independent_refutation_or_static_rule",
                "policy",
                "authz_bypass_or_misbind_trace",
            ]
            assert queue_item["next_action"] == "resolve_evidence_gaps"
            assert queue_item["required_evidence"] == expected_required_evidence
            assert queue_item["quality_gate_reasons"] == ["required_evidence_missing"]
            assert queue_item["raw_priority_score"] > queue_item["priority_score"]

        control_center_response = client.get(
            f"/mythos/campaigns/{campaign_id}/control-center"
        )
        assert control_center_response.status_code == 200
        control_center = control_center_response.json()
        hunt_suggestion = next(
            suggestion
            for suggestion in control_center["research_queue_suggestions"]
            if suggestion["source"] == "mythos_pipeline_autonomous_hunt_queue"
        )
        assert hunt_suggestion["required_evidence"] == expected_required_evidence
        assert hunt_suggestion["quality_gate_reasons"] == ["required_evidence_missing"]
        assert hunt_suggestion["raw_priority_score"] == queue_item["raw_priority_score"]
        assert hunt_suggestion["human_approval_required"] is True
        assert hunt_suggestion["execution_allowed"] is False
        assert "secret-token" not in str(control_center)
        assert "Authorization" not in str(control_center)

        materialize_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks",
            json={
                "queue_key": hunt_suggestion["queue_key"],
                "requester": "lead_reviewer",
                "reason": "Review learned evidence gaps before any validation.",
            },
        )
        assert materialize_response.status_code == 200
        task = materialize_response.json()

        review_response = client.get(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review"
        )
        assert review_response.status_code == 200
        review = review_response.json()
        assert review["autonomous_candidate_context"]["required_evidence"] == (
            expected_required_evidence
        )
        assert review["autonomous_candidate_context"]["quality_gate_reasons"] == [
            "required_evidence_missing"
        ]
        assert (
            review["autonomous_candidate_context"]["raw_priority_score"]
            == queue_item["raw_priority_score"]
        )
        assert review["latest_review_plan"] is not None

        stages_response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")
        assert stages_response.status_code == 200
        materialized_stage = next(
            stage
            for stage in stages_response.json()
            if stage["stage_key"] == "research_queue_materialized"
        )
        assert materialized_stage["payload"]["required_evidence"] == (
            expected_required_evidence
        )
        assert materialized_stage["payload"]["quality_gate_reasons"] == [
            "required_evidence_missing"
        ]
        assert materialized_stage["payload"]["raw_priority_score"] == queue_item[
            "raw_priority_score"
        ]
        review_plan_stage = next(
            stage
            for stage in stages_response.json()
            if stage["stage_key"] == "research_task_review_plan"
        )
        assert review_plan_stage["payload"]["required_evidence"] == (
            expected_required_evidence
        )
        assert review_plan_stage["payload"]["quality_gate_reasons"] == [
            "required_evidence_missing"
        ]
        assert review_plan_stage["payload"]["raw_priority_score"] == queue_item[
            "raw_priority_score"
        ]
        assert "secret-token" not in str(review)
        assert "Authorization" not in str(review)
        assert "secret-token" not in str(stages_response.json())
        assert "Authorization" not in str(stages_response.json())
    finally:
        app.dependency_overrides.clear()


def test_autonomous_hunt_queue_metadata_cannot_disable_human_approval_gate():
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
                name="Autonomous hunt queue approval gate campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed.",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
            )
            repository.upsert_campaign_budget(
                campaign_id=campaign.id,
                time_budget_minutes=30,
                token_budget=1000,
                tool_call_budget=10,
                validation_budget=1,
            )
            campaign_id = campaign.id

        dry_run_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert dry_run_response.status_code == 200
        dry_run = dry_run_response.json()
        run_id = dry_run["run_id"]
        queue_item = dry_run["autonomous_hunt_queue"][0]

        with testing_session() as session:
            repository = DatabaseRepository(session)
            run = repository.get_pipeline_run(run_id)
            assert run is not None
            payload = dict(run.payload)
            queue = [dict(item) for item in payload["autonomous_hunt_queue"]]
            queue[0]["human_approval_required"] = False
            queue[0]["blocked_actions"] = []
            queue[0]["safety_notes"] = []
            payload["autonomous_hunt_queue"] = queue
            run.payload = payload
            session.add(run)
            session.commit()

        control_center_response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")
        assert control_center_response.status_code == 200
        suggestion = next(
            item
            for item in control_center_response.json()["research_queue_suggestions"]
            if item["source"] == "mythos_pipeline_autonomous_hunt_queue"
        )
        assert suggestion["queue_key"] == f"autonomous_hunt:{run_id}:{queue_item['queue_id']}"
        assert suggestion["human_approval_required"] is True
        assert suggestion["blocked_action_count"] == len(queue_item["blocked_actions"])
        assert suggestion["execution_allowed"] is False

        materialize_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks",
            json={
                "queue_key": suggestion["queue_key"],
                "requester": "lead_reviewer",
                "reason": "Review candidate without weakening human gates.",
            },
        )
        assert materialize_response.status_code == 200
        task = materialize_response.json()
        with testing_session() as session:
            repository = DatabaseRepository(session)
            stored_task = repository.session.get(main_module.CampaignTaskRecord, task["id"])
            assert stored_task is not None
            assert stored_task.payload["human_approval_required"] is True
            assert stored_task.payload["blocked_actions"] == queue_item["blocked_actions"]
            assert stored_task.payload["safety_notes"] == queue_item["safety_notes"]
            assert stored_task.payload["execution_allowed"] is False
            assert stored_task.payload["dispatch_allowed"] is False

        review_response = client.get(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review"
        )
        assert review_response.status_code == 200
        review = review_response.json()
        assert review["autonomous_candidate_context"]["human_approval_required"] is True
        assert review["autonomous_candidate_context"]["blocked_actions"] == queue_item["blocked_actions"]
        assert review["autonomous_candidate_context"]["safety_notes"] == queue_item["safety_notes"]
        assert review["execution_allowed"] is False
        assert review["dispatch_allowed"] is False
        assert review["suggested_refutation_decision"]["human_review_required"] is True

        stages_response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")
        assert stages_response.status_code == 200
        plan_stage = next(
            stage
            for stage in stages_response.json()
            if stage["stage_key"] == "research_task_review_plan"
        )
        assert plan_stage["payload"]["human_approval_required"] is True
        assert plan_stage["payload"]["blocked_action_count"] == len(queue_item["blocked_actions"])
        assert plan_stage["payload"]["execution_allowed"] is False
        assert plan_stage["payload"]["dispatch_allowed"] is False
        assert plan_stage["payload"]["validation_allowed"] is False
    finally:
        app.dependency_overrides.clear()


def test_out_of_scope_autonomous_hunt_queue_is_not_available_to_campaign():
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
                name="Out of scope autonomous hunt queue campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
            )
            repository.save_pipeline_run(
                program_id="program_example",
                asset="api.example.com",
                policy_text="Testing allowed",
                scope_status="out_of_scope",
                hypothesis_count=1,
                blocked_count=0,
                report_title="Out of scope autonomous queue",
                payload={
                    "autonomous_hunt_queue": [
                        {
                            "queue_id": "hunt_queue_out_of_scope",
                            "candidate_id": "out_of_scope_candidate",
                            "candidate_status": "awaiting_human_approval",
                            "playbook_id": "bola_idor",
                            "priority_score": 95,
                            "status": "awaiting_human_approval",
                            "blocked_actions": ["execute_live_validation"],
                            "safety_notes": ["human_review_required"],
                        }
                    ],
                    "hypothesis_assessments": [
                        {
                            "candidate_id": "out_of_scope_candidate",
                            "candidate_status": "awaiting_human_approval",
                            "hypothesis": {
                                "hypothesis": "Out of scope candidate must not be queued.",
                                "validation_mode": "two_account_authorization_check",
                            },
                            "refutation": {
                                "status": "pending",
                                "questions": ["Is the target in scope?"],
                            },
                            "validation_plan": {
                                "status": "blocked",
                                "steps": ["Do not validate out-of-scope target."],
                            },
                        }
                    ],
                },
            )
            campaign_id = campaign.id

        control_center_response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")
        assert control_center_response.status_code == 200
        suggestions = control_center_response.json()["research_queue_suggestions"]
        assert not any(
            suggestion["source"] == "mythos_pipeline_autonomous_hunt_queue"
            for suggestion in suggestions
        )

        materialize_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks",
            json={
                "queue_key": "autonomous_hunt:pipeline_run_missing:hunt_queue_out_of_scope",
                "requester": "lead_reviewer",
                "reason": "Should not materialize out-of-scope queue.",
            },
        )
        assert materialize_response.status_code == 409
        assert materialize_response.json()["detail"] == "research_queue_suggestion_not_available"
    finally:
        app.dependency_overrides.clear()


def test_autonomous_hunt_task_payload_cannot_disable_human_approval_gate():
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
                name="Autonomous hunt task payload approval gate campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed.",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
            )
            repository.upsert_campaign_budget(
                campaign_id=campaign.id,
                time_budget_minutes=30,
                token_budget=1000,
                tool_call_budget=10,
                validation_budget=1,
            )
            campaign_id = campaign.id

        dry_run_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert dry_run_response.status_code == 200
        dry_run = dry_run_response.json()
        run_id = dry_run["run_id"]
        queue_item = dry_run["autonomous_hunt_queue"][0]
        queue_key = f"autonomous_hunt:{run_id}:{queue_item['queue_id']}"

        materialize_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks",
            json={
                "queue_key": queue_key,
                "requester": "lead_reviewer",
                "reason": "Review candidate before any validation.",
            },
        )
        assert materialize_response.status_code == 200
        task_id = materialize_response.json()["id"]

        with testing_session() as session:
            task = session.get(main_module.CampaignTaskRecord, task_id)
            assert task is not None
            payload = dict(task.payload)
            payload["human_approval_required"] = False
            task.payload = payload
            session.add(task)
            session.commit()

        review_response = client.get(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task_id}/review"
        )
        assert review_response.status_code == 200
        review = review_response.json()
        assert review["autonomous_candidate_context"]["human_approval_required"] is True
        assert review["suggested_refutation_decision"]["human_review_required"] is True
        assert review["execution_allowed"] is False
        assert review["dispatch_allowed"] is False

        stages_response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")
        assert stages_response.status_code == 200
        plan_stage = next(
            stage
            for stage in stages_response.json()
            if stage["stage_key"] == "research_task_review_plan"
        )
        assert plan_stage["payload"]["human_approval_required"] is True
        assert plan_stage["payload"]["execution_allowed"] is False
        assert plan_stage["payload"]["dispatch_allowed"] is False
        assert plan_stage["payload"]["validation_allowed"] is False
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_points_to_hypothesis_board_for_reasoning_review():
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
                name="Reasoning review campaign",
                autonomy_level="level_1_local_validation",
                scope_status="in_scope",
                policy_text="Testing allowed. Authorization: Bearer secret-token",
                default_asset="api.example.com",
                allowed_tools=["static_analyzer"],
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
            campaign_id = campaign.id

        dry_run_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert dry_run_response.status_code == 200
        run_id = dry_run_response.json()["run_id"]

        with testing_session() as session:
            repository = DatabaseRepository(session)
            repository.save_pipeline_stage(
                pipeline_run_id=run_id,
                campaign_id=campaign_id,
                task_id=None,
                stage_key="campaign_report_preview",
                stage_order=20,
                status="awaiting_review",
                input_refs=[f"campaign:{campaign_id}"],
                output_refs=[f"pipeline_run:{run_id}"],
                safety_gate_state="awaiting_review",
                stop_reason=None,
                payload={
                    "review_gate": "human_review_required",
                    "submission_allowed": False,
                    "raw_payload_processed": False,
                },
            )

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["safe_next_action"] == "review_hypothesis_board"
        assert control_center["execution_allowed"] is False
        assert "SECRET POLICY" not in str(control_center)
        assert "secret-token" not in str(control_center)
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_points_to_attack_surface_map_for_target_model_review():
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
                name="Target model review campaign",
                autonomy_level="level_1_local_validation",
                scope_status="in_scope",
                policy_text="Testing allowed. Authorization: Bearer secret-token",
                default_asset="api.example.com",
                allowed_tools=["static_analyzer"],
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
            run = repository.save_pipeline_run(
                program_id="program_example",
                asset="api.example.com",
                policy_text="SECRET POLICY: In scope api.example.com.",
                scope_status="in_scope",
                hypothesis_count=0,
                blocked_count=0,
                report_title=None,
                payload={
                    "target_model": {
                        "endpoints": [
                            {
                                "path": "/files/{file_id}/export",
                                "method": "GET",
                                "summary": "Authorization: Bearer secret-token",
                            }
                        ],
                        "objects": [{"name": "file", "identifiers": ["file_id"]}],
                        "roles": ["member"],
                        "sensitive_actions": [
                            {
                                "action": "export",
                                "route": "/files/{file_id}/export",
                                "roles": ["member"],
                            }
                        ],
                        "relationships": [],
                    },
                    "hypothesis_assessments": [],
                },
            )
            repository.save_pipeline_stage(
                pipeline_run_id=run.id,
                campaign_id=campaign.id,
                task_id=None,
                stage_key="target_model",
                stage_order=1,
                status="completed",
                input_refs=[f"pipeline_run:{run.id}", "Authorization: Bearer secret-token"],
                output_refs=[f"target_model:{run.id}"],
                safety_gate_state="static_analysis_only",
                stop_reason=None,
                payload={
                    "raw_payload_processed": False,
                    "execution_allowed": False,
                    "report_submission_allowed": False,
                },
            )
            campaign_id = campaign.id

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["safe_next_action"] == "review_attack_surface_map"
        assert control_center["execution_allowed"] is False
        assert "SECRET POLICY" not in str(control_center)
        assert "secret-token" not in str(control_center)
        assert "Authorization" not in str(control_center)
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_routes_promotion_block_to_evidence_review():
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
                name="Promotion blocked campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed. Authorization: Bearer secret-token",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
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
            repository.save_pipeline_stage(
                pipeline_run_id="pipeline_run_1",
                campaign_id=campaign.id,
                task_id=None,
                stage_key="finding_promotion_blocked",
                stage_order=1,
                status="blocked",
                input_refs=["pipeline_run:pipeline_run_1?Authorization=Bearer secret-token"],
                output_refs=[],
                safety_gate_state="manual_review_required",
                stop_reason="blocked_by_research_feedback_gate",
                payload={
                    "reason": "blocked_by_research_feedback_gate",
                    "blocked_stage_count": 1,
                    "provenance_ref_count": 6,
                    "finding_promotion_allowed": False,
                    "report_submission_allowed": False,
                    "raw_payload_processed": False,
                },
            )
            campaign_id = campaign.id

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["safe_next_action"] == "review_blocked_promotion"
        assert control_center["execution_allowed"] is False
        assert control_center["blocked_reasons"] == ["blocked_by_research_feedback_gate"]
        assert control_center["promotion_review"] == {
            "blocked_attempt_count": 1,
            "finding_promotion_allowed": False,
            "latest_reason": "blocked_by_research_feedback_gate",
            "next_allowed_action": "Review blocked promotion evidence before retrying candidate promotion.",
            "provenance_ref_count": 6,
            "report_submission_allowed": False,
            "required_evidence_blocked_count": 0,
            "validation_feedback_review_count": 0,
        }
        assert "secret-token" not in str(control_center)
        assert "Authorization" not in str(control_center)
        assert "execution_allowed: True" not in str(control_center)
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_summarizes_research_feedback_before_promotion_attempt():
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
                name="Research feedback promotion gate campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed. Authorization: Bearer secret-token",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
            )
            repository.update_campaign_status(campaign.id, "running")
            repository.save_pipeline_stage(
                pipeline_run_id="pipeline_run_1",
                campaign_id=campaign.id,
                task_id="campaign_task_1",
                stage_key="research_task_validation_feedback",
                stage_order=1,
                status="evidence_recorded",
                input_refs=[
                    f"campaign:{campaign.id}",
                    "campaign_task:campaign_task_1",
                    "research_plan:research_plan_1",
                    "refutation_decision:refutation_decision_1",
                    "approval:approval_1",
                    "validation_run:validation_run_1",
                    "Authorization: Bearer secret-token",
                ],
                output_refs=["validation_run:validation_run_1"],
                safety_gate_state="advisory_validation_feedback_only",
                stop_reason=None,
                payload={
                    "source": "research_task_refutation_decision",
                    "plan_id": "research_plan_1",
                    "decision_id": "refutation_decision_1",
                    "approval_id": "approval_1",
                    "validation_run_id": "validation_run_1",
                    "outcome": "observed",
                    "evidence_ref_count": 2,
                    "finding_confirmation_allowed": False,
                    "finding_promotion_allowed": False,
                    "report_submission_allowed": False,
                },
            )
            campaign_id = campaign.id

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["execution_allowed"] is False
        assert control_center["promotion_review"] == {
            "blocked_attempt_count": 0,
            "finding_promotion_allowed": False,
            "latest_reason": "research_validation_feedback_is_advisory",
            "next_allowed_action": "Review validation feedback before candidate promotion.",
            "provenance_ref_count": 6,
            "report_submission_allowed": False,
            "required_evidence_blocked_count": 0,
            "validation_feedback_review_count": 0,
        }
        assert "secret-token" not in str(control_center)
        assert "Authorization" not in str(control_center)
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_summarizes_reviewed_validation_feedback_before_promotion():
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
                name="Reviewed feedback promotion gate campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed. Authorization: Bearer secret-token",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
            )
            repository.update_campaign_status(campaign.id, "running")
            repository.save_validation_run(
                campaign_id=campaign.id,
                task_id="campaign_task_1",
                approval_id="approval_1",
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="evidence_recorded",
                safety_gate_state="manual_result_recorded",
                plan_digest="research_plan:research_plan_1",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=2,
                summary="Manual validation result recorded.",
                payload={
                    "manual_result": {
                        "outcome": "observed",
                        "summary": "Observed with sanitized test accounts. Authorization: Bearer secret-token",
                        "evidence_refs": ["sanitized_request_response"],
                    },
                    "execution_allowed": False,
                    "report_submission_allowed": False,
                },
            )
            feedback_stage = repository.save_pipeline_stage(
                pipeline_run_id="pipeline_run_1",
                campaign_id=campaign.id,
                task_id="campaign_task_1",
                stage_key="research_task_validation_feedback",
                stage_order=1,
                status="evidence_recorded",
                input_refs=[
                    f"campaign:{campaign.id}",
                    "campaign_task:campaign_task_1",
                    "research_plan:research_plan_1",
                    "refutation_decision:refutation_decision_1",
                    "approval:approval_1",
                    "validation_run:validation_run_1",
                    "Authorization: Bearer secret-token",
                ],
                output_refs=["validation_run:validation_run_1"],
                safety_gate_state="advisory_validation_feedback_only",
                stop_reason=None,
                payload={
                    "source": "research_task_refutation_decision",
                    "plan_id": "research_plan_1",
                    "decision_id": "refutation_decision_1",
                    "approval_id": "approval_1",
                    "validation_run_id": "validation_run_1",
                    "outcome": "observed",
                    "evidence_ref_count": 2,
                    "finding_confirmation_allowed": False,
                    "finding_promotion_allowed": False,
                    "report_submission_allowed": False,
                },
            )
            repository.save_pipeline_stage(
                pipeline_run_id="pipeline_run_1",
                campaign_id=campaign.id,
                task_id="campaign_task_1",
                stage_key="research_task_validation_feedback_review",
                stage_order=2,
                status="completed",
                input_refs=[
                    f"campaign:{campaign.id}",
                    "campaign_task:campaign_task_1",
                    f"pipeline_stage:{feedback_stage.id}",
                    "validation_run:validation_run_1",
                    "Authorization: Bearer secret-token",
                ],
                output_refs=[f"pipeline_stage:{feedback_stage.id}"],
                safety_gate_state="manual_review_required",
                stop_reason=None,
                payload={
                    "source": "human_validation_feedback_review",
                    "reviewed_stage_id": feedback_stage.id,
                    "decision": "allow_finding_promotion",
                    "reviewer": "lead_reviewer",
                    "rationale": "Reviewed sanitized evidence. Authorization: Bearer secret-token",
                    "finding_confirmation_allowed": True,
                    "report_submission_allowed": False,
                    "execution_allowed": False,
                    "dispatch_allowed": False,
                    "validation_allowed": False,
                    "raw_payload_processed": False,
                },
            )
            campaign_id = campaign.id

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["safe_next_action"] == "promote_finding_candidate"
        assert control_center["execution_allowed"] is False
        assert control_center["promotion_review"] == {
            "blocked_attempt_count": 0,
            "finding_promotion_allowed": True,
            "latest_reason": "validation_feedback_review_allowed_finding_promotion",
            "next_allowed_action": "Promote to finding candidate only after explicit human action.",
            "provenance_ref_count": 6,
            "report_submission_allowed": False,
            "required_evidence_blocked_count": 0,
            "validation_feedback_review_count": 1,
        }
        assert "Observed with sanitized test accounts" not in str(control_center)
        assert "Reviewed sanitized evidence" not in str(control_center)
        assert "secret-token" not in str(control_center)
        assert "Authorization" not in str(control_center)
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_blocks_finding_promotion_with_unresolved_required_evidence():
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
                name="Unresolved required evidence campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed. Authorization: Bearer secret-token",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
            )
            repository.update_campaign_status(campaign.id, "running")
            feedback_stage = repository.save_pipeline_stage(
                pipeline_run_id="pipeline_run_1",
                campaign_id=campaign.id,
                task_id="campaign_task_1",
                stage_key="research_task_validation_feedback",
                stage_order=1,
                status="evidence_recorded",
                input_refs=[
                    f"campaign:{campaign.id}",
                    "campaign_task:campaign_task_1",
                    "research_plan:research_plan_1",
                    "validation_run:validation_run_1",
                    "Authorization: Bearer secret-token",
                ],
                output_refs=["validation_run:validation_run_1"],
                safety_gate_state="advisory_validation_feedback_only",
                stop_reason=None,
                payload={
                    "source": "research_task_refutation_decision",
                    "plan_id": "research_plan_1",
                    "validation_run_id": "validation_run_1",
                    "outcome": "observed",
                    "evidence_ref_count": 2,
                    "finding_confirmation_allowed": False,
                    "finding_promotion_allowed": False,
                    "report_submission_allowed": False,
                },
            )
            repository.save_pipeline_stage(
                pipeline_run_id="pipeline_run_1",
                campaign_id=campaign.id,
                task_id="campaign_task_1",
                stage_key="research_task_validation_feedback_review",
                stage_order=2,
                status="completed",
                input_refs=[
                    f"campaign:{campaign.id}",
                    "campaign_task:campaign_task_1",
                    f"pipeline_stage:{feedback_stage.id}",
                    "validation_run:validation_run_1",
                    "Authorization: Bearer secret-token",
                ],
                output_refs=[f"pipeline_stage:{feedback_stage.id}"],
                safety_gate_state="manual_review_required",
                stop_reason=None,
                payload={
                    "source": "human_validation_feedback_review",
                    "reviewed_stage_id": feedback_stage.id,
                    "decision": "allow_finding_promotion",
                    "reviewer": "lead_reviewer",
                    "rationale": "Reviewed sanitized evidence. Authorization: Bearer secret-token",
                    "finding_confirmation_allowed": True,
                    "report_submission_allowed": False,
                    "execution_allowed": False,
                    "dispatch_allowed": False,
                    "validation_allowed": False,
                    "raw_payload_processed": False,
                },
            )
            repository.save_pipeline_stage(
                pipeline_run_id="pipeline_run_1",
                campaign_id=campaign.id,
                task_id="campaign_task_2",
                stage_key="research_task_review_plan",
                stage_order=3,
                status="auto_drafted",
                input_refs=[
                    f"campaign:{campaign.id}",
                    "campaign_task:campaign_task_2",
                    "research_queue:autonomous_hunt:pipeline_run_1:hunt_queue_1",
                    "Authorization: Bearer secret-token",
                ],
                output_refs=["research_plan:research_plan_2"],
                safety_gate_state="advisory_plan_only",
                stop_reason=None,
                payload={
                    "plan_id": "research_plan_2",
                    "required_evidence": [
                        "independent_refutation_or_static_rule",
                        "policy",
                    ],
                    "execution_allowed": False,
                    "dispatch_allowed": False,
                    "validation_allowed": False,
                    "report_submission_allowed": False,
                    "raw_payload_processed": False,
                },
            )
            campaign_id = campaign.id

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["safe_next_action"] != "promote_finding_candidate"
        assert control_center["safe_next_action"] == "review_evidence_or_report_drafts"
        assert control_center["promotion_review"]["finding_promotion_allowed"] is False
        assert control_center["promotion_review"]["latest_reason"] == "required_evidence_unresolved"
        assert control_center["promotion_review"]["required_evidence_blocked_count"] == 1
        assert control_center["promotion_review"]["validation_feedback_review_count"] == 1
        assert control_center["promotion_review"]["report_submission_allowed"] is False
        assert "independent_refutation_or_static_rule" not in str(control_center["promotion_review"])
        assert "policy" not in str(control_center["promotion_review"])
        assert "secret-token" not in str(control_center)
        assert "Authorization" not in str(control_center)
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_ignores_orphan_validation_feedback_review():
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
                name="Orphan validation feedback review campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed.",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
            )
            repository.update_campaign_status(campaign.id, "running")
            repository.save_pipeline_stage(
                pipeline_run_id="pipeline_run_1",
                campaign_id=campaign.id,
                task_id="campaign_task_1",
                stage_key="research_task_validation_feedback_review",
                stage_order=1,
                status="completed",
                input_refs=[
                    f"campaign:{campaign.id}",
                    "campaign_task:campaign_task_1",
                    "pipeline_stage:missing_feedback_stage",
                    "validation_run:validation_run_1",
                ],
                output_refs=["pipeline_stage:missing_feedback_stage"],
                safety_gate_state="manual_review_required",
                stop_reason=None,
                payload={
                    "source": "human_validation_feedback_review",
                    "reviewed_stage_id": "missing_feedback_stage",
                    "decision": "allow_finding_promotion",
                    "reviewer": "lead_reviewer",
                    "rationale": "Review without a stored feedback stage must not unlock promotion.",
                    "finding_confirmation_allowed": True,
                    "report_submission_allowed": False,
                    "execution_allowed": False,
                    "dispatch_allowed": False,
                    "validation_allowed": False,
                    "raw_payload_processed": False,
                },
            )
            campaign_id = campaign.id

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["safe_next_action"] != "promote_finding_candidate"
        assert control_center["promotion_review"]["finding_promotion_allowed"] is False
        assert control_center["promotion_review"]["report_submission_allowed"] is False
        assert control_center["promotion_review"]["validation_feedback_review_count"] == 0
        assert control_center["promotion_review"]["provenance_ref_count"] == 0
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_prioritizes_scope_block_over_reviewed_feedback():
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
                name="Out-of-scope reviewed feedback campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="out_of_scope",
                policy_text="Testing is no longer allowed.",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
            )
            repository.update_campaign_status(campaign.id, "running")
            feedback_stage = repository.save_pipeline_stage(
                pipeline_run_id="pipeline_run_1",
                campaign_id=campaign.id,
                task_id="campaign_task_1",
                stage_key="research_task_validation_feedback",
                stage_order=1,
                status="evidence_recorded",
                input_refs=[
                    f"campaign:{campaign.id}",
                    "campaign_task:campaign_task_1",
                    "validation_run:validation_run_1",
                ],
                output_refs=["validation_run:validation_run_1"],
                safety_gate_state="advisory_validation_feedback_only",
                stop_reason=None,
                payload={
                    "outcome": "observed",
                    "finding_promotion_allowed": False,
                    "report_submission_allowed": False,
                },
            )
            repository.save_pipeline_stage(
                pipeline_run_id="pipeline_run_1",
                campaign_id=campaign.id,
                task_id="campaign_task_1",
                stage_key="research_task_validation_feedback_review",
                stage_order=2,
                status="completed",
                input_refs=[
                    f"campaign:{campaign.id}",
                    "campaign_task:campaign_task_1",
                    f"pipeline_stage:{feedback_stage.id}",
                    "validation_run:validation_run_1",
                ],
                output_refs=[f"pipeline_stage:{feedback_stage.id}"],
                safety_gate_state="manual_review_required",
                stop_reason=None,
                payload={
                    "source": "human_validation_feedback_review",
                    "reviewed_stage_id": feedback_stage.id,
                    "decision": "allow_finding_promotion",
                    "reviewer": "lead_reviewer",
                    "rationale": "Reviewed sanitized evidence.",
                    "finding_confirmation_allowed": True,
                    "report_submission_allowed": False,
                    "execution_allowed": False,
                    "dispatch_allowed": False,
                    "validation_allowed": False,
                    "raw_payload_processed": False,
                },
            )
            campaign_id = campaign.id

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["blocked_reasons"] == ["scope_not_in_scope"]
        assert control_center["safe_next_action"] == "resolve_blockers"
        assert control_center["promotion_review"]["finding_promotion_allowed"] is True
        assert control_center["execution_allowed"] is False
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_prioritizes_promotion_block_over_hypothesis_review():
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
                name="Promotion block priority campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed.",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
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
            run = repository.save_pipeline_run(
                program_id="program_example",
                asset="api.example.com",
                policy_text="Testing allowed.",
                scope_status="in_scope",
                hypothesis_count=1,
                blocked_count=0,
                report_title=None,
                payload={
                    "hypothesis_assessments": [
                        {
                            "exploit_chain": {"primitives": ["object id swap"]},
                            "refutation": {"questions": ["Does ownership bind the object id?"]},
                        },
                    ],
                },
            )
            repository.save_pipeline_stage(
                pipeline_run_id=run.id,
                campaign_id=campaign.id,
                task_id=None,
                stage_key="campaign_report_preview",
                stage_order=1,
                status="completed",
                input_refs=[f"pipeline_run:{run.id}"],
                output_refs=[],
                safety_gate_state="manual_review_required",
                stop_reason=None,
                payload={},
            )
            repository.save_pipeline_stage(
                pipeline_run_id=run.id,
                campaign_id=campaign.id,
                task_id=None,
                stage_key="finding_promotion_blocked",
                stage_order=2,
                status="blocked",
                input_refs=[f"pipeline_run:{run.id}"],
                output_refs=[],
                safety_gate_state="manual_review_required",
                stop_reason="blocked_by_research_feedback_gate",
                payload={
                    "reason": "blocked_by_research_feedback_gate",
                    "blocked_stage_count": 1,
                    "provenance_ref_count": 4,
                    "finding_promotion_allowed": False,
                    "report_submission_allowed": False,
                    "raw_payload_processed": False,
                },
            )
            campaign_id = campaign.id

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["safe_next_action"] == "review_blocked_promotion"
        assert control_center["promotion_review"]["blocked_attempt_count"] == 1
        assert control_center["promotion_review"]["provenance_ref_count"] == 4
        assert control_center["execution_allowed"] is False
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_points_to_research_review_for_queued_review_tasks():
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
                name="Queued review campaign",
                autonomy_level="level_0_read_only",
                scope_status="in_scope",
                policy_text="Testing allowed.",
                default_asset="api.example.com",
                allowed_tools=["static_analyzer"],
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
                task_type="research_queue_review",
                agent_type="human_research_reviewer",
                title="Review advisory research queue",
                input_refs=["research_queue:idor_review"],
                payload={
                    "execution_allowed": False,
                    "dispatch_allowed": False,
                    "safety_gate": "advisory_memory_only",
                },
            )
            repository.update_campaign_task_status(task.id, "queued_review")
            campaign_id = campaign.id

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["safe_next_action"] == "review_ready_tasks"
        assert control_center["execution_allowed"] is False
        assert "dispatch_ready_tasks" not in str(control_center)
        assert '"execution_allowed": true' not in str(control_center).lower()
        assert '"dispatch_allowed": true' not in str(control_center).lower()
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_ignores_other_campaign_finding_candidates():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            source_campaign = repository.create_campaign(
                program_id="program_example",
                name="Source finding candidate campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed. Authorization: Bearer secret-token",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
            )
            unrelated_campaign = repository.create_campaign(
                program_id="program_example",
                name="Unrelated campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed. Authorization: Bearer other-secret-token",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
            )
            for campaign in [source_campaign, unrelated_campaign]:
                repository.update_campaign_status(campaign.id, "running")
                repository.upsert_campaign_budget(
                    campaign_id=campaign.id,
                    time_budget_minutes=30,
                    token_budget=1000,
                    tool_call_budget=10,
                    validation_budget=1,
                )
            source_campaign_id = source_campaign.id
            unrelated_campaign_id = unrelated_campaign.id

        dry_run_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert dry_run_response.status_code == 200
        run_id = dry_run_response.json()["run_id"]

        with testing_session() as session:
            repository = DatabaseRepository(session)
            repository.save_pipeline_stage(
                pipeline_run_id=run_id,
                campaign_id=source_campaign_id,
                task_id=None,
                stage_key="campaign_report_preview",
                stage_order=20,
                status="awaiting_review",
                input_refs=[f"campaign:{source_campaign_id}"],
                output_refs=[f"pipeline_run:{run_id}"],
                safety_gate_state="awaiting_review",
                stop_reason=None,
                payload={"submission_allowed": False, "raw_payload_processed": False},
            )

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        claim_id = next(
            claim["claim_id"]
            for claim in preview_response.json()["claim_ledger"]
            if claim["claim_type"] == "observed_fact"
        )

        observation_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/manual-observations",
            json={
                "claim_id": claim_id,
                "observation_type": "request_response_diff",
                "observer": "lead_reviewer",
                "observation": "Safe test-account diff showed an authorization boundary.",
                "evidence_refs": ["sanitized_request_response"],
                "safety_notes": ["test_accounts_only", "no_real_user_data"],
            },
        )
        assert observation_response.status_code == 200
        decision_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/claim-review-decisions",
            json={
                "claim_id": claim_id,
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Confirmed with sanitized fixture.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )
        assert decision_response.status_code == 200
        candidate_response = client.post(f"/mythos/pipeline/runs/{run_id}/finding-candidates")
        assert candidate_response.status_code == 200

        source_response = client.get(f"/mythos/campaigns/{source_campaign_id}/control-center")
        unrelated_response = client.get(f"/mythos/campaigns/{unrelated_campaign_id}/control-center")

        assert source_response.status_code == 200
        assert unrelated_response.status_code == 200
        assert source_response.json()["safe_next_action"] == "record_learning_outcome"
        unrelated_control_center = unrelated_response.json()
        assert unrelated_control_center["safe_next_action"] == "plan_next_tick"
        assert unrelated_control_center["execution_allowed"] is False
        assert "report_ready" not in str(unrelated_control_center)
        assert "secret-token" not in str(unrelated_control_center)
        assert "SECRET POLICY" not in str(unrelated_control_center)
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_reviews_learning_signal_without_finding_candidate():
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
                name="Learning signal campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed. Authorization: Bearer secret-token",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
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
            campaign_id = campaign.id

        dry_run_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert dry_run_response.status_code == 200
        run_id = dry_run_response.json()["run_id"]

        with testing_session() as session:
            repository = DatabaseRepository(session)
            repository.save_pipeline_stage(
                pipeline_run_id=run_id,
                campaign_id=campaign_id,
                task_id=None,
                stage_key="campaign_report_preview",
                stage_order=20,
                status="awaiting_review",
                input_refs=[f"campaign:{campaign_id}"],
                output_refs=[f"pipeline_run:{run_id}"],
                safety_gate_state="awaiting_review",
                stop_reason=None,
                payload={"submission_allowed": False, "raw_payload_processed": False},
            )

        outcome_response = client.post(
            "/mythos/brain/outcomes",
            json={
                "run_id": run_id,
                "outcome": "informative",
                "notes": "Informative safe fixture; Authorization: Bearer secret-token",
                "evidence_quality": "adequate",
            },
        )
        assert outcome_response.status_code == 200

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["safe_next_action"] == "review_learning_outcome"
        assert control_center["execution_allowed"] is False
        assert "Informative safe fixture" not in str(control_center)
        assert "secret-token" not in str(control_center)
        assert "SECRET POLICY" not in str(control_center)
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_requires_learning_outcome_audit_stage():
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
                name="Learning usage without audit campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed.",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
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
            campaign_id = campaign.id

        dry_run_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert dry_run_response.status_code == 200
        run_id = dry_run_response.json()["run_id"]
        artifact_id = dry_run_response.json()["artifact"]["artifact_id"]

        with testing_session() as session:
            repository = DatabaseRepository(session)
            repository.save_pipeline_stage(
                pipeline_run_id=run_id,
                campaign_id=campaign_id,
                task_id=None,
                stage_key="campaign_report_preview",
                stage_order=20,
                status="awaiting_review",
                input_refs=[f"campaign:{campaign_id}"],
                output_refs=[f"pipeline_run:{run_id}"],
                safety_gate_state="awaiting_review",
                stop_reason=None,
                payload={"submission_allowed": False, "raw_payload_processed": False},
            )
            signal = repository.save_learning_signal(
                program_id="program_example",
                playbook_id="bola_idor",
                outcome="accepted",
                surface_key="file_id:export",
                notes="Safe advisory learning fixture.",
                bounty_amount=None,
                severity_delta=None,
                evidence_quality="strong",
                triager_feedback=None,
                target_relationships=[],
            )
            repository.append_artifact_usage_records(
                artifact_id=artifact_id,
                usage_records=[
                    {
                        "usage_type": "learning_signal",
                        "ref": f"learning_signal:{signal.id}",
                        "run_id": run_id,
                        "stage": "mythos_brain",
                        "learning_signal_id": signal.id,
                        "outcome": "accepted",
                        "playbook_id": "bola_idor",
                        "surface_key": "file_id:export",
                    }
                ],
            )

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["safe_next_action"] != "review_learning_outcome"
        assert control_center["execution_allowed"] is False
        assert "report_ready" not in str(control_center)
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
        assert runs[0]["allowed_to_execute"] is False
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


def test_approval_decision_blocks_when_campaign_is_out_of_scope():
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
                name="Out of scope approval campaign",
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
                reason="Approve test-account validation.",
                requested_action="two_account_authorization_check",
                asset=campaign.default_asset,
                validation_mode="two_account_authorization_check",
                plan_digest="out_of_scope_approval_plan",
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
                plan_digest="out_of_scope_approval_plan",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Awaiting approval",
                payload={},
            )
            campaign.scope_status = "out_of_scope"
            session.add(campaign)
            session.commit()
            approval_id = approval.id
            validation_id = validation.id

        decision_response = client.post(
            f"/mythos/approvals/{approval_id}/decisions",
            json={
                "decision": "approved",
                "actor": "lead_reviewer",
                "reason": "Approved after scope changed.",
            },
        )

        assert decision_response.status_code == 409
        assert decision_response.json()["detail"] == "scope_not_in_scope"
        with testing_session() as session:
            approval = session.get(ApprovalRecord, approval_id)
            validation = DatabaseRepository(session).get_validation_run(validation_id)
            assert approval.status == "pending"
            assert validation.approval_id is None
            assert validation.status == "awaiting_approval"
            assert validation.safety_gate_state == "awaiting_approval"
            assert validation.allowed_to_execute is False
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
                payload=validation_scope_guard_payload(),
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
        assert body["validation_run"]["preflight_passed"] is True
        assert body["validation_run"]["allowed_to_execute"] is True
        assert body["validation_run"]["execution_started"] is False
        assert body["execution_started"] is False
        assert "secret-token" not in str(body)
        assert "session=secret" not in str(body)
    finally:
        app.dependency_overrides.clear()


def test_validation_run_preflight_blocks_exhausted_validation_budget_after_approval():
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
                name="Budgeted preflight campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
                payload=validation_scope_guard_payload(),
            )
            repository.upsert_campaign_budget(
                campaign_id=campaign.id,
                time_budget_minutes=30,
                token_budget=1000,
                tool_call_budget=10,
                validation_budget=0,
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
                plan_digest="plan_digest_budget_exhausted_preflight",
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
                plan_digest="plan_digest_budget_exhausted_preflight",
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
            "reason": "budget_exhausted",
        }
        assert body["validation_run"]["status"] == "blocked"
        assert body["validation_run"]["safety_gate_state"] == "blocked"
        assert body["validation_run"]["allowed_to_execute"] is False
        assert body["execution_started"] is False
    finally:
        app.dependency_overrides.clear()


def test_validation_run_preflight_blocks_consumed_campaign_validation_budget():
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
                name="Consumed validation budget campaign",
                autonomy_level="level_1_local_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                allowed_tools=["static_analyzer"],
                created_by="operator",
                payload=validation_scope_guard_payload(
                    allowed_validation=["static_analyzer"]
                ),
            )
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
            first_validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="static_analyzer",
                target_ref=f"campaign:{campaign.id}",
                status="ready",
                safety_gate_state="allowed",
                plan_digest="plan_digest_campaign_budget_first",
                approval_required=False,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="First local validation",
                payload={},
            )
            second_validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="static_analyzer",
                target_ref=f"campaign:{campaign.id}",
                status="ready",
                safety_gate_state="allowed",
                plan_digest="plan_digest_campaign_budget_second",
                approval_required=False,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Second local validation should exceed campaign budget",
                payload={},
            )
            first_validation_id = first_validation.id
            second_validation_id = second_validation.id

        first_preflight_response = client.post(
            f"/mythos/validation-runs/{first_validation_id}/preflight"
        )
        assert first_preflight_response.status_code == 200
        assert first_preflight_response.json()["decision"] == {
            "allowed": True,
            "reason": "allowed_validation",
        }

        first_result_response = client.post(
            f"/mythos/validation-runs/{first_validation_id}/manual-results",
            json={
                "outcome": "needs_more_evidence",
                "reviewer": "lead_reviewer",
                "summary": "Campaign validation budget has been consumed.",
                "evidence_refs": [],
            },
        )
        assert first_result_response.status_code == 200

        second_preflight_response = client.post(
            f"/mythos/validation-runs/{second_validation_id}/preflight"
        )

        assert second_preflight_response.status_code == 200
        body = second_preflight_response.json()
        assert body["decision"] == {
            "allowed": False,
            "reason": "budget_exhausted",
        }
        assert body["validation_run"]["status"] == "blocked"
        assert body["validation_run"]["safety_gate_state"] == "blocked"
        assert body["validation_run"]["allowed_to_execute"] is False
        assert body["execution_started"] is False

        control_response = client.get(
            f"/mythos/campaigns/{body['validation_run']['campaign_id']}/control-center"
        )
        assert control_response.status_code == 200
        control_center = control_response.json()
        assert control_center["budget"]["validation_budget"] == 1
        assert control_center["budget"]["validation_budget_used"] == 1
        assert control_center["budget"]["validation_budget_remaining"] == 0
        assert "budget_exhausted" in control_center["blocked_reasons"]
    finally:
        app.dependency_overrides.clear()


def test_validation_run_preflight_matches_approval_with_safe_url_asset():
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
                name="URL asset preflight campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="https://api.example.com/path?session=secret",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
                payload=validation_scope_guard_payload(
                    asset="https://api.example.com/path"
                ),
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
                asset="https://api.example.com/path?session=secret",
                validation_mode="two_account_authorization_check",
                plan_digest="plan_digest_url_asset_preflight",
                autonomy_level=campaign.autonomy_level,
                safety_gate_state="awaiting_approval",
            )
            validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="two_account_authorization_check",
                target_ref="https://api.example.com/path?session=secret",
                status="planned",
                safety_gate_state="awaiting_approval",
                plan_digest="plan_digest_url_asset_preflight",
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
            "allowed": True,
            "reason": "approved_validation_record",
        }
        assert body["validation_run"]["id"] == validation_id
        assert body["validation_run"]["status"] == "preflight_passed"
        assert body["validation_run"]["allowed_to_execute"] is True
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
                payload=validation_scope_guard_payload(allowed_validation=[]),
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


def test_validation_run_preflight_blocks_expired_approval_record():
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
                name="Expired approval preflight campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
                payload=validation_scope_guard_payload(),
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
                plan_digest="plan_digest_expired_preflight",
                autonomy_level=campaign.autonomy_level,
                safety_gate_state="awaiting_approval",
                expires_at=datetime.now(UTC) - timedelta(minutes=1),
            )
            validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="planned",
                safety_gate_state="awaiting_approval",
                plan_digest="plan_digest_expired_preflight",
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
                "reason": "Approved for a short window.",
            },
        )
        assert decision_response.status_code == 409
        assert decision_response.json()["detail"] == "Approval record expired"

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
        assert body["validation_run"]["safety_gate_state"] == "blocked"
        assert body["validation_run"]["allowed_to_execute"] is False
        assert body["execution_started"] is False
    finally:
        app.dependency_overrides.clear()


def test_validation_run_preflight_blocks_mismatched_scope_reference():
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
                name="Scope reference approval campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
                payload=validation_scope_guard_payload(),
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
                reason="Approve only the cited policy scope.",
                scope_reference="policy:in-scope-api",
                requested_action="two_account_authorization_check",
                asset=campaign.default_asset,
                validation_mode="two_account_authorization_check",
                plan_digest="plan_digest_scope_reference",
                autonomy_level=campaign.autonomy_level,
                safety_gate_state="awaiting_approval",
            )
            validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=approval.id,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="ready",
                safety_gate_state="approved_validation_record",
                plan_digest="plan_digest_scope_reference",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Incorrectly bound approval should not pass preflight",
                payload={"scope_reference": "policy:other-asset"},
            )
            approval_id = approval.id
            validation_id = validation.id

        decision_response = client.post(
            f"/mythos/approvals/{approval_id}/decisions",
            json={
                "decision": "approved",
                "actor": "lead_reviewer",
                "reason": "Approved for the cited policy scope only.",
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
            "reason": "approval_record_required",
        }
        assert body["validation_run"]["status"] == "blocked"
        assert body["validation_run"]["safety_gate_state"] == "blocked"
        assert body["validation_run"]["allowed_to_execute"] is False
        assert body["execution_started"] is False
    finally:
        app.dependency_overrides.clear()


def test_validation_run_preflight_blocks_unapproved_allowed_accounts():
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
                name="Allowed accounts preflight campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
                payload=validation_scope_guard_payload(),
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
                reason="Approve only selected test accounts.",
                requested_action="two_account_authorization_check",
                asset=campaign.default_asset,
                validation_mode="two_account_authorization_check",
                plan_digest="plan_digest_allowed_accounts_preflight",
                autonomy_level=campaign.autonomy_level,
                safety_gate_state="awaiting_approval",
                payload={"allowed_accounts": ["owner_test", "member_test"]},
            )
            validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=approval.id,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="ready",
                safety_gate_state="approved_validation_record",
                plan_digest="plan_digest_allowed_accounts_preflight",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Incorrect account binding should not pass preflight",
                payload={"allowed_accounts": ["owner_test", "outside_test"]},
            )
            approval_id = approval.id
            validation_id = validation.id

        decision_response = client.post(
            f"/mythos/approvals/{approval_id}/decisions",
            json={
                "decision": "approved",
                "actor": "lead_reviewer",
                "reason": "Approved for selected test accounts only.",
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
            "reason": "approval_record_required",
        }
        assert body["validation_run"]["status"] == "blocked"
        assert body["validation_run"]["safety_gate_state"] == "blocked"
        assert body["validation_run"]["allowed_to_execute"] is False
        assert body["execution_started"] is False
    finally:
        app.dependency_overrides.clear()


def test_validation_run_preflight_blocks_exhausted_approval_validation_budget():
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
                name="Approval budget preflight campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
                payload=validation_scope_guard_payload(),
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
                reason="Approve one validation run.",
                requested_action="two_account_authorization_check",
                asset=campaign.default_asset,
                validation_mode="two_account_authorization_check",
                plan_digest="plan_digest_approval_budget_preflight",
                autonomy_level=campaign.autonomy_level,
                safety_gate_state="awaiting_approval",
                payload={"validation_budget": 1},
            )
            first_validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=approval.id,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="preflight_passed",
                safety_gate_state="scope_guard_preflight_passed",
                plan_digest="plan_digest_approval_budget_preflight",
                approval_required=True,
                allowed_to_execute=True,
                evidence_ref_count=0,
                summary="Already consumed approval budget",
                payload={},
            )
            second_validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=approval.id,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="ready",
                safety_gate_state="approved_validation_record",
                plan_digest="plan_digest_approval_budget_preflight",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Should not pass once approval budget is consumed",
                payload={},
            )
            approval_id = approval.id
            first_validation_id = first_validation.id
            second_validation_id = second_validation.id

        decision_response = client.post(
            f"/mythos/approvals/{approval_id}/decisions",
            json={
                "decision": "approved",
                "actor": "lead_reviewer",
                "reason": "Approved for one validation run only.",
            },
        )
        assert decision_response.status_code == 200

        first_result_response = client.post(
            f"/mythos/validation-runs/{first_validation_id}/manual-results",
            json={
                "outcome": "needs_more_evidence",
                "reviewer": "lead_reviewer",
                "summary": "Budget-consuming run was reviewed.",
                "evidence_refs": [],
            },
        )
        assert first_result_response.status_code == 200

        preflight_response = client.post(
            f"/mythos/validation-runs/{second_validation_id}/preflight"
        )

        assert preflight_response.status_code == 200
        body = preflight_response.json()
        assert body["decision"] == {
            "allowed": False,
            "reason": "approval_budget_exhausted",
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
                payload=validation_scope_guard_payload(allowed_validation=[]),
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
                payload=validation_scope_guard_payload(),
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
                payload=validation_scope_guard_payload(),
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


def test_validation_run_manual_result_records_redacted_evidence_after_preflight():
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
                name="Manual result campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
                payload=validation_scope_guard_payload(),
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
                plan_digest="manual_result_plan",
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
                plan_digest="manual_result_plan",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Awaiting approval",
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
        preflight_response = client.post(
            f"/mythos/validation-runs/{validation_id}/preflight"
        )
        assert preflight_response.status_code == 200
        assert preflight_response.json()["decision"]["allowed"] is True

        result_response = client.post(
            f"/mythos/validation-runs/{validation_id}/manual-results",
            json={
                "outcome": "observed",
                "reviewer": "lead_reviewer",
                "summary": "Observed safe diff; Authorization: Bearer secret-token",
                "evidence_refs": [
                    "sanitized_request_response",
                    "Cookie: session=secret",
                ],
            },
        )

        assert result_response.status_code == 200
        result = result_response.json()
        assert result["status"] == "evidence_recorded"
        assert result["safety_gate_state"] == "manual_evidence_recorded"
        assert result["allowed_to_execute"] is False
        assert result["evidence_ref_count"] == 1
        assert result["summary"] == "Manual validation result recorded: observed"
        assert "secret-token" not in str(result)
        assert "session=secret" not in str(result)

        runs_response = client.get(f"/mythos/campaigns/{campaign_id}/validation-runs")
        assert runs_response.status_code == 200
        runs = runs_response.json()
        assert runs[0]["id"] == validation_id
        assert runs[0]["status"] == "evidence_recorded"
        assert runs[0]["evidence_ref_count"] == 1
        assert "secret-token" not in str(runs)
        assert "session=secret" not in str(runs)

        stages_response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")
        assert stages_response.status_code == 200
        stages = stages_response.json()
        manual_result_stages = [
            stage for stage in stages if stage["stage_key"] == "validation_manual_result"
        ]
        assert len(manual_result_stages) == 1
        assert manual_result_stages[0]["status"] == "evidence_recorded"
        assert manual_result_stages[0]["safety_gate_state"] == "manual_evidence_recorded"
        assert manual_result_stages[0]["output_refs"] == [f"validation_run:{validation_id}"]
        assert manual_result_stages[0]["payload"] == {
            "outcome": "observed",
            "reviewer": "lead_reviewer",
            "evidence_ref_count": 1,
            "execution_started": False,
            "validation_result_review": {
                "source_type": "manual_safe_observation",
                "redaction_status": "redacted",
                "evidence_quality": "adequate",
                "quality_score": 45,
                "promotion_review_ready": False,
                "quality_reasons": [
                    "manual_result_recorded",
                    "has_report_safe_evidence",
                    "sensitive_material_redacted",
                    "promotion_blocked_by_redaction_review",
                    "unsupported_evidence_refs",
                    "promotion_blocked_by_unsupported_evidence",
                ],
                "safe_evidence_ref_count": 1,
                "unsafe_evidence_ref_count": 1,
            },
        }
        assert "secret-token" not in str(stages)
        assert "session=secret" not in str(stages)

        with testing_session() as session:
            stored_run = session.get(ValidationRunRecord, validation_id)
            assert stored_run.payload["validation_result_review"] == {
                "source_type": "manual_safe_observation",
                "redaction_status": "redacted",
                "evidence_quality": "adequate",
                "quality_score": 45,
                "promotion_review_ready": False,
                "quality_reasons": [
                    "manual_result_recorded",
                    "has_report_safe_evidence",
                    "sensitive_material_redacted",
                    "promotion_blocked_by_redaction_review",
                    "unsupported_evidence_refs",
                    "promotion_blocked_by_unsupported_evidence",
                ],
                "safe_evidence_ref_count": 1,
                "unsafe_evidence_ref_count": 1,
            }
            assert "secret-token" not in str(stored_run.payload)
            assert "session=secret" not in str(stored_run.payload)
    finally:
        app.dependency_overrides.clear()


def test_validation_run_manual_result_retry_reuses_record_without_duplicate_feedback():
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
                name="Manual result retry campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
                payload=validation_scope_guard_payload(),
            )
            repository.update_campaign_status(campaign.id, "running")
            repository.upsert_campaign_budget(
                campaign_id=campaign.id,
                time_budget_minutes=30,
                token_budget=1000,
                tool_call_budget=10,
                validation_budget=3,
            )
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="report_chain_review",
                agent_type="report_agent",
                title="Review validation retry",
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
                plan_digest="manual_result_retry_plan",
                autonomy_level=campaign.autonomy_level,
                safety_gate_state="awaiting_approval",
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
            validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="planned",
                safety_gate_state="awaiting_approval",
                plan_digest="manual_result_retry_plan",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Awaiting approval",
                payload={
                    "source": "research_task_refutation_decision",
                    "plan_id": "plan_retry",
                    "decision_id": "decision_retry",
                    "approval_record_id": approval.id,
                },
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
        preflight_response = client.post(
            f"/mythos/validation-runs/{validation_id}/preflight"
        )
        assert preflight_response.status_code == 200
        assert preflight_response.json()["decision"]["allowed"] is True

        manual_result_payload = {
            "outcome": "observed",
            "reviewer": "lead_reviewer",
            "summary": "Observed safe diff.",
            "evidence_refs": ["sanitized_request_response"],
        }
        first_response = client.post(
            f"/mythos/validation-runs/{validation_id}/manual-results",
            json=manual_result_payload,
        )
        retry_response = client.post(
            f"/mythos/validation-runs/{validation_id}/manual-results",
            json=manual_result_payload,
        )

        assert first_response.status_code == 200
        assert retry_response.status_code == 200
        assert retry_response.json()["id"] == validation_id
        assert retry_response.json()["status"] == "evidence_recorded"

        stages_response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")
        assert stages_response.status_code == 200
        stage_keys = [stage["stage_key"] for stage in stages_response.json()]
        assert stage_keys.count("validation_manual_result") == 1
        assert stage_keys.count("research_task_validation_feedback") == 1
    finally:
        app.dependency_overrides.clear()


def test_validation_run_manual_result_retry_blocks_when_scope_changes_after_recording():
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
                name="Manual result retry scope changed campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
                payload=validation_scope_guard_payload(),
            )
            repository.update_campaign_status(campaign.id, "running")
            repository.upsert_campaign_budget(
                campaign_id=campaign.id,
                time_budget_minutes=30,
                token_budget=1000,
                tool_call_budget=10,
                validation_budget=3,
            )
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="report_chain_review",
                agent_type="report_agent",
                title="Review validation retry after scope change",
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
                plan_digest="manual_result_retry_scope_changed_plan",
                autonomy_level=campaign.autonomy_level,
                safety_gate_state="awaiting_approval",
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
            validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="planned",
                safety_gate_state="awaiting_approval",
                plan_digest="manual_result_retry_scope_changed_plan",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Awaiting approval",
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
        preflight_response = client.post(
            f"/mythos/validation-runs/{validation_id}/preflight"
        )
        assert preflight_response.status_code == 200
        assert preflight_response.json()["decision"]["allowed"] is True

        manual_result_payload = {
            "outcome": "observed",
            "reviewer": "lead_reviewer",
            "summary": "Observed safe diff.",
            "evidence_refs": ["sanitized_request_response"],
        }
        first_response = client.post(
            f"/mythos/validation-runs/{validation_id}/manual-results",
            json=manual_result_payload,
        )
        assert first_response.status_code == 200
        with testing_session() as session:
            repository = DatabaseRepository(session)
            stage_keys_after_first_result = [
                stage.stage_key
                for stage in repository.list_campaign_pipeline_stages(campaign_id)
            ]

        with testing_session() as session:
            campaign = session.get(CampaignRecord, campaign_id)
            campaign.scope_status = "out_of_scope"
            session.add(campaign)
            session.commit()

        retry_response = client.post(
            f"/mythos/validation-runs/{validation_id}/manual-results",
            json=manual_result_payload,
        )

        assert retry_response.status_code == 409
        assert retry_response.json()["detail"] == "scope_not_in_scope"

        with testing_session() as session:
            repository = DatabaseRepository(session)
            stage_keys = [
                stage.stage_key
                for stage in repository.list_campaign_pipeline_stages(campaign_id)
            ]
            assert stage_keys == stage_keys_after_first_result
            assert stage_keys.count("validation_manual_result") == 1
    finally:
        app.dependency_overrides.clear()


def test_validation_run_manual_result_retry_rejects_different_payload_after_recording():
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
                name="Manual result changed retry campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
                payload=validation_scope_guard_payload(),
            )
            repository.update_campaign_status(campaign.id, "running")
            repository.upsert_campaign_budget(
                campaign_id=campaign.id,
                time_budget_minutes=30,
                token_budget=1000,
                tool_call_budget=10,
                validation_budget=3,
            )
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="report_chain_review",
                agent_type="report_agent",
                title="Review changed validation retry",
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
                plan_digest="manual_result_changed_retry_plan",
                autonomy_level=campaign.autonomy_level,
                safety_gate_state="awaiting_approval",
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
            validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="planned",
                safety_gate_state="awaiting_approval",
                plan_digest="manual_result_changed_retry_plan",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Awaiting approval",
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
        preflight_response = client.post(
            f"/mythos/validation-runs/{validation_id}/preflight"
        )
        assert preflight_response.status_code == 200
        assert preflight_response.json()["decision"]["allowed"] is True

        first_response = client.post(
            f"/mythos/validation-runs/{validation_id}/manual-results",
            json={
                "outcome": "observed",
                "reviewer": "lead_reviewer",
                "summary": "Observed safe diff.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )
        changed_retry_response = client.post(
            f"/mythos/validation-runs/{validation_id}/manual-results",
            json={
                "outcome": "observed",
                "reviewer": "lead_reviewer",
                "summary": "Trying to change the audited result.",
                "evidence_refs": ["different_sanitized_request_response"],
            },
        )

        assert first_response.status_code == 200
        assert changed_retry_response.status_code == 409
        assert (
            changed_retry_response.json()["detail"]
            == "Validation run preflight has not passed"
        )

        stages_response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")
        assert stages_response.status_code == 200
        stage_keys = [stage["stage_key"] for stage in stages_response.json()]
        assert stage_keys.count("validation_manual_result") == 1
    finally:
        app.dependency_overrides.clear()


def test_validation_run_manual_result_blocks_when_campaign_scope_changes_after_preflight():
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
                name="Manual result out of scope campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
                payload=validation_scope_guard_payload(),
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
                plan_digest="manual_result_scope_changed_plan",
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
                plan_digest="manual_result_scope_changed_plan",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Awaiting approval",
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
        preflight_response = client.post(
            f"/mythos/validation-runs/{validation_id}/preflight"
        )
        assert preflight_response.status_code == 200
        assert preflight_response.json()["decision"]["allowed"] is True

        with testing_session() as session:
            repository = DatabaseRepository(session)
            scoped_campaign = repository.get_campaign(campaign_id)
            scoped_campaign.scope_status = "out_of_scope"
            session.add(scoped_campaign)
            session.commit()

        runs_response = client.get(f"/mythos/campaigns/{campaign_id}/validation-runs")
        assert runs_response.status_code == 200
        scoped_run = runs_response.json()[0]
        assert scoped_run["id"] == validation_id
        assert scoped_run["preflight_passed"] is True
        assert scoped_run["allowed_to_execute"] is False

        control_center_response = client.get(
            f"/mythos/campaigns/{campaign_id}/control-center"
        )
        assert control_center_response.status_code == 200
        control_center_run = control_center_response.json()["validation_runs"][0]
        assert control_center_run["id"] == validation_id
        assert control_center_run["allowed_to_execute"] is False

        result_response = client.post(
            f"/mythos/validation-runs/{validation_id}/manual-results",
            json={
                "outcome": "observed",
                "reviewer": "lead_reviewer",
                "summary": "Should not record after scope changed.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )

        assert result_response.status_code == 409
        assert result_response.json()["detail"] == "scope_not_in_scope"

        with testing_session() as session:
            repository = DatabaseRepository(session)
            validation = repository.get_validation_run(validation_id)
            assert validation.status == "preflight_passed"
            assert validation.evidence_ref_count == 0
            manual_result_stages = [
                stage
                for stage in repository.list_campaign_pipeline_stages(campaign_id)
                if stage.stage_key == "validation_manual_result"
            ]
            assert manual_result_stages == []
    finally:
        app.dependency_overrides.clear()


def test_validation_run_manual_result_keeps_redacted_only_evidence_in_gap_state():
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
                name="Manual result evidence gap campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
                payload=validation_scope_guard_payload(),
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
                plan_digest="manual_result_gap_plan",
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
                plan_digest="manual_result_gap_plan",
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

        result_response = client.post(
            f"/mythos/validation-runs/{validation_id}/manual-results",
            json={
                "outcome": "observed",
                "reviewer": "lead_reviewer",
                "summary": "Observed only sensitive evidence refs.",
                "evidence_refs": [
                    "Authorization: Bearer secret-token",
                    "Cookie: session=secret",
                ],
            },
        )

        assert result_response.status_code == 200
        result = result_response.json()
        assert result["status"] == "needs_evidence"
        assert result["safety_gate_state"] == "manual_evidence_gap_recorded"
        assert result["allowed_to_execute"] is False
        assert result["evidence_ref_count"] == 0
        assert "secret-token" not in str(result)
        assert "session=secret" not in str(result)
    finally:
        app.dependency_overrides.clear()


def test_validation_run_manual_result_ignores_unsupported_evidence_refs_for_status():
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
                name="Manual result unsupported evidence campaign",
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
            validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="local_code_review",
                target_ref=f"campaign:{campaign.id}",
                status="preflight_passed",
                safety_gate_state="scope_guard_preflight_passed",
                plan_digest="manual_result_unsupported_ref_plan",
                approval_required=False,
                allowed_to_execute=True,
                evidence_ref_count=0,
                summary="Preflight passed",
                payload={},
            )
            validation_id = validation.id

        result_response = client.post(
            f"/mythos/validation-runs/{validation_id}/manual-results",
            json={
                "outcome": "observed",
                "reviewer": "lead_reviewer",
                "summary": "Unsupported evidence refs must stay advisory.",
                "evidence_refs": ["unsupported_screenshot_ref"],
            },
        )

        assert result_response.status_code == 200
        result = result_response.json()
        assert result["status"] == "needs_evidence"
        assert result["safety_gate_state"] == "manual_evidence_gap_recorded"
        assert result["allowed_to_execute"] is False
        assert result["evidence_ref_count"] == 0
    finally:
        app.dependency_overrides.clear()


def test_validation_run_manual_result_requires_preflight_passed_state():
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
                name="Manual result blocked campaign",
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
            validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="ready",
                safety_gate_state="approved_validation_record",
                plan_digest="manual_result_blocked_plan",
                approval_required=True,
                allowed_to_execute=True,
                evidence_ref_count=0,
                summary="Ready but not preflighted",
                payload={},
            )
            validation_id = validation.id

        result_response = client.post(
            f"/mythos/validation-runs/{validation_id}/manual-results",
            json={
                "outcome": "observed",
                "reviewer": "lead_reviewer",
                "summary": "Should not record before preflight.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )

        assert result_response.status_code == 409
        assert result_response.json()["detail"] == "Validation run preflight has not passed"
    finally:
        app.dependency_overrides.clear()


def test_validation_run_response_blocks_no_approval_run_when_campaign_scope_changes():
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
                name="No approval scope changed campaign",
                autonomy_level="level_1_local_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                created_by="operator",
            )
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="report_chain_review",
                agent_type="report_agent",
                title="Review local validation gate",
                input_refs=[f"campaign:{campaign.id}"],
                payload={},
            )
            validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="static_analyzer",
                target_ref=f"campaign:{campaign.id}",
                status="preflight_passed",
                safety_gate_state="scope_guard_preflight_passed",
                plan_digest="no_approval_scope_changed_plan",
                approval_required=False,
                allowed_to_execute=True,
                evidence_ref_count=0,
                summary="Local validation preflight passed.",
                payload={},
            )
            campaign.scope_status = "out_of_scope"
            session.add(campaign)
            session.commit()
            campaign_id = campaign.id
            validation_id = validation.id

        runs_response = client.get(f"/mythos/campaigns/{campaign_id}/validation-runs")
        assert runs_response.status_code == 200
        run = runs_response.json()[0]
        assert run["id"] == validation_id
        assert run["preflight_passed"] is True
        assert run["allowed_to_execute"] is False

        control_center_response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")
        assert control_center_response.status_code == 200
        control_run = control_center_response.json()["validation_runs"][0]
        assert control_run["id"] == validation_id
        assert control_run["allowed_to_execute"] is False
    finally:
        app.dependency_overrides.clear()


def test_validation_run_manual_result_blocks_no_approval_run_when_campaign_scope_changes():
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
                name="No approval manual result scope changed campaign",
                autonomy_level="level_1_local_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                created_by="operator",
            )
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="report_chain_review",
                agent_type="report_agent",
                title="Review local validation gate",
                input_refs=[f"campaign:{campaign.id}"],
                payload={},
            )
            validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="static_analyzer",
                target_ref=f"campaign:{campaign.id}",
                status="preflight_passed",
                safety_gate_state="scope_guard_preflight_passed",
                plan_digest="no_approval_manual_result_scope_changed_plan",
                approval_required=False,
                allowed_to_execute=True,
                evidence_ref_count=0,
                summary="Local validation preflight passed.",
                payload={},
            )
            campaign.scope_status = "out_of_scope"
            session.add(campaign)
            session.commit()
            campaign_id = campaign.id
            validation_id = validation.id

        result_response = client.post(
            f"/mythos/validation-runs/{validation_id}/manual-results",
            json={
                "outcome": "observed",
                "reviewer": "lead_reviewer",
                "summary": "Should not record after scope changed.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )

        assert result_response.status_code == 409
        assert result_response.json()["detail"] == "scope_not_in_scope"

        with testing_session() as session:
            repository = DatabaseRepository(session)
            validation = repository.get_validation_run(validation_id)
            assert validation is not None
            assert validation.status == "preflight_passed"
            assert validation.evidence_ref_count == 0
            stage_keys = [
                stage.stage_key
                for stage in repository.list_campaign_pipeline_stages(campaign_id)
            ]
            assert "validation_manual_result" not in stage_keys
            assert "research_task_validation_feedback" not in stage_keys
    finally:
        app.dependency_overrides.clear()


def test_validation_run_manual_result_requires_active_preflight_permission():
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
                name="Stale preflight campaign",
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
            validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="preflight_passed",
                safety_gate_state="scope_guard_preflight_passed",
                plan_digest="manual_result_stale_preflight_plan",
                approval_required=False,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Stale preflight state",
                payload={},
            )
            validation_id = validation.id

        result_response = client.post(
            f"/mythos/validation-runs/{validation_id}/manual-results",
            json={
                "outcome": "observed",
                "reviewer": "lead_reviewer",
                "summary": "Should not record from stale preflight.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )

        assert result_response.status_code == 409
        assert result_response.json()["detail"] == "Validation run preflight is not active"
    finally:
        app.dependency_overrides.clear()


def test_validation_run_preflight_after_manual_result_is_rejected_without_mutation():
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
                name="Preflight after manual result campaign",
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
            validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="preflight_passed",
                safety_gate_state="scope_guard_preflight_passed",
                plan_digest="preflight_after_manual_result_plan",
                approval_required=False,
                allowed_to_execute=True,
                evidence_ref_count=0,
                summary="Preflight passed",
                payload={
                    "scope_guard_preflight": {
                        "allowed": True,
                        "reason": "human_controlled_preflight",
                    },
                },
            )
            validation_id = validation.id

        result_response = client.post(
            f"/mythos/validation-runs/{validation_id}/manual-results",
            json={
                "outcome": "observed",
                "reviewer": "lead_reviewer",
                "summary": "Observed safe diff.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )
        assert result_response.status_code == 200

        with testing_session() as session:
            repository = DatabaseRepository(session)
            stored = repository.get_validation_run(validation_id)
            assert stored is not None
            original_status = stored.status
            original_safety_gate_state = stored.safety_gate_state
            original_allowed_to_execute = stored.allowed_to_execute
            original_finished_at = stored.finished_at
            original_payload = dict(stored.payload)

        preflight_response = client.post(
            f"/mythos/validation-runs/{validation_id}/preflight"
        )

        assert preflight_response.status_code == 409
        assert preflight_response.json()["detail"] == "Validation run already has manual result"

        with testing_session() as session:
            repository = DatabaseRepository(session)
            stored = repository.get_validation_run(validation_id)
            assert stored is not None
            assert stored.status == original_status
            assert stored.safety_gate_state == original_safety_gate_state
            assert stored.allowed_to_execute == original_allowed_to_execute
            assert stored.finished_at == original_finished_at
            assert stored.payload == original_payload
    finally:
        app.dependency_overrides.clear()


def test_validation_run_manual_result_requires_active_approval_after_preflight():
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
                name="Expired post-preflight approval campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
                payload=validation_scope_guard_payload(),
            )
            repository.update_campaign_status(campaign.id, "running")
            repository.upsert_campaign_budget(
                campaign_id=campaign.id,
                time_budget_minutes=30,
                token_budget=1000,
                tool_call_budget=10,
                validation_budget=3,
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
                plan_digest="manual_result_expired_approval_plan",
                autonomy_level=campaign.autonomy_level,
                safety_gate_state="awaiting_approval",
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
            validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="planned",
                safety_gate_state="awaiting_approval",
                plan_digest="manual_result_expired_approval_plan",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Awaiting approval",
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
        preflight_response = client.post(
            f"/mythos/validation-runs/{validation_id}/preflight"
        )
        assert preflight_response.status_code == 200
        assert preflight_response.json()["decision"]["allowed"] is True

        with testing_session() as session:
            approval = session.get(ApprovalRecord, approval_id)
            assert approval is not None
            approval.expires_at = datetime.now(UTC) - timedelta(minutes=1)
            session.add(approval)
            session.commit()

        runs_response = client.get(f"/mythos/campaigns/{campaign_id}/validation-runs")
        assert runs_response.status_code == 200
        expired_run = runs_response.json()[0]
        assert expired_run["id"] == validation_id
        assert expired_run["preflight_passed"] is True
        assert expired_run["allowed_to_execute"] is False

        control_center_response = client.get(
            f"/mythos/campaigns/{campaign_id}/control-center"
        )
        assert control_center_response.status_code == 200
        control_center_run = control_center_response.json()["validation_runs"][0]
        assert control_center_run["id"] == validation_id
        assert control_center_run["allowed_to_execute"] is False
        assert control_center_response.json()["safe_next_action"] == "review_validation_queue"

        result_response = client.post(
            f"/mythos/validation-runs/{validation_id}/manual-results",
            json={
                "outcome": "observed",
                "reviewer": "lead_reviewer",
                "summary": "Should not record after approval expiry.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )

        assert result_response.status_code == 409
        assert result_response.json()["detail"] == "Validation run approval is not active"

        stages_response = client.get(f"/mythos/campaigns/{campaign_id}/pipeline-stages")
        assert stages_response.status_code == 200
        stage_keys = [stage["stage_key"] for stage in stages_response.json()]
        assert "validation_manual_result" not in stage_keys
        assert "research_task_validation_feedback" not in stage_keys
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_points_to_evidence_review_after_manual_evidence():
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
                name="Evidence review campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
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
            approval = repository.create_approval_record(
                campaign_id=campaign.id,
                task_id=task.id,
                program_id=campaign.program_id,
                approval_type="validation_batch",
                actor="operator",
                reason="Approved evidence review validation",
                requested_action="two_account_authorization_check",
                asset=campaign.default_asset,
                validation_mode="two_account_authorization_check",
                plan_digest="evidence_review_plan",
                autonomy_level=campaign.autonomy_level,
                safety_gate_state="approved_validation_record",
            )
            repository.decide_approval_record(
                approval_id=approval.id,
                decision="approved",
                actor="lead_reviewer",
                reason="Approved for test accounts only.",
            )
            repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=approval.id,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="evidence_recorded",
                safety_gate_state="manual_evidence_recorded",
                plan_digest="evidence_review_plan",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=2,
                summary="Manual validation result recorded: observed",
                payload={
                    "manual_result": {
                        "summary": "Observed safe diff; Authorization: Bearer secret-token",
                        "evidence_refs": ["Cookie: session=secret"],
                    }
                },
            )
            campaign_id = campaign.id

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["safe_next_action"] == "review_evidence_or_report_drafts"
        assert control_center["validation_runs"][0]["id"].startswith("validation_run_")
        assert control_center["validation_runs"][0]["status"] == "evidence_recorded"
        assert control_center["validation_runs"][0]["evidence_ref_count"] == 2
        assert control_center["execution_allowed"] is False
        assert "secret-token" not in str(control_center)
        assert "session=secret" not in str(control_center)
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_ignores_manual_evidence_status_without_audited_result():
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
                name="Unaudited evidence status campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
                created_by="operator",
            )
            repository.update_campaign_status(campaign.id, "running")
            repository.upsert_campaign_budget(
                campaign_id=campaign.id,
                time_budget_minutes=30,
                token_budget=1000,
                tool_call_budget=10,
                validation_budget=3,
            )
            validation_run = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=None,
                approval_id=None,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="evidence_recorded",
                safety_gate_state="manual_evidence_recorded",
                plan_digest="unaudited_evidence_status",
                approval_required=False,
                allowed_to_execute=False,
                evidence_ref_count=2,
                summary="Legacy status without audited manual result.",
                payload={},
            )
            campaign_id = campaign.id
            validation_run_id = validation_run.id

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["safe_next_action"] == "plan_next_tick"
        assert control_center["validation_runs"][0]["id"] == validation_run_id
        assert control_center["validation_runs"][0]["status"] == "evidence_recorded"
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_prioritizes_manual_evidence_over_learning_review():
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
                name="Evidence before learning campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="Testing allowed. Authorization: Bearer secret-token",
                default_asset="api.example.com",
                allowed_tools=["two_account_authorization_check"],
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
            approval = repository.create_approval_record(
                campaign_id=campaign.id,
                task_id=task.id,
                program_id=campaign.program_id,
                approval_type="validation_batch",
                actor="operator",
                reason="Approved evidence review validation",
                requested_action="two_account_authorization_check",
                asset=campaign.default_asset,
                validation_mode="two_account_authorization_check",
                plan_digest="manual_evidence_before_learning",
                autonomy_level=campaign.autonomy_level,
                safety_gate_state="approved_validation_record",
            )
            repository.decide_approval_record(
                approval_id=approval.id,
                decision="approved",
                actor="lead_reviewer",
                reason="Approved for test accounts only.",
            )
            repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=approval.id,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="evidence_recorded",
                safety_gate_state="manual_evidence_recorded",
                plan_digest="manual_evidence_before_learning",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=1,
                summary="Manual validation result recorded: observed",
                payload={
                    "manual_result": {
                        "summary": "Observed safe diff; Authorization: Bearer secret-token",
                        "evidence_refs": ["Cookie: session=secret"],
                    }
                },
            )
            campaign_id = campaign.id

        dry_run_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert dry_run_response.status_code == 200
        run_id = dry_run_response.json()["run_id"]

        with testing_session() as session:
            repository = DatabaseRepository(session)
            repository.save_pipeline_stage(
                pipeline_run_id=run_id,
                campaign_id=campaign_id,
                task_id=None,
                stage_key="campaign_report_preview",
                stage_order=20,
                status="awaiting_review",
                input_refs=[f"campaign:{campaign_id}"],
                output_refs=[f"pipeline_run:{run_id}"],
                safety_gate_state="awaiting_review",
                stop_reason=None,
                payload={"submission_allowed": False, "raw_payload_processed": False},
            )
            signal = repository.save_learning_signal(
                program_id="program_example",
                playbook_id="bola_idor",
                outcome="informative",
                surface_key="file_id:export",
                notes="Informative safe fixture; Authorization: Bearer secret-token",
                evidence_quality="adequate",
            )
            pipeline_run = repository.get_pipeline_run(run_id)
            assert pipeline_run is not None
            artifact_id = pipeline_run.payload["artifact"]["artifact_id"]
            repository.append_artifact_usage_records(
                artifact_id=artifact_id,
                usage_records=[
                    {
                        "usage_type": "learning_signal",
                        "run_id": run_id,
                        "ref": f"learning_signal:{signal.id}",
                        "learning_signal_id": signal.id,
                    }
                ],
            )

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["safe_next_action"] == "review_evidence_or_report_drafts"
        assert control_center["execution_allowed"] is False
        assert "Informative safe fixture" not in str(control_center)
        assert "secret-token" not in str(control_center)
        assert "SECRET POLICY" not in str(control_center)
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


def test_campaign_approved_decision_replay_does_not_rewrite_audit_or_resync_runs():
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
                name="Approved replay campaign",
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
                reason="Approval request",
                requested_action="two_account_authorization_check",
                asset=campaign.default_asset,
                validation_mode="two_account_authorization_check",
                plan_digest="approval_replay_plan",
                autonomy_level=campaign.autonomy_level,
                safety_gate_state="awaiting_approval",
            )
            first_run = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="planned",
                safety_gate_state="awaiting_approval",
                plan_digest="approval_replay_plan",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Awaiting approval",
                payload={},
            )
            campaign_id = campaign.id
            task_id = task.id
            approval_id = approval.id
            first_run_id = first_run.id

        first_decision_response = client.post(
            f"/mythos/approvals/{approval_id}/decisions",
            json={
                "decision": "approved",
                "actor": "lead_reviewer",
                "reason": "Approved for this validation batch.",
            },
        )
        assert first_decision_response.status_code == 200
        approved = first_decision_response.json()
        first_decided_at = approved["decided_at"]
        assert approved["status"] == "approved"
        assert approved["decided_by"] == "lead_reviewer"
        assert approved["decision_reason"] == "Approved for this validation batch."

        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.get_campaign(campaign_id)
            assert campaign is not None
            late_run = repository.save_validation_run(
                campaign_id=campaign_id,
                task_id=task_id,
                approval_id=None,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign_id}",
                status="planned",
                safety_gate_state="awaiting_approval",
                plan_digest="approval_replay_plan",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Late run must not be unlocked by replay",
                payload={},
            )
            late_run_id = late_run.id

        replay_response = client.post(
            f"/mythos/approvals/{approval_id}/decisions",
            json={
                "decision": "approved",
                "actor": "replay_actor",
                "reason": "Trying to replay approval after the audited decision.",
            },
        )

        assert replay_response.status_code == 409
        assert replay_response.json()["detail"] == "Approval record already decided"

        approvals_response = client.get(f"/mythos/campaigns/{campaign_id}/approvals")
        assert approvals_response.status_code == 200
        stored_approval = approvals_response.json()[0]
        assert stored_approval["id"] == approval_id
        assert stored_approval["status"] == "approved"
        assert stored_approval["decided_by"] == "lead_reviewer"
        assert stored_approval["decision_reason"] == "Approved for this validation batch."
        assert stored_approval["decided_at"] == first_decided_at

        runs_response = client.get(f"/mythos/campaigns/{campaign_id}/validation-runs")
        assert runs_response.status_code == 200
        runs_by_id = {run["id"]: run for run in runs_response.json()}
        assert runs_by_id[first_run_id]["approval_id"] == approval_id
        assert runs_by_id[first_run_id]["status"] == "ready"
        assert runs_by_id[late_run_id]["approval_id"] is None
        assert runs_by_id[late_run_id]["status"] == "awaiting_approval"
        assert runs_by_id[late_run_id]["allowed_to_execute"] is False
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize("terminal_decision", ["expired", "used"])
def test_campaign_terminal_approval_blocks_matching_validation_run(terminal_decision):
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
                name="Expired approval campaign",
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
                reason="Approval request",
                requested_action="two_account_authorization_check",
                asset=campaign.default_asset,
                validation_mode="two_account_authorization_check",
                plan_digest="plan_digest_expired",
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
                plan_digest="plan_digest_expired",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Awaiting approval",
                payload={},
            )
            campaign_id = campaign.id
            approval_id = approval.id

        approve_response = client.post(
            f"/mythos/approvals/{approval_id}/decisions",
            json={
                "decision": "approved",
                "actor": "lead_reviewer",
                "reason": "Approved for preflight only.",
            },
        )
        assert approve_response.status_code == 200

        terminal_response = client.post(
            f"/mythos/approvals/{approval_id}/decisions",
            json={
                "decision": terminal_decision,
                "actor": "lead_reviewer",
                "reason": f"Approval marked {terminal_decision} before preflight.",
            },
        )

        assert terminal_response.status_code == 200
        assert terminal_response.json()["status"] == terminal_decision

        runs_response = client.get(f"/mythos/campaigns/{campaign_id}/validation-runs")
        assert runs_response.status_code == 200
        run = runs_response.json()[0]
        assert run["approval_id"] == approval_id
        assert run["status"] == "blocked"
        assert run["safety_gate_state"] == "blocked"
        assert run["allowed_to_execute"] is False
    finally:
        app.dependency_overrides.clear()


def test_campaign_approved_validation_still_requires_preflight_review():
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
                name="Approved validation preflight campaign",
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
                output_refs=["validation_run:approved"],
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
                plan_digest="plan_digest_preflight_required",
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
                plan_digest="plan_digest_preflight_required",
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
                "decision": "approved",
                "actor": "lead_reviewer",
                "reason": "Approved for preflight only.",
            },
        )
        assert decision_response.status_code == 200

        runs_response = client.get(f"/mythos/campaigns/{campaign_id}/validation-runs")
        assert runs_response.status_code == 200
        run = runs_response.json()[0]
        assert run["approval_id"] == approval_id
        assert run["status"] == "ready"
        assert run["safety_gate_state"] == "approved_validation_record"
        assert run["allowed_to_execute"] is False

        control_response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")
        assert control_response.status_code == 200
        control_center = control_response.json()
        assert control_center["safe_next_action"] == "review_validation_queue"
        assert control_center["execution_allowed"] is False
    finally:
        app.dependency_overrides.clear()


def test_campaign_ready_validation_run_with_polluted_execution_flag_still_requires_preflight():
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
                name="Polluted execution flag preflight campaign",
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
                plan_digest="plan_digest_polluted_execution_flag",
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
                plan_digest="plan_digest_polluted_execution_flag",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Awaiting approval",
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
                "reason": "Approved for preflight only.",
            },
        )
        assert decision_response.status_code == 200

        with testing_session() as session:
            validation = session.get(ValidationRunRecord, validation_id)
            assert validation is not None
            validation.allowed_to_execute = True
            session.add(validation)
            session.commit()

        runs_response = client.get(f"/mythos/campaigns/{campaign_id}/validation-runs")
        assert runs_response.status_code == 200
        run = runs_response.json()[0]
        assert run["id"] == validation_id
        assert run["status"] == "ready"
        assert run["preflight_passed"] is False
        assert run["allowed_to_execute"] is False

        control_response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")
        assert control_response.status_code == 200
        control_center = control_response.json()
        assert control_center["validation_runs"][0]["allowed_to_execute"] is False
        assert control_center["safe_next_action"] == "review_validation_queue"
        assert control_center["execution_allowed"] is False
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
                "policy_text": "api.example.com is in scope. No automation. Authorization: Bearer secret-token",
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
        assert control_center["validation_runs"] == []
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


def test_campaign_control_center_routes_requested_approval_to_review_queue():
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
                name="Requested approval campaign",
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
                title="Review validation approval",
                input_refs=[f"campaign:{campaign.id}"],
                payload={},
            )
            approval = repository.create_approval_record(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_type="validation_batch",
                actor="operator",
                reason="Approval has been requested.",
                requested_action="two_account_authorization_check",
                safety_gate_state="awaiting_approval",
            )
            approval.status = "requested"
            session.add(approval)
            session.commit()
            campaign_id = campaign.id

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["approvals"][0]["status"] == "requested"
        assert control_center["safe_next_action"] == "review_approval_queue"
        assert control_center["execution_allowed"] is False
    finally:
        app.dependency_overrides.clear()


def test_campaign_control_center_ignores_expired_pending_approval_for_next_action():
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
                name="Expired approval next action campaign",
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
            repository.create_approval_record(
                campaign_id=campaign.id,
                approval_type="validation_batch",
                actor="operator",
                reason="Expired approval request.",
                requested_action="two_account_authorization_check",
                safety_gate_state="awaiting_approval",
                expires_at=datetime.now(UTC) - timedelta(minutes=1),
            )
            campaign_id = campaign.id

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["approvals"][0]["status"] == "pending"
        assert control_center["approvals"][0]["expires_at"] is not None
        assert control_center["safe_next_action"] == "plan_next_tick"
        assert control_center["execution_allowed"] is False
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


def test_campaign_control_center_points_to_manual_observation_after_preflight_passes():
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
                name="Preflight passed manual observation campaign",
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
                title="Review preflight-passed validation",
                input_refs=[f"campaign:{campaign.id}"],
                payload={},
            )
            validation_run = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=None,
                validation_mode="local_code_review",
                target_ref=f"campaign:{campaign.id}",
                status="preflight_passed",
                safety_gate_state="scope_guard_preflight_passed",
                plan_digest="local_plan_1",
                approval_required=False,
                allowed_to_execute=True,
                evidence_ref_count=0,
                summary="Preflight passed; Authorization: Bearer secret-token",
                payload={"raw_request": "Cookie: session=secret"},
            )
            campaign_id = campaign.id

        response = client.get(f"/mythos/campaigns/{campaign_id}/control-center")

        assert response.status_code == 200
        control_center = response.json()
        assert control_center["validation_runs"][0]["id"] == validation_run.id
        assert control_center["validation_runs"][0]["preflight_passed"] is True
        assert control_center["safe_next_action"] == "record_validation_observation"
        assert control_center["execution_allowed"] is False
        assert "secret-token" not in str(control_center)
        assert "session=secret" not in str(control_center)
    finally:
        app.dependency_overrides.clear()
