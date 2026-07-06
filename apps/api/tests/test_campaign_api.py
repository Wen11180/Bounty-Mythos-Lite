from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_session
from app.db_models import ApprovalRecord
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
                "policy_text": "Testing allowed",
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
        assert candidate_response.json()["submission_recommendation"] == "promote_to_finding_candidate"

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
        assert review_control_center["research_queue_suggestions"] == [
            {
                "queue_key": "reasoning_memory:bola_idor",
                "title": "Review bola_idor reasoning memory",
                "source": "mythos_brain_reasoning_memory",
                "playbook_id": "bola_idor",
                "surface_key": "file_id:export",
                "priority_score": 69,
                "safety_gate": "advisory_memory_only",
                "next_allowed_action": "Review hypothesis board and plan non-destructive evidence work.",
                "execution_allowed": False,
            }
        ]
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
        }
        assert "Accepted safe fixture" not in str(review_workspace)
        assert "secret-token" not in str(review_workspace)
        assert "Authorization" not in str(review_workspace)

        plan_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review-plans",
            json={
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
            },
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

        decision_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-queue/tasks/{task['id']}/review-decisions",
            json={
                "plan_id": updated_plan["plan_id"],
                "reviewer": "lead_reviewer",
                "decision": "needs_evidence",
                "rationale": "Need redacted proof before validation; Authorization: Bearer secret-token",
                "refutation_answers": [
                    "Current summaries do not yet prove missing ownership checks.",
                ],
            },
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
        }
        assert "secret-token" not in str(control_center)
        assert "Authorization" not in str(control_center)
        assert "execution_allowed: True" not in str(control_center)
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
        assert "secret-token" not in str(stages)
        assert "session=secret" not in str(stages)
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
