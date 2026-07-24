import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, Event, Thread
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.main as main_module
from app.db import Base, get_session
from app.db_models import CampaignLocalToolExecutionSlotRecord, CampaignTaskRecord
from app.execution_registry import ExecutionAuthorizationDecision
from app.execution_registry.local_runner import RegisteredLocalToolRun
from app.main import app
from app.research_director.runtime import (
    LOCAL_TOOL_APPROVAL_TYPE,
    LOCAL_TOOL_TASK_SCHEMA,
    ensure_campaign_local_tool_approval,
)
from app.repository import DatabaseRepository, seed_sample_data


client = TestClient(app)


def _testing_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine)
    with factory() as session:
        seed_sample_data(session)
    return factory


def _create_local_execution_slot_task(
    repository: DatabaseRepository,
    *,
    campaign_id: str,
    tool_id: str,
    source_snapshot_digest: str,
    plan_suffix: str,
) -> CampaignTaskRecord:
    return repository.create_campaign_task(
        campaign_id=campaign_id,
        task_type="research_director_local_tool_run",
        agent_type="registered_local_tool",
        title=f"Run registered local {tool_id} analysis",
        payload={
            "schema_version": LOCAL_TOOL_TASK_SCHEMA,
            "execution_lease_required": True,
            "research_plan_id": f"research_plan_{plan_suffix}",
            "research_plan_digest": f"sha256:{plan_suffix * 64}",
            "source_snapshot_digest": source_snapshot_digest,
            "tool_id": tool_id,
        },
    )


def _local_execution_slot(
    repository: DatabaseRepository,
    *,
    campaign_id: str,
    source_snapshot_digest: str,
) -> CampaignLocalToolExecutionSlotRecord | None:
    return repository.session.scalar(
        select(CampaignLocalToolExecutionSlotRecord).where(
            CampaignLocalToolExecutionSlotRecord.campaign_id == campaign_id,
            CampaignLocalToolExecutionSlotRecord.source_snapshot_digest
            == source_snapshot_digest,
        )
    )


def test_director_local_run_uses_current_plan_and_verified_workspace_snapshot(
    tmp_path: Path,
    monkeypatch,
):
    testing_session = _testing_session()
    (tmp_path / "inputs").mkdir()
    code_path = tmp_path / "inputs" / "code.py"
    code_path.write_text("requests.get(url)\n", encoding="utf-8")

    def override_get_session():
        with testing_session() as session:
            yield session

    def fake_subprocess(command, **kwargs):
        return SimpleNamespace(
            returncode=1,
            stdout=json.dumps(
                {
                    "results": [
                        {
                            "check_id": "mythos.local.ssrf-fetch",
                            "path": str(code_path),
                            "start": {"line": 1},
                            "extra": {"message": "outbound fetch"},
                        }
                    ]
                }
            ),
            stderr="",
        )

    app.dependency_overrides[get_session] = override_get_session
    monkeypatch.setattr(
        main_module,
        "load_authorized_campaign_inputs",
        lambda _snapshot: {
            "source_snapshot_digest": f"sha256:{'a' * 64}",
            "authorized_local_root": str(tmp_path),
        },
    )
    monkeypatch.setattr(
        "app.semgrep_runner.find_semgrep_binary",
        lambda explicit=None: "semgrep-fake",
    )
    monkeypatch.setattr("app.semgrep_runner.subprocess.run", fake_subprocess)
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id="program_example",
                name="Director executable local analysis campaign",
                autonomy_level="level_1_local_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.test",
                allowed_tools=["static_analyzer"],
                created_by="operator",
                payload={
                    "source_snapshot_digest": f"sha256:{'a' * 64}",
                    "workspace_snapshot": {"schema_version": "test"},
                    "scope_guard_rule": {
                        "asset": "api.example.test",
                        "scope_status": "in_scope",
                        "automation": "limited",
                        "allowed_validation": ["static_analyzer"],
                        "forbidden": [],
                        "human_approval_required": False,
                    },
                    "saved_scope_guard": {
                        "authorized_local_root": str(tmp_path),
                    },
                },
            )
            repository.update_campaign_status(campaign.id, "running")
            campaign_id = campaign.id

        plan_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-director/plan"
        )
        assert plan_response.status_code == 200
        plan = plan_response.json()

        run_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-director/local-tools/semgrep_local/run",
            json={"plan_id": plan["plan_id"], "plan_digest": plan["plan_digest"]},
        )

        assert run_response.status_code == 409
        assert run_response.json() == {"detail": "human_approval_required"}
        with testing_session() as session:
            repository = DatabaseRepository(session)
            execution_task = next(
                task
                for task in repository.list_campaign_tasks(campaign_id)
                if task.task_type == "research_director_local_tool_run"
            )
            approvals = repository.list_campaign_approval_records(campaign_id)
            assert execution_task.status == "awaiting_approval"
            assert len(approvals) == 1
            assert approvals[0].approval_type == LOCAL_TOOL_APPROVAL_TYPE
            assert approvals[0].task_id == execution_task.id
            assert approvals[0].plan_digest == plan["plan_digest"]
            assert approvals[0].status == "pending"
            assert (
                repository.decide_approval_record(
                    approval_id=approvals[0].id,
                    decision="approved",
                    actor="operator",
                    reason="Approved offline local static analysis.",
                )
                is not None
            )

        run_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-director/local-tools/semgrep_local/run",
            json={"plan_id": plan["plan_id"], "plan_digest": plan["plan_digest"]},
        )
        assert run_response.status_code == 200
        body = run_response.json()
        assert body["execution_started"] is True
        assert body["result"]["status"] == "completed"
        assert body["result"]["finding_count"] == 1
        assert body["scanner_run"]["tool_name"] == "semgrep_local"
        assert body["scanner_run"]["finding_count"] == 1
        assert body["advisory_artifact_id"].startswith("artifact_")
        assert "outbound fetch" not in str(body)

        next_plan_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-director/plan"
        )
        assert next_plan_response.status_code == 200
        next_plan = next_plan_response.json()
        assert next_plan["action_kind"] == "research_task"
        assert next_plan["action_id"] == "candidate_refutation"
        assert "evidence_gap_requires_refutation" in next_plan["reasons"]

        with testing_session() as session:
            repository = DatabaseRepository(session)
            stages = [
                stage
                for stage in repository.list_campaign_pipeline_stages(campaign_id)
                if stage.stage_key == "research_director_local_tool_run"
            ]
            assert len(stages) == 1
            assert stages[0].payload["execution_allowed"] is False
            assert stages[0].payload["report_submission_allowed"] is False
            execution_tasks = [
                task
                for task in repository.list_campaign_tasks(campaign_id)
                if task.task_type == "research_director_local_tool_run"
            ]
            assert len(execution_tasks) == 1
            assert execution_tasks[0].status == "completed"
            assert execution_tasks[0].execution_claim_id is None
            assert execution_tasks[0].payload["schema_version"] == LOCAL_TOOL_TASK_SCHEMA
            assert execution_tasks[0].payload["execution_lease_required"] is True
            assert execution_tasks[0].payload["research_plan_digest"] == plan[
                "plan_digest"
            ]
            execution_runs = [
                run
                for run in repository.list_campaign_agent_runs(campaign_id)
                if run.task_id == execution_tasks[0].id
            ]
            assert len(execution_runs) == 1
            assert execution_runs[0].status == "completed"
            assert execution_runs[0].safety_gate_state == "allowed"
            artifacts = repository.list_artifacts(
                program_id="program_example",
                asset="api.example.test",
            )
            assert len(artifacts) == 1
            assert artifacts[0].derived_facts["advisory_findings"] == [
                {
                    "rule_id": "mythos.local.ssrf-fetch",
                    "path": "inputs/code.py",
                    "line": 1,
                }
            ]
            assert "outbound fetch" not in str(artifacts[0])
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize("decision", ("denied", "expired"))
def test_director_local_run_does_not_execute_with_inactive_approval(
    tmp_path: Path,
    monkeypatch,
    decision: str,
):
    testing_session = _testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    monkeypatch.setattr(
        main_module,
        "load_authorized_campaign_inputs",
        lambda _snapshot: {
            "source_snapshot_digest": f"sha256:{'e' * 64}",
            "authorized_local_root": str(tmp_path),
        },
    )
    monkeypatch.setattr(
        main_module,
        "run_registered_local_tool",
        lambda _request: pytest.fail("inactive approval reached local runner"),
    )
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id="program_example",
                name="Director inactive approval campaign",
                autonomy_level="level_1_local_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.test",
                allowed_tools=["static_analyzer"],
                created_by="operator",
                payload={
                    "source_snapshot_digest": f"sha256:{'e' * 64}",
                    "workspace_snapshot": {"schema_version": "test"},
                    "scope_guard_rule": {
                        "asset": "api.example.test",
                        "scope_status": "in_scope",
                        "automation": "limited",
                        "allowed_validation": ["static_analyzer"],
                        "forbidden": [],
                        "human_approval_required": False,
                    },
                    "saved_scope_guard": {
                        "authorized_local_root": str(tmp_path),
                    },
                },
            )
            repository.update_campaign_status(campaign.id, "running")
            campaign_id = campaign.id

        plan = client.post(
            f"/mythos/campaigns/{campaign_id}/research-director/plan"
        ).json()
        pending_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-director/local-tools/semgrep_local/run",
            json={"plan_id": plan["plan_id"], "plan_digest": plan["plan_digest"]},
        )
        assert pending_response.status_code == 409
        assert pending_response.json() == {"detail": "human_approval_required"}

        with testing_session() as session:
            repository = DatabaseRepository(session)
            approval = repository.list_campaign_approval_records(campaign_id)[0]
            assert (
                repository.decide_approval_record(
                    approval_id=approval.id,
                    decision=decision,
                    actor="operator",
                    reason="Approval is not active for this local run.",
                )
                is not None
            )

        response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-director/local-tools/semgrep_local/run",
            json={"plan_id": plan["plan_id"], "plan_digest": plan["plan_digest"]},
        )
        assert response.status_code == 409
        assert response.json() == {"detail": "human_approval_required"}

        with testing_session() as session:
            repository = DatabaseRepository(session)
            task = next(
                task
                for task in repository.list_campaign_tasks(campaign_id)
                if task.task_type == "research_director_local_tool_run"
            )
            approvals = repository.list_campaign_approval_records(campaign_id)

            assert task.status == "awaiting_approval"
            assert task.execution_claim_id is None
            assert repository.list_campaign_agent_runs(campaign_id) == []
            assert repository.list_campaign_scanner_runs(campaign_id) == []
            expected_status = "pending" if decision == "expired" else "denied"
            assert approvals[0].status == expected_status
            assert len(approvals) == (2 if decision == "expired" else 1)
    finally:
        app.dependency_overrides.clear()


def test_director_local_run_rolls_back_staged_evidence_after_lease_expiry(
    tmp_path: Path,
    monkeypatch,
):
    testing_session = _testing_session()
    (tmp_path / "inputs").mkdir()
    code_path = tmp_path / "inputs" / "code.py"
    code_path.write_text("requests.get(url)\n", encoding="utf-8")

    def override_get_session():
        with testing_session() as session:
            yield session

    def fake_subprocess(command, **kwargs):
        return SimpleNamespace(
            returncode=1,
            stdout=json.dumps(
                {
                    "results": [
                        {
                            "check_id": "mythos.local.ssrf-fetch",
                            "path": str(code_path),
                            "start": {"line": 1},
                        }
                    ]
                }
            ),
            stderr="",
        )

    app.dependency_overrides[get_session] = override_get_session
    monkeypatch.setattr(
        main_module,
        "load_authorized_campaign_inputs",
        lambda _snapshot: {
            "source_snapshot_digest": f"sha256:{'d' * 64}",
            "authorized_local_root": str(tmp_path),
        },
    )
    monkeypatch.setattr(
        "app.semgrep_runner.find_semgrep_binary",
        lambda explicit=None: "semgrep-fake",
    )
    monkeypatch.setattr("app.semgrep_runner.subprocess.run", fake_subprocess)
    original_record_stage = main_module._record_research_director_local_tool_run

    def expire_lease_after_output_staging(**kwargs):
        stage = original_record_stage(**kwargs)
        repository = kwargs["repository"]
        task = repository.session.get(CampaignTaskRecord, kwargs["task"].id)
        assert task is not None
        task.execution_lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        repository.session.flush()
        return stage

    monkeypatch.setattr(
        main_module,
        "_record_research_director_local_tool_run",
        expire_lease_after_output_staging,
    )
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id="program_example",
                name="Director staged-output lease campaign",
                autonomy_level="level_1_local_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.test",
                allowed_tools=["static_analyzer"],
                created_by="operator",
                payload={
                    "source_snapshot_digest": f"sha256:{'d' * 64}",
                    "workspace_snapshot": {"schema_version": "test"},
                    "scope_guard_rule": {
                        "asset": "api.example.test",
                        "scope_status": "in_scope",
                        "automation": "limited",
                        "allowed_validation": ["static_analyzer"],
                        "forbidden": [],
                        "human_approval_required": False,
                    },
                    "saved_scope_guard": {
                        "authorized_local_root": str(tmp_path),
                    },
                },
            )
            repository.update_campaign_status(campaign.id, "running")
            repository.upsert_campaign_budget(
                campaign_id=campaign.id,
                time_budget_minutes=30,
                token_budget=1000,
                tool_call_budget=1,
                validation_budget=1,
            )
            campaign_id = campaign.id

        plan = client.post(
            f"/mythos/campaigns/{campaign_id}/research-director/plan"
        ).json()
        pending_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-director/local-tools/semgrep_local/run",
            json={"plan_id": plan["plan_id"], "plan_digest": plan["plan_digest"]},
        )
        assert pending_response.status_code == 409
        assert pending_response.json() == {"detail": "human_approval_required"}
        with testing_session() as session:
            repository = DatabaseRepository(session)
            approval = repository.list_campaign_approval_records(campaign_id)[0]
            assert (
                repository.decide_approval_record(
                    approval_id=approval.id,
                    decision="approved",
                    actor="operator",
                    reason="Approved offline local static analysis.",
                )
                is not None
            )
        response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-director/local-tools/semgrep_local/run",
            json={"plan_id": plan["plan_id"], "plan_digest": plan["plan_digest"]},
        )

        assert response.status_code == 409
        assert response.json() == {"detail": "local_tool_execution_lease_lost"}
        with testing_session() as session:
            repository = DatabaseRepository(session)
            task = next(
                task
                for task in repository.list_campaign_tasks(campaign_id)
                if task.task_type == "research_director_local_tool_run"
            )
            local_run_stages = [
                stage
                for stage in repository.list_campaign_pipeline_stages(campaign_id)
                if stage.stage_key == "research_director_local_tool_run"
            ]

            assert task.status == "running"
            assert repository.list_campaign_scanner_runs(campaign_id) == []
            assert repository.list_artifacts(
                program_id="program_example",
                asset="api.example.test",
            ) == []
            assert local_run_stages == []
            reservation_runs = repository.list_campaign_local_tool_call_reservations(
                campaign_id
            )
            assert len(reservation_runs) == 1
            reservation_payload = reservation_runs[0].payload
            assert reservation_payload["tool_call_reserved"] is True
            assert reservation_payload["tool_call_reservation_task_id"] == task.id
            assert reservation_payload.get("command_hash") is None
            assert reservation_payload.get("finding_count") in {None, 0}
            assert "advisory_findings" not in reservation_payload
            campaign = repository.get_campaign(campaign_id)
            assert campaign is not None
            assert main_module._research_director_remaining_tool_calls(
                campaign=campaign,
                repository=repository,
            ) == 0
    finally:
        app.dependency_overrides.clear()


def test_director_local_run_rejects_an_already_claimed_plan(tmp_path: Path, monkeypatch):
    testing_session = _testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    monkeypatch.setattr(
        main_module,
        "load_authorized_campaign_inputs",
        lambda _snapshot: {
            "source_snapshot_digest": f"sha256:{'b' * 64}",
            "authorized_local_root": str(tmp_path),
        },
    )
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id="program_example",
                name="Director single-claim campaign",
                autonomy_level="level_1_local_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.test",
                allowed_tools=["static_analyzer"],
                created_by="operator",
                payload={
                    "source_snapshot_digest": f"sha256:{'b' * 64}",
                    "workspace_snapshot": {"schema_version": "test"},
                    "scope_guard_rule": {
                        "asset": "api.example.test",
                        "scope_status": "in_scope",
                        "automation": "limited",
                        "allowed_validation": ["static_analyzer"],
                        "forbidden": [],
                        "human_approval_required": False,
                    },
                    "saved_scope_guard": {
                        "authorized_local_root": str(tmp_path),
                    },
                },
            )
            repository.update_campaign_status(campaign.id, "running")
            campaign_id = campaign.id

        plan_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-director/plan"
        )
        assert plan_response.status_code == 200
        plan = plan_response.json()

        pending_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-director/local-tools/semgrep_local/run",
            json={"plan_id": plan["plan_id"], "plan_digest": plan["plan_digest"]},
        )
        assert pending_response.status_code == 409
        assert pending_response.json() == {"detail": "human_approval_required"}
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.get_campaign(campaign_id)
            assert campaign is not None
            task = next(
                task
                for task in repository.list_campaign_tasks(campaign_id)
                if task.task_type == "research_director_local_tool_run"
            )
            approval = repository.list_campaign_approval_records(campaign_id)[0]
            assert (
                repository.decide_approval_record(
                    approval_id=approval.id,
                    decision="approved",
                    actor="operator",
                    reason="Approved offline local static analysis.",
                )
                is not None
            )
            assert repository.update_campaign_task_status(task.id, "queued") is not None
            claimed = repository.claim_campaign_task_execution(task.id)
            assert claimed is not None
            assert claimed.status == "running"

        run_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-director/local-tools/semgrep_local/run",
            json={"plan_id": plan["plan_id"], "plan_digest": plan["plan_digest"]},
        )

        assert run_response.status_code == 409
        assert run_response.json()["detail"] == "research_director_plan_consumed"
        with testing_session() as session:
            repository = DatabaseRepository(session)
            assert repository.list_campaign_scanner_runs(campaign_id) == []
    finally:
        app.dependency_overrides.clear()


def test_director_local_run_records_a_fixed_failure_without_leaving_a_lease(
    tmp_path: Path,
    monkeypatch,
):
    testing_session = _testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    def fail_local_tool(_request):
        raise RuntimeError("authorization=must-not-leak")

    app.dependency_overrides[get_session] = override_get_session
    monkeypatch.setattr(
        main_module,
        "load_authorized_campaign_inputs",
        lambda _snapshot: {
            "source_snapshot_digest": f"sha256:{'c' * 64}",
            "authorized_local_root": str(tmp_path),
        },
    )
    monkeypatch.setattr(
        main_module,
        "run_registered_local_tool",
        fail_local_tool,
    )
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id="program_example",
                name="Director durable local failure campaign",
                autonomy_level="level_1_local_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.test",
                allowed_tools=["static_analyzer"],
                created_by="operator",
                payload={
                    "source_snapshot_digest": f"sha256:{'c' * 64}",
                    "workspace_snapshot": {"schema_version": "test"},
                    "scope_guard_rule": {
                        "asset": "api.example.test",
                        "scope_status": "in_scope",
                        "automation": "limited",
                        "allowed_validation": ["static_analyzer"],
                        "forbidden": [],
                        "human_approval_required": False,
                    },
                    "saved_scope_guard": {
                        "authorized_local_root": str(tmp_path),
                    },
                },
            )
            repository.update_campaign_status(campaign.id, "running")
            campaign_id = campaign.id

        plan = client.post(
            f"/mythos/campaigns/{campaign_id}/research-director/plan"
        ).json()
        pending_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-director/local-tools/semgrep_local/run",
            json={"plan_id": plan["plan_id"], "plan_digest": plan["plan_digest"]},
        )
        assert pending_response.status_code == 409
        assert pending_response.json() == {"detail": "human_approval_required"}
        with testing_session() as session:
            repository = DatabaseRepository(session)
            approval = repository.list_campaign_approval_records(campaign_id)[0]
            assert (
                repository.decide_approval_record(
                    approval_id=approval.id,
                    decision="approved",
                    actor="operator",
                    reason="Approved offline local static analysis.",
                )
                is not None
            )
        response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-director/local-tools/semgrep_local/run",
            json={"plan_id": plan["plan_id"], "plan_digest": plan["plan_digest"]},
        )

        assert response.status_code == 503
        assert response.json() == {"detail": "local_tool_runtime_failed"}
        assert "must-not-leak" not in response.text
        with testing_session() as session:
            repository = DatabaseRepository(session)
            task = next(
                task
                for task in repository.list_campaign_tasks(campaign_id)
                if task.task_type == "research_director_local_tool_run"
            )
            assert task.status == "failed"
            assert task.execution_claim_id is None
            assert task.execution_lease_expires_at is None
            agent_run = next(
                run
                for run in repository.list_campaign_agent_runs(campaign_id)
                if run.task_id == task.id
            )
            assert agent_run.status == "failed"
            assert agent_run.stop_reason == "local_tool_runtime_failed"
            assert "must-not-leak" not in str(agent_run)
    finally:
        app.dependency_overrides.clear()


def test_director_local_run_does_not_queue_second_tool_while_first_is_running(
    tmp_path: Path,
    monkeypatch,
):
    testing_session = _testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    monkeypatch.setattr(
        main_module,
        "load_authorized_campaign_inputs",
        lambda _snapshot: {
            "source_snapshot_digest": f"sha256:{'d' * 64}",
            "authorized_local_root": str(tmp_path),
        },
    )
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id="program_example",
                name="Director serialized local tools campaign",
                autonomy_level="level_1_local_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.test",
                allowed_tools=["static_analyzer", "codeql_local"],
                created_by="operator",
                payload={
                    "source_snapshot_digest": f"sha256:{'d' * 64}",
                    "workspace_snapshot": {"schema_version": "test"},
                    "scope_guard_rule": {
                        "asset": "api.example.test",
                        "scope_status": "in_scope",
                        "automation": "limited",
                        "allowed_validation": ["static_analyzer"],
                        "forbidden": [],
                        "human_approval_required": False,
                    },
                    "saved_scope_guard": {
                        "authorized_local_root": str(tmp_path),
                    },
                },
            )
            repository.update_campaign_status(campaign.id, "running")
            repository.upsert_campaign_budget(
                campaign_id=campaign.id,
                time_budget_minutes=30,
                token_budget=1000,
                tool_call_budget=2,
                validation_budget=1,
            )
            campaign_id = campaign.id

        semgrep_plan = client.post(
            f"/mythos/campaigns/{campaign_id}/research-director/plan"
        ).json()
        pending = client.post(
            f"/mythos/campaigns/{campaign_id}/research-director/local-tools/semgrep_local/run",
            json={
                "plan_id": semgrep_plan["plan_id"],
                "plan_digest": semgrep_plan["plan_digest"],
            },
        )
        assert pending.status_code == 409
        assert pending.json() == {"detail": "human_approval_required"}
        with testing_session() as session:
            repository = DatabaseRepository(session)
            semgrep_task = next(
                task
                for task in repository.list_campaign_tasks(campaign_id)
                if task.task_type == "research_director_local_tool_run"
            )
            semgrep_task_id = semgrep_task.id
            approval = repository.list_campaign_approval_records(campaign_id)[0]
            assert (
                repository.decide_approval_record(
                    approval_id=approval.id,
                    decision="approved",
                    actor="operator",
                    reason="Approved offline local static analysis.",
                )
                is not None
            )
            assert repository.update_campaign_task_status(semgrep_task.id, "queued") is not None
            running = repository.claim_campaign_task_execution(semgrep_task.id)
            assert running is not None
            assert running.execution_claim_id is not None
            reservation = repository.reserve_campaign_local_tool_call(
                campaign_id=campaign_id,
                task_id=running.id,
                execution_claim_id=running.execution_claim_id,
                research_plan_id=semgrep_plan["plan_id"],
                research_plan_digest=semgrep_plan["plan_digest"],
                source_snapshot_digest=f"sha256:{'d' * 64}",
                tool_id="semgrep_local",
            )
            assert reservation is not None

        codeql_plan_response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-director/plan"
        )
        assert codeql_plan_response.status_code == 200
        codeql_plan = codeql_plan_response.json()
        assert codeql_plan["action_id"] == "codeql_local"

        response = client.post(
            f"/mythos/campaigns/{campaign_id}/research-director/local-tools/codeql_local/run",
            json={
                "plan_id": codeql_plan["plan_id"],
                "plan_digest": codeql_plan["plan_digest"],
            },
        )

        assert response.status_code == 409
        assert response.json() == {"detail": "active_local_tool_task"}
        with testing_session() as session:
            repository = DatabaseRepository(session)
            tasks = [
                task
                for task in repository.list_campaign_tasks(campaign_id)
                if task.task_type == "research_director_local_tool_run"
            ]
            assert [(task.id, task.status) for task in tasks] == [
                (semgrep_task_id, "running")
            ]
    finally:
        app.dependency_overrides.clear()


def test_director_local_run_claim_is_atomic_across_database_sessions(
    tmp_path: Path,
    monkeypatch,
):
    database_path = tmp_path / "research-director-local-claim.db"
    engine = create_engine(
        f"sqlite+pysqlite:///{database_path.as_posix()}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    source_snapshot_digest = f"sha256:{'e' * 64}"
    (tmp_path / "inputs").mkdir()
    (tmp_path / "inputs" / "code.py").write_text(
        "requests.get(url)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        main_module,
        "load_authorized_campaign_inputs",
        lambda _snapshot: {
            "source_snapshot_digest": source_snapshot_digest,
            "authorized_local_root": str(tmp_path),
        },
    )
    runner_started = Event()
    release_runner = Event()
    rejected_request = Event()
    runner_calls: list[str] = []

    def fake_local_tool(request):
        runner_calls.append(request.authorization.tool_id)
        runner_started.set()
        assert release_runner.wait(timeout=10)
        return RegisteredLocalToolRun(
            tool_id=request.authorization.tool_id,
            status="completed",
            runner_status="semgrep_local_completed",
            command_hash=f"sha256:{'f' * 64}",
            command_executed=True,
            finding_count=0,
            advisory_findings=[],
            authorization=ExecutionAuthorizationDecision(
                eligible=True,
                reason="eligible",
                execution_tier="local",
            ),
            safety_gate_state="allowed",
        )

    monkeypatch.setattr(main_module, "run_registered_local_tool", fake_local_tool)
    setup_session = Session()
    try:
        repository = DatabaseRepository(setup_session)
        seed_sample_data(setup_session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Atomic direct local-tool claim campaign",
            autonomy_level="level_1_local_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.test",
            allowed_tools=["static_analyzer"],
            created_by="operator",
            payload={
                "source_snapshot_digest": source_snapshot_digest,
                "workspace_snapshot": {"schema_version": "test"},
                "scope_guard_rule": {
                    "asset": "api.example.test",
                    "scope_status": "in_scope",
                    "automation": "limited",
                    "allowed_validation": ["static_analyzer"],
                    "forbidden": [],
                    "human_approval_required": False,
                },
                "saved_scope_guard": {"authorized_local_root": str(tmp_path)},
            },
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        plan = main_module.build_mythos_research_director_plan(
            campaign.id,
            session=setup_session,
        )
        assert plan.action_id == "semgrep_local"
        request = main_module.ResearchDirectorLocalToolRunRequest(
            plan_id=plan.plan_id,
            plan_digest=plan.plan_digest,
        )
        with pytest.raises(HTTPException) as pending:
            main_module.run_mythos_research_director_local_tool(
                campaign.id,
                "semgrep_local",
                request,
                session=setup_session,
            )
        assert pending.value.detail == "human_approval_required"
        approval = repository.list_campaign_approval_records(campaign.id)[0]
        assert (
            repository.decide_approval_record(
                approval_id=approval.id,
                decision="approved",
                actor="operator",
                reason="Approved offline local static analysis.",
            )
            is not None
        )
        campaign_id = campaign.id
    finally:
        setup_session.close()

    barrier = Barrier(2)
    results: list[tuple[str, object]] = []
    errors: list[BaseException] = []

    def run_approved_request():
        session = Session()
        try:
            barrier.wait(timeout=10)
            response = main_module.run_mythos_research_director_local_tool(
                campaign_id,
                "semgrep_local",
                request,
                session=session,
            )
            results.append(("completed", response.execution_started))
        except HTTPException as exc:
            results.append(("http_error", exc.detail))
            rejected_request.set()
        except BaseException as exc:
            errors.append(exc)
        finally:
            session.close()

    threads = [Thread(target=run_approved_request), Thread(target=run_approved_request)]
    for thread in threads:
        thread.start()
    try:
        assert runner_started.wait(timeout=10)
        assert rejected_request.wait(timeout=10)
        release_runner.set()
        for thread in threads:
            thread.join(timeout=10)

        verification_session = Session()
        try:
            repository = DatabaseRepository(verification_session)
            tasks = [
                task
                for task in repository.list_campaign_tasks(campaign_id)
                if task.task_type == "research_director_local_tool_run"
            ]
            slot = _local_execution_slot(
                repository,
                campaign_id=campaign_id,
                source_snapshot_digest=source_snapshot_digest,
            )

            assert all(not thread.is_alive() for thread in threads)
            assert errors == []
            assert sorted(results) == [
                ("completed", True),
                ("http_error", "research_director_plan_consumed"),
            ]
            assert runner_calls == ["semgrep_local"]
            assert slot is not None
            assert slot.active_task_id is None
            assert slot.active_execution_claim_id is None
            assert [(task.status, task.execution_claim_id) for task in tasks] == [
                ("completed", None)
            ]
        finally:
            verification_session.close()
    finally:
        release_runner.set()
        for thread in threads:
            thread.join(timeout=10)
        engine.dispose()


def test_local_execution_slot_serializes_distinct_tools_and_releases_on_completion(
    tmp_path: Path,
):
    database_path = tmp_path / "research-director-local-slot.db"
    engine = create_engine(
        f"sqlite+pysqlite:///{database_path.as_posix()}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    source_snapshot_digest = f"sha256:{'a' * 64}"
    setup_session = Session()
    try:
        repository = DatabaseRepository(setup_session)
        seed_sample_data(setup_session)
        campaign = repository.create_campaign(
            program_id=None,
            name="Atomic distinct local-tool claim campaign",
            autonomy_level="level_1_local_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="local.example",
            allowed_tools=["static_analyzer", "codeql_local"],
            created_by="operator",
            payload={"source_snapshot_digest": source_snapshot_digest},
        )
        semgrep_task = _create_local_execution_slot_task(
            repository,
            campaign_id=campaign.id,
            tool_id="semgrep_local",
            source_snapshot_digest=source_snapshot_digest,
            plan_suffix="b",
        )
        codeql_task = _create_local_execution_slot_task(
            repository,
            campaign_id=campaign.id,
            tool_id="codeql_local",
            source_snapshot_digest=source_snapshot_digest,
            plan_suffix="c",
        )
        campaign_id = campaign.id
        semgrep_task_id = semgrep_task.id
        codeql_task_id = codeql_task.id
    finally:
        setup_session.close()

    barrier = Barrier(2)
    results: list[tuple[str, str | None]] = []
    errors: list[BaseException] = []

    def claim(task_id: str):
        session = Session()
        try:
            repository = DatabaseRepository(session)
            barrier.wait(timeout=10)
            task = repository.claim_campaign_task_execution(task_id)
            results.append((task_id, task.execution_claim_id if task is not None else None))
        except BaseException as exc:
            errors.append(exc)
        finally:
            session.close()

    threads = [
        Thread(target=claim, args=(semgrep_task_id,)),
        Thread(target=claim, args=(codeql_task_id,)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    verification_session = Session()
    try:
        repository = DatabaseRepository(verification_session)
        successful = [result for result in results if result[1] is not None]
        failed = [result for result in results if result[1] is None]

        assert all(not thread.is_alive() for thread in threads)
        assert errors == []
        assert len(successful) == 1
        assert len(failed) == 1
        winning_task_id, execution_claim_id = successful[0]
        waiting_task_id = failed[0][0]
        slot = _local_execution_slot(
            repository,
            campaign_id=campaign_id,
            source_snapshot_digest=source_snapshot_digest,
        )
        assert slot is not None
        assert slot.active_task_id == winning_task_id
        assert slot.active_execution_claim_id == execution_claim_id

        assert (
            repository.finish_campaign_task_execution(
                task_id=winning_task_id,
                execution_claim_id=execution_claim_id,
                task_status="completed",
                task_output_refs=[],
                agent_status="completed",
                agent_output_refs=[],
                safety_gate_state="allowed",
                stop_reason=None,
                payload={},
            )
            is not None
        )
        slot = _local_execution_slot(
            repository,
            campaign_id=campaign_id,
            source_snapshot_digest=source_snapshot_digest,
        )
        assert slot is not None
        assert slot.active_task_id is None
        assert slot.active_execution_claim_id is None

        waiting_task = repository.claim_campaign_task_execution(waiting_task_id)
        assert waiting_task is not None
        assert waiting_task.status == "running"
        assert waiting_task.execution_claim_id is not None
        assert (
            repository.finish_campaign_task_execution(
                task_id=waiting_task.id,
                execution_claim_id=waiting_task.execution_claim_id,
                task_status="completed",
                task_output_refs=[],
                agent_status="completed",
                agent_output_refs=[],
                safety_gate_state="allowed",
                stop_reason=None,
                payload={},
            )
            is not None
        )

        new_snapshot_task = _create_local_execution_slot_task(
            repository,
            campaign_id=campaign_id,
            tool_id="semgrep_local",
            source_snapshot_digest=f"sha256:{'d' * 64}",
            plan_suffix="d",
        )
        assert repository.claim_campaign_task_execution(new_snapshot_task.id) is not None
    finally:
        verification_session.close()
        engine.dispose()


def test_local_execution_slots_are_isolated_by_source_snapshot(tmp_path: Path):
    database_path = tmp_path / "research-director-snapshot-slots.db"
    engine = create_engine(
        f"sqlite+pysqlite:///{database_path.as_posix()}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    first_snapshot_digest = f"sha256:{'a' * 64}"
    second_snapshot_digest = f"sha256:{'b' * 64}"
    session = Session()
    try:
        repository = DatabaseRepository(session)
        seed_sample_data(session)
        campaign = repository.create_campaign(
            program_id=None,
            name="Snapshot-isolated local-tool execution slots",
            autonomy_level="level_1_local_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="local.example",
            allowed_tools=["static_analyzer", "codeql_local"],
            created_by="operator",
            payload={"source_snapshot_digest": second_snapshot_digest},
        )
        first_snapshot_task = _create_local_execution_slot_task(
            repository,
            campaign_id=campaign.id,
            tool_id="semgrep_local",
            source_snapshot_digest=first_snapshot_digest,
            plan_suffix="a",
        )
        second_snapshot_task = _create_local_execution_slot_task(
            repository,
            campaign_id=campaign.id,
            tool_id="codeql_local",
            source_snapshot_digest=second_snapshot_digest,
            plan_suffix="b",
        )
        now = datetime.now(UTC)
        first_claim = repository.claim_campaign_task_execution(
            first_snapshot_task.id,
            now=now,
        )
        second_claim = repository.claim_campaign_task_execution(
            second_snapshot_task.id,
            now=now,
        )

        assert first_claim is not None
        assert second_claim is not None
        assert first_claim.execution_claim_id is not None
        assert second_claim.execution_claim_id is not None
        first_slot = _local_execution_slot(
            repository,
            campaign_id=campaign.id,
            source_snapshot_digest=first_snapshot_digest,
        )
        second_slot = _local_execution_slot(
            repository,
            campaign_id=campaign.id,
            source_snapshot_digest=second_snapshot_digest,
        )
        assert first_slot is not None
        assert second_slot is not None
        assert first_slot.active_task_id == first_snapshot_task.id
        assert second_slot.active_task_id == second_snapshot_task.id

        assert first_claim.execution_lease_expires_at is not None
        expired = repository.expire_campaign_task_execution(
            first_snapshot_task.id,
            now=first_claim.execution_lease_expires_at + timedelta(seconds=1),
        )
        assert expired is not None
        retry_task = _create_local_execution_slot_task(
            repository,
            campaign_id=campaign.id,
            tool_id="semgrep_local",
            source_snapshot_digest=first_snapshot_digest,
            plan_suffix="c",
        )
        retry_claim = repository.claim_campaign_task_execution(retry_task.id)

        assert retry_claim is not None
        second_slot = _local_execution_slot(
            repository,
            campaign_id=campaign.id,
            source_snapshot_digest=second_snapshot_digest,
        )
        assert second_slot is not None
        assert second_slot.active_task_id == second_snapshot_task.id
    finally:
        session.close()
        engine.dispose()


def test_local_tool_approval_creation_is_atomic(tmp_path: Path):
    database_path = tmp_path / "research-director-local-approval.db"
    engine = create_engine(
        f"sqlite+pysqlite:///{database_path.as_posix()}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    source_snapshot_digest = f"sha256:{'a' * 64}"
    plan_digest = f"sha256:{'b' * 64}"
    setup_session = Session()
    try:
        repository = DatabaseRepository(setup_session)
        seed_sample_data(setup_session)
        campaign = repository.create_campaign(
            program_id=None,
            name="Atomic local-tool approval creation",
            autonomy_level="level_1_local_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="local.example",
            allowed_tools=["static_analyzer"],
            created_by="operator",
            payload={"source_snapshot_digest": source_snapshot_digest},
        )
        task = _create_local_execution_slot_task(
            repository,
            campaign_id=campaign.id,
            tool_id="semgrep_local",
            source_snapshot_digest=source_snapshot_digest,
            plan_suffix="b",
        )
        campaign_id = campaign.id
        task_id = task.id
    finally:
        setup_session.close()

    barrier = Barrier(2)
    approval_ids: list[str] = []
    errors: list[BaseException] = []

    def create_approval():
        session = Session()
        try:
            repository = DatabaseRepository(session)
            campaign = repository.get_campaign(campaign_id)
            task = session.get(CampaignTaskRecord, task_id)
            assert campaign is not None
            assert task is not None
            barrier.wait(timeout=10)
            approval = ensure_campaign_local_tool_approval(
                campaign=campaign,
                task=task,
                source_snapshot_digest=source_snapshot_digest,
                tool_id="semgrep_local",
                plan_digest=plan_digest,
                repository=repository,
            )
            approval_ids.append(approval.id)
        except BaseException as exc:
            errors.append(exc)
        finally:
            session.close()

    threads = [Thread(target=create_approval), Thread(target=create_approval)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    verification_session = Session()
    try:
        repository = DatabaseRepository(verification_session)
        approvals = repository.list_campaign_approval_records(campaign_id)

        assert all(not thread.is_alive() for thread in threads)
        assert errors == []
        assert len(approval_ids) == 2
        assert len(set(approval_ids)) == 1
        assert len(approvals) == 1
        assert approvals[0].id == approval_ids[0]
        assert approvals[0].status == "pending"
    finally:
        verification_session.close()
        engine.dispose()


def test_generic_dispatch_rejects_local_tool_tasks():
    testing_session = _testing_session()
    source_snapshot_digest = f"sha256:{'a' * 64}"
    with testing_session() as session:
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id=None,
            name="Generic local-tool dispatch rejection",
            autonomy_level="level_1_local_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="local.example",
            allowed_tools=["static_analyzer"],
            created_by="operator",
            payload={"source_snapshot_digest": source_snapshot_digest},
        )
        task = _create_local_execution_slot_task(
            repository,
            campaign_id=campaign.id,
            tool_id="semgrep_local",
            source_snapshot_digest=source_snapshot_digest,
            plan_suffix="a",
        )

        assert (
            repository.mark_campaign_task_dispatched(
                task.id,
                execution_claim_id="agent_run_generic_local_task",
            )
            is None
        )

        persisted_task = session.get(CampaignTaskRecord, task.id)
        assert persisted_task is not None
        assert persisted_task.status == "queued"
        assert persisted_task.execution_claim_id is None
        assert (
            _local_execution_slot(
                repository,
                campaign_id=campaign.id,
                source_snapshot_digest=source_snapshot_digest,
            )
            is None
        )
        assert repository.list_campaign_agent_runs(campaign.id) == []


def test_atomic_local_tool_dispatch_does_not_leave_losing_agent_run(tmp_path: Path):
    database_path = tmp_path / "research-director-atomic-dispatch.db"
    engine = create_engine(
        f"sqlite+pysqlite:///{database_path.as_posix()}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    source_snapshot_digest = f"sha256:{'a' * 64}"
    setup_session = Session()
    try:
        repository = DatabaseRepository(setup_session)
        seed_sample_data(setup_session)
        campaign = repository.create_campaign(
            program_id=None,
            name="Atomic local-tool dispatch",
            autonomy_level="level_1_local_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="local.example",
            allowed_tools=["static_analyzer", "codeql_local"],
            created_by="operator",
            payload={"source_snapshot_digest": source_snapshot_digest},
        )
        first_task = _create_local_execution_slot_task(
            repository,
            campaign_id=campaign.id,
            tool_id="semgrep_local",
            source_snapshot_digest=source_snapshot_digest,
            plan_suffix="d",
        )
        second_task = _create_local_execution_slot_task(
            repository,
            campaign_id=campaign.id,
            tool_id="codeql_local",
            source_snapshot_digest=source_snapshot_digest,
            plan_suffix="e",
        )
        campaign_id = campaign.id
        first_task_id = first_task.id
        second_task_id = second_task.id
    finally:
        setup_session.close()

    barrier = Barrier(2)
    results: list[tuple[str, str | None]] = []
    errors: list[BaseException] = []

    def dispatch(task_id: str):
        session = Session()
        try:
            repository = DatabaseRepository(session)
            barrier.wait(timeout=10)
            dispatched = repository.dispatch_research_director_local_tool_task(
                task_id=task_id,
                agent_payload={"raw_payload_processed": False},
            )
            results.append(
                (
                    task_id,
                    dispatched[1].id if dispatched is not None else None,
                )
            )
        except BaseException as exc:
            errors.append(exc)
        finally:
            session.close()

    threads = [
        Thread(target=dispatch, args=(first_task_id,)),
        Thread(target=dispatch, args=(second_task_id,)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    verification_session = Session()
    try:
        repository = DatabaseRepository(verification_session)
        successful = [result for result in results if result[1] is not None]
        failed = [result for result in results if result[1] is None]
        tasks = {
            task.id: task for task in repository.list_campaign_tasks(campaign_id)
        }
        agent_runs = repository.list_campaign_agent_runs(campaign_id)

        assert all(not thread.is_alive() for thread in threads)
        assert errors == []
        assert len(successful) == 1
        assert len(failed) == 1
        assert len(agent_runs) == 1
        winning_task_id, execution_claim_id = successful[0]
        losing_task_id = failed[0][0]
        assert agent_runs[0].id == execution_claim_id
        assert agent_runs[0].task_id == winning_task_id
        assert tasks[winning_task_id].status == "dispatched"
        assert tasks[losing_task_id].status == "queued"
        assert tasks[losing_task_id].execution_claim_id is None
    finally:
        verification_session.close()
        engine.dispose()


def test_local_execution_slot_releases_after_lease_expiry(tmp_path: Path):
    database_path = tmp_path / "research-director-local-slot-expiry.db"
    engine = create_engine(
        f"sqlite+pysqlite:///{database_path.as_posix()}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    source_snapshot_digest = f"sha256:{'a' * 64}"
    session = Session()
    try:
        repository = DatabaseRepository(session)
        seed_sample_data(session)
        campaign = repository.create_campaign(
            program_id=None,
            name="Expired local-tool execution slot campaign",
            autonomy_level="level_1_local_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="local.example",
            allowed_tools=["static_analyzer", "codeql_local"],
            created_by="operator",
            payload={"source_snapshot_digest": source_snapshot_digest},
        )
        expired_task = _create_local_execution_slot_task(
            repository,
            campaign_id=campaign.id,
            tool_id="semgrep_local",
            source_snapshot_digest=source_snapshot_digest,
            plan_suffix="e",
        )
        next_task = _create_local_execution_slot_task(
            repository,
            campaign_id=campaign.id,
            tool_id="codeql_local",
            source_snapshot_digest=source_snapshot_digest,
            plan_suffix="f",
        )
        now = datetime.now(UTC)
        claimed = repository.claim_campaign_task_execution(expired_task.id, now=now)
        assert claimed is not None
        assert claimed.execution_lease_expires_at is not None

        expired = repository.expire_campaign_task_execution(
            claimed.id,
            now=claimed.execution_lease_expires_at + timedelta(seconds=1),
        )
        assert expired is not None
        assert expired.status == "failed"
        slot = _local_execution_slot(
            repository,
            campaign_id=campaign.id,
            source_snapshot_digest=source_snapshot_digest,
        )
        assert slot is not None
        assert slot.active_task_id is None
        assert slot.active_execution_claim_id is None

        claimed_next = repository.claim_campaign_task_execution(next_task.id)
        assert claimed_next is not None
        assert claimed_next.status == "running"
    finally:
        session.close()
        engine.dispose()
