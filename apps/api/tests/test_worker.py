from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.repository import DatabaseRepository, seed_sample_data
from app.worker import tasks as worker_tasks
from app.config import get_settings
from app.worker.tasks import dispatch_agent_task, ping, run_agent_task


def build_repository():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    seed_sample_data(session)
    return DatabaseRepository(session), session


def test_ping_task_returns_pong():
    assert ping.run() == "pong"


def test_dispatch_agent_task_enqueues_only_campaign_task_id(monkeypatch):
    calls: list[tuple[tuple, dict]] = []

    class FakeAsyncResult:
        id = "celery_task_1"

    def fake_delay(*args, **kwargs):
        calls.append((args, kwargs))
        return FakeAsyncResult()

    monkeypatch.setattr(worker_tasks.run_agent_task_from_queue, "delay", fake_delay)

    result = dispatch_agent_task(campaign_task_id="campaign_task_1")

    assert calls == [(("campaign_task_1",), {})]
    assert result == {
        "campaign_task_id": "campaign_task_1",
        "dispatch_mode": "celery",
        "celery_task_id": "celery_task_1",
    }


def test_dispatch_agent_task_can_run_inline_without_celery(monkeypatch):
    monkeypatch.setenv("WORKER_DISPATCH_MODE", "inline")
    get_settings.cache_clear()
    calls: list[str] = []

    def fake_run(campaign_task_id: str):
        calls.append(campaign_task_id)
        return {"status": "completed", "task_id": campaign_task_id}

    monkeypatch.setattr(worker_tasks.run_agent_task_from_queue, "run", fake_run)

    try:
        result = dispatch_agent_task(campaign_task_id="campaign_task_1")
    finally:
        get_settings.cache_clear()

    assert calls == ["campaign_task_1"]
    assert result == {
        "campaign_task_id": "campaign_task_1",
        "dispatch_mode": "inline",
        "result": {"status": "completed", "task_id": "campaign_task_1"},
    }


def test_run_agent_task_reloads_task_by_id_and_completes_safe_read_only_work():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Worker campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map surface",
            input_refs=["campaign:worker"],
            payload={"raw": "Authorization: Bearer secret-token"},
        )

        result = run_agent_task(task.id, repository=repository)

        assert result["status"] == "completed"
        assert result["task_id"] == task.id
        updated_task = repository.list_campaign_tasks(campaign.id)[0]
        agent_run = repository.list_campaign_agent_runs(campaign.id)[0]
        assert updated_task.status == "completed"
        assert updated_task.output_refs[0] == f"agent_run:{agent_run.id}"
        assert any(ref.startswith("codebase_map:") for ref in updated_task.output_refs)
        assert agent_run.status == "completed"
        assert agent_run.safety_gate_state == "allowed"
        assert agent_run.input_refs == [f"campaign_task:{task.id}"]
        assert "secret-token" not in str(updated_task.payload)
        assert "secret-token" not in str(agent_run.payload)
    finally:
        session.close()


def test_run_agent_task_reconciles_existing_dispatched_agent_run():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Worker reconcile campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate candidates",
            input_refs=[f"campaign:{campaign.id}"],
            payload={"raw": "Authorization: Bearer secret-token"},
        )
        dispatched_run = repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=task.id,
            agent_type=task.agent_type,
            status="dispatched",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=[],
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={"dispatch_contract": "id_only"},
        )

        result = run_agent_task(task.id, repository=repository)

        agent_runs = repository.list_campaign_agent_runs(campaign.id)
        updated_task = repository.list_campaign_tasks(campaign.id)[0]
        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]
        assert result["status"] == "completed"
        assert result["agent_run_id"] == dispatched_run.id
        assert len(agent_runs) == 1
        assert len(pipeline_runs) == 1
        assert pipeline_runs[0].payload["hypotheses"][0]["hypothesis_id"] == (
            "campaign_worker_hypothesis_1"
        )
        assert agent_runs[0].id == dispatched_run.id
        assert agent_runs[0].status == "completed"
        assert any(ref.startswith("pipeline_run:") for ref in agent_runs[0].output_refs)
        assert updated_task.output_refs[0] == f"agent_run:{dispatched_run.id}"
        assert any(ref.startswith("pipeline_run:") for ref in updated_task.output_refs)
        assert "secret-token" not in str(agent_runs[0].payload)
    finally:
        session.close()


def test_run_agent_task_extracts_authorized_codebase_facts_without_secret_payloads():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Static code map campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        task = repository.create_campaign_task(
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
from fastapi import APIRouter, Depends
from pydantic import BaseModel

router = APIRouter()

class FileExport(BaseModel):
    file_id: str
    owner_id: str

@router.get("/files/{file_id}/export")
def export_file(file_id: str, current_user = Depends(require_user)):
    authorize_owner_or_admin(current_user, file_id)
    return send_file(file_id)
""",
                    }
                ],
                "authorization": "Bearer secret-token",
            },
        )

        result = run_agent_task(task.id, repository=repository)

        assert result["status"] == "completed"
        maps = repository.list_campaign_codebase_maps(campaign.id)
        facts = repository.list_campaign_codebase_facts(campaign.id)
        scanner_runs = repository.list_campaign_scanner_runs(campaign.id)

        assert len(maps) == 1
        assert maps[0].repository == "authorized/service"
        assert maps[0].route_count == 1
        assert maps[0].handler_count == 1
        assert maps[0].model_count == 1
        assert maps[0].authz_check_count == 1
        assert maps[0].sensitive_sink_count == 1
        assert maps[0].payload == {
            "file_count": 1,
            "mapping_mode": "static_code_snippet_analysis",
            "raw_payload_processed": False,
        }

        facts_by_type = {fact.fact_type: fact for fact in facts}
        assert set(facts_by_type) == {
            "authz_check",
            "data_model",
            "route_handler",
            "sensitive_sink",
        }
        assert facts_by_type["route_handler"].source_path == "apps/api/routes/files.py"
        assert facts_by_type["route_handler"].symbol_name == "export_file"
        assert facts_by_type["route_handler"].route_method == "GET"
        assert facts_by_type["route_handler"].route_path == "/files/{file_id}/export"
        assert facts_by_type["authz_check"].authz_hint == "owner_or_admin_check"
        assert facts_by_type["sensitive_sink"].symbol_name == "send_file"
        assert facts_by_type["data_model"].symbol_name == "FileExport"

        assert len(scanner_runs) == 1
        assert scanner_runs[0].tool_name == "mythos_static_code_mapper"
        assert scanner_runs[0].candidate_count == 4
        assert "secret-token" not in str(maps + facts + scanner_runs)
        assert "Bearer" not in str(maps + facts + scanner_runs)
    finally:
        session.close()


def test_run_agent_task_maps_authorized_api_and_har_artifacts_into_route_facts():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="API artifact map campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized API and HAR",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_api_artifacts": [
                    {
                        "kind": "openapi",
                        "source_name": "openapi.json",
                        "payload": {
                            "paths": {
                                "/files/{file_id}/export": {
                                    "parameters": [
                                        {
                                            "name": "file_id",
                                            "in": "path",
                                            "required": True,
                                        },
                                        {
                                            "name": "Authorization",
                                            "in": "header",
                                        },
                                    ],
                                    "get": {
                                        "operationId": "exportFile",
                                        "security": [{"bearerAuth": []}],
                                        "parameters": [
                                            {"name": "download", "in": "query"},
                                            {"name": "session_token", "in": "query"},
                                        ],
                                        "requestBody": {
                                            "content": {
                                                "application/json": {
                                                    "schema": {
                                                        "type": "object",
                                                        "properties": {
                                                            "format": {"type": "string"},
                                                            "password": {"type": "string"},
                                                        },
                                                    }
                                                }
                                            }
                                        },
                                    }
                                }
                            }
                        },
                    },
                    {
                        "kind": "har",
                        "source_name": "capture.har",
                        "payload": {
                            "log": {
                                "entries": [
                                    {
                                        "request": {
                                            "method": "GET",
                                            "url": "https://authorized.example/files/123/export?token=secret-token",
                                        }
                                    }
                                ]
                            }
                        },
                    },
                ],
                "authorization": "Bearer secret-token",
            },
        )

        result = run_agent_task(task.id, repository=repository)

        assert result["status"] == "completed"
        maps = repository.list_campaign_codebase_maps(campaign.id)
        facts = repository.list_campaign_codebase_facts(campaign.id)
        route_facts = [fact for fact in facts if fact.fact_type == "route_handler"]

        assert len(maps) == 1
        assert maps[0].route_count == 2
        assert maps[0].payload["mapping_mode"] == "authorized_attack_surface_analysis"
        assert maps[0].payload["api_artifact_route_count"] == 2
        assert {fact.source_path for fact in route_facts} == {
            "capture.har",
            "openapi.json",
        }
        assert {
            (fact.route_method, fact.route_path, fact.symbol_name)
            for fact in route_facts
        } == {
            ("GET", "/[REDACTED]", "har_get_[REDACTED]"),
            ("GET", "/files/{file_id}/export", "exportFile"),
        }
        assert all(
            fact.payload["mapping_mode"] == "authorized_api_artifact"
            for fact in route_facts
        )
        assert "secret-token" not in str(maps + facts)
        assert "Bearer" not in str(maps + facts)
    finally:
        session.close()


def test_run_agent_task_generates_hypothesis_from_codebase_facts():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Code fact hypothesis campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
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
            title="Generate code-backed hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={"authorization": "Bearer secret-token"},
        )

        map_result = run_agent_task(map_task.id, repository=repository)
        result = run_agent_task(hypothesis_task.id, repository=repository)

        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]
        assert map_result["status"] == "completed"
        assert result["status"] == "completed"
        assert len(pipeline_runs) == 1

        payload = pipeline_runs[0].payload
        hypothesis = payload["hypotheses"][0]
        assessment = payload["hypothesis_assessments"][0]

        assert pipeline_runs[0].hypothesis_count == 1
        assert hypothesis["hypothesis_id"] == "codebase_fact_hypothesis_1"
        assert hypothesis["hypothesis"] == (
            "Review GET /files/{file_id}/export for object authorization boundary drift."
        )
        assert hypothesis["source_facts"] == [
            {
                "fact_ref": "codebase_fact:route_handler:/files/{file_id}/export",
                "artifact_kind": "code",
                "fact_type": "route_handler",
                "route_method": "GET",
                "route_path": "/files/{file_id}/export",
                "source_path": "apps/api/routes/files.py",
                "symbol_name": "export_file",
            },
            {
                "fact_ref": "codebase_fact:authz_check:owner_or_admin_check",
                "artifact_kind": "code",
                "authz_hint": "owner_or_admin_check",
                "fact_type": "authz_check",
                "source_path": "apps/api/routes/files.py",
                "symbol_name": "authorize_owner_or_admin",
            },
            {
                "fact_ref": "codebase_fact:sensitive_sink:send_file",
                "artifact_kind": "code",
                "fact_type": "sensitive_sink",
                "source_path": "apps/api/routes/files.py",
                "symbol_name": "send_file",
            },
        ]
        assert payload["target_model"] == {
            "objects": ["file"],
            "roles": ["user", "owner"],
            "sensitive_actions": ["GET /files/{file_id}/export"],
            "source_fact_refs": [
                "codebase_fact:route_handler:/files/{file_id}/export",
                "codebase_fact:authz_check:owner_or_admin_check",
                "codebase_fact:sensitive_sink:send_file",
            ],
        }
        assert assessment["candidate_id"] == "codebase_fact_hypothesis_1"
        assert assessment["candidate_status"] == "needs_human_review"
        assert assessment["refutation"]["reasons"] == ["codebase_fact_candidate_not_validated"]
        assert assessment["exploit_chain"]["primitives"] == [
            "GET /files/{file_id}/export",
            "owner_or_admin_check",
            "send_file",
        ]
        assert assessment["validation_plan"]["human_approval_required"] is True
        assert "secret-token" not in str(payload)
        assert "Bearer" not in str(payload)
    finally:
        session.close()


def test_run_agent_task_correlates_api_artifact_with_code_route_and_gates_api_only_candidate():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="API plus code hypothesis campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized code and API",
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
    return send_file(file_id)
""",
                    }
                ],
                "authorized_api_artifacts": [
                    {
                        "kind": "openapi",
                        "source_name": "openapi.json",
                        "payload": {
                            "paths": {
                                "/files/{file_id}/export": {
                                    "get": {"operationId": "exportFile"}
                                },
                                "/teams/{team_id}/invite": {
                                    "parameters": [
                                        {
                                            "name": "team_id",
                                            "in": "path",
                                            "required": True,
                                        }
                                    ],
                                    "post": {"operationId": "inviteTeamMember"}
                                },
                            }
                        },
                    }
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate correlated hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        assert run_agent_task(map_task.id, repository=repository)["status"] == "completed"
        assert (
            run_agent_task(hypothesis_task.id, repository=repository)["status"]
            == "completed"
        )

        pipeline_run = repository.list_pipeline_runs_for_program("program_example")[0]
        payload = pipeline_run.payload

        assert pipeline_run.hypothesis_count == 2
        file_assessment = next(
            assessment
            for assessment in payload["hypothesis_assessments"]
            if assessment["hypothesis"]["hypothesis_id"] == "codebase_fact_hypothesis_1"
        )
        team_assessment = next(
            assessment
            for assessment in payload["hypothesis_assessments"]
            if assessment["hypothesis"]["hypothesis_id"] == "codebase_fact_hypothesis_2"
        )

        file_source_facts = file_assessment["hypothesis"]["source_facts"]
        assert [
            fact["artifact_kind"]
            for fact in file_source_facts
            if fact["fact_type"] == "route_handler"
        ] == ["code", "api"]
        assert "api_artifact_candidate" not in file_assessment["hunter_assessment"]["reasons"]

        assert team_assessment["hypothesis"]["source_facts"][0]["artifact_kind"] == "api"
        assert team_assessment["hypothesis"]["source_facts"][0]["api_shape"] == {
            "path_parameters": ["team_id"]
        }
        assert "api_artifact_candidate" in team_assessment["hunter_assessment"]["reasons"]
        assert "api_shape:object_identifier_present" in team_assessment[
            "hunter_assessment"
        ]["reasons"]
        assert "missing_evidence:declared_authentication_or_scope_model" in team_assessment[
            "hunter_assessment"
        ]["reasons"]
        assert "declared_authentication_or_scope_model" in team_assessment[
            "hypothesis"
        ]["evidence_needed"]
        assert (
            "Resolve the declared authentication or scope model before preparing validation evidence."
            in team_assessment["validation_plan"]["steps"]
        )
        team_queue_item = next(
            item
            for item in payload["autonomous_hunt_queue"]
            if item["candidate_id"] == team_assessment["candidate_id"]
        )
        assert team_queue_item["status"] == "awaiting_evidence_review"
        assert team_queue_item["next_action"] == "resolve_evidence_gaps"
        assert team_queue_item["required_evidence"] == [
            "local_code_or_har_correlation",
            "declared_authentication_or_scope_model",
        ]
        assert team_queue_item["quality_gate_reasons"] == ["required_evidence_missing"]
        assert team_queue_item["human_approval_required"] is True
        assert "secret-token" not in str(payload)
        assert "Bearer" not in str(payload)
    finally:
        session.close()


def test_run_agent_task_marks_api_har_route_correlation_as_satisfied_evidence():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="API HAR correlated hypothesis campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized API and HAR",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_api_artifacts": [
                    {
                        "kind": "openapi",
                        "source_name": "openapi.json",
                        "payload": {
                            "paths": {
                                "/files/123/export": {
                                    "get": {"operationId": "exportFile"}
                                }
                            }
                        },
                    },
                    {
                        "kind": "har",
                        "source_name": "traffic.har",
                        "payload": {
                            "log": {
                                "entries": [
                                    {
                                        "request": {
                                            "method": "GET",
                                            "url": "https://authorized.example/files/123/export",
                                        }
                                    }
                                ]
                            }
                        },
                    },
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate correlated API HAR hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        assert run_agent_task(map_task.id, repository=repository)["status"] == "completed"
        assert (
            run_agent_task(hypothesis_task.id, repository=repository)["status"]
            == "completed"
        )

        payload = repository.list_pipeline_runs()[0].payload
        assessment = payload["hypothesis_assessments"][0]
        hunter = assessment["hunter_assessment"]
        hunt_queue = payload["autonomous_hunt_queue"][0]

        assert [
            fact["artifact_kind"]
            for fact in assessment["hypothesis"]["source_facts"]
            if fact["fact_type"] == "route_handler"
        ] == ["api", "har"]
        assert "api_artifact_candidate" in hunter["reasons"]
        assert "evidence_satisfied:local_code_or_har_correlation" in hunter["reasons"]
        assert "evidence_satisfied:local_code_or_api_schema_correlation" in hunter[
            "reasons"
        ]
        assert "cross_artifact_route_correlation" in hunter["evidence_focus"]
        assert hunt_queue["status"] == "awaiting_human_approval"
        assert hunt_queue["next_action"] == "review_validation_plan"
        assert hunt_queue["satisfied_evidence"] == [
            "local_code_or_har_correlation",
            "local_code_or_api_schema_correlation",
        ]
        assert "required_evidence" not in hunt_queue
        assert "quality_gate_reasons" not in hunt_queue
        assert hunt_queue["human_approval_required"] is True
        assert hunt_queue["blocked_actions"] == [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
            "bypass_scope_guard",
        ]
        assert "Authorization" not in str(payload)
        assert "secret-token" not in str(payload)
    finally:
        session.close()


def test_run_agent_task_correlates_template_routes_with_concrete_har_path():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Template route correlation campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map template route with concrete traffic",
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
    return send_file(file_id)
""",
                    }
                ],
                "authorized_api_artifacts": [
                    {
                        "kind": "openapi",
                        "source_name": "openapi.json",
                        "payload": {
                            "paths": {
                                "/files/{file_id}/export": {
                                    "parameters": [
                                        {
                                            "name": "file_id",
                                            "in": "path",
                                            "required": True,
                                        },
                                        {
                                            "name": "Authorization",
                                            "in": "header",
                                        },
                                    ],
                                    "get": {
                                        "operationId": "exportFile",
                                        "security": [{"bearerAuth": []}],
                                        "parameters": [
                                            {"name": "download", "in": "query"},
                                            {"name": "session_token", "in": "query"},
                                        ],
                                        "requestBody": {
                                            "content": {
                                                "application/json": {
                                                    "schema": {
                                                        "type": "object",
                                                        "properties": {
                                                            "format": {"type": "string"},
                                                            "password": {"type": "string"},
                                                        },
                                                    }
                                                }
                                            }
                                        },
                                    }
                                }
                            }
                        },
                    },
                    {
                        "kind": "har",
                        "source_name": "traffic.har",
                        "payload": {
                            "log": {
                                "entries": [
                                    {
                                        "request": {
                                            "method": "GET",
                                            "url": "https://authorized.example/files/123/export",
                                            "headers": [
                                                {
                                                    "name": "Authorization",
                                                    "value": "Bearer secret-token",
                                                }
                                            ],
                                        }
                                    }
                                ]
                            }
                        },
                    },
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate template-correlated hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        assert run_agent_task(map_task.id, repository=repository)["status"] == "completed"
        assert (
            run_agent_task(hypothesis_task.id, repository=repository)["status"]
            == "completed"
        )

        pipeline_run = repository.list_pipeline_runs_for_program("program_example")[0]
        payload = pipeline_run.payload

        assert pipeline_run.hypothesis_count == 1
        assessment = payload["hypothesis_assessments"][0]
        hunter = assessment["hunter_assessment"]
        hunt_queue = payload["autonomous_hunt_queue"][0]

        assert [
            fact["artifact_kind"]
            for fact in assessment["hypothesis"]["source_facts"]
            if fact["fact_type"] == "route_handler"
        ] == ["code", "api", "har"]
        api_fact = next(
            fact
            for fact in assessment["hypothesis"]["source_facts"]
            if fact["fact_type"] == "route_handler" and fact["artifact_kind"] == "api"
        )
        assert api_fact["api_shape"] == {
            "path_parameters": ["file_id"],
            "query_parameters": ["download"],
            "body_fields": ["format"],
            "request_body_present": True,
            "security_declared": True,
        }
        assert "codebase_route_candidate" in hunter["reasons"]
        assert "authorization_gap_candidate" in hunter["reasons"]
        assert "sensitive_sink_present" in hunter["reasons"]
        assert "evidence_satisfied:local_code_or_har_correlation" in hunter["reasons"]
        assert "evidence_satisfied:local_code_or_api_schema_correlation" in hunter[
            "reasons"
        ]
        assert "api_shape:object_identifier_present" in hunter["reasons"]
        assert "api_shape:request_body_present" in hunter["reasons"]
        assert "cross_artifact_route_correlation" in hunter["evidence_focus"]
        assert "api_object_identifier_shape" in hunter["evidence_focus"]
        assert "request_body_field_review" in hunter["evidence_focus"]
        assert "approved_test_object_id_matrix" in assessment["hypothesis"][
            "evidence_needed"
        ]
        assert "request_body_field_policy_review" in assessment["hypothesis"][
            "evidence_needed"
        ]
        assert "declared_authentication_or_scope_model" not in assessment[
            "hypothesis"
        ]["evidence_needed"]
        validation_steps = assessment["validation_plan"]["steps"]
        assert (
            "Map API object identifier fields to approved test objects before any two-account comparison."
            in validation_steps
        )
        assert (
            "Review request body field names locally; do not store raw body values or secrets."
            in validation_steps
        )
        assert (
            "Use only redacted HAR method and path evidence; ignore headers, cookies, and request values."
            in validation_steps
        )
        assert not any("raw body values" in step and "secret-token" in step for step in validation_steps)
        assert hunt_queue["status"] == "awaiting_evidence_review"
        assert hunt_queue["next_action"] == "resolve_evidence_gaps"
        assert hunt_queue["satisfied_evidence"] == [
            "local_code_or_har_correlation",
            "local_code_or_api_schema_correlation",
        ]
        assert hunt_queue["evidence_needed"] == assessment["hypothesis"][
            "evidence_needed"
        ]
        assert hunt_queue["safe_validation_plan"] == validation_steps
        assert hunt_queue["safe_validation_step_count"] == len(validation_steps)
        assert hunt_queue["validation_plan_status"] == "approval_required"
        assert hunt_queue["required_evidence"] == [
            "independent_refutation_or_static_rule"
        ]
        assert "local_code_or_har_correlation" not in hunt_queue["required_evidence"]
        assert "local_code_or_api_schema_correlation" not in hunt_queue[
            "required_evidence"
        ]
        assert hunt_queue["quality_gate_reasons"] == ["required_evidence_missing"]
        assert hunt_queue["human_approval_required"] is True
        assert hunt_queue["blocked_actions"] == [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
            "bypass_scope_guard",
        ]
        assert "Authorization" not in str(payload)
        assert "secret-token" not in str(payload)
        assert "session_token" not in str(payload)
        assert "password" not in str(payload)
        assert "execute_live_validation" in hunt_queue["blocked_actions"]
        assert "submit_report" in hunt_queue["blocked_actions"]
    finally:
        session.close()


def test_run_agent_task_generates_multiple_hypotheses_from_multiple_code_routes():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Multi route hypothesis campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
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

@router.post("/teams/{team_id}/invites")
def create_team_invite(team_id: str):
    require_role(team_id, "owner")
    return update_role(team_id)
""",
                    }
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate multi-route code-backed hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={"authorization": "Bearer secret-token"},
        )

        run_agent_task(map_task.id, repository=repository)
        result = run_agent_task(hypothesis_task.id, repository=repository)

        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]
        assert result["status"] == "completed"
        assert len(pipeline_runs) == 1

        payload = pipeline_runs[0].payload
        hypotheses = payload["hypotheses"]
        assessments = payload["hypothesis_assessments"]
        hunt_queue = payload["autonomous_hunt_queue"]

        assert pipeline_runs[0].hypothesis_count == 2
        assert [item["hypothesis"] for item in hypotheses] == [
            "Review GET /files/{file_id}/export for object authorization boundary drift.",
            "Review POST /teams/{team_id}/invites for object authorization boundary drift.",
        ]
        assert [item["candidate_id"] for item in assessments] == [
            "codebase_fact_hypothesis_1",
            "codebase_fact_hypothesis_2",
        ]
        assert [item["hypothesis_index"] for item in assessments] == [0, 1]
        assert payload["target_model"]["objects"] == ["file", "team"]
        assert payload["target_model"]["sensitive_actions"] == [
            "GET /files/{file_id}/export",
            "POST /teams/{team_id}/invites",
        ]
        assert payload["target_model"]["source_fact_refs"] == [
            "codebase_fact:route_handler:/files/{file_id}/export",
            "codebase_fact:authz_check:owner_or_admin_check",
            "codebase_fact:sensitive_sink:send_file",
            "codebase_fact:route_handler:/teams/{team_id}/invites",
            "codebase_fact:authz_check:role_check",
            "codebase_fact:sensitive_sink:update_role",
        ]
        assert assessments[0]["exploit_chain"]["primitives"] == [
            "GET /files/{file_id}/export",
            "owner_or_admin_check",
            "send_file",
        ]
        assert assessments[1]["exploit_chain"]["primitives"] == [
            "POST /teams/{team_id}/invites",
            "role_check",
            "update_role",
        ]
        assert all(item["validation_plan"]["human_approval_required"] is True for item in assessments)
        assert all(item["candidate_status"] == "needs_human_review" for item in assessments)
        file_hunter = assessments[0]["hunter_assessment"]
        role_hunter = assessments[1]["hunter_assessment"]
        assert file_hunter["playbook_id"] == "bola_idor"
        assert file_hunter["hunter_priority_score"] == 56
        assert "refutation_evidence:same_handler_object_authz" in file_hunter["reasons"]
        assert "missing_evidence:authz_bypass_or_misbind_trace" in file_hunter["reasons"]
        assert "same_handler_object_authz_trace" in file_hunter["evidence_focus"]
        assert "authz_bypass_or_misbind_trace" in file_hunter["evidence_focus"]
        assert role_hunter["playbook_id"] == "role_boundary"
        assert role_hunter["hunter_priority_score"] == 72
        assert "refutation_evidence:same_handler_object_authz" not in role_hunter["reasons"]
        assert hypotheses[0]["hunter_assessment"] == assessments[0]["hunter_assessment"]
        assert hypotheses[1]["hunter_assessment"] == assessments[1]["hunter_assessment"]
        assert hypotheses[0]["priority_score"] == assessments[0]["hunter_assessment"][
            "hunter_priority_score"
        ]
        assert hypotheses[1]["priority_score"] == assessments[1]["hunter_assessment"][
            "hunter_priority_score"
        ]
        assert [item["candidate_id"] for item in hunt_queue] == [
            "codebase_fact_hypothesis_2",
            "codebase_fact_hypothesis_1",
        ]
        assert [item["top_candidate_rank"] for item in hunt_queue] == [1, 2]
        assert hunt_queue[0]["evidence_trace_summary"]["trace_status"] == "traceable"
        assert hunt_queue[0]["report_readiness"]["status"] == "needs_safe_validation_plan"
        assert hunt_queue[0]["report_readiness"]["report_submission_allowed"] is False
        assert hunt_queue[1]["required_evidence"] == ["authz_bypass_or_misbind_trace"]
        assert hunt_queue[1]["report_readiness"]["status"] == "blocked_by_required_evidence"
        assert all(item["human_approval_required"] is True for item in hunt_queue)
        assert all("execute_live_validation" in item["blocked_actions"] for item in hunt_queue)
        assert "secret-token" not in str(payload)
        assert "Bearer" not in str(payload)
    finally:
        session.close()


def test_run_agent_task_applies_program_lessons_to_code_hunt_queue():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Lesson-aware code hunt campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        for index in range(2):
            repository.save_learning_signal(
                program_id="program_example",
                playbook_id="bola_idor",
                outcome="accepted",
                surface_key="file_id:export",
                notes=f"Accepted safe fixture {index}; Authorization: Bearer secret-token",
                evidence_quality="strong",
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

@router.post("/teams/{team_id}/invites")
def create_team_invite(team_id: str):
    require_role(team_id, "owner")
    return update_role(team_id)
""",
                    }
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate lesson-aware hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        run_agent_task(map_task.id, repository=repository)
        run_agent_task(hypothesis_task.id, repository=repository)

        pipeline_run = repository.list_pipeline_runs()[0]
        payload = pipeline_run.payload
        assessments = payload["hypothesis_assessments"]
        file_assessment = assessments[0]["hunter_assessment"]
        role_assessment = assessments[1]["hunter_assessment"]

        assert file_assessment["playbook_id"] == "bola_idor"
        assert file_assessment["hunter_priority_score"] == 64
        assert "lesson:applied:boost" in file_assessment["reasons"]
        assert "lesson:boost:accepted_strong_evidence" in file_assessment["reasons"]
        assert "refutation_evidence:same_handler_object_authz" in file_assessment["reasons"]
        assert "advisory_memory_only" in file_assessment["safety_notes"]
        assert role_assessment["hunter_priority_score"] == 72
        assert payload["autonomous_hunt_queue"][0]["candidate_id"] == "codebase_fact_hypothesis_2"
        file_queue_item = next(
            item
            for item in payload["autonomous_hunt_queue"]
            if item["candidate_id"] == "codebase_fact_hypothesis_1"
        )
        assert file_queue_item["raw_priority_score"] == 64
        assert file_queue_item["priority_score"] == 39
        assert file_queue_item["status"] == "awaiting_evidence_review"
        assert file_queue_item["human_approval_required"] is True
        assert "secret-token" not in str(payload)
        assert "Bearer" not in str(payload)
    finally:
        session.close()


def test_run_agent_task_routes_evidence_needed_lessons_to_evidence_review_queue():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Evidence-needed lesson code hunt campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        repository.save_learning_signal(
            program_id="program_example",
            playbook_id="bola_idor",
            outcome="informative",
            surface_key="file_id:export",
            notes="Candidate needed more evidence before ranking boost.",
            evidence_quality="weak",
            target_relationships=[
                "candidate:H-001",
                "evidence_ready:false",
                "trace_status:needs_evidence",
                "missing_evidence:independent_cross_check",
                "missing_required_artifact:policy",
                "learned_evidence:lesson_evidence_needed_missing_evidence_independent_cross_check",
            ],
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

        run_agent_task(map_task.id, repository=repository)
        run_agent_task(hypothesis_task.id, repository=repository)

        payload = repository.list_pipeline_runs()[0].payload
        hunter = payload["hypothesis_assessments"][0]["hunter_assessment"]
        hunt_queue = payload["autonomous_hunt_queue"][0]

        assert "lesson:applied:evidence_needed" in hunter["reasons"]
        assert "lesson:evidence_needed:missing_evidence:independent_cross_check" in hunter[
            "reasons"
        ]
        assert hunt_queue["next_action"] == "resolve_evidence_gaps"
        assert hunt_queue["required_evidence"] == [
            "independent_refutation_or_static_rule",
            "policy",
            "authz_bypass_or_misbind_trace",
        ]
        assert hunt_queue["status"] == "awaiting_evidence_review"
        assert hunt_queue["human_approval_required"] is True
        assert hunt_queue["blocked_actions"] == [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
            "bypass_scope_guard",
        ]
        assert "secret-token" not in str(payload)
        assert "Bearer" not in str(payload)
    finally:
        session.close()


def test_worker_hunt_queue_demotes_duplicate_risk_before_ranking():
    queue = worker_tasks._worker_autonomous_hunt_queue(
        [
            {
                "candidate_id": "high_duplicate_risk",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 95,
                    "duplicate_risk_score": 80,
                    "reasons": [
                        "codebase_route_candidate",
                        "lesson:applied:duplicate_watch",
                    ],
                },
            },
            {
                "candidate_id": "clean_code_backed_candidate",
                "hunter_assessment": {
                    "playbook_id": "role_boundary",
                    "hunter_priority_score": 72,
                    "duplicate_risk_score": 20,
                    "reasons": ["codebase_route_candidate"],
                },
            },
        ]
    )

    assert queue[0]["candidate_id"] == "clean_code_backed_candidate"
    duplicate_item = queue[1]
    assert duplicate_item["candidate_id"] == "high_duplicate_risk"
    assert duplicate_item["raw_priority_score"] == 95
    assert duplicate_item["priority_score"] < queue[0]["priority_score"]
    assert duplicate_item["status"] == "awaiting_deduplication_review"
    assert duplicate_item["next_action"] == "deduplicate_candidate"
    assert duplicate_item["required_evidence"] == [
        "prior_submission_search",
        "candidate_similarity_review",
    ]
    assert duplicate_item["quality_gate_reasons"] == ["duplicate_risk_high"]
    assert duplicate_item["human_approval_required"] is True
    assert duplicate_item["blocked_actions"] == [
        "execute_live_validation",
        "touch_real_user_data",
        "submit_report",
        "bypass_scope_guard",
    ]


def test_worker_hunt_queue_routes_direct_missing_evidence_reasons_to_review():
    queue = worker_tasks._worker_autonomous_hunt_queue(
        [
            {
                "candidate_id": "missing_independent_review",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 88,
                    "duplicate_risk_score": 10,
                    "reasons": [
                        "codebase_route_candidate",
                        "missing_evidence:independent_cross_check",
                        "missing_required_artifact:policy",
                    ],
                },
                "hypothesis": {
                    "source_facts": [
                        {
                            "fact_ref": "codebase_fact:route_handler:/files/{file_id}/export",
                            "artifact_kind": "code",
                        }
                    ]
                },
            }
        ]
    )

    queue_item = queue[0]
    assert queue_item["status"] == "awaiting_evidence_review"
    assert queue_item["next_action"] == "resolve_evidence_gaps"
    assert queue_item["required_evidence"] == [
        "independent_refutation_or_static_rule",
        "policy",
    ]
    assert queue_item["raw_priority_score"] == 88
    assert queue_item["priority_score"] == 63
    assert queue_item["quality_gate_reasons"] == ["required_evidence_missing"]
    assert queue_item["human_approval_required"] is True


def test_worker_hunt_queue_accepts_cross_artifact_route_correlation_as_evidence():
    queue = worker_tasks._worker_autonomous_hunt_queue(
        [
            {
                "candidate_id": "api_har_correlated_candidate",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 88,
                    "duplicate_risk_score": 10,
                    "reasons": [
                        "codebase_route_candidate",
                        "api_artifact_candidate",
                    ],
                },
                "hypothesis": {
                    "source_facts": [
                        {
                            "fact_ref": "api_artifact:route:GET:/files/{file_id}/export",
                            "artifact_kind": "api",
                            "fact_type": "route_handler",
                        },
                        {
                            "fact_ref": "har_artifact:route:GET:/files/{file_id}/export",
                            "artifact_kind": "har",
                            "fact_type": "route_handler",
                        },
                    ]
                },
            }
        ]
    )

    queue_item = queue[0]
    assert queue_item["status"] == "awaiting_human_approval"
    assert queue_item["next_action"] == "review_validation_plan"
    assert queue_item["priority_score"] == 88
    assert queue_item["satisfied_evidence"] == [
        "local_code_or_har_correlation",
        "local_code_or_api_schema_correlation",
    ]
    assert queue_item["evidence_trace_summary"] == {
        "trace_status": "traceable",
        "source_fact_count": 2,
        "traceable_source_fact_count": 2,
        "route_fact_count": 2,
        "artifact_kinds": ["api", "har"],
        "source_fact_types": ["route_handler"],
        "report_submission_allowed": False,
    }
    assert queue_item["report_readiness"] == {
        "status": "needs_safe_validation_plan",
        "submission_blocked": True,
        "report_submission_allowed": False,
        "required_evidence_count": 0,
        "safe_validation_step_count": 0,
        "trace_status": "traceable",
        "next_allowed_action": "Draft a non-destructive validation plan before report drafting.",
    }
    assert "required_evidence" not in queue_item
    assert "quality_gate_reasons" not in queue_item
    assert "raw_priority_score" not in queue_item
    assert queue_item["human_approval_required"] is True
    assert queue_item["blocked_actions"] == [
        "execute_live_validation",
        "touch_real_user_data",
        "submit_report",
        "bypass_scope_guard",
    ]


def test_worker_hunt_queue_returns_ranked_top_five_candidates_only():
    queue = worker_tasks._worker_autonomous_hunt_queue(
        [
            {
                "candidate_id": f"candidate_{score}",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": score,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
            }
            for score in [30, 90, 70, 95, 50, 85]
        ]
    )

    assert [item["candidate_id"] for item in queue] == [
        "candidate_95",
        "candidate_90",
        "candidate_85",
        "candidate_70",
        "candidate_50",
    ]
    assert [item["top_candidate_rank"] for item in queue] == [1, 2, 3, 4, 5]
    assert "candidate_30" not in [item["candidate_id"] for item in queue]
    assert all(item["human_approval_required"] is True for item in queue)
    assert all("submit_report" in item["blocked_actions"] for item in queue)


def test_worker_hunt_queue_demotes_same_route_duplicate_candidates():
    queue = worker_tasks._worker_autonomous_hunt_queue(
        [
            {
                "candidate_id": "same_route_lower",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 78,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
                "hypothesis": {
                    "source_facts": [
                        {
                            "fact_ref": "api_artifact:route:GET:/files/{file_id}/export",
                            "artifact_kind": "api",
                            "fact_type": "route_handler",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                        }
                    ]
                },
            },
            {
                "candidate_id": "unique_route",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 82,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
                "hypothesis": {
                    "source_facts": [
                        {
                            "fact_ref": "api_artifact:route:GET:/teams/{team_id}/members",
                            "artifact_kind": "api",
                            "fact_type": "route_handler",
                            "route_method": "GET",
                            "route_path": "/teams/{team_id}/members",
                        }
                    ]
                },
            },
            {
                "candidate_id": "same_route_best",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 90,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
                "hypothesis": {
                    "source_facts": [
                        {
                            "fact_ref": "har_artifact:route:GET:/files/{file_id}/export",
                            "artifact_kind": "har",
                            "fact_type": "route_handler",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                        }
                    ]
                },
            },
        ]
    )

    assert [item["candidate_id"] for item in queue] == [
        "same_route_best",
        "unique_route",
        "same_route_lower",
    ]
    assert [item["top_candidate_rank"] for item in queue] == [1, 2, 3]
    lower_duplicate = queue[2]
    assert lower_duplicate["priority_score"] == 58
    assert lower_duplicate["raw_priority_score"] == 78
    assert lower_duplicate["status"] == "awaiting_deduplication_review"
    assert lower_duplicate["next_action"] == "deduplicate_candidate"
    assert lower_duplicate["required_evidence"] == [
        "prior_submission_search",
        "candidate_similarity_review",
    ]
    assert lower_duplicate["quality_gate_reasons"] == ["similar_candidate_shape"]
    assert all("_candidate_similarity_key" not in item for item in queue)
    assert all(item["human_approval_required"] is True for item in queue)


def test_worker_hunt_queue_evidence_trace_summary_filters_sensitive_labels():
    queue = worker_tasks._worker_autonomous_hunt_queue(
        [
            {
                "candidate_id": "sensitive_trace_labels",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 72,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
                "hypothesis": {
                    "source_facts": [
                        {
                            "fact_ref": "codebase_fact:route_handler:/files/{file_id}/export",
                            "artifact_kind": "Authorization",
                            "fact_type": "session_token",
                        },
                        {
                            "fact_ref": "codebase_fact:route_handler:/teams/{team_id}/members",
                            "artifact_kind": "code",
                            "fact_type": "route_handler",
                        },
                    ]
                },
            }
        ]
    )

    summary = queue[0]["evidence_trace_summary"]
    assert summary == {
        "trace_status": "needs_evidence",
        "source_fact_count": 2,
        "traceable_source_fact_count": 1,
        "route_fact_count": 1,
        "artifact_kinds": ["code"],
        "source_fact_types": ["route_handler"],
        "report_submission_allowed": False,
    }
    assert "Authorization" not in str(summary)
    assert "session_token" not in str(summary)
    assert queue[0]["report_readiness"] == {
        "status": "blocked_by_evidence_trace",
        "submission_blocked": True,
        "report_submission_allowed": False,
        "required_evidence_count": 0,
        "safe_validation_step_count": 0,
        "trace_status": "needs_evidence",
        "next_allowed_action": "Confirm candidate source facts are traceable before report drafting.",
    }


def test_worker_hunt_queue_marks_traceable_planned_candidate_report_draft_ready():
    queue = worker_tasks._worker_autonomous_hunt_queue(
        [
            {
                "candidate_id": "report_ready_candidate",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 88,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
                "hypothesis": {
                    "evidence_needed": ["approved_test_object_id_matrix"],
                    "source_facts": [
                        {
                            "fact_ref": "api_artifact:route:GET:/files/{file_id}/export",
                            "artifact_kind": "api",
                            "fact_type": "route_handler",
                        },
                        {
                            "fact_ref": "har_artifact:route:GET:/files/{file_id}/export",
                            "artifact_kind": "har",
                            "fact_type": "route_handler",
                        },
                    ],
                },
                "validation_plan": {
                    "status": "approval_required",
                    "steps": [
                        "Confirm scope and approved test accounts before validation.",
                        "Use only redacted HAR method and path evidence.",
                    ],
                },
            }
        ]
    )

    queue_item = queue[0]
    assert queue_item["report_readiness"] == {
        "status": "submission_blocked_draft_ready",
        "submission_blocked": True,
        "report_submission_allowed": False,
        "required_evidence_count": 0,
        "safe_validation_step_count": 2,
        "trace_status": "traceable",
        "next_allowed_action": "Prepare a submission-blocked draft for human redaction review.",
    }
    assert queue_item["safe_validation_step_count"] == 2
    assert queue_item["evidence_trace_summary"]["trace_status"] == "traceable"
    assert "required_evidence" not in queue_item


def test_worker_hunt_queue_deduplicates_template_and_concrete_route_shapes():
    queue = worker_tasks._worker_autonomous_hunt_queue(
        [
            {
                "candidate_id": "api_template_route",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 88,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
                "hypothesis": {
                    "source_facts": [
                        {
                            "fact_ref": "api_artifact:route:GET:/files/{file_id}/export",
                            "artifact_kind": "api",
                            "fact_type": "route_handler",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                        }
                    ]
                },
            },
            {
                "candidate_id": "har_concrete_route",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 84,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
                "hypothesis": {
                    "source_facts": [
                        {
                            "fact_ref": "har_artifact:route:GET:/files/123/export",
                            "artifact_kind": "har",
                            "fact_type": "route_handler",
                            "route_method": "GET",
                            "route_path": "/files/123/export",
                        }
                    ]
                },
            },
            {
                "candidate_id": "different_concrete_route",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 80,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
                "hypothesis": {
                    "source_facts": [
                        {
                            "fact_ref": "har_artifact:route:GET:/teams/123/members",
                            "artifact_kind": "har",
                            "fact_type": "route_handler",
                            "route_method": "GET",
                            "route_path": "/teams/123/members",
                        }
                    ]
                },
            },
        ]
    )

    assert [item["candidate_id"] for item in queue] == [
        "api_template_route",
        "different_concrete_route",
        "har_concrete_route",
    ]
    concrete_duplicate = queue[2]
    assert concrete_duplicate["priority_score"] == 64
    assert concrete_duplicate["raw_priority_score"] == 84
    assert concrete_duplicate["status"] == "awaiting_deduplication_review"
    assert concrete_duplicate["required_evidence"] == [
        "prior_submission_search",
        "candidate_similarity_review",
    ]
    assert concrete_duplicate["quality_gate_reasons"] == ["similar_candidate_shape"]
    assert all("_candidate_similarity_key" not in item for item in queue)


def test_worker_hunt_queue_demotes_untraceable_candidate_before_ranking():
    queue = worker_tasks._worker_autonomous_hunt_queue(
        [
            {
                "candidate_id": "untraceable_high_score",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 90,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
                "hypothesis": {"source_facts": []},
            },
            {
                "candidate_id": "traceable_lower_score",
                "hunter_assessment": {
                    "playbook_id": "role_boundary",
                    "hunter_priority_score": 70,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
                "hypothesis": {
                    "source_facts": [
                        {
                            "fact_ref": "codebase_fact:route_handler:/teams/{team_id}/invites",
                            "artifact_kind": "code",
                        }
                    ]
                },
            },
        ]
    )

    assert queue[0]["candidate_id"] == "traceable_lower_score"
    untraceable_item = queue[1]
    assert untraceable_item["candidate_id"] == "untraceable_high_score"
    assert untraceable_item["status"] == "awaiting_evidence_review"
    assert untraceable_item["next_action"] == "resolve_evidence_gaps"
    assert untraceable_item["required_evidence"] == ["traceable_source_fact"]
    assert untraceable_item["quality_gate_reasons"] == ["source_trace_missing"]
    assert untraceable_item["raw_priority_score"] == 90
    assert untraceable_item["priority_score"] < queue[0]["priority_score"]


def test_run_agent_task_does_not_borrow_hypothesis_facts_from_unrelated_files():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Code fact source scoping campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
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
    return {"file_id": file_id}
""",
                    },
                    {
                        "path": "apps/api/routes/admin.py",
                        "content": """
def admin_archive(file_id: str):
    authorize_owner_or_admin(file_id)
    return send_file(file_id)
""",
                    },
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate code-backed hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        map_result = run_agent_task(map_task.id, repository=repository)
        result = run_agent_task(hypothesis_task.id, repository=repository)

        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]
        payload = pipeline_runs[0].payload
        assessment = payload["hypothesis_assessments"][0]

        assert map_result["status"] == "completed"
        assert result["status"] == "completed"
        assert payload["hypotheses"][0]["source_facts"] == [
            {
                "fact_ref": "codebase_fact:route_handler:/files/{file_id}/export",
                "artifact_kind": "code",
                "fact_type": "route_handler",
                "route_method": "GET",
                "route_path": "/files/{file_id}/export",
                "source_path": "apps/api/routes/files.py",
                "symbol_name": "export_file",
            }
        ]
        assert payload["target_model"]["source_fact_refs"] == [
            "codebase_fact:route_handler:/files/{file_id}/export"
        ]
        assert assessment["exploit_chain"]["primitives"] == ["GET /files/{file_id}/export"]
    finally:
        session.close()


def test_run_agent_task_does_not_borrow_hypothesis_facts_from_unrelated_handlers():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Code fact handler scoping campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
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
    return {"file_id": file_id}

def admin_archive(file_id: str):
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
            title="Generate handler-scoped hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        map_result = run_agent_task(map_task.id, repository=repository)
        result = run_agent_task(hypothesis_task.id, repository=repository)

        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]
        payload = pipeline_runs[0].payload
        assessment = payload["hypothesis_assessments"][0]

        assert map_result["status"] == "completed"
        assert result["status"] == "completed"
        assert payload["hypotheses"][0]["source_facts"] == [
            {
                "fact_ref": "codebase_fact:route_handler:/files/{file_id}/export",
                "artifact_kind": "code",
                "fact_type": "route_handler",
                "route_method": "GET",
                "route_path": "/files/{file_id}/export",
                "source_path": "apps/api/routes/files.py",
                "symbol_name": "export_file",
            }
        ]
        assert payload["target_model"]["source_fact_refs"] == [
            "codebase_fact:route_handler:/files/{file_id}/export"
        ]
        assert assessment["exploit_chain"]["primitives"] == ["GET /files/{file_id}/export"]
    finally:
        session.close()


def test_run_agent_task_ignores_comment_and_string_calls_when_mapping_code_facts():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Code fact lexical scoping campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
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
                        "content": '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    # authorize_owner_or_admin(file_id) is intentionally not active code
    note = "send_file(file_id) should not be mapped from documentation text"
    return {"file_id": file_id, "note": note}
''',
                    }
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate lexical code-backed hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        map_result = run_agent_task(map_task.id, repository=repository)
        result = run_agent_task(hypothesis_task.id, repository=repository)

        facts = repository.list_campaign_codebase_facts(campaign.id)
        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]
        payload = pipeline_runs[0].payload
        assessment = payload["hypothesis_assessments"][0]

        assert map_result["status"] == "completed"
        assert result["status"] == "completed"
        assert {fact.fact_type for fact in facts} == {"route_handler"}
        assert payload["hypotheses"][0]["source_facts"] == [
            {
                "fact_ref": "codebase_fact:route_handler:/files/{file_id}/export",
                "artifact_kind": "code",
                "fact_type": "route_handler",
                "route_method": "GET",
                "route_path": "/files/{file_id}/export",
                "source_path": "apps/api/routes/files.py",
                "symbol_name": "export_file",
            }
        ]
        assert payload["target_model"]["source_fact_refs"] == [
            "codebase_fact:route_handler:/files/{file_id}/export"
        ]
        assert assessment["exploit_chain"]["primitives"] == ["GET /files/{file_id}/export"]
    finally:
        session.close()


def test_run_agent_task_does_not_attach_module_level_calls_to_route_hypotheses():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Code fact module scope campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
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
authorize_owner_or_admin("startup-check")
send_file("startup-check")

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    return {"file_id": file_id}
""",
                    }
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate module-scope-safe hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        map_result = run_agent_task(map_task.id, repository=repository)
        result = run_agent_task(hypothesis_task.id, repository=repository)

        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]
        payload = pipeline_runs[0].payload
        assessment = payload["hypothesis_assessments"][0]

        assert map_result["status"] == "completed"
        assert result["status"] == "completed"
        assert payload["hypotheses"][0]["source_facts"] == [
            {
                "fact_ref": "codebase_fact:route_handler:/files/{file_id}/export",
                "artifact_kind": "code",
                "fact_type": "route_handler",
                "route_method": "GET",
                "route_path": "/files/{file_id}/export",
                "source_path": "apps/api/routes/files.py",
                "symbol_name": "export_file",
            }
        ]
        assert payload["target_model"]["source_fact_refs"] == [
            "codebase_fact:route_handler:/files/{file_id}/export"
        ]
        assert assessment["exploit_chain"]["primitives"] == ["GET /files/{file_id}/export"]
    finally:
        session.close()


def test_run_agent_task_does_not_attach_post_handler_module_calls_to_route_hypotheses():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Code fact post handler module scope campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
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
    return {"file_id": file_id}

authorize_owner_or_admin("startup-check")
send_file("startup-check")
""",
                    }
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate post-handler module-scope-safe hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        map_result = run_agent_task(map_task.id, repository=repository)
        result = run_agent_task(hypothesis_task.id, repository=repository)

        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]
        payload = pipeline_runs[0].payload
        assessment = payload["hypothesis_assessments"][0]

        assert map_result["status"] == "completed"
        assert result["status"] == "completed"
        assert payload["hypotheses"][0]["source_facts"] == [
            {
                "fact_ref": "codebase_fact:route_handler:/files/{file_id}/export",
                "artifact_kind": "code",
                "fact_type": "route_handler",
                "route_method": "GET",
                "route_path": "/files/{file_id}/export",
                "source_path": "apps/api/routes/files.py",
                "symbol_name": "export_file",
            }
        ]
        assert payload["target_model"]["source_fact_refs"] == [
            "codebase_fact:route_handler:/files/{file_id}/export"
        ]
        assert assessment["exploit_chain"]["primitives"] == ["GET /files/{file_id}/export"]
    finally:
        session.close()


def test_run_agent_task_plans_validation_against_codebase_fact_target():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Code fact validation plan campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
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
        report_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_chain_review",
            agent_type="report_agent",
            title="Review code-backed validation gate",
            input_refs=[f"campaign:{campaign.id}"],
            payload={"cookie": "session=secret"},
        )

        map_result = run_agent_task(map_task.id, repository=repository)
        result = run_agent_task(report_task.id, repository=repository)

        validation_runs = repository.list_campaign_validation_runs(campaign.id)
        approvals = repository.list_campaign_approval_records(campaign.id)

        assert map_result["status"] == "completed"
        assert result["status"] == "completed"
        assert len(validation_runs) == 1
        assert len(approvals) == 1
        validation_run = validation_runs[0]
        approval = approvals[0]

        assert validation_run.target_ref == "codebase_fact:route_handler:/files/{file_id}/export"
        assert validation_run.approval_required is True
        assert validation_run.allowed_to_execute is False
        assert validation_run.safety_gate_state == "awaiting_approval"
        assert validation_run.summary == (
            "Validation is planned for mapped code fact GET /files/{file_id}/export but blocked pending durable human approval."
        )
        assert validation_run.payload == {
            "approval_record_id": approval.id,
            "no_live_requests": True,
            "raw_payload_processed": False,
            "source_fact_refs": [
                "codebase_fact:route_handler:/files/{file_id}/export",
                "codebase_fact:authz_check:owner_or_admin_check",
                "codebase_fact:sensitive_sink:send_file",
            ],
            "target_route": "GET /files/{file_id}/export",
        }
        assert approval.requested_action == "two_account_authorization_check"
        assert approval.asset == "authorized/service"
        assert approval.plan_digest == validation_run.plan_digest
        assert "session=secret" not in str(validation_runs + approvals)
    finally:
        session.close()


def test_run_agent_task_prioritizes_authorization_gap_candidate_without_execution():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Authorization gap hypothesis campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
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
            title="Generate code-backed hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={"authorization": "Bearer secret-token"},
        )

        map_result = run_agent_task(map_task.id, repository=repository)
        result = run_agent_task(hypothesis_task.id, repository=repository)

        facts = repository.list_campaign_codebase_facts(campaign.id)
        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]

        assert map_result["status"] == "completed"
        assert result["status"] == "completed"
        assert {fact.fact_type for fact in facts} == {
            "authorization_gap_candidate",
            "route_handler",
            "sensitive_sink",
        }
        assert len(pipeline_runs) == 1

        payload = pipeline_runs[0].payload
        assessment = payload["hypothesis_assessments"][0]
        hunt_queue = payload["autonomous_hunt_queue"][0]

        assert assessment["candidate_status"] == "needs_human_review"
        assert assessment["validation_plan"]["human_approval_required"] is True
        assert {
            fact["fact_type"] for fact in assessment["hypothesis"]["source_facts"]
        } == {
            "authorization_gap_candidate",
            "route_handler",
            "sensitive_sink",
        }
        persisted_gap = next(
            fact for fact in facts if fact.fact_type == "authorization_gap_candidate"
        )
        assert persisted_gap.payload["root_cause"] == "missing_object_ownership_check"
        assert persisted_gap.payload["security_invariant"] == (
            "Object-level actions must verify requester ownership or role before sensitive sinks run."
        )
        assert persisted_gap.payload["sink_symbols"] == ["send_file"]
        source_gap = next(
            fact
            for fact in assessment["hypothesis"]["source_facts"]
            if fact["fact_type"] == "authorization_gap_candidate"
        )
        assert source_gap["root_cause"] == "missing_object_ownership_check"
        assert source_gap["security_invariant"] == (
            "Object-level actions must verify requester ownership or role before sensitive sinks run."
        )
        assert source_gap["sink_symbols"] == ["send_file"]
        assert source_gap["sink_count"] == 1
        assert source_gap["review_state"] == "needs_human_review"
        assert source_gap["execution_allowed"] is False
        assert source_gap["validation_allowed"] is False
        assert source_gap["report_submission_allowed"] is False
        assert "missing_handler_authz_check" in assessment["exploit_chain"]["primitives"]
        assert hunt_queue["status"] == "awaiting_evidence_review"
        assert hunt_queue["next_action"] == "resolve_evidence_gaps"
        assert hunt_queue["required_evidence"] == ["independent_refutation_or_static_rule"]
        assert hunt_queue["quality_gate_reasons"] == ["required_evidence_missing"]
        assert hunt_queue["raw_priority_score"] > hunt_queue["priority_score"]
        assert hunt_queue["human_approval_required"] is True
        assert hunt_queue["blocked_actions"] == [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
            "bypass_scope_guard",
        ]
        assert "secret-token" not in str(facts + pipeline_runs)
        assert "Bearer" not in str(facts + pipeline_runs)
    finally:
        session.close()


def test_run_agent_task_boosts_authorization_gap_candidate_over_mapped_authz_route():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Authorization gap triage campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
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
    return send_file(file_id)

@router.post("/teams/{team_id}/invites")
def create_team_invite(team_id: str):
    require_role(team_id, "owner")
    return update_role(team_id)
""",
                    }
                ],
                "authorization": "Bearer secret-token",
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate gap-aware hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        run_agent_task(map_task.id, repository=repository)
        result = run_agent_task(hypothesis_task.id, repository=repository)

        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]
        assert result["status"] == "completed"
        assert len(pipeline_runs) == 1

        payload = pipeline_runs[0].payload
        assessments = payload["hypothesis_assessments"]
        file_assessment = assessments[0]
        role_assessment = assessments[1]
        file_hunter = file_assessment["hunter_assessment"]
        role_hunter = role_assessment["hunter_assessment"]

        assert "authorization_gap_candidate" in {
            fact["fact_type"] for fact in file_assessment["hypothesis"]["source_facts"]
        }
        assert "authorization_gap_candidate" not in {
            fact["fact_type"] for fact in role_assessment["hypothesis"]["source_facts"]
        }
        assert "authorization_gap_candidate" in file_hunter["reasons"]
        assert file_hunter["hunter_priority_score"] > role_hunter["hunter_priority_score"]
        file_queue_item = next(
            item
            for item in payload["autonomous_hunt_queue"]
            if item["candidate_id"] == file_assessment["candidate_id"]
        )
        assert payload["autonomous_hunt_queue"][0]["candidate_id"] == role_assessment["candidate_id"]
        assert file_queue_item["status"] == "awaiting_evidence_review"
        assert file_queue_item["next_action"] == "resolve_evidence_gaps"
        assert file_queue_item["required_evidence"] == [
            "independent_refutation_or_static_rule"
        ]
        assert file_queue_item["quality_gate_reasons"] == [
            "required_evidence_missing"
        ]
        assert file_queue_item["human_approval_required"] is True
        assert file_assessment["refutation"]["questions"][0] == (
            "Can same-handler authorization evidence refute the missing access-control check candidate?"
        )
        assert file_assessment["validation_plan"]["human_approval_required"] is True
        assert "secret-token" not in str(payload)
        assert "Bearer" not in str(payload)
    finally:
        session.close()


def test_run_agent_task_blocks_out_of_scope_campaign_without_processing_payload():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Blocked worker campaign",
            autonomy_level="level_0_read_only",
            scope_status="out_of_scope",
            policy_text="Testing not allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe",
            payload={"cookie": "session=secret"},
        )

        result = run_agent_task(task.id, repository=repository)

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "scope_not_in_scope"
        updated_task = repository.list_campaign_tasks(campaign.id)[0]
        agent_run = repository.list_campaign_agent_runs(campaign.id)[0]
        assert updated_task.status == "blocked"
        assert agent_run.status == "blocked"
        assert agent_run.safety_gate_state == "blocked"
        assert "session=secret" not in str(agent_run.payload)
    finally:
        session.close()


def test_run_agent_task_blocks_existing_dispatched_run_without_duplicate_record():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Blocked reconcile campaign",
            autonomy_level="level_0_read_only",
            scope_status="out_of_scope",
            policy_text="Testing not allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe",
            payload={"cookie": "session=secret"},
        )
        dispatched_run = repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=task.id,
            agent_type=task.agent_type,
            status="dispatched",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=[],
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={"dispatch_contract": "id_only"},
        )

        result = run_agent_task(task.id, repository=repository)

        agent_runs = repository.list_campaign_agent_runs(campaign.id)
        assert result["status"] == "blocked"
        assert result["agent_run_id"] == dispatched_run.id
        assert len(agent_runs) == 1
        assert agent_runs[0].status == "blocked"
        assert agent_runs[0].safety_gate_state == "blocked"
        assert agent_runs[0].stop_reason == "scope_not_in_scope"
        assert "session=secret" not in str(agent_runs[0].payload)
    finally:
        session.close()


def test_run_agent_task_blocks_paused_campaign_with_specific_stop_reason():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Paused worker campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing paused",
            default_asset="api.example.com",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "paused")
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map surface",
            payload={"cookie": "session=secret"},
        )

        result = run_agent_task(task.id, repository=repository)

        updated_task = repository.list_campaign_tasks(campaign.id)[0]
        agent_run = repository.list_campaign_agent_runs(campaign.id)[0]
        assert result["status"] == "blocked"
        assert result["stop_reason"] == "campaign_paused"
        assert updated_task.status == "blocked"
        assert agent_run.status == "blocked"
        assert agent_run.stop_reason == "campaign_paused"
        assert repository.list_campaign_codebase_maps(campaign.id) == []
        assert "session=secret" not in str(agent_run.payload)
    finally:
        session.close()


def test_run_agent_task_allows_read_only_work_when_validation_budget_is_zero():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Budget exhausted worker campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing budget",
            default_asset="api.example.com",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=None,
            token_budget=None,
            tool_call_budget=None,
            validation_budget=0,
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map surface",
            payload={"cookie": "session=secret"},
        )

        result = run_agent_task(task.id, repository=repository)

        updated_task = repository.list_campaign_tasks(campaign.id)[0]
        agent_run = repository.list_campaign_agent_runs(campaign.id)[0]
        assert result["status"] == "completed"
        assert result["stop_reason"] is None
        assert updated_task.status == "completed"
        assert agent_run.status == "completed"
        assert repository.list_campaign_codebase_maps(campaign.id)
        assert "session=secret" not in str(agent_run.payload)
    finally:
        session.close()


def test_run_agent_task_blocks_recorded_token_budget_without_materializing_artifacts():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Token exhausted worker campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing budget",
            default_asset="api.example.com",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=None,
            token_budget=100,
            tool_call_budget=None,
            validation_budget=None,
        )
        repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=None,
            agent_type="semantic_audit_agent",
            status="completed",
            safety_gate_state="allowed",
            stop_reason=None,
            payload={"token_usage": {"total_tokens": 100}},
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map surface",
        )

        result = run_agent_task(task.id, repository=repository)

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "budget_exhausted"
        assert repository.list_campaign_codebase_maps(campaign.id) == []
    finally:
        session.close()


def test_run_agent_task_blocks_consumed_tool_call_budget_without_materializing_artifacts():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Consumed tool budget worker campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing budget",
            default_asset="api.example.com",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=None,
            token_budget=None,
            tool_call_budget=1,
            validation_budget=None,
        )
        first_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe",
        )
        repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=first_task.id,
            agent_type=first_task.agent_type,
            status="completed",
            input_refs=[f"campaign_task:{first_task.id}"],
            output_refs=[],
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={"raw_payload_processed": False},
        )
        second_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map surface",
            payload={"cookie": "session=secret"},
        )

        result = run_agent_task(second_task.id, repository=repository)

        updated_tasks = repository.list_campaign_tasks(campaign.id)
        agent_runs = repository.list_campaign_agent_runs(campaign.id)
        blocked_run = next(run for run in agent_runs if run.task_id == second_task.id)
        assert result["status"] == "blocked"
        assert result["stop_reason"] == "budget_exhausted"
        assert len(agent_runs) == 2
        assert blocked_run.status == "blocked"
        assert blocked_run.safety_gate_state == "blocked"
        assert blocked_run.stop_reason == "budget_exhausted"
        assert next(task for task in updated_tasks if task.id == second_task.id).status == "blocked"
        assert repository.list_campaign_codebase_maps(campaign.id) == []
        assert "session=secret" not in str(blocked_run.payload)
    finally:
        session.close()


def test_run_agent_task_materializes_read_only_research_artifacts_by_task_type():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Artifact worker campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed. Authorization: Bearer secret-token",
            default_asset="api.example.com",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        tasks = [
            repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="attack_surface_mapping",
                agent_type="target_model_agent",
                title="Map attack surface",
                payload={"raw": "Authorization: Bearer secret-token"},
            ),
            repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="hypothesis_generation",
                agent_type="hypothesis_agent",
                title="Generate hypotheses",
                payload={"cookie": "session=secret"},
            ),
            repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="report_chain_review",
                agent_type="report_agent",
                title="Review report chain",
                payload={"api_key": "secret-token"},
            ),
        ]

        results = [run_agent_task(task.id, repository=repository) for task in tasks]

        assert [result["status"] for result in results] == ["completed", "completed", "completed"]

        codebase_maps = repository.list_campaign_codebase_maps(campaign.id)
        codebase_facts = repository.list_campaign_codebase_facts(campaign.id)
        scanner_runs = repository.list_campaign_scanner_runs(campaign.id)
        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]
        validation_runs = repository.list_campaign_validation_runs(campaign.id)
        approvals = repository.list_campaign_approval_records(campaign.id)

        assert len(codebase_maps) == 1
        assert len(codebase_facts) == 1
        assert len(scanner_runs) == 1
        assert codebase_maps[0].safety_gate_state == "allowed"
        assert codebase_facts[0].authz_hint == "authorization_boundary_candidate"
        assert scanner_runs[0].tool_name == "mythos_static_mapper"

        assert len(pipeline_runs) == 1
        assert pipeline_runs[0].hypothesis_count == 1
        assert pipeline_runs[0].blocked_count == 1
        assert pipeline_runs[0].payload["campaign_id"] == campaign.id
        assert pipeline_runs[0].payload["source_task_id"] == tasks[1].id
        worker_assessment = pipeline_runs[0].payload["hypothesis_assessments"][0]
        assert worker_assessment["refutation"]["questions"]
        assert worker_assessment["exploit_chain"]["primitives"]
        assert worker_assessment["exploit_chain"]["preconditions"]
        assert worker_assessment["exploit_chain"]["safety_notes"] == [
            "non_executable_chain_summary",
            "no_payloads_or_requests",
            "human_review_required",
        ]
        linked_preview_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.pipeline_run_id == pipeline_runs[0].id
        ]
        assert len(linked_preview_stages) == 1
        assert linked_preview_stages[0].stage_key == "campaign_report_preview"
        assert linked_preview_stages[0].status == "awaiting_review"
        assert linked_preview_stages[0].safety_gate_state == "awaiting_review"

        assert len(validation_runs) == 1
        assert validation_runs[0].approval_required is True
        assert validation_runs[0].allowed_to_execute is False
        assert validation_runs[0].status == "awaiting_approval"
        assert len(approvals) == 1
        assert approvals[0].status == "pending"

        output_refs = [
            ref
            for task in repository.list_campaign_tasks(campaign.id)
            for ref in task.output_refs
        ]
        assert any(ref.startswith("codebase_map:") for ref in output_refs)
        assert any(ref.startswith("pipeline_run:") for ref in output_refs)
        assert any(ref.startswith("validation_run:") for ref in output_refs)
        assert "secret-token" not in str(
            codebase_maps
            + codebase_facts
            + scanner_runs
            + pipeline_runs
            + validation_runs
            + approvals
        )
        assert "session=secret" not in str(
            codebase_maps
            + codebase_facts
            + scanner_runs
            + pipeline_runs
            + validation_runs
            + approvals
        )
    finally:
        session.close()
