from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_session
from app.main import app
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


def test_research_director_plan_is_snapshot_bound_and_audited_without_execution():
    testing_session = _testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id="program_example",
                name="Director local analysis campaign",
                autonomy_level="level_1_local_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.test",
                allowed_tools=["static_analyzer"],
                created_by="operator",
                payload={
                    "source_snapshot_digest": f"sha256:{'a' * 64}",
                    "scope_guard_rule": {
                        "asset": "api.example.test",
                        "scope_status": "in_scope",
                        "automation": "limited",
                        "allowed_validation": ["static_analyzer"],
                        "forbidden": [],
                        "human_approval_required": False,
                    },
                    "saved_scope_guard": {
                        "authorized_local_root": "C:/authorized/workspace/code",
                    },
                },
            )
            repository.update_campaign_status(campaign.id, "running")
            campaign_id = campaign.id

        response = client.post(f"/mythos/campaigns/{campaign_id}/research-director/plan")

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ready"
        assert body["action_kind"] == "local_tool"
        assert body["action_id"] == "semgrep_local"
        assert body["dispatch_allowed"] is True
        assert body["candidate_promotion_allowed"] is False
        assert body["report_submission_allowed"] is False
        assert "authorized_local_root" not in str(body)

        with testing_session() as session:
            repository = DatabaseRepository(session)
            stages = [
                stage
                for stage in repository.list_campaign_pipeline_stages(campaign_id)
                if stage.stage_key == "research_director_plan"
            ]
            assert len(stages) == 1
            assert stages[0].input_refs == [
                f"campaign:{campaign_id}",
                f"source_snapshot:sha256:{'a' * 64}",
            ]
            assert stages[0].payload["plan_digest"] == body["plan_digest"]
            assert stages[0].payload["execution_allowed"] is False
            assert stages[0].payload["report_submission_allowed"] is False
    finally:
        app.dependency_overrides.clear()


def test_research_director_plan_offers_explicit_dependency_sbom_local_tool():
    testing_session = _testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id="program_example",
                name="Director dependency advisory campaign",
                autonomy_level="level_1_local_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.test",
                allowed_tools=["dependency_sbom_local"],
                created_by="operator",
                payload={
                    "source_snapshot_digest": f"sha256:{'b' * 64}",
                    "scope_guard_rule": {
                        "asset": "api.example.test",
                        "scope_status": "in_scope",
                        "automation": "limited",
                        "allowed_validation": ["static_analyzer"],
                        "forbidden": [],
                        "human_approval_required": False,
                    },
                    "saved_scope_guard": {
                        "authorized_local_root": "C:/authorized/workspace/code",
                    },
                },
            )
            repository.update_campaign_status(campaign.id, "running")
            campaign_id = campaign.id

        response = client.post(f"/mythos/campaigns/{campaign_id}/research-director/plan")

        assert response.status_code == 200
        body = response.json()
        assert body["action_kind"] == "local_tool"
        assert body["action_id"] == "dependency_sbom_local"
        assert body["execution_tier"] == "local"
        assert body["dispatch_allowed"] is True
        assert body["candidate_promotion_allowed"] is False
        assert body["report_submission_allowed"] is False
    finally:
        app.dependency_overrides.clear()


def test_research_director_plan_falls_back_to_read_only_work_after_tool_budget_is_used():
    testing_session = _testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id="program_example",
                name="Director budget campaign",
                autonomy_level="level_1_local_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.test",
                allowed_tools=["static_analyzer"],
                created_by="operator",
                payload={
                    "source_snapshot_digest": f"sha256:{'b' * 64}",
                    "scope_guard_rule": {
                        "asset": "api.example.test",
                        "scope_status": "in_scope",
                        "automation": "limited",
                        "allowed_validation": ["static_analyzer"],
                        "forbidden": [],
                        "human_approval_required": False,
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
            repository.save_scanner_run(
                campaign_id=campaign.id,
                codebase_map_id=None,
                tool_name="semgrep_local",
                command_hash=f"sha256:{'c' * 64}",
                status="semgrep_local_completed",
                finding_count=0,
                candidate_count=0,
                summary="Advisory local run",
                safety_gate_state="allowed",
                payload={
                    "research_director_tool_run": True,
                    "tool_call_consumed": True,
                    "command_executed": True,
                },
            )
            campaign_id = campaign.id

        response = client.post(f"/mythos/campaigns/{campaign_id}/research-director/plan")

        assert response.status_code == 200
        assert response.json()["status"] == "ready"
        assert response.json()["action_kind"] == "research_task"
        assert response.json()["action_id"] == "attack_surface_mapping"
        assert response.json()["dispatch_allowed"] is False
    finally:
        app.dependency_overrides.clear()


def test_research_director_plan_continues_static_coverage_after_semgrep_advisory():
    testing_session = _testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id="program_example",
                name="Director multi-engine campaign",
                autonomy_level="level_1_local_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.test",
                allowed_tools=["static_analyzer", "codeql_local"],
                created_by="operator",
                payload={
                    "source_snapshot_digest": f"sha256:{'d' * 64}",
                    "scope_guard_rule": {
                        "asset": "api.example.test",
                        "scope_status": "in_scope",
                        "automation": "limited",
                        "allowed_validation": ["static_analyzer"],
                        "forbidden": [],
                        "human_approval_required": False,
                    },
                    "saved_scope_guard": {
                        "authorized_local_root": "C:/authorized/workspace/code",
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
            repository.save_artifact(
                program_id="program_example",
                asset="api.example.test",
                kind="static_advisory",
                source_type="registered_local_tool",
                source_hash=f"sha256:{'e' * 64}",
                ingestion_status="advisory_only",
                provenance={
                    "campaign_id": campaign.id,
                    "tool_id": "semgrep_local",
                    "source_snapshot_digest": f"sha256:{'d' * 64}",
                },
                payload_summary={"finding_count": 1},
                derived_facts={
                    "advisory_findings": [
                        {
                            "rule_id": "mythos.local.ssrf-fetch",
                            "path": "routes.py",
                            "line": 12,
                        }
                    ]
                },
            )
            repository.save_scanner_run(
                campaign_id=campaign.id,
                codebase_map_id=None,
                tool_name="semgrep_local",
                command_hash=f"sha256:{'f' * 64}",
                status="semgrep_local_completed",
                finding_count=1,
                candidate_count=0,
                summary="Advisory local run",
                safety_gate_state="allowed",
                payload={
                    "research_director_tool_run": True,
                    "tool_call_consumed": True,
                    "command_executed": True,
                    "source_snapshot_digest": f"sha256:{'d' * 64}",
                },
            )
            campaign_id = campaign.id

        response = client.post(f"/mythos/campaigns/{campaign_id}/research-director/plan")

        assert response.status_code == 200
        assert response.json()["action_kind"] == "local_tool"
        assert response.json()["action_id"] == "codeql_local"
    finally:
        app.dependency_overrides.clear()


def test_research_director_plan_does_not_inherit_completed_tool_from_old_snapshot():
    testing_session = _testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id="program_example",
                name="Director snapshot refresh campaign",
                autonomy_level="level_1_local_validation",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.test",
                allowed_tools=["static_analyzer"],
                created_by="operator",
                payload={
                    "source_snapshot_digest": f"sha256:{'a' * 64}",
                    "scope_guard_rule": {
                        "asset": "api.example.test",
                        "scope_status": "in_scope",
                        "automation": "limited",
                        "allowed_validation": ["static_analyzer"],
                        "forbidden": [],
                        "human_approval_required": False,
                    },
                    "saved_scope_guard": {
                        "authorized_local_root": "C:/authorized/workspace/code",
                    },
                },
            )
            repository.update_campaign_status(campaign.id, "running")
            repository.save_scanner_run(
                campaign_id=campaign.id,
                codebase_map_id=None,
                tool_name="semgrep_local",
                command_hash=f"sha256:{'b' * 64}",
                status="semgrep_local_completed",
                finding_count=0,
                candidate_count=0,
                summary="Previous snapshot advisory local run",
                safety_gate_state="allowed",
                payload={
                    "research_director_tool_run": True,
                    "tool_call_consumed": True,
                    "command_executed": True,
                    "source_snapshot_digest": f"sha256:{'c' * 64}",
                },
            )
            campaign_id = campaign.id

        response = client.post(f"/mythos/campaigns/{campaign_id}/research-director/plan")

        assert response.status_code == 200
        assert response.json()["action_kind"] == "local_tool"
        assert response.json()["action_id"] == "semgrep_local"
    finally:
        app.dependency_overrides.clear()
