from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.repository import DatabaseRepository, seed_sample_data
from app.worker.tasks import ping, run_agent_task


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
        assert result["status"] == "completed"
        assert result["agent_run_id"] == dispatched_run.id
        assert len(agent_runs) == 1
        assert agent_runs[0].id == dispatched_run.id
        assert agent_runs[0].status == "completed"
        assert any(ref.startswith("pipeline_run:") for ref in agent_runs[0].output_refs)
        assert updated_task.output_refs[0] == f"agent_run:{dispatched_run.id}"
        assert any(ref.startswith("pipeline_run:") for ref in updated_task.output_refs)
        assert "secret-token" not in str(agent_runs[0].payload)
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
