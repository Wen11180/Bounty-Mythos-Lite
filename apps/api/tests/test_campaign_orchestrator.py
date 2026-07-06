from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.campaign_orchestrator import tick_campaign
from app.db import Base
from app.repository import DatabaseRepository, seed_sample_data
from app.worker.tasks import run_agent_task


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


def test_tick_does_not_dispatch_paused_campaign():
    repository, session = build_repository()
    dispatched: list[dict] = []
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Paused campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "paused")

        result = tick_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda **kwargs: dispatched.append(kwargs),
        )

        assert result["status"] == "paused"
        assert result["stop_reasons"] == ["campaign_paused"]
        assert dispatched == []
    finally:
        session.close()


def test_tick_does_not_dispatch_draft_campaign():
    repository, session = build_repository()
    dispatched: list[dict] = []
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Draft campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )

        result = tick_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda **kwargs: dispatched.append(kwargs),
        )

        assert result["status"] == "blocked"
        assert result["stop_reasons"] == ["campaign_not_running"]
        assert dispatched == []
        assert repository.list_campaign_tasks(campaign.id) == []
        stages = repository.list_campaign_pipeline_stages(campaign.id)
        assert len(stages) == 1
        assert stages[0].stage_key == "campaign_tick"
        assert stages[0].status == "blocked"
        assert stages[0].stop_reason == "campaign_not_running"
    finally:
        session.close()


def test_tick_does_not_dispatch_when_budget_exhausted():
    repository, session = build_repository()
    dispatched: list[dict] = []
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Budget exhausted",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=0,
            token_budget=0,
            tool_call_budget=0,
            validation_budget=0,
        )

        result = tick_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda **kwargs: dispatched.append(kwargs),
        )

        assert result["status"] == "blocked"
        assert result["stop_reasons"] == ["budget_exhausted"]
        assert dispatched == []
    finally:
        session.close()


def test_tick_does_not_dispatch_out_of_scope_campaign():
    repository, session = build_repository()
    dispatched: list[dict] = []
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Out of scope campaign",
            autonomy_level="level_0_read_only",
            scope_status="out_of_scope",
            policy_text="Testing not allowed for this asset",
            default_asset="api.example.com",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")

        result = tick_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda **kwargs: dispatched.append(kwargs),
        )

        assert result["status"] == "blocked"
        assert result["stop_reasons"] == ["scope_not_in_scope"]
        assert dispatched == []
        assert repository.list_campaign_tasks(campaign.id) == []
        stages = repository.list_campaign_pipeline_stages(campaign.id)
        assert len(stages) == 1
        assert stages[0].stage_key == "campaign_tick"
        assert stages[0].status == "blocked"
        assert stages[0].stop_reason == "scope_not_in_scope"
    finally:
        session.close()


def test_tick_dispatches_only_campaign_task_ids_for_safe_read_only_research_queue():
    repository, session = build_repository()
    dispatched: list[dict] = []
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Runnable campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed. Authorization: Bearer secret-token",
            default_asset="api.example.com",
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

        result = tick_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda **kwargs: dispatched.append(kwargs),
        )

        assert result["status"] == "dispatched"
        assert len(dispatched) == 4
        assert all(list(payload) == ["campaign_task_id"] for payload in dispatched)
        assert all(payload["campaign_task_id"].startswith("campaign_task_") for payload in dispatched)
        tasks = repository.list_campaign_tasks(campaign.id)
        agent_runs = repository.list_campaign_agent_runs(campaign.id)
        stages = repository.list_campaign_pipeline_stages(campaign.id)

        assert {task.task_type for task in tasks} == {
            "campaign_observation",
            "attack_surface_mapping",
            "hypothesis_generation",
            "report_chain_review",
        }
        assert {run.agent_type for run in agent_runs} == {
            "orchestrator_agent",
            "target_model_agent",
            "hypothesis_agent",
            "report_agent",
        }
        assert all(run.safety_gate_state == "allowed" for run in agent_runs)
        assert {stage.stage_key for stage in stages} == {
            "campaign_observation",
            "attack_surface_mapping",
            "hypothesis_generation",
            "report_chain_review",
        }
        assert "secret-token" not in str(tasks + agent_runs + stages + dispatched)
    finally:
        session.close()


def test_tick_does_not_duplicate_active_research_queue():
    repository, session = build_repository()
    dispatched: list[dict] = []
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Idempotent campaign",
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
            tool_call_budget=10,
            validation_budget=1,
        )

        first = tick_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda **kwargs: dispatched.append(kwargs),
        )
        second = tick_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda **kwargs: dispatched.append(kwargs),
        )

        assert first["status"] == "dispatched"
        assert second["status"] == "active_tasks_exist"
        assert second["dispatched_task_ids"] == []
        assert second["stop_reasons"] == ["active_tasks_exist"]
        assert len(repository.list_campaign_tasks(campaign.id)) == 4
        assert len(repository.list_campaign_agent_runs(campaign.id)) == 4
        assert len(dispatched) == 4
    finally:
        session.close()


def test_tick_enters_review_gate_after_research_cycle_materializes_artifacts():
    repository, session = build_repository()
    dispatched: list[dict] = []
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Cycle review campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed. Authorization: Bearer secret-token",
            default_asset="api.example.com",
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

        first = tick_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda **kwargs: dispatched.append(kwargs),
        )
        for task_id in first["dispatched_task_ids"]:
            run_agent_task(task_id, repository=repository)

        second = tick_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda **kwargs: dispatched.append(kwargs),
        )

        assert first["status"] == "dispatched"
        assert second["status"] == "awaiting_review"
        assert second["dispatched_task_ids"] == []
        assert second["stop_reasons"] == [
            "approval_required",
            "validation_approval_required",
        ]
        assert second["next_actions"] == [
            "review_approval_queue",
            "review_validation_queue",
            "review_hypothesis_board",
            "review_attack_surface_map",
        ]
        assert len(repository.list_campaign_tasks(campaign.id)) == 4
        assert len(dispatched) == 4

        assert len(repository.list_campaign_codebase_facts(campaign.id)) == 1
        assert len(repository.list_campaign_approval_records(campaign.id)) == 1
        assert len(repository.list_campaign_validation_runs(campaign.id)) == 1
        assert repository.list_campaign_validation_runs(campaign.id)[0].allowed_to_execute is False

        review_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.stage_key == "campaign_cycle_review"
        ]
        assert len(review_stages) == 1
        assert review_stages[0].status == "awaiting_review"
        assert review_stages[0].safety_gate_state == "awaiting_approval"
        assert review_stages[0].stop_reason == "validation_approval_required"
        assert "secret-token" not in str(second)
        assert "secret-token" not in str(review_stages)
    finally:
        session.close()


def test_tick_points_to_evidence_review_after_manual_validation_evidence():
    repository, session = build_repository()
    dispatched: list[dict] = []
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Evidence review cycle campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed. Authorization: Bearer secret-token",
            default_asset="api.example.com",
            target_classes=["idor"],
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

        first = tick_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda **kwargs: dispatched.append(kwargs),
        )
        for task_id in first["dispatched_task_ids"]:
            run_agent_task(task_id, repository=repository)

        approval = repository.list_campaign_approval_records(campaign.id)[0]
        repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Approved for test accounts only.",
        )
        validation_run = repository.list_campaign_validation_runs(campaign.id)[0]
        repository.record_validation_run_preflight(
            validation_run.id,
            allowed=True,
            reason="approved_validation_record",
        )
        repository.record_validation_run_manual_result(
            validation_run.id,
            outcome="observed",
            reviewer="lead_reviewer",
            summary="Observed safe diff; Authorization: Bearer secret-token",
            evidence_refs=["sanitized_request_response", "Cookie: session=secret"],
        )

        second = tick_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda **kwargs: dispatched.append(kwargs),
        )

        assert second["status"] == "awaiting_review"
        assert second["dispatched_task_ids"] == []
        assert second["stop_reasons"] == ["campaign_cycle_review_required"]
        assert second["next_actions"] == [
            "review_evidence_or_report_drafts",
            "review_hypothesis_board",
            "review_attack_surface_map",
        ]
        assert len(repository.list_campaign_tasks(campaign.id)) == 4
        assert len(dispatched) == 4
        review_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.stage_key == "campaign_cycle_review"
        ]
        assert len(review_stages) == 1
        assert review_stages[0].status == "awaiting_review"
        assert review_stages[0].safety_gate_state == "allowed"
        assert review_stages[0].stop_reason == "campaign_cycle_review_required"
        assert "secret-token" not in str(second)
        assert "session=secret" not in str(second)
        assert "secret-token" not in str(review_stages)
        assert "session=secret" not in str(review_stages)
    finally:
        session.close()


def test_tick_dispatches_next_read_only_cycle_after_cycle_review_is_completed():
    repository, session = build_repository()
    dispatched: list[dict] = []
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Reviewed next cycle campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed. Authorization: Bearer secret-token",
            default_asset="api.example.com",
            target_classes=["idor"],
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

        first = tick_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda **kwargs: dispatched.append(kwargs),
        )
        for task_id in first["dispatched_task_ids"]:
            run_agent_task(task_id, repository=repository)

        approval = repository.list_campaign_approval_records(campaign.id)[0]
        repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Approved for test accounts only.",
        )
        validation_run = repository.list_campaign_validation_runs(campaign.id)[0]
        repository.record_validation_run_preflight(
            validation_run.id,
            allowed=True,
            reason="approved_validation_record",
        )
        repository.record_validation_run_manual_result(
            validation_run.id,
            outcome="observed",
            reviewer="lead_reviewer",
            summary="Observed safe diff; Authorization: Bearer secret-token",
            evidence_refs=["sanitized_request_response", "Cookie: session=secret"],
        )

        review = tick_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda **kwargs: dispatched.append(kwargs),
        )
        review_stage = next(
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.stage_key == "campaign_cycle_review"
            and stage.status == "awaiting_review"
        )
        repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=campaign.id,
            task_id=None,
            stage_key="campaign_cycle_review",
            stage_order=review_stage.stage_order,
            status="completed",
            input_refs=review_stage.input_refs,
            output_refs=review_stage.output_refs,
            safety_gate_state="allowed",
            stop_reason=None,
            payload={
                "review_gate": "human_review_completed",
                "raw_payload_processed": False,
            },
        )

        next_cycle = tick_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda **kwargs: dispatched.append(kwargs),
        )

        assert review["status"] == "awaiting_review"
        assert next_cycle["status"] == "dispatched"
        assert next_cycle["stop_reasons"] == []
        assert len(next_cycle["dispatched_task_ids"]) == 4
        assert len(dispatched) == 8
        assert len(repository.list_campaign_tasks(campaign.id)) == 8
        assert all(list(payload) == ["campaign_task_id"] for payload in dispatched)
        assert "secret-token" not in str(next_cycle)
        assert "session=secret" not in str(next_cycle)
    finally:
        session.close()
