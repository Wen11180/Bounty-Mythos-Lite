from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.autonomous_research_runtime as autonomous_research_runtime
import app.candidate_hunter_loop as candidate_hunter_loop
import app.intelligence_benchmark.candidate_report_bridge as candidate_report_bridge
from app.autonomous_research_runtime import select_autonomous_research_work
from app.campaign_orchestrator import campaign_elapsed_minutes
from app.db import Base
from app.program_rule_intake.scope_resolver import EffectiveProgramRuleResolution
from app.repository import DatabaseRepository, seed_sample_data
from app.worker.tasks import run_agent_task


SOURCE_SNAPSHOT_DIGEST = "sha256:" + "a" * 64


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


def runtime_campaign_payload(source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST):
    payload = {
        "scope_guard_rule": {
            "asset": "api.example.com",
            "scope_status": "in_scope",
            "automation": "none",
            "allowed_validation": [],
            "forbidden": [],
            "human_approval_required": True,
        },
    }
    if source_snapshot_digest is not None:
        payload["source_snapshot_digest"] = source_snapshot_digest
    return payload


def false_safety_fields():
    return {
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }


def runtime_safety_fields():
    return {
        **false_safety_fields(),
        "raw_payload_processed": False,
        "raw_payload_in_dispatch": False,
    }


def save_completed_runtime_stage(
    repository,
    campaign,
    task_type,
    stage_order,
    output_refs=None,
    source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
):
    return repository.save_pipeline_stage(
        pipeline_run_id=None,
        campaign_id=campaign.id,
        task_id=None,
        stage_key=f"autonomous_research:{task_type}",
        stage_order=stage_order,
        status="completed",
        input_refs=[f"campaign:{campaign.id}"],
        output_refs=output_refs or [],
        safety_gate_state="allowed",
        stop_reason=None,
        payload={
            "runtime_schema": "autonomous_research_v1",
            "source_snapshot_digest": source_snapshot_digest,
            "idempotency_key": f"runtime:{campaign.id}:{task_type}",
            **runtime_safety_fields(),
        },
    )


def test_selects_observation_for_new_running_in_scope_campaign():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None

        result = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
            now=datetime(2026, 7, 18, tzinfo=UTC),
        )

        assert result["status"] == "ready"
        assert result["task_type"] == "campaign_observation"
        assert result["source_snapshot_digest"] == SOURCE_SNAPSHOT_DIGEST
        assert result["execution_allowed"] is False
        assert result["validation_allowed"] is False
        assert result["candidate_promotion_allowed"] is False
        assert result["report_submission_allowed"] is False
    finally:
        session.close()


def test_blocks_non_read_only_campaign_before_selecting_runtime_work():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Assisted autonomous runtime campaign",
            autonomy_level="level_1_assisted",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None

        result = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "autonomy_level_not_read_only"
        assert repository.list_campaign_tasks(campaign.id) == []
    finally:
        session.close()


def test_blocks_campaign_without_a_stored_scope_guard_rule():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Unscoped autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload={"source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST},
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None

        result = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "scope_guard_rule_missing"
        assert result["task_type"] is None
    finally:
        session.close()


def test_blocks_campaign_when_the_current_program_rule_is_stale(monkeypatch):
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Stale program rule autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        monkeypatch.setattr(
            autonomous_research_runtime,
            "resolve_effective_program_rule",
            lambda *_args: EffectiveProgramRuleResolution(
                source_backed=True,
                reason="program_rule_source_stale",
            ),
            raising=False,
        )

        result = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
            now=datetime(2026, 7, 18, tzinfo=UTC),
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "program_rule_source_stale"
        assert result["task_type"] is None
    finally:
        session.close()


def test_blocks_out_of_scope_campaign_without_work_selection():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Out of scope autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="out_of_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None

        result = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "scope_not_in_scope"
        assert result["task_type"] is None
        assert result["execution_allowed"] is False
        assert result["validation_allowed"] is False
        assert result["candidate_promotion_allowed"] is False
        assert result["report_submission_allowed"] is False
    finally:
        session.close()


def test_blocks_non_running_campaign_without_work_selection():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Draft autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )

        result = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "campaign_not_running"
        assert result["task_type"] is None
    finally:
        session.close()


def test_blocks_campaign_without_a_safe_source_snapshot_digest():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Missing source snapshot",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(None),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None

        result = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "source_snapshot_digest_required"
        assert result["task_type"] is None
    finally:
        session.close()


def test_blocks_campaign_with_a_malformed_source_snapshot_digest():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Malformed source snapshot",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload("sha256:not-a-digest"),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None

        result = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "source_snapshot_digest_required"
        assert result["task_type"] is None
    finally:
        session.close()


def test_advances_completed_runtime_stages_in_dependency_order():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Ordered autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None

        work_items = [
            "campaign_observation",
            "attack_surface_mapping",
            "hypothesis_generation",
            "candidate_refutation",
            "finding_dedup_and_rank",
            "report_review",
        ]
        for stage_order, task_type in enumerate(work_items):
            result = select_autonomous_research_work(
                campaign=campaign,
                repository=repository,
            )
            assert result["status"] == "ready"
            assert result["task_type"] == task_type
            if task_type != "report_review":
                save_completed_runtime_stage(
                    repository,
                    campaign,
                    task_type,
                    stage_order,
                )
    finally:
        session.close()


def test_blocks_work_selection_when_an_autonomous_task_is_active():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Active autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe authorized campaign state",
            payload={
                "runtime_schema": "autonomous_research_v1",
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST,
                **runtime_safety_fields(),
            },
        )

        result = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "active_runtime_task"
        assert result["task_type"] is None
    finally:
        session.close()


def test_awaiting_review_campaign_stops_runtime_work():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Awaiting review runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "awaiting_review")
        assert campaign is not None

        result = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "human_review_required"
        assert result["task_type"] is None
    finally:
        session.close()


def test_awaiting_review_stops_the_campaign_budget_clock():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Awaiting review budget campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        campaign.payload = {
            **campaign.payload,
            "budget_started_at": "2026-07-18T12:00:00+00:00",
        }
        session.add(campaign)
        session.commit()
        campaign = repository.update_campaign_status(campaign.id, "awaiting_review")
        assert campaign is not None
        paused_at = datetime.fromisoformat(campaign.payload["budget_paused_at"])

        elapsed_at_gate = campaign_elapsed_minutes(campaign, now=paused_at)
        elapsed_after_review = campaign_elapsed_minutes(
            campaign,
            now=paused_at + timedelta(minutes=10),
        )

        assert elapsed_after_review == elapsed_at_gate
    finally:
        session.close()


def test_blocks_work_selection_after_a_safe_runtime_stage_is_blocked():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Blocked autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=campaign.id,
            task_id=None,
            stage_key="autonomous_research:attack_surface_mapping",
            stage_order=1,
            status="blocked",
            input_refs=[f"campaign:{campaign.id}"],
            output_refs=[],
            safety_gate_state="blocked",
            stop_reason="workspace_snapshot_changed",
            payload=autonomous_research_runtime._runtime_stage_payload(
                campaign_id=campaign.id,
                task_type="attack_surface_mapping",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
                outcome="blocked:workspace_snapshot_changed",
            ),
        )

        result = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "workspace_snapshot_changed"
        assert result["task_type"] is None
    finally:
        session.close()


def test_blocks_when_a_prior_runtime_stage_has_an_unsafe_snapshot_digest():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Unsafe runtime stage campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=campaign.id,
            task_id=None,
            stage_key="autonomous_research:campaign_observation",
            stage_order=0,
            status="completed",
            input_refs=[f"campaign:{campaign.id}"],
            output_refs=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={
                "runtime_schema": "autonomous_research_v1",
                "source_snapshot_digest": "sha256:not-a-digest",
                "idempotency_key": f"runtime:{campaign.id}:campaign_observation",
            },
        )

        result = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "malformed_runtime_stage"
        assert result["task_type"] is None
    finally:
        session.close()


def test_blocks_when_a_prior_runtime_stage_has_an_unsafe_permission_field():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Unsafe runtime stage permissions campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=campaign.id,
            task_id=None,
            stage_key="autonomous_research:campaign_observation",
            stage_order=0,
            status="completed",
            input_refs=[f"campaign:{campaign.id}"],
            output_refs=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={
                "runtime_schema": "autonomous_research_v1",
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST,
                "idempotency_key": f"runtime:{campaign.id}:campaign_observation",
                **runtime_safety_fields(),
                "execution_allowed": True,
            },
        )

        result = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "malformed_runtime_stage"
        assert result["task_type"] is None
    finally:
        session.close()


def test_blocks_when_a_prior_runtime_stage_uses_a_different_source_snapshot():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Stale runtime stage campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        prior_digest = "sha256:" + "b" * 64
        repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=campaign.id,
            task_id=None,
            stage_key="autonomous_research:campaign_observation",
            stage_order=0,
            status="completed",
            input_refs=[f"campaign:{campaign.id}"],
            output_refs=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={
                "runtime_schema": "autonomous_research_v1",
                "source_snapshot_digest": prior_digest,
                "idempotency_key": f"runtime:{campaign.id}:campaign_observation",
                **runtime_safety_fields(),
            },
        )

        result = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "source_snapshot_changed"
        assert result["task_type"] is None
    finally:
        session.close()


def test_blocks_when_an_active_runtime_task_uses_a_different_source_snapshot():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Stale active runtime task campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe authorized campaign state",
            payload={
                "runtime_schema": "autonomous_research_v1",
                "source_snapshot_digest": "sha256:" + "b" * 64,
                **runtime_safety_fields(),
            },
        )

        result = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "source_snapshot_changed"
        assert result["task_type"] is None
    finally:
        session.close()


def test_blocks_paused_and_terminal_campaigns_with_their_safe_stop_reason():
    repository, session = build_repository()
    try:
        expected_stop_reasons = {
            "paused": "campaign_paused",
            "blocked": "campaign_blocked",
            "canceled": "campaign_canceled",
            "completed": "campaign_completed",
            "failed": "campaign_failed",
        }
        for status, stop_reason in expected_stop_reasons.items():
            campaign = repository.create_campaign(
                program_id="program_example",
                name=f"{status} autonomous runtime campaign",
                autonomy_level="level_0_read_only",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                created_by="operator",
                payload=runtime_campaign_payload(),
            )
            campaign = repository.update_campaign_status(campaign.id, status)
            assert campaign is not None

            result = select_autonomous_research_work(
                campaign=campaign,
                repository=repository,
            )

            assert result["status"] == "blocked"
            assert result["stop_reason"] == stop_reason
            assert result["task_type"] is None
    finally:
        session.close()


def test_blocks_campaign_when_an_existing_budget_is_exhausted():
    repository, session = build_repository()
    try:
        exhausted_budgets = (
            (0, None, None),
            (None, 0, None),
            (None, None, 0),
        )
        for time_budget, token_budget, tool_call_budget in exhausted_budgets:
            campaign = repository.create_campaign(
                program_id="program_example",
                name="Exhausted autonomous runtime campaign",
                autonomy_level="level_0_read_only",
                scope_status="in_scope",
                policy_text="Testing allowed",
                default_asset="api.example.com",
                created_by="operator",
                payload=runtime_campaign_payload(),
            )
            campaign = repository.update_campaign_status(campaign.id, "running")
            assert campaign is not None
            repository.upsert_campaign_budget(
                campaign_id=campaign.id,
                time_budget_minutes=time_budget,
                token_budget=token_budget,
                tool_call_budget=tool_call_budget,
                validation_budget=None,
            )

            result = select_autonomous_research_work(
                campaign=campaign,
                repository=repository,
            )

            assert result["status"] == "blocked"
            assert result["stop_reason"] == "budget_exhausted"
            assert result["task_type"] is None
    finally:
        session.close()


def test_blocks_campaign_when_its_time_budget_has_elapsed():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Elapsed autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        campaign.payload = {
            **campaign.payload,
            "budget_started_at": "2026-07-18T12:00:00+00:00",
        }
        session.add(campaign)
        session.commit()
        session.refresh(campaign)
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=5,
            token_budget=None,
            tool_call_budget=None,
            validation_budget=None,
        )

        result = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
            now=datetime(2026, 7, 18, 12, 5, tzinfo=UTC),
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "budget_exhausted"
        assert result["task_type"] is None
    finally:
        session.close()


def test_blocks_campaign_when_its_token_budget_has_been_used():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Token exhausted autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=None,
            agent_type="orchestrator_agent",
            status="completed",
            input_refs=[],
            output_refs=[],
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={"token_usage": {"total_tokens": 10}},
        )
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=None,
            token_budget=10,
            tool_call_budget=None,
            validation_budget=None,
        )

        result = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "budget_exhausted"
        assert result["task_type"] is None
    finally:
        session.close()


def test_blocks_campaign_when_its_tool_call_budget_has_been_used():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Tool budget exhausted autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=None,
            agent_type="orchestrator_agent",
            status="completed",
            input_refs=[],
            output_refs=[],
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={},
        )
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=None,
            token_budget=None,
            tool_call_budget=1,
            validation_budget=None,
        )

        result = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "budget_exhausted"
        assert result["task_type"] is None
    finally:
        session.close()


def test_tick_creates_and_dispatches_one_safe_runtime_task():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Dispatchable autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        dispatched_task_ids = []

        def dispatcher(*, campaign_task_id):
            dispatched_task_ids.append(campaign_task_id)
            return {"campaign_task_id": campaign_task_id}

        result = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=dispatcher,
            now=datetime(2026, 7, 18, tzinfo=UTC),
        )

        tasks = repository.list_campaign_tasks(campaign.id)
        runs = repository.list_campaign_agent_runs(campaign.id)
        stages = repository.list_campaign_pipeline_stages(campaign.id)
        assert result["status"] == "dispatched"
        assert result["campaign_task_id"] == tasks[0].id
        assert dispatched_task_ids == [tasks[0].id]
        assert len(tasks) == 1
        assert tasks[0].task_type == "campaign_observation"
        assert tasks[0].status == "dispatched"
        assert tasks[0].input_refs == [
            f"campaign:{campaign.id}",
            f"source_snapshot:{SOURCE_SNAPSHOT_DIGEST}",
        ]
        assert tasks[0].payload["runtime_schema"] == "autonomous_research_v1"
        assert tasks[0].payload["source_snapshot_digest"] == SOURCE_SNAPSHOT_DIGEST
        assert tasks[0].payload["dispatch_contract"] == "id_only"
        assert tasks[0].payload["raw_payload_in_dispatch"] is False
        assert tasks[0].payload["idempotency_key"].startswith("sha256:")
        assert tasks[0].payload["execution_allowed"] is False
        assert tasks[0].payload["validation_allowed"] is False
        assert tasks[0].payload["candidate_promotion_allowed"] is False
        assert tasks[0].payload["report_submission_allowed"] is False
        assert len(runs) == 1
        assert runs[0].task_id == tasks[0].id
        assert runs[0].status == "dispatched"
        assert runs[0].safety_gate_state == "allowed"
        assert len(stages) == 1
        assert stages[0].task_id == tasks[0].id
        assert stages[0].stage_key == "autonomous_research:campaign_observation"
        assert stages[0].status == "dispatched"
        assert stages[0].payload["runtime_schema"] == "autonomous_research_v1"
        assert stages[0].payload["source_snapshot_digest"] == SOURCE_SNAPSHOT_DIGEST
        assert stages[0].payload["dispatch_contract"] == "id_only"
        assert result["execution_allowed"] is False
        assert result["validation_allowed"] is False
        assert result["candidate_promotion_allowed"] is False
        assert result["report_submission_allowed"] is False
    finally:
        session.close()


def test_worker_allows_the_runtime_task_that_reserves_the_last_tool_call():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Reserved tool-call autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=None,
            token_budget=None,
            tool_call_budget=1,
            validation_budget=None,
        )
        dispatched = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: {"campaign_task_id": campaign_task_id},
        )

        result = run_agent_task(
            dispatched["campaign_task_id"],
            repository=repository,
        )

        assert result["status"] == "completed"
        assert result["stop_reason"] is None
    finally:
        session.close()


def test_runtime_task_claim_is_idempotent_for_one_task_identity():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Claimed autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        task_kwargs = {
            "task_id": "campaign_task_runtime_claim_test",
            "campaign_id": campaign.id,
            "task_type": "campaign_observation",
            "agent_type": "orchestrator_agent",
            "title": "Observe authorized campaign state",
            "input_refs": [f"campaign:{campaign.id}"],
            "payload": {
                "runtime_schema": "autonomous_research_v1",
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST,
                **runtime_safety_fields(),
            },
        }

        first_task, first_claimed = repository.claim_campaign_task(**task_kwargs)
        second_task, second_claimed = repository.claim_campaign_task(**task_kwargs)

        assert first_claimed is True
        assert second_claimed is False
        assert first_task.id == second_task.id
        assert len(repository.list_campaign_tasks(campaign.id)) == 1
    finally:
        session.close()


def test_tick_does_not_dispatch_when_another_tick_claimed_the_same_work(monkeypatch):
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Contended autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        original_claim = repository.claim_campaign_task

        def contended_claim(**kwargs):
            task, _claimed = original_claim(**kwargs)
            return task, False

        monkeypatch.setattr(repository, "claim_campaign_task", contended_claim)
        dispatched_task_ids = []

        result = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(campaign_task_id),
        )

        tasks = repository.list_campaign_tasks(campaign.id)
        assert result["status"] == "awaiting_evidence"
        assert result["stop_reason"] == "active_runtime_task"
        assert result["campaign_task_id"] == tasks[0].id
        assert len(tasks) == 1
        assert tasks[0].status == "queued"
        assert repository.list_campaign_agent_runs(campaign.id) == []
        assert repository.list_campaign_pipeline_stages(campaign.id) == []
        assert dispatched_task_ids == []
    finally:
        session.close()


def test_worker_completion_appends_runtime_stage_and_advances_selection():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Worker-complete autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None

        dispatched = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: {"campaign_task_id": campaign_task_id},
        )
        completed = run_agent_task(
            dispatched["campaign_task_id"],
            repository=repository,
        )

        stages = repository.list_campaign_pipeline_stages(campaign.id)
        next_selection = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
        )
        assert completed["status"] == "completed"
        assert {stage.status for stage in stages} == {"dispatched", "completed"}
        assert all(
            stage.stage_key == "autonomous_research:campaign_observation"
            for stage in stages
        )
        completed_stage = next(stage for stage in stages if stage.status == "completed")
        assert completed_stage.payload["runtime_schema"] == "autonomous_research_v1"
        assert completed_stage.payload["source_snapshot_digest"] == SOURCE_SNAPSHOT_DIGEST
        assert completed_stage.payload["execution_allowed"] is False
        assert completed_stage.payload["validation_allowed"] is False
        assert completed_stage.payload["candidate_promotion_allowed"] is False
        assert completed_stage.payload["report_submission_allowed"] is False
        assert next_selection["status"] == "ready"
        assert next_selection["task_type"] == "attack_surface_mapping"
    finally:
        session.close()


def test_explicit_retry_reuses_a_failed_runtime_task_without_duplicate_work():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Retryable autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        failed_dispatches = []

        def failing_dispatcher(*, campaign_task_id):
            failed_dispatches.append(campaign_task_id)
            raise RuntimeError("queue unavailable")

        first = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=failing_dispatcher,
        )
        task_id = first["campaign_task_id"]
        retry_dispatches = []

        second = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: retry_dispatches.append(campaign_task_id),
        )

        tasks = repository.list_campaign_tasks(campaign.id)
        stages = repository.list_campaign_pipeline_stages(campaign.id)
        assert first["status"] == "blocked"
        assert first["stop_reason"] == "dispatch_failed"
        assert failed_dispatches == [task_id]
        assert second["status"] == "dispatched"
        assert second["campaign_task_id"] == task_id
        assert retry_dispatches == [task_id]
        assert len(tasks) == 1
        assert tasks[0].id == task_id
        assert tasks[0].status == "dispatched"
        assert {stage.status for stage in stages} == {"dispatched", "failed"}
        assert len(stages) == 3
    finally:
        session.close()


def test_tick_blocks_report_review_without_a_persisted_projection():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Unsupported runtime work campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        for stage_order, task_type in enumerate(
            (
                "campaign_observation",
                "attack_surface_mapping",
                "hypothesis_generation",
                "candidate_refutation",
                "finding_dedup_and_rank",
            )
        ):
            save_completed_runtime_stage(
                repository,
                campaign,
                task_type,
                stage_order,
            )
        dispatched_task_ids = []

        result = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(campaign_task_id),
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "candidate_hunter_projection_missing"
        assert result["campaign_task_id"] is None
        assert dispatched_task_ids == []
        assert repository.list_campaign_tasks(campaign.id) == []
    finally:
        session.close()


def test_tick_dispatches_candidate_refutation_from_the_persisted_hypothesis_run():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Candidate refutation autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        pipeline_run = repository.save_pipeline_run(
            program_id=campaign.program_id,
            asset=campaign.default_asset,
            policy_text=campaign.policy_text_hash,
            policy_text_is_hash=True,
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=1,
            report_title=None,
            payload={
                "campaign_id": campaign.id,
                "hypotheses": [
                    {
                        "hypothesis_id": "H-001",
                        "vuln_type": "authorization_boundary",
                        "priority_score": 50,
                        "source_facts": [],
                    }
                ],
            },
        )
        save_completed_runtime_stage(repository, campaign, "campaign_observation", 0)
        save_completed_runtime_stage(repository, campaign, "attack_surface_mapping", 1)
        save_completed_runtime_stage(
            repository,
            campaign,
            "hypothesis_generation",
            2,
            output_refs=[f"pipeline_run:{pipeline_run.id}"],
        )
        dispatched_task_ids = []

        result = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(campaign_task_id),
            now=datetime.now(UTC) + timedelta(seconds=60),
        )

        tasks = repository.list_campaign_tasks(campaign.id)
        assert result["status"] == "dispatched"
        assert result["campaign_task_id"] == tasks[0].id
        assert dispatched_task_ids == [tasks[0].id]
        assert tasks[0].task_type == "candidate_refutation"
        assert tasks[0].input_refs[-1] == f"pipeline_run:{pipeline_run.id}"
        assert tasks[0].payload["pipeline_run_id"] == pipeline_run.id
        worker_result = run_agent_task(tasks[0].id, repository=repository)
        candidate_hunter_stages = [
            stage
            for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
            if stage.stage_key.startswith("candidate_hunter_")
        ]
        runtime_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.task_id == tasks[0].id
            and stage.stage_key.startswith("autonomous_research:")
        ]

        assert worker_result["status"] == "awaiting_evidence"
        assert len(repository.list_campaigns()) == 1
        assert {
            stage.stage_key for stage in candidate_hunter_stages
        } == {
            "candidate_hunter_snapshot",
            "candidate_hunter_evidence_request",
            "candidate_hunter_decision",
            "candidate_hunter_rerank",
        }
        assert all(stage.campaign_id == campaign.id for stage in candidate_hunter_stages)
        assert all(stage.task_id == tasks[0].id for stage in candidate_hunter_stages)
        assert {stage.status for stage in runtime_stages} == {
            "dispatched",
            "awaiting_evidence",
        }
    finally:
        session.close()


def test_worker_refutes_with_persisted_multilang_facts_without_source_body():
    repository, session = build_repository()
    try:
        source_marker = "raw-java-source-must-not-reach-runtime-projection"
        route = "/records/{recordId}"
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Persisted multilang refutation campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        codebase_map = repository.save_codebase_map(
            campaign_id=campaign.id,
            source_ref="campaign_task:attack_surface_mapping",
            repository=campaign.default_asset,
            commit_ref=None,
            status="mapped",
            route_count=1,
            handler_count=1,
            model_count=0,
            authz_check_count=1,
            sensitive_sink_count=1,
            provenance_refs=[f"campaign:{campaign.id}"],
            safety_gate_state="allowed",
            payload={"raw_payload_processed": False},
        )
        fact_kwargs = {
            "codebase_map_id": codebase_map.id,
            "campaign_id": campaign.id,
            "sensitivity_label": "authorized_local_code",
            "provenance_refs": [f"codebase_map:{codebase_map.id}"],
        }
        repository.save_codebase_fact(
            **fact_kwargs,
            fact_type="route_handler",
            source_path="src/RecordsController.java",
            symbol_name="readRecord",
            route_method="GET",
            route_path=route,
            authz_hint=None,
            payload={
                "handler": "readRecord",
                "line": 4,
                "raw_source": source_marker,
            },
        )
        repository.save_codebase_fact(
            **fact_kwargs,
            fact_type="service_call",
            source_path="src/RecordsController.java",
            symbol_name="verifyRecordAccess",
            route_method=None,
            route_path=None,
            authz_hint=None,
            payload={"handler": "readRecord", "caller": "readRecord", "line": 5},
        )
        repository.save_codebase_fact(
            **fact_kwargs,
            fact_type="authz_check",
            source_path="src/RecordsController.java",
            symbol_name="verifyRecordAccess",
            route_method=None,
            route_path=None,
            authz_hint="ownership_boundary_check",
            payload={"handler": "verifyRecordAccess", "line": 8},
        )
        repository.save_codebase_fact(
            **fact_kwargs,
            fact_type="sensitive_sink",
            source_path="src/RecordsController.java",
            symbol_name="sendFile",
            route_method=None,
            route_path=None,
            authz_hint=None,
            payload={"handler": "readRecord", "line": 12},
        )
        pipeline_run = repository.save_pipeline_run(
            program_id=campaign.program_id,
            asset=campaign.default_asset,
            policy_text=campaign.policy_text_hash,
            policy_text_is_hash=True,
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=1,
            report_title=None,
            payload={
                "campaign_id": campaign.id,
                "hypotheses": [
                    {
                        "hypothesis_id": "H-java-001",
                        "vuln_type": "authorization_boundary",
                        "location": f"GET {route}",
                        "priority_score": 80,
                        "source_facts": [
                            {
                                "fact_type": "authorization_gap_candidate",
                                "artifact_kind": "code",
                                "source_path": "src/RecordsController.java",
                                "symbol_name": "readRecord",
                                "route_method": "GET",
                                "route_path": route,
                                "root_cause": "missing_object_ownership_check",
                            },
                            {
                                "fact_type": "api_surface",
                                "artifact_kind": "api",
                                "route_method": "GET",
                                "route_path": route,
                            },
                            {"fact_type": "har_context", "artifact_kind": "har"},
                        ],
                    }
                ],
            },
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_refutation",
            agent_type="candidate_hunter_agent",
            title="Refute candidate hypotheses from persisted evidence",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload={
                "runtime_schema": "autonomous_research_v1",
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST,
                "pipeline_run_id": pipeline_run.id,
                **runtime_safety_fields(),
            },
        )

        result = run_agent_task(task.id, repository=repository)

        decision_stage = next(
            stage
            for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
            if stage.stage_key == "candidate_hunter_decision"
            and stage.payload["round"] == 2
        )
        assert result["status"] == "completed"
        assert decision_stage.payload["candidate_decisions"][0]["disposition"] == "refuted"
        assert not any(
            item.task_type == "candidate_hunter_evidence_inspection"
            for item in repository.list_campaign_tasks(campaign.id)
        )
        assert source_marker not in json.dumps(
            [
                stage.payload
                for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
            ]
        )
    finally:
        session.close()


def test_worker_blocks_report_review_without_a_persisted_projection():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Worker-blocked autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_review",
            agent_type="report_agent",
            title="Build submission-blocked report review",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "runtime_schema": "autonomous_research_v1",
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST,
                **runtime_safety_fields(),
            },
        )

        result = run_agent_task(task.id, repository=repository)

        stages = repository.list_campaign_pipeline_stages(campaign.id)
        persisted_task = repository.session.get(type(task), task.id)
        assert result["status"] == "blocked"
        assert result["stop_reason"] == "candidate_hunter_projection_missing"
        assert persisted_task is not None
        assert persisted_task.status == "blocked"
        assert len(stages) == 1
        assert stages[0].status == "blocked"
        assert stages[0].stage_key == "autonomous_research:report_review"
        assert stages[0].stop_reason == "candidate_hunter_projection_missing"
    finally:
        session.close()


def test_worker_ranks_only_retained_candidates_from_the_persisted_projection(monkeypatch):
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Dedup autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        pipeline_run = repository.save_pipeline_run(
            program_id=campaign.program_id,
            asset=campaign.default_asset,
            policy_text=campaign.policy_text_hash,
            scope_status="in_scope",
            hypothesis_count=2,
            blocked_count=1,
            report_title=None,
            payload={"campaign_id": campaign.id, "hypotheses": []},
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="finding_dedup_and_rank",
            agent_type="triage_agent",
            title="Deduplicate and rank retained candidates",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload={
                "runtime_schema": "autonomous_research_v1",
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST,
                "pipeline_run_id": pipeline_run.id,
                **runtime_safety_fields(),
            },
        )
        retained = {
            "candidate_id": "H-retained",
            "vuln_type": "authorization_boundary",
            "root_cause_id": "missing_ownership:read_record",
            "route": {"method": "GET", "path": "/records/{record_id}"},
            "source_fact_refs": ["code:records.py:read_record"],
            "evidence_trace_status": "traceable",
            "human_validation_readiness": "ready",
            "survived_kill_score": 90,
            "evidence_completeness_score": 80,
            "priority_score": 70,
            **false_safety_fields(),
        }
        refuted = {
            **retained,
            "candidate_id": "H-refuted",
            "root_cause_id": "ownership_guard:read_record",
            "survived_kill_score": 100,
        }
        monkeypatch.setattr(
            candidate_hunter_loop,
            "load_candidate_hunter_projection",
            lambda **_kwargs: {
                "status": "ready",
                "pipeline_run_id": pipeline_run.id,
                "final_candidates": [retained, refuted],
                "candidate_decisions": [
                    {
                        "candidate_id": "H-retained",
                        "disposition": "retained",
                    },
                    {
                        "candidate_id": "H-refuted",
                        "disposition": "refuted",
                    },
                ],
                **false_safety_fields(),
            },
        )

        result = run_agent_task(task.id, repository=repository)

        ranking_stage = next(
            stage
            for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
            if stage.stage_key == "autonomous_finding_dedup_and_rank"
        )
        assert result["status"] == "completed"
        assert ranking_stage.status == "completed"
        assert ranking_stage.payload["top_candidates"] == [
            {
                "candidate_id": "H-retained",
                "rank": 1,
                "survived_kill_score": 90,
                "evidence_completeness_score": 80,
                "priority_score": 70,
                **false_safety_fields(),
            }
        ]
        assert ranking_stage.payload["excluded_candidate_ids"] == ["H-refuted"]
    finally:
        session.close()


def test_report_review_keeps_the_runtime_awaiting_human_review(monkeypatch):
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Report review autonomous runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        for stage_order, task_type in enumerate(
            (
                "campaign_observation",
                "attack_surface_mapping",
                "hypothesis_generation",
                "candidate_refutation",
                "finding_dedup_and_rank",
            )
        ):
            save_completed_runtime_stage(
                repository,
                campaign,
                task_type,
                stage_order,
            )
        pipeline_run = repository.save_pipeline_run(
            program_id=campaign.program_id,
            asset=campaign.default_asset,
            policy_text=campaign.policy_text_hash,
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=1,
            report_title=None,
            payload={"campaign_id": campaign.id, "hypotheses": []},
        )
        repository.save_pipeline_stage(
            pipeline_run_id=pipeline_run.id,
            campaign_id=campaign.id,
            task_id=None,
            stage_key="autonomous_finding_dedup_and_rank",
            stage_order=30,
            status="completed",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            output_refs=[],
            safety_gate_state="safe",
            stop_reason=None,
            payload={
                "schema_version": "autonomous_finding_dedup_and_rank_v1",
                "pipeline_run_id": pipeline_run.id,
                "idempotency_key": "report-review-test",
                "top_candidates": [
                    {
                        "candidate_id": "H-retained",
                        "rank": 1,
                        "survived_kill_score": 90,
                        "evidence_completeness_score": 80,
                        "priority_score": 70,
                        **false_safety_fields(),
                    }
                ],
                "excluded_candidate_ids": [],
                "submission_blocked": True,
                "raw_payload_processed": False,
                **false_safety_fields(),
            },
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_review",
            agent_type="report_agent",
            title="Build submission-blocked report review",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload={
                "runtime_schema": "autonomous_research_v1",
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST,
                "pipeline_run_id": pipeline_run.id,
                **runtime_safety_fields(),
            },
        )
        retained = {
            "candidate_id": "H-retained",
            "vuln_type": "authorization_boundary",
            "root_cause_id": "missing_ownership:read_record",
            "route": {"method": "GET", "path": "/records/{record_id}"},
            "source_fact_refs": ["code:records.py:read_record"],
            "evidence_trace_status": "traceable",
            "human_validation_readiness": "ready",
            **false_safety_fields(),
        }
        monkeypatch.setattr(
            candidate_hunter_loop,
            "load_candidate_hunter_projection",
            lambda **_kwargs: {
                "status": "ready",
                "pipeline_run_id": pipeline_run.id,
                "final_candidates": [retained],
                "candidate_decisions": [
                    {"candidate_id": "H-retained", "disposition": "retained"}
                ],
                **false_safety_fields(),
            },
        )
        monkeypatch.setattr(
            candidate_report_bridge,
            "build_submission_blocked_report_bundle",
            lambda candidate: {
                "candidate_id": candidate["candidate_id"],
                "submission_blocked": True,
                "human_review_required": True,
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
                "confirmed_vulnerability": False,
                "report_draft": {"title": "Submission-blocked review"},
            },
        )

        result = run_agent_task(task.id, repository=repository)

        report_stage = next(
            stage
            for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
            if stage.stage_key == "autonomous_report_review"
        )
        assert result["status"] == "completed"
        assert report_stage.status == "completed"
        assert report_stage.payload["submission_blocked"] is True
        assert report_stage.payload["human_review_required"] is True
        assert report_stage.payload["execution_allowed"] is False
        assert report_stage.payload["validation_allowed"] is False
        assert report_stage.payload["report_submission_allowed"] is False
        assert report_stage.payload["report_drafts"] == [
            {
                "candidate_id": "H-retained",
                "submission_blocked": True,
                "human_review_required": True,
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
                "confirmed_vulnerability": False,
                "report_draft": {"title": "Submission-blocked review"},
            }
        ]
        validation_handoffs = [
            item
            for item in repository.list_campaign_tasks(campaign.id)
            if item.task_type == "validation_handoff"
        ]
        assert len(validation_handoffs) == 1
        assert validation_handoffs[0].status == "awaiting_approval"
        assert validation_handoffs[0].payload["submission_blocked"] is True
        assert validation_handoffs[0].payload["execution_allowed"] is False
        assert validation_handoffs[0].payload["validation_allowed"] is False
        assert validation_handoffs[0].payload["report_submission_allowed"] is False
        assert validation_handoffs[0].payload["source_snapshot_digest"] == SOURCE_SNAPSHOT_DIGEST
        runtime_report_stage = next(
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.task_id == task.id
            and stage.stage_key == "autonomous_research:report_review"
            and stage.status == "completed"
        )
        assert f"campaign_task:{validation_handoffs[0].id}" in runtime_report_stage.output_refs
        assert repository.list_campaign_validation_runs(campaign.id) == []
        assert repository.list_campaign_approval_records(campaign.id) == []
        dispatched_task_ids = []

        next_tick = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(campaign_task_id),
        )

        assert next_tick["status"] == "awaiting_review"
        assert next_tick["stop_reason"] == "human_review_required"
        assert dispatched_task_ids == []
    finally:
        session.close()


def test_runtime_completion_does_not_emit_a_stage_for_an_unsafe_task_payload():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Unsafe completion payload campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe authorized campaign state",
            payload={
                "runtime_schema": "autonomous_research_v1",
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST,
                **runtime_safety_fields(),
                "execution_allowed": True,
            },
        )

        autonomous_research_runtime.record_autonomous_research_task_completion(
            task=task,
            repository=repository,
        )

        assert repository.list_campaign_pipeline_stages(campaign.id) == []
    finally:
        session.close()


def test_runtime_rejects_an_active_task_that_contains_raw_source_material():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Raw runtime payload campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe authorized campaign state",
            payload={
                "runtime_schema": "autonomous_research_v1",
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST,
                "authorized_code_files": ["routes.py"],
                **runtime_safety_fields(),
            },
        )

        result = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "malformed_runtime_task"
    finally:
        session.close()


def test_worker_does_not_dispatch_a_human_approval_handoff():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Approval handoff campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        handoff = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="validation_handoff",
            agent_type="human_review",
            title="Review submission-blocked validation handoff",
            payload={
                "submission_blocked": True,
                "human_review_required": True,
                "approval_required": True,
                **false_safety_fields(),
            },
        )
        handoff = repository.update_campaign_task_status(handoff.id, "awaiting_approval")
        assert handoff is not None

        result = run_agent_task(handoff.id, repository=repository)

        persisted_handoff = repository.session.get(type(handoff), handoff.id)
        assert result["status"] == "awaiting_approval"
        assert result["stop_reason"] == "human_approval_required"
        assert persisted_handoff is not None
        assert persisted_handoff.status == "awaiting_approval"
        assert repository.list_campaign_agent_runs(campaign.id) == []
    finally:
        session.close()


def test_worker_does_not_reopen_a_completed_human_approval_handoff():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Completed approval handoff campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        handoff = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="validation_handoff",
            agent_type="human_review",
            title="Review submission-blocked validation handoff",
            payload={
                "submission_blocked": True,
                "human_review_required": True,
                "approval_required": True,
                **false_safety_fields(),
            },
        )
        handoff = repository.update_campaign_task_status(handoff.id, "completed")
        assert handoff is not None

        result = run_agent_task(handoff.id, repository=repository)

        persisted_handoff = repository.session.get(type(handoff), handoff.id)
        assert result == {
            "status": "completed",
            "task_id": handoff.id,
            "stop_reason": None,
        }
        assert persisted_handoff is not None
        assert persisted_handoff.status == "completed"
        assert repository.list_campaign_agent_runs(campaign.id) == []
    finally:
        session.close()


def test_worker_does_not_rerun_a_completed_runtime_task_on_duplicate_delivery():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Duplicate runtime delivery campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe authorized campaign state",
            payload={
                "runtime_schema": "autonomous_research_v1",
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST,
                **runtime_safety_fields(),
            },
        )
        repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=task.id,
            agent_type=task.agent_type,
            status="completed",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=[f"campaign_task:{task.id}:completed"],
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={"raw_payload_processed": False},
        )
        task = repository.update_campaign_task_status(task.id, "completed")
        assert task is not None

        result = run_agent_task(task.id, repository=repository)

        assert result["status"] == "completed"
        assert result["stop_reason"] is None
        assert len(repository.list_campaign_agent_runs(campaign.id)) == 1
    finally:
        session.close()


def test_tick_recovers_a_claimed_runtime_task_without_a_dispatch_record():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Claim recovery campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        task, claimed = repository.claim_campaign_task(
            task_id=autonomous_research_runtime._runtime_task_id(
                campaign_id=campaign.id,
                task_type="campaign_observation",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            ),
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe authorized campaign state",
            input_refs=[
                f"campaign:{campaign.id}",
                f"source_snapshot:{SOURCE_SNAPSHOT_DIGEST}",
            ],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="campaign_observation",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            ),
        )
        assert claimed is True
        dispatched_task_ids = []

        result = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(campaign_task_id),
        )

        persisted_task = repository.session.get(type(task), task.id)
        stages = repository.list_campaign_pipeline_stages(campaign.id)
        assert result["status"] == "dispatched"
        assert result["campaign_task_id"] == task.id
        assert dispatched_task_ids == [task.id]
        assert persisted_task is not None
        assert persisted_task.status == "dispatched"
        assert [stage.status for stage in stages] == ["dispatched"]
        assert len(repository.list_campaign_agent_runs(campaign.id)) == 1
    finally:
        session.close()


def test_tick_recovers_a_running_runtime_task_without_an_agent_run_or_stage():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Running claim recovery campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        task, claimed = repository.claim_campaign_task(
            task_id=autonomous_research_runtime._runtime_task_id(
                campaign_id=campaign.id,
                task_type="campaign_observation",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            ),
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe authorized campaign state",
            input_refs=[
                f"campaign:{campaign.id}",
                f"source_snapshot:{SOURCE_SNAPSHOT_DIGEST}",
            ],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="campaign_observation",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            ),
        )
        assert claimed is True
        task = repository.update_campaign_task_status(task.id, "running")
        assert task is not None
        dispatched_task_ids = []

        result = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(campaign_task_id),
        )

        persisted_task = repository.session.get(type(task), task.id)
        assert result["status"] == "dispatched"
        assert result["campaign_task_id"] == task.id
        assert dispatched_task_ids == [task.id]
        assert persisted_task is not None
        assert persisted_task.status == "dispatched"
        assert len(repository.list_campaign_agent_runs(campaign.id)) == 1
    finally:
        session.close()


def test_tick_does_not_redispatch_a_running_runtime_task_with_an_atomic_claim():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Live worker claim campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        task, claimed = repository.claim_campaign_task(
            task_id=autonomous_research_runtime._runtime_task_id(
                campaign_id=campaign.id,
                task_type="campaign_observation",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            ),
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe authorized campaign state",
            input_refs=[
                f"campaign:{campaign.id}",
                f"source_snapshot:{SOURCE_SNAPSHOT_DIGEST}",
            ],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="campaign_observation",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            ),
        )
        assert claimed is True
        claimed_task = repository.claim_campaign_task_execution(task.id)
        assert claimed_task is not None
        dispatched_task_ids = []

        result = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(campaign_task_id),
        )

        assert result["status"] == "awaiting_evidence"
        assert result["stop_reason"] == "recovery_dispatch_state_ambiguous"
        assert dispatched_task_ids == []
        assert len(repository.list_campaign_agent_runs(campaign.id)) == 1
    finally:
        session.close()


def test_tick_recovers_a_completed_runtime_task_missing_its_completion_stage():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Completion recovery campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        task, claimed = repository.claim_campaign_task(
            task_id=autonomous_research_runtime._runtime_task_id(
                campaign_id=campaign.id,
                task_type="campaign_observation",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            ),
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe authorized campaign state",
            input_refs=[
                f"campaign:{campaign.id}",
                f"source_snapshot:{SOURCE_SNAPSHOT_DIGEST}",
            ],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="campaign_observation",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            ),
        )
        assert claimed is True
        repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=task.id,
            agent_type=task.agent_type,
            status="completed",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=[f"campaign_task:{task.id}:completed"],
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={"raw_payload_processed": False},
        )
        task = repository.update_campaign_task_status(task.id, "completed")
        assert task is not None
        dispatched_task_ids = []

        result = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(campaign_task_id),
        )

        stages = repository.list_campaign_pipeline_stages(campaign.id)
        assert result["status"] == "completed"
        assert result["campaign_task_id"] == task.id
        assert dispatched_task_ids == []
        assert [stage.status for stage in stages] == ["completed"]
        assert stages[0].stage_key == "autonomous_research:campaign_observation"
        assert len(repository.list_campaign_agent_runs(campaign.id)) == 1
    finally:
        session.close()


def test_tick_waits_60_seconds_before_dispatching_the_next_runtime_work_item():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Cadenced runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        stage = save_completed_runtime_stage(
            repository,
            campaign,
            "campaign_observation",
            0,
        )
        stage.created_at = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
        session.add(stage)
        session.commit()
        dispatched_task_ids = []

        early_result = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(campaign_task_id),
            now=datetime(2026, 7, 18, 12, 0, 59, tzinfo=UTC),
        )
        due_result = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(campaign_task_id),
            now=datetime(2026, 7, 18, 12, 1, tzinfo=UTC),
        )

        assert early_result["status"] == "blocked"
        assert early_result["stop_reason"] == "tick_not_due"
        assert due_result["status"] == "dispatched"
        assert dispatched_task_ids == [due_result["campaign_task_id"]]
    finally:
        session.close()


def test_blocks_a_snapshot_after_20_local_runtime_work_items():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Bounded runtime campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        for index in range(20):
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="campaign_observation",
                agent_type="orchestrator_agent",
                title="Observe authorized campaign state",
                payload=autonomous_research_runtime._runtime_task_payload(
                    campaign_id=campaign.id,
                    task_type="campaign_observation",
                    source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
                ),
            )
            task = repository.update_campaign_task_status(task.id, "failed")
            assert task is not None

        result = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "snapshot_work_item_limit_reached"
    finally:
        session.close()


def test_runtime_evidence_resume_normalizes_snapshot_digest_and_advances_to_ranking(
    tmp_path,
):
    repository, session = build_repository()
    try:
        code = '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str, current_user):
    verify_record_access(record_id, current_user)
    return send_file(record_id)

def verify_record_access(record_id: str, current_user):
    record = load_record(record_id)
    if record.owner_id != current_user.id:
        raise PermissionError()
    return record
'''
        (tmp_path / "routes.py").write_text(code, encoding="utf-8")
        source_manifest = [
            {
                "source_path": "routes.py",
                "content_digest": sha256(code.encode("utf-8")).hexdigest(),
            }
        ]
        source_snapshot_digest = "sha256:" + sha256(
            json.dumps(
                source_manifest,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Runtime evidence resume campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset=str(tmp_path),
            allowed_tools=["candidate_hunter_local_evidence_inspector"],
            created_by="operator",
            payload={
                "scope_guard_rule": {
                    "asset": str(tmp_path),
                    "scope_status": "in_scope",
                    "automation": "none",
                    "allowed_validation": [],
                    "forbidden": [],
                    "human_approval_required": True,
                },
                "source_snapshot_digest": source_snapshot_digest,
                "source_manifest": source_manifest,
                "saved_scope_guard": {
                    "scope_status": "in_scope",
                    "authorized_local_root": str(tmp_path),
                },
                "inspector_tool_allowlist": [
                    "candidate_hunter_local_evidence_inspector"
                ],
                **runtime_safety_fields(),
            },
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        pipeline_run = repository.save_pipeline_run(
            program_id=campaign.program_id,
            asset=campaign.default_asset,
            policy_text=campaign.policy_text_hash,
            policy_text_is_hash=True,
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=1,
            report_title=None,
            payload={
                "campaign_id": campaign.id,
                "hypotheses": [
                    {
                        "hypothesis_id": "H-001",
                        "vuln_type": "authorization",
                        "location": "GET /records/{record_id}",
                        "priority_score": 80,
                        "source_facts": [
                            {
                                "fact_type": "authorization_gap_candidate",
                                "artifact_kind": "code",
                                "source_path": "routes.py",
                                "symbol_name": "read_record",
                                "route_method": "GET",
                                "route_path": "/records/{record_id}",
                                "root_cause": "missing_object_ownership_check",
                            },
                            {
                                "fact_type": "api_surface",
                                "artifact_kind": "api",
                                "route_method": "GET",
                                "route_path": "/records/{record_id}",
                            },
                            {
                                "fact_type": "har_context",
                                "artifact_kind": "har",
                                "route_method": "GET",
                                "route_path": "/records/{record_id}",
                            },
                        ],
                    }
                ],
            },
        )
        assert pipeline_run.policy_text_hash == campaign.policy_text_hash
        save_completed_runtime_stage(
            repository,
            campaign,
            "campaign_observation",
            0,
            source_snapshot_digest=source_snapshot_digest,
        )
        save_completed_runtime_stage(
            repository,
            campaign,
            "attack_surface_mapping",
            1,
            source_snapshot_digest=source_snapshot_digest,
        )
        save_completed_runtime_stage(
            repository,
            campaign,
            "hypothesis_generation",
            2,
            output_refs=[f"pipeline_run:{pipeline_run.id}"],
            source_snapshot_digest=source_snapshot_digest,
        )
        dispatched_task_ids = []

        tick_result = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(campaign_task_id),
            now=datetime.now(UTC) + timedelta(seconds=60),
        )
        refutation_task = repository.session.get(
            type(repository.list_campaign_tasks(campaign.id)[0]),
            tick_result["campaign_task_id"],
        )
        assert refutation_task is not None
        assert tick_result["status"] == "dispatched"
        assert run_agent_task(refutation_task.id, repository=repository)["status"] == "awaiting_evidence"
        evidence_task = next(
            task
            for task in repository.list_campaign_tasks(campaign.id)
            if task.task_type == "candidate_hunter_evidence_inspection"
        )

        resumed = run_agent_task(evidence_task.id, repository=repository)
        selection = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
        )

        runtime_stages = repository.list_campaign_pipeline_stages(campaign.id)
        assert dispatched_task_ids == [refutation_task.id]
        assert resumed["status"] == "completed", resumed["stop_reason"]
        assert refutation_task.status == "completed"
        assert any(
            stage.task_id == refutation_task.id
            and stage.stage_key == "autonomous_research:candidate_refutation"
            and stage.status == "completed"
            for stage in runtime_stages
        )
        assert selection["status"] == "ready"
        assert selection["task_type"] == "finding_dedup_and_rank"
    finally:
        session.close()
