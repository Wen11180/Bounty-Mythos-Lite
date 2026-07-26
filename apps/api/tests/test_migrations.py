from importlib.util import module_from_spec, spec_from_file_location
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.orm import sessionmaker

import app.db as database
import app.repository as repository
from app.db import initialize_database
from app.db_models import (
    AgentRunRecord,
    CampaignLocalToolExecutionSlotRecord,
    CampaignTaskRecord,
)
from app.repository import DatabaseRepository


PROGRAM_RULE_TABLES = {
    "program_rule_sources",
    "program_rule_snapshots",
    "program_scope_rules",
}
WAKEUP_TABLES = {"autonomous_research_wakeup_states"}
LOCAL_TOOL_SLOT_TABLES = {"campaign_local_tool_execution_slots"}
AUTOPILOT_TABLES = {
    "campaign_authorizations",
    "campaign_assets",
    "campaign_asset_admission_events",
    "research_branches",
    "validation_plans",
    "execution_leases",
    "execution_request_ledger",
    "autopilot_observations",
}
HEAD_REVISION = "0030_bounty_autopilot_observation_replay_guard"

def _insert_pre_autopilot_campaign(session, *, campaign_id, name, status, payload, allowed_tools):
    """Insert a campaigns row against pre-0020 schema (no campaign_mode column)."""
    session.execute(
        text(
            """
            INSERT INTO campaigns (
                id, program_id, name, autonomy_level, scope_status, policy_text_hash,
                default_asset, target_classes, allowed_tools, created_by, status, payload, created_at
            ) VALUES (
                :id, NULL, :name, :autonomy_level, :scope_status, :policy_text_hash,
                :default_asset, :target_classes, :allowed_tools, :created_by, :status, :payload, :created_at
            )
            """
        ),
        {
            "id": campaign_id,
            "name": name,
            "autonomy_level": "level_1_local_validation",
            "scope_status": "in_scope",
            "policy_text_hash": f"sha256:{'b' * 64}",
            "default_asset": "local.example",
            "target_classes": "[]",
            "allowed_tools": json.dumps(allowed_tools),
            "created_by": "operator",
            "status": status,
            "payload": json.dumps(payload),
            "created_at": datetime.now(UTC).replace(tzinfo=None),
        },
    )



def test_initialize_database_distinguishes_engines_when_legacy_ids_collide(monkeypatch):
    calls = []
    monkeypatch.setattr(database, "ensure_database_schema", calls.append)
    monkeypatch.setattr(database, "id", lambda _engine: 1, raising=False)
    monkeypatch.setattr(repository, "seed_sample_data", lambda _session: None)

    first_engine = create_engine("sqlite:///:memory:")
    second_engine = create_engine("sqlite:///:memory:")
    try:
        database.initialize_database(first_engine)
        database.initialize_database(second_engine)
    finally:
        first_engine.dispose()
        second_engine.dispose()

    assert calls == [first_engine, second_engine]


def test_evidence_aware_migration_widens_postgresql_version_identifier(monkeypatch):
    api_root = Path(__file__).resolve().parents[1]
    spec = spec_from_file_location(
        "migration_0003_evidence_aware_learning_signals",
        str(
            api_root
            / "migrations"
            / "versions"
            / "0003_evidence_aware_learning_signals.py"
        ),
    )
    assert spec is not None
    assert spec.loader is not None
    migration = module_from_spec(spec)
    spec.loader.exec_module(migration)
    calls = []

    class FakeOperations:
        def get_bind(self):
            return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

        def alter_column(self, table_name, column_name, **kwargs):
            calls.append((table_name, column_name, kwargs))

    monkeypatch.setattr(migration, "op", FakeOperations())

    migration._widen_alembic_version_identifier()

    assert len(calls) == 1
    table_name, column_name, kwargs = calls[0]
    assert (table_name, column_name) == ("alembic_version", "version_num")
    assert kwargs["existing_nullable"] is False
    assert kwargs["existing_type"].length == 32
    assert kwargs["type_"].length == 64


def test_alembic_head_includes_learning_relationships_and_campaign_core(tmp_path, monkeypatch):
    database_path = tmp_path / "migration-check.db"
    database_url = f"sqlite:///{database_path}"
    monkeypatch.setenv("DATABASE_URL", database_url)

    api_root = Path(__file__).resolve().parents[1]
    config = Config(str(api_root / "alembic.ini"))
    config.set_main_option("script_location", str(api_root / "migrations"))
    command.upgrade(config, "head")

    engine = create_engine(database_url)
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    learning_columns = {
        column["name"]
        for column in inspector.get_columns("learning_signals")
    }
    learning_indexes = inspector.get_indexes("learning_signals")
    approval_columns = {
        column["name"]
        for column in inspector.get_columns("approval_records")
    }
    source_columns = {
        column["name"]
        for column in inspector.get_columns("program_rule_sources")
    }
    snapshot_columns = {
        column["name"]
        for column in inspector.get_columns("program_rule_snapshots")
    }
    rule_columns = {
        column["name"]
        for column in inspector.get_columns("program_scope_rules")
    }
    wakeup_columns = {
        column["name"]
        for column in inspector.get_columns("autonomous_research_wakeup_states")
    }
    campaign_task_columns = {
        column["name"] for column in inspector.get_columns("campaign_tasks")
    }
    local_tool_slot_columns = {
        column["name"]
        for column in inspector.get_columns("campaign_local_tool_execution_slots")
    }
    execution_lease_columns = {
        column["name"] for column in inspector.get_columns("execution_leases")
    }
    execution_lease_indexes = inspector.get_indexes("execution_leases")
    request_ledger_indexes = inspector.get_indexes("execution_request_ledger")
    observation_columns = {
        column["name"] for column in inspector.get_columns("autopilot_observations")
    }
    observation_indexes = inspector.get_indexes("autopilot_observations")
    llm_run_columns = {
        column["name"]: column for column in inspector.get_columns("llm_runs")
    }

    assert "target_relationships" in learning_columns
    assert "identity_hash" in learning_columns
    assert "field_pilot_feedback" in learning_columns
    assert any(
        index["name"] == "uq_learning_signals_identity_hash"
        and index["column_names"] == ["identity_hash"]
        and index.get("unique")
        for index in learning_indexes
    )
    assert "expires_at" in approval_columns
    assert {
        "campaigns",
        "campaign_budgets",
        "campaign_tasks",
        "agent_runs",
        "approval_records",
        "pipeline_stages",
        "codebase_maps",
        "codebase_facts",
        "scanner_runs",
        "validation_runs",
        "campaign_local_tool_execution_slots",
    } | AUTOPILOT_TABLES <= tables
    assert PROGRAM_RULE_TABLES <= tables
    assert WAKEUP_TABLES <= tables
    assert {
        "canonical_url",
        "refresh_interval_seconds",
        "claim_token_digest",
        "approved_snapshot_id",
        "pending_snapshot_id",
    } <= source_columns
    assert {
        "normalized_sha256",
        "extraction",
        "evidence",
        "openapi_candidates",
        "execution_allowed",
        "lease_grant_allowed",
        "scope_change_allowed",
        "review_bypass_allowed",
        "report_submission_allowed",
    } <= snapshot_columns
    assert {
        "approved_snapshot_id",
        "canonical_asset",
        "source_evidence_refs",
        "approval_digest",
    } <= rule_columns
    assert {
        "after_campaign_id",
        "lease_token_digest",
        "lease_expires_at",
        "next_due_at",
        "last_cycle_completed_at",
        "last_cycle_status",
        "last_cycle_stop_reason",
        "last_cycle_processed_count",
        "last_cycle_outcome_counts",
        "execution_allowed",
        "validation_allowed",
        "report_submission_allowed",
    } <= wakeup_columns
    assert {
        "execution_claim_id",
        "execution_heartbeat_at",
        "execution_lease_expires_at",
    } <= campaign_task_columns
    assert {
        "campaign_id",
        "source_snapshot_digest",
        "active_task_id",
        "active_execution_claim_id",
        "legacy_active_task_count",
    } <= local_tool_slot_columns
    assert {
        "authorization_id",
        "expires_at",
        "duration_reserved_seconds",
        "cost_units_reserved",
    } <= execution_lease_columns
    assert {"lease_id", "reservation_id", "comparison_reservation_id"} <= observation_columns
    assert llm_run_columns["created_at"]["nullable"] is False
    assert any(
        index["name"] == "ix_execution_leases_campaign_status"
        and index["column_names"] == ["campaign_id", "status"]
        for index in execution_lease_indexes
    )
    assert any(
        index["name"] == "ix_execution_leases_campaign_authorization_status"
        and index["column_names"] == ["campaign_id", "authorization_id", "status"]
        for index in execution_lease_indexes
    )
    assert any(
        index["name"] == "ix_execution_request_ledger_campaign_lease"
        and index["column_names"] == ["campaign_id", "lease_id"]
        for index in request_ledger_indexes
    )
    assert any(
        index["name"] == "ix_autopilot_observations_campaign_branch"
        and index["column_names"] == ["campaign_id", "branch_id"]
        for index in observation_indexes
    )
    assert any(
        index["name"]
        == "uq_autopilot_observations_campaign_comparison_reservation"
        and index["column_names"] == ["campaign_id", "comparison_reservation_id"]
        and index.get("unique")
        for index in observation_indexes
    )

    source_unique = {
        tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints("program_rule_sources")
    }
    snapshot_unique = {
        tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints("program_rule_snapshots")
    }
    rule_unique = {
        tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints("program_scope_rules")
    }
    local_tool_slot_unique = {
        tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints(
            "campaign_local_tool_execution_slots"
        )
    }
    assert {("canonical_url",), ("program_id",)} <= source_unique
    assert ("source_id", "normalized_sha256") in snapshot_unique
    assert ("approved_snapshot_id", "canonical_asset") in rule_unique
    assert ("campaign_id", "source_snapshot_digest") in local_tool_slot_unique

    snapshot_checks = {
        constraint["name"]
        for constraint in inspector.get_check_constraints("program_rule_snapshots")
    }
    assert {
        "ck_program_rule_snapshots_execution_allowed_false",
        "ck_program_rule_snapshots_lease_grant_allowed_false",
        "ck_program_rule_snapshots_scope_change_allowed_false",
        "ck_program_rule_snapshots_review_bypass_allowed_false",
        "ck_program_rule_snapshots_report_submission_allowed_false",
    } <= snapshot_checks
    wakeup_checks = {
        constraint["name"]
        for constraint in inspector.get_check_constraints(
            "autonomous_research_wakeup_states"
        )
    }
    assert {
        "ck_autonomous_research_wakeup_execution_allowed_false",
        "ck_autonomous_research_wakeup_validation_allowed_false",
        "ck_autonomous_research_wakeup_report_submission_allowed_false",
    } <= wakeup_checks
    engine.dispose()
    command.check(config)


def test_schema_alignment_migration_backfills_legacy_llm_run_timestamp(tmp_path, monkeypatch):
    database_path = tmp_path / "schema-alignment.db"
    database_url = f"sqlite:///{database_path}"
    monkeypatch.setenv("DATABASE_URL", database_url)

    api_root = Path(__file__).resolve().parents[1]
    config = Config(str(api_root / "alembic.ini"))
    config.set_main_option("script_location", str(api_root / "migrations"))
    command.upgrade(config, "0028_bounty_autopilot_r2_observation_pair")

    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO llm_runs (
                    id, provider, model, purpose, prompt_hash, mode, safety_notes, created_at
                ) VALUES (
                    :id, :provider, :model, :purpose, :prompt_hash, :mode, :safety_notes, NULL
                )
                """
            ),
            {
                "id": "legacy-null-created-at",
                "provider": "test-provider",
                "model": "test-model",
                "purpose": "general",
                "prompt_hash": "sha256:legacy",
                "mode": "test",
                "safety_notes": "[]",
            },
        )
    engine.dispose()

    command.upgrade(config, "head")

    engine = create_engine(database_url)
    with engine.connect() as connection:
        created_at = connection.execute(
            text("SELECT created_at FROM llm_runs WHERE id = :id"),
            {"id": "legacy-null-created-at"},
        ).scalar_one()
    assert created_at is not None
    created_at_column = next(
        column
        for column in inspect(engine).get_columns("llm_runs")
        if column["name"] == "created_at"
    )
    assert created_at_column["nullable"] is False
    engine.dispose()


@pytest.mark.parametrize(
    "rows",
    (
        (
            ("one", "reservation_one", "reservation_replayed_comparison"),
            ("two", "reservation_two", "reservation_replayed_comparison"),
        ),
        (
            ("one", "reservation_one", "reservation_replayed_cross_role"),
            ("two", "reservation_replayed_cross_role", "reservation_two"),
        ),
    ),
    ids=("comparison_reuse", "cross_role_reuse"),
)
def test_observation_replay_guard_rejects_legacy_reservation_reuse(
    tmp_path,
    monkeypatch,
    rows,
):
    database_path = tmp_path / "observation-replay-guard.db"
    database_url = f"sqlite:///{database_path}"
    monkeypatch.setenv("DATABASE_URL", database_url)

    api_root = Path(__file__).resolve().parents[1]
    config = Config(str(api_root / "alembic.ini"))
    config.set_main_option("script_location", str(api_root / "migrations"))
    command.upgrade(config, "0029_bounty_autopilot_schema_alignment")

    engine = create_engine(database_url)
    now = datetime.now(UTC)
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO campaigns (
                    id, name, autonomy_level, scope_status, policy_text_hash,
                    default_asset, target_classes, allowed_tools, created_by,
                    status, payload, created_at
                ) VALUES (
                    :id, :name, :autonomy_level, :scope_status, :policy_text_hash,
                    :default_asset, :target_classes, :allowed_tools, :created_by,
                    :status, :payload, :created_at
                )
                """
            ),
            {
                "id": "campaign_replayed_comparison",
                "name": "Replayed comparison migration fixture",
                "autonomy_level": "level_0_read_only",
                "scope_status": "in_scope",
                "policy_text_hash": "sha256:" + ("a" * 64),
                "default_asset": "127.0.0.1",
                "target_classes": "[]",
                "allowed_tools": "[]",
                "created_by": "operator",
                "status": "running",
                "payload": "{}",
                "created_at": now,
            },
        )
        for suffix, reservation_id, comparison_reservation_id in rows:
            connection.execute(
                text(
                    """
                    INSERT INTO autopilot_observations (
                        id, campaign_id, observation_id, branch_id, plan_digest,
                        lease_id, reservation_id, comparison_reservation_id,
                        grade, outcome_class, payload, created_at
                    ) VALUES (
                        :id, :campaign_id, :observation_id, :branch_id, :plan_digest,
                        :lease_id, :reservation_id, :comparison_reservation_id,
                        :grade, :outcome_class, :payload, :created_at
                    )
                    """
                ),
                {
                    "id": f"obs_row_replay_{suffix}",
                    "campaign_id": "campaign_replayed_comparison",
                    "observation_id": f"obs_replay_{suffix}",
                    "branch_id": "branch_replay",
                    "plan_digest": "sha256:" + ("b" * 64),
                    "lease_id": "lease_replay",
                    "reservation_id": reservation_id,
                    "comparison_reservation_id": comparison_reservation_id,
                    "grade": "L2_corroborated",
                    "outcome_class": "ok",
                    "payload": "{}",
                    "created_at": now,
                },
            )
    engine.dispose()

    with pytest.raises(
        RuntimeError,
        match="autopilot_observation_reservation_replay",
    ):
        command.upgrade(config, "head")


def test_program_rule_migration_downgrade_removes_only_new_tables(tmp_path, monkeypatch):
    database_path = tmp_path / "program-rule-downgrade.db"
    database_url = f"sqlite:///{database_path}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    api_root = Path(__file__).resolve().parents[1]
    config = Config(str(api_root / "alembic.ini"))
    config.set_main_option("script_location", str(api_root / "migrations"))
    command.upgrade(config, "head")

    engine = create_engine(database_url)
    tables_before = set(inspect(engine).get_table_names())
    engine.dispose()

    command.downgrade(config, "0012_field_pilot_feedback")

    engine = create_engine(database_url)
    tables_after = set(inspect(engine).get_table_names())
    with engine.connect() as connection:
        version = connection.execute(text("select version_num from alembic_version")).scalar_one()
    new_tables = (
        PROGRAM_RULE_TABLES
        | WAKEUP_TABLES
        | LOCAL_TOOL_SLOT_TABLES
        | AUTOPILOT_TABLES
    )
    assert new_tables <= tables_before
    assert new_tables.isdisjoint(tables_after)
    assert tables_after == tables_before - new_tables
    assert version == "0012_field_pilot_feedback"
    engine.dispose()


def test_local_tool_slot_migration_backfills_active_task(tmp_path, monkeypatch):
    database_path = tmp_path / "local-tool-slot-backfill.db"
    database_url = f"sqlite:///{database_path}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    api_root = Path(__file__).resolve().parents[1]
    config = Config(str(api_root / "alembic.ini"))
    config.set_main_option("script_location", str(api_root / "migrations"))
    command.upgrade(config, "0018_campaign_tool_call_reservations")

    engine = create_engine(database_url)
    Session = sessionmaker(bind=engine)
    source_snapshot_digest = f"sha256:{'a' * 64}"
    now = datetime.now(UTC)
    with Session() as session:
        _insert_pre_autopilot_campaign(
            session,
            campaign_id="campaign_active_local_slot",
            name="Active local-tool migration campaign",
            status="dispatched",
            payload={"source_snapshot_digest": source_snapshot_digest},
            allowed_tools=["static_analyzer"],
        )
        campaign = SimpleNamespace(id="campaign_active_local_slot")
        task = CampaignTaskRecord(
            id="campaign_task_active_local_slot",
            campaign_id=campaign.id,
            task_type="research_director_local_tool_run",
            agent_type="registered_local_tool",
            title="Run active local analysis",
            status="running",
            input_refs=[],
            output_refs=[],
            payload={
                "schema_version": "research_director_local_tool_run_v1",
                "execution_lease_required": True,
                "research_plan_id": "research_plan_active_slot",
                "research_plan_digest": f"sha256:{'c' * 64}",
                "source_snapshot_digest": source_snapshot_digest,
                "tool_id": "semgrep_local",
            },
            execution_claim_id="agent_run_active_local_slot",
            execution_heartbeat_at=now,
            execution_lease_expires_at=now,
        )
        agent_run = AgentRunRecord(
            id="agent_run_active_local_slot",
            campaign_id=campaign.id,
            task_id=task.id,
            agent_type="registered_local_tool",
            status="running",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=[],
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={},
        )
        session.add_all([task, agent_run])
        session.commit()
        campaign_id = campaign.id
        task_id = task.id
        agent_run_id = agent_run.id

    command.upgrade(config, "head")

    with Session() as session:
        slot = session.scalar(
            select(CampaignLocalToolExecutionSlotRecord).where(
                CampaignLocalToolExecutionSlotRecord.campaign_id == campaign_id,
                CampaignLocalToolExecutionSlotRecord.source_snapshot_digest
                == source_snapshot_digest,
            )
        )
        assert slot is not None
        assert slot.active_task_id == task_id
        assert slot.active_execution_claim_id == agent_run_id
        assert slot.legacy_active_task_count == 0

        repository = DatabaseRepository(session)
        completed = repository.finish_campaign_task_execution(
            task_id=task_id,
            execution_claim_id=agent_run_id,
            task_status="completed",
            task_output_refs=[],
            agent_status="completed",
            agent_output_refs=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={},
        )
        assert completed is not None
        slot = session.scalar(
            select(CampaignLocalToolExecutionSlotRecord).where(
                CampaignLocalToolExecutionSlotRecord.id == slot.id
            )
        )
        assert slot is not None
        assert slot.active_task_id is None
        assert slot.active_execution_claim_id is None
    engine.dispose()


def test_local_tool_slot_migration_keeps_legacy_tasks_blocking_until_finished(
    tmp_path,
    monkeypatch,
):
    database_path = tmp_path / "local-tool-slot-legacy-blocking.db"
    database_url = f"sqlite:///{database_path}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    api_root = Path(__file__).resolve().parents[1]
    config = Config(str(api_root / "alembic.ini"))
    config.set_main_option("script_location", str(api_root / "migrations"))
    command.upgrade(config, "0018_campaign_tool_call_reservations")

    engine = create_engine(database_url)
    Session = sessionmaker(bind=engine)
    source_snapshot_digest = f"sha256:{'a' * 64}"
    now = datetime.now(UTC)
    campaign_id = "campaign_duplicate_local_slot"
    owner_task_id = "campaign_task_local_slot_owner"
    legacy_task_id = "campaign_task_local_slot_legacy"
    owner_agent_run_id = "agent_run_local_slot_owner"
    legacy_agent_run_id = "agent_run_local_slot_legacy"
    with Session() as session:
        _insert_pre_autopilot_campaign(
            session,
            campaign_id=campaign_id,
            name="Duplicate active local-tool migration campaign",
            status="running",
            payload={"source_snapshot_digest": source_snapshot_digest},
            allowed_tools=["static_analyzer", "codeql_local"],
        )
        campaign = SimpleNamespace(id=campaign_id)
        owner_task = CampaignTaskRecord(
            id=owner_task_id,
            campaign_id=campaign.id,
            task_type="research_director_local_tool_run",
            agent_type="registered_local_tool",
            title="Run owner local analysis",
            status="running",
            input_refs=[],
            output_refs=[],
            payload={
                "schema_version": "research_director_local_tool_run_v1",
                "execution_lease_required": True,
                "research_plan_id": "research_plan_local_slot_owner",
                "research_plan_digest": f"sha256:{'c' * 64}",
                "source_snapshot_digest": source_snapshot_digest,
                "tool_id": "semgrep_local",
            },
            execution_claim_id=owner_agent_run_id,
            execution_heartbeat_at=now,
            execution_lease_expires_at=now + timedelta(minutes=15),
            created_at=now,
        )
        legacy_task = CampaignTaskRecord(
            id=legacy_task_id,
            campaign_id=campaign.id,
            task_type="research_director_local_tool_run",
            agent_type="registered_local_tool",
            title="Run duplicate local analysis",
            status="dispatched",
            input_refs=[],
            output_refs=[],
            payload={
                "schema_version": "research_director_local_tool_run_v1",
                "execution_lease_required": True,
                "research_plan_id": "research_plan_local_slot_legacy",
                "research_plan_digest": f"sha256:{'d' * 64}",
                "source_snapshot_digest": source_snapshot_digest,
                "tool_id": "codeql_local",
            },
            execution_claim_id=legacy_agent_run_id,
            execution_heartbeat_at=now,
            execution_lease_expires_at=now + timedelta(minutes=15),
            created_at=now + timedelta(seconds=1),
        )
        session.add_all(
            [
                owner_task,
                legacy_task,
                AgentRunRecord(
                    id=owner_agent_run_id,
                    campaign_id=campaign.id,
                    task_id=owner_task.id,
                    agent_type="registered_local_tool",
                    status="running",
                    input_refs=[f"campaign_task:{owner_task.id}"],
                    output_refs=[],
                    tool_calls=[],
                    safety_gate_state="allowed",
                    stop_reason=None,
                    payload={},
                ),
                AgentRunRecord(
                    id=legacy_agent_run_id,
                    campaign_id=campaign.id,
                    task_id=legacy_task.id,
                    agent_type="registered_local_tool",
                    status="dispatched",
                    input_refs=[f"campaign_task:{legacy_task.id}"],
                    output_refs=[],
                    tool_calls=[],
                    safety_gate_state="allowed",
                    stop_reason=None,
                    payload={},
                ),
            ]
        )
        session.commit()

    command.upgrade(config, "head")

    with Session() as session:
        repository = DatabaseRepository(session)
        tasks = {
            task.id: task for task in repository.list_campaign_tasks(campaign_id)
        }
        slot = session.scalar(
            select(CampaignLocalToolExecutionSlotRecord).where(
                CampaignLocalToolExecutionSlotRecord.campaign_id == campaign_id,
                CampaignLocalToolExecutionSlotRecord.source_snapshot_digest
                == source_snapshot_digest,
            )
        )
        assert slot is not None
        assert slot.active_task_id == owner_task_id
        assert slot.active_execution_claim_id == owner_agent_run_id
        assert slot.legacy_active_task_count == 1
        assert tasks[legacy_task_id].payload["local_tool_execution_slot_legacy"] is True
        claimed_legacy_task = repository.claim_campaign_task_execution(
            legacy_task_id,
            now=now,
        )
        assert claimed_legacy_task is not None
        assert claimed_legacy_task.status == "running"
        assert claimed_legacy_task.execution_claim_id == legacy_agent_run_id

        waiting_task = repository.create_campaign_task(
            campaign_id=campaign_id,
            task_type="research_director_local_tool_run",
            agent_type="registered_local_tool",
            title="Run waiting local analysis",
            payload={
                "schema_version": "research_director_local_tool_run_v1",
                "execution_lease_required": True,
                "research_plan_id": "research_plan_local_slot_waiting",
                "research_plan_digest": f"sha256:{'e' * 64}",
                "source_snapshot_digest": source_snapshot_digest,
                "tool_id": "semgrep_local",
            },
        )
        assert (
            repository.dispatch_research_director_local_tool_task(
                task_id=waiting_task.id,
                agent_payload={"raw_payload_processed": False},
            )
            is None
        )

        assert (
            repository.finish_campaign_task_execution(
                task_id=owner_task_id,
                execution_claim_id=owner_agent_run_id,
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
        slot = session.scalar(
            select(CampaignLocalToolExecutionSlotRecord).where(
                CampaignLocalToolExecutionSlotRecord.id == slot.id
            )
        )
        assert slot is not None
        assert slot.active_task_id is None
        assert slot.active_execution_claim_id is None
        assert slot.legacy_active_task_count == 1
        assert (
            repository.dispatch_research_director_local_tool_task(
                task_id=waiting_task.id,
                agent_payload={"raw_payload_processed": False},
            )
            is None
        )

        assert (
            repository.expire_campaign_task_execution(
                legacy_task_id,
                now=now + timedelta(minutes=16),
            )
            is not None
        )
        slot = session.scalar(
            select(CampaignLocalToolExecutionSlotRecord).where(
                CampaignLocalToolExecutionSlotRecord.id == slot.id
            )
        )
        assert slot is not None
        assert slot.active_task_id is None
        assert slot.active_execution_claim_id is None
        assert slot.legacy_active_task_count == 0

        dispatched = repository.dispatch_research_director_local_tool_task(
            task_id=waiting_task.id,
            agent_payload={"raw_payload_processed": False},
        )
        assert dispatched is not None
        assert dispatched[0].id == waiting_task.id
        assert dispatched[1].task_id == waiting_task.id
    engine.dispose()


def test_initialize_database_upgrades_persistent_sqlite_from_0010(tmp_path, monkeypatch):
    database_path = tmp_path / "studio-0010.db"
    database_url = f"sqlite:///{database_path}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    api_root = Path(__file__).resolve().parents[1]
    config = Config(str(api_root / "alembic.ini"))
    config.set_main_option("script_location", str(api_root / "migrations"))
    command.upgrade(config, "0010_learning_signal_identity_hash")

    engine = create_engine(database_url)
    initialize_database(engine)

    with engine.connect() as connection:
        version = connection.execute(text("select version_num from alembic_version")).scalar_one()
    unique_constraints = inspect(engine).get_unique_constraints("artifacts")
    assert version == HEAD_REVISION
    assert any(
        constraint["name"] == "uq_artifacts_program_source_hash"
        and constraint["column_names"] == ["program_id", "source_hash"]
        for constraint in unique_constraints
    )
    engine.dispose()


def test_initialize_database_adopts_unversioned_0010_sqlite(tmp_path, monkeypatch):
    database_path = tmp_path / "studio-unversioned-0010.db"
    database_url = f"sqlite:///{database_path}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    api_root = Path(__file__).resolve().parents[1]
    config = Config(str(api_root / "alembic.ini"))
    config.set_main_option("script_location", str(api_root / "migrations"))
    command.upgrade(config, "0010_learning_signal_identity_hash")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("drop table alembic_version"))

    initialize_database(engine)

    with engine.connect() as connection:
        version = connection.execute(text("select version_num from alembic_version")).scalar_one()
    assert version == HEAD_REVISION
    assert any(
        constraint["name"] == "uq_artifacts_program_source_hash"
        for constraint in inspect(engine).get_unique_constraints("artifacts")
    )
    engine.dispose()


def test_initialize_database_adopts_unversioned_field_pilot_schema(tmp_path, monkeypatch):
    database_path = tmp_path / "studio-unversioned-field-pilot.db"
    database_url = f"sqlite:///{database_path}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    api_root = Path(__file__).resolve().parents[1]
    config = Config(str(api_root / "alembic.ini"))
    config.set_main_option("script_location", str(api_root / "migrations"))
    command.upgrade(config, "0012_field_pilot_feedback")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("drop table alembic_version"))

    initialize_database(engine)

    with engine.connect() as connection:
        version = connection.execute(text("select version_num from alembic_version")).scalar_one()
    assert version == HEAD_REVISION
    assert "field_pilot_feedback" in {
        column["name"] for column in inspect(engine).get_columns("learning_signals")
    }
    assert PROGRAM_RULE_TABLES <= set(inspect(engine).get_table_names())
    engine.dispose()


def test_initialize_database_adopts_unversioned_program_rule_schema(tmp_path, monkeypatch):
    database_path = tmp_path / "studio-unversioned-program-rule.db"
    database_url = f"sqlite:///{database_path}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    api_root = Path(__file__).resolve().parents[1]
    config = Config(str(api_root / "alembic.ini"))
    config.set_main_option("script_location", str(api_root / "migrations"))
    command.upgrade(config, "head")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("drop table alembic_version"))

    initialize_database(engine)

    with engine.connect() as connection:
        version = connection.execute(text("select version_num from alembic_version")).scalar_one()
    assert version == HEAD_REVISION
    assert PROGRAM_RULE_TABLES <= set(inspect(engine).get_table_names())
    assert WAKEUP_TABLES <= set(inspect(engine).get_table_names())
    engine.dispose()
