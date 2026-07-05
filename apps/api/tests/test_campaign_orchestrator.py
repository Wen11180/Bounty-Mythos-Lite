from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.campaign_orchestrator import tick_campaign
from app.db import Base
from app.repository import DatabaseRepository, seed_sample_data


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


def test_tick_dispatches_only_campaign_task_id_for_safe_read_only_task():
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
        assert len(dispatched) == 1
        assert list(dispatched[0]) == ["campaign_task_id"]
        assert dispatched[0]["campaign_task_id"].startswith("campaign_task_")
        assert repository.list_campaign_tasks(campaign.id)[0].task_type == "campaign_observation"
        assert repository.list_campaign_agent_runs(campaign.id)[0].safety_gate_state == "allowed"
    finally:
        session.close()
