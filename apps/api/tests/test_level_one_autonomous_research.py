from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.autonomous_research_runtime import select_autonomous_research_work
from app.db import Base
from app.repository import DatabaseRepository, seed_sample_data


SNAPSHOT_DIGEST = f"sha256:{'c' * 64}"


def _repository():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    seed_sample_data(session)
    return DatabaseRepository(session), session


def _running_campaign(repository: DatabaseRepository, *, autonomy_level: str):
    campaign = repository.create_campaign(
        program_id=None,
        name=f"{autonomy_level} research campaign",
        autonomy_level=autonomy_level,
        scope_status="in_scope",
        policy_text="Authorized local review only.",
        default_asset="local.example",
        allowed_tools=["static_analyzer"],
        created_by="operator",
        payload={
            "source_snapshot_digest": SNAPSHOT_DIGEST,
            "scope_guard_rule": {
                "asset": "local.example",
                "scope_status": "in_scope",
                "automation": "limited",
                "allowed_validation": ["static_analyzer"],
                "forbidden": [],
                "human_approval_required": False,
            },
        },
    )
    updated = repository.update_campaign_status(campaign.id, "running")
    assert updated is not None
    return updated


def test_level_one_campaign_runs_the_read_only_research_sequence_and_wakes():
    repository, session = _repository()
    try:
        level_zero = _running_campaign(
            repository,
            autonomy_level="level_0_read_only",
        )
        level_one = _running_campaign(
            repository,
            autonomy_level="level_1_local_validation",
        )

        selection = select_autonomous_research_work(
            campaign=level_one,
            repository=repository,
        )
        wakeup_ids = {
            item["id"] for item in repository.list_autonomous_wakeup_campaigns()
        }

        assert selection["status"] == "ready"
        assert selection["task_type"] == "campaign_observation"
        assert level_zero.id in wakeup_ids
        assert level_one.id in wakeup_ids
        assert selection["execution_allowed"] is False
        assert selection["validation_allowed"] is False

        repository.upsert_campaign_budget(
            campaign_id=level_one.id,
            time_budget_minutes=30,
            token_budget=1000,
            tool_call_budget=1,
            validation_budget=1,
        )
        repository.save_scanner_run(
            campaign_id=level_one.id,
            codebase_map_id=None,
            tool_name="semgrep_local",
            command_hash=f"sha256:{'d' * 64}",
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

        exhausted = select_autonomous_research_work(
            campaign=level_one,
            repository=repository,
        )
        assert exhausted["status"] == "ready"
        assert exhausted["task_type"] == "campaign_observation"
        assert exhausted["execution_allowed"] is False
        assert exhausted["validation_allowed"] is False
    finally:
        session.close()
