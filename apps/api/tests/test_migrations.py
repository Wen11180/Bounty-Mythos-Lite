from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


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
    approval_columns = {
        column["name"]
        for column in inspector.get_columns("approval_records")
    }

    assert "target_relationships" in learning_columns
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
    } <= tables
