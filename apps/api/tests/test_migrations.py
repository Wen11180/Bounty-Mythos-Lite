from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from app.db import initialize_database


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
    } <= tables


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
    assert version == "0012_field_pilot_feedback"
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
    assert version == "0012_field_pilot_feedback"
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
    command.upgrade(config, "head")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("drop table alembic_version"))

    initialize_database(engine)

    with engine.connect() as connection:
        version = connection.execute(text("select version_num from alembic_version")).scalar_one()
    assert version == "0012_field_pilot_feedback"
    assert "field_pilot_feedback" in {
        column["name"] for column in inspect(engine).get_columns("learning_signals")
    }
    engine.dispose()
