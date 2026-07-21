from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from app.db import initialize_database


PROGRAM_RULE_TABLES = {
    "program_rule_sources",
    "program_rule_snapshots",
    "program_scope_rules",
}
WAKEUP_TABLES = {"autonomous_research_wakeup_states"}


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
        "lease_started_at",
        "lease_expires_at",
        "execution_allowed",
        "validation_allowed",
        "report_submission_allowed",
    } <= wakeup_columns

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
    assert {("canonical_url",), ("program_id",)} <= source_unique
    assert ("source_id", "normalized_sha256") in snapshot_unique
    assert ("approved_snapshot_id", "canonical_asset") in rule_unique

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
    new_tables = PROGRAM_RULE_TABLES | WAKEUP_TABLES
    assert new_tables <= tables_before
    assert new_tables.isdisjoint(tables_after)
    assert tables_after == tables_before - new_tables
    assert version == "0012_field_pilot_feedback"
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
    assert version == "0014_autonomous_research_wakeup"
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
    assert version == "0014_autonomous_research_wakeup"
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
    assert version == "0014_autonomous_research_wakeup"
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
    assert version == "0014_autonomous_research_wakeup"
    assert PROGRAM_RULE_TABLES <= set(inspect(engine).get_table_names())
    assert WAKEUP_TABLES <= set(inspect(engine).get_table_names())
    engine.dispose()
