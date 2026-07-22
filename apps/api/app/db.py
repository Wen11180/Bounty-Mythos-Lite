from collections.abc import Iterator
from functools import lru_cache
from pathlib import Path
from weakref import WeakSet

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, inspect
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import get_settings


class Base(DeclarativeBase):
    pass


_initialized_engines: WeakSet[Engine] = WeakSet()


def _engine_kwargs(database_url: str) -> dict:
    if database_url.startswith("sqlite"):
        kwargs = {"connect_args": {"check_same_thread": False}}
        if database_url.endswith(":memory:"):
            kwargs["poolclass"] = StaticPool
        return kwargs
    return {}


@lru_cache
def get_engine() -> Engine:
    settings = get_settings()
    return create_engine(settings.database_url, **_engine_kwargs(settings.database_url))


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)


def create_tables(engine: Engine) -> None:
    import app.db_models  # noqa: F401

    Base.metadata.create_all(bind=engine)


def ensure_database_schema(engine: Engine) -> None:
    if engine.dialect.name == "sqlite" and engine.url.database in {None, "", ":memory:"}:
        create_tables(engine)
        return

    config = _alembic_config(engine)
    _adopt_supported_unversioned_schema(engine, config)
    command.upgrade(config, "head")


def initialize_database(engine: Engine | None = None) -> None:
    engine = engine or get_engine()
    if engine in _initialized_engines:
        return

    ensure_database_schema(engine)
    if engine.dialect.name == "sqlite":
        SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
        with SessionLocal() as session:
            from app.repository import seed_sample_data

            seed_sample_data(session)
    _initialized_engines.add(engine)


def _alembic_config(engine: Engine) -> Config:
    api_root = Path(__file__).resolve().parents[1]
    config = Config(str(api_root / "alembic.ini"))
    config.set_main_option("script_location", str(api_root / "migrations"))
    config.attributes["database_url_override"] = engine.url.render_as_string(
        hide_password=False
    )
    return config


def _adopt_supported_unversioned_schema(engine: Engine, config: Config) -> None:
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    if not tables or "alembic_version" in tables:
        return

    required_tables = {
        "approval_records",
        "artifacts",
        "learning_signals",
        "programs",
        "validation_runs",
    }
    learning_columns = {column["name"] for column in inspector.get_columns("learning_signals")}
    approval_columns = {column["name"] for column in inspector.get_columns("approval_records")}
    if (
        not required_tables.issubset(tables)
        or "identity_hash" not in learning_columns
        or "expires_at" not in approval_columns
    ):
        raise RuntimeError("database_schema_unversioned")

    unique_constraints = inspector.get_unique_constraints("artifacts")
    unique_columns = {tuple(constraint["column_names"]) for constraint in unique_constraints}
    program_rule_tables = {
        "program_rule_sources",
        "program_rule_snapshots",
        "program_scope_rules",
    }
    present_program_rule_tables = program_rule_tables & tables
    if program_rule_tables.issubset(tables):
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
        if (
            {"canonical_url", "claim_token_digest"}.issubset(source_columns)
            and {
                "normalized_sha256",
                "report_submission_allowed",
            }.issubset(snapshot_columns)
            and {"canonical_asset", "approval_digest"}.issubset(rule_columns)
            and {("canonical_url",), ("program_id",)}.issubset(source_unique)
            and ("source_id", "normalized_sha256") in snapshot_unique
            and ("approved_snapshot_id", "canonical_asset") in rule_unique
        ):
            wakeup_table = "autonomous_research_wakeup_states"
            if wakeup_table in tables:
                wakeup_columns = {
                    column["name"]
                    for column in inspector.get_columns(wakeup_table)
                }
                if not {
                    "after_campaign_id",
                    "lease_token_digest",
                    "lease_started_at",
                    "lease_expires_at",
                    "execution_allowed",
                    "validation_allowed",
                    "report_submission_allowed",
                }.issubset(wakeup_columns):
                    raise RuntimeError("database_schema_unversioned")
                campaign_task_columns = {
                    column["name"]
                    for column in inspector.get_columns("campaign_tasks")
                }
                if {
                    "execution_claim_id",
                    "execution_heartbeat_at",
                    "execution_lease_expires_at",
                }.issubset(campaign_task_columns):
                    wakeup_cycle_columns = {
                        "last_cycle_completed_at",
                        "last_cycle_status",
                        "last_cycle_stop_reason",
                        "last_cycle_processed_count",
                        "last_cycle_outcome_counts",
                    }
                    if not wakeup_cycle_columns.issubset(wakeup_columns):
                        revision = "0015_campaign_task_execution_lease"
                    elif "next_due_at" not in wakeup_columns:
                        revision = "0016_autonomous_research_wakeup_cycle_summary"
                    else:
                        revision = "0017_autonomous_research_wakeup_cadence"
                else:
                    revision = "0014_autonomous_research_wakeup"
            else:
                revision = "0013_program_rule_intake"
        else:
            raise RuntimeError("database_schema_unversioned")
    elif present_program_rule_tables:
        raise RuntimeError("database_schema_unversioned")
    elif (
        ("program_id", "source_hash") in unique_columns
        and "field_pilot_feedback" in learning_columns
    ):
        revision = "0012_field_pilot_feedback"
    elif ("program_id", "source_hash") in unique_columns:
        revision = "0011_artifact_program_scope"
    elif ("source_hash",) in unique_columns:
        revision = "0010_learning_signal_identity_hash"
    else:
        raise RuntimeError("database_schema_unversioned")
    command.stamp(config, revision)


def get_session() -> Iterator[Session]:
    initialize_database()
    with get_session_factory()() as session:
        yield session
