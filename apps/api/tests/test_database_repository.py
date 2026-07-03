from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.repository import DatabaseRepository, seed_sample_data


def build_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)(), engine


def test_database_schema_includes_core_tables():
    session, engine = build_session()
    try:
        tables = set(inspect(engine).get_table_names())
    finally:
        session.close()

    assert {"programs", "findings", "reports", "llm_runs"} <= tables


def test_repository_reads_seeded_programs_findings_and_reports():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)

        programs = repository.list_programs()
        findings = repository.list_findings()
        reports = repository.list_reports()

        assert programs[0].name == "Example Program"
        assert findings[0].id == "finding_2026_001"
        assert findings[0].evidence_refs == ["evidence/request-user-a-to-user-b-metadata.json"]
        assert reports[0].finding_id == "finding_2026_001"
    finally:
        session.close()
