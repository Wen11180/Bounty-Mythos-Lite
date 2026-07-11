from fastapi.testclient import TestClient

from app.db import Base, get_session
from app.main import app
from app.repository import seed_sample_data
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


client = TestClient(app)


def empty_testing_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)


def test_health_returns_ok():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "bounty-mythos-api"}


def test_programs_endpoint_returns_sample_programs():
    response = client.get("/programs")

    assert response.status_code == 200
    programs = response.json()
    assert programs[0]["name"] == "Example Program"
    assert programs[0]["scope_status"] == "in_scope"


def test_findings_endpoint_exposes_safety_state():
    response = client.get("/findings")

    assert response.status_code == 200
    finding = response.json()[0]
    assert finding["validation_status"] == "safely_validated"
    assert finding["submission_recommendation"] == "human_review_required"


def test_reports_endpoint_returns_report_draft():
    response = client.get("/reports")

    assert response.status_code == 200
    report = response.json()[0]
    assert report["finding_id"] == "finding_2026_001"
    assert "误报排除" in report["draft"]


def test_programs_endpoint_uses_database_session_dependency():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine)

    with testing_session() as session:
        seed_sample_data(session)

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        response = client.get("/programs")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()[0]["id"] == "program_example"


def test_programs_endpoint_creates_first_program_in_empty_database():
    testing_session = empty_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        response = client.post(
            "/programs",
            json={
                "id": "program_acme",
                "name": "Acme Bug Bounty",
                "platform": "HackerOne",
                "bounty_range": "See program policy",
                "scope_status": "needs_review",
                "automation": "needs_review",
                "testing_accounts": "not_configured",
                "api_docs": "imported",
                "public_code": "available",
                "duplicate_risk": "unknown",
                "priority": "A",
            },
        )
        listed = client.get("/programs")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 201
    assert response.json()["id"] == "program_acme"
    assert listed.json() == [response.json()]


def test_programs_endpoint_rejects_duplicate_program_id():
    testing_session = empty_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    payload = {
        "id": "program_acme",
        "name": "Acme Bug Bounty",
        "platform": "HackerOne",
        "bounty_range": "See program policy",
        "scope_status": "needs_review",
        "automation": "needs_review",
        "testing_accounts": "not_configured",
        "api_docs": "imported",
        "public_code": "available",
        "duplicate_risk": "unknown",
        "priority": "A",
    }
    app.dependency_overrides[get_session] = override_get_session
    try:
        assert client.post("/programs", json=payload).status_code == 201
        duplicate = client.post("/programs", json=payload)
    finally:
        app.dependency_overrides.clear()

    assert duplicate.status_code == 409
    assert duplicate.json() == {"detail": "Program already exists"}
