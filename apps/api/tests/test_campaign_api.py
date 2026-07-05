from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_session
from app.main import app
from app.repository import seed_sample_data


client = TestClient(app)


def build_testing_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine)
    with testing_session() as session:
        seed_sample_data(session)
    return testing_session


def test_campaign_api_creates_lists_and_controls_campaign_lifecycle():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        create_response = client.post(
            "/mythos/campaigns",
            json={
                "program_id": "program_example",
                "name": "Authorized autonomous research",
                "autonomy_level": "level_1_local_validation",
                "scope_status": "in_scope",
                "policy_text": "Testing allowed. Authorization: Bearer secret-token",
                "default_asset": "api.example.com",
                "target_classes": ["idor"],
                "allowed_tools": ["static_analyzer"],
                "created_by": "operator@example.com",
                "budget": {
                    "time_budget_minutes": 60,
                    "token_budget": 10000,
                    "tool_call_budget": 50,
                    "validation_budget": 3,
                },
            },
        )
        assert create_response.status_code == 200
        created = create_response.json()
        assert created["id"].startswith("campaign_")
        assert created["status"] == "draft"
        assert created["policy_text_hash"]
        assert "policy_text" not in created
        assert created["budget"]["status"] == "active"

        list_response = client.get("/mythos/campaigns")
        assert list_response.status_code == 200
        assert list_response.json()[0]["id"] == created["id"]

        start_response = client.post(f"/mythos/campaigns/{created['id']}/start")
        assert start_response.status_code == 200
        assert start_response.json()["status"] == "running"

        pause_response = client.post(f"/mythos/campaigns/{created['id']}/pause")
        assert pause_response.status_code == 200
        assert pause_response.json()["status"] == "paused"

        resume_response = client.post(f"/mythos/campaigns/{created['id']}/resume")
        assert resume_response.status_code == 200
        assert resume_response.json()["status"] == "running"
    finally:
        app.dependency_overrides.clear()


def test_campaign_api_rejects_missing_program():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        response = client.post(
            "/mythos/campaigns",
            json={
                "program_id": "missing",
                "name": "Invalid campaign",
                "autonomy_level": "level_0_read_only",
                "scope_status": "in_scope",
                "policy_text": "Testing allowed",
                "default_asset": "api.example.com",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 404
    assert response.json()["detail"] == "Program not found"
