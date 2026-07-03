from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_session
from app.main import app


client = TestClient(app)


def override_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def _override_get_session():
        with testing_session() as session:
            yield session

    return _override_get_session


def test_mythos_pipeline_dry_run_returns_first_safe_chain():
    response = client.post(
        "/mythos/pipeline/dry-run",
        json={
            "asset": "api.example.com",
            "policy_text": "In scope: api.example.com. Automation limited. DoS is forbidden.",
            "openapi": {
                "paths": {
                    "/files/{file_id}/export": {
                        "get": {"operationId": "exportFile"},
                    }
                }
            },
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["scope_rule"]["scope_status"] == "in_scope"
    assert body["target_model"]["sensitive_actions"][0]["action"] == "export"
    assert body["invariants"][0]["rule_id"] == "private_file_access_control"
    assert body["hypotheses"][0]["validation_mode"] == "two_account_authorization_check"
    assert body["refutation"]["status"] == "blocked"
    assert body["validation_plan"]["status"] == "blocked"
    assert body["report_draft"]["human_review_required"] is True


def test_mythos_pipeline_dry_run_persists_artifact_run_without_plaintext_policy():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "artifact_kind": "postman",
                "artifact_payload": {
                    "item": [
                        {
                            "request": {
                                "method": "GET",
                                "url": "https://api.example.com/files/{file_id}/export",
                            }
                        }
                    ]
                },
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["run_id"].startswith("pipeline_run_")
        assert body["artifact_kind"] == "postman"
        assert body["target_model"]["sensitive_actions"][0]["action"] == "export"

        runs_response = client.get("/mythos/pipeline/runs")
        assert runs_response.status_code == 200
        runs = runs_response.json()
        assert len(runs) == 1
        assert runs[0]["id"] == body["run_id"]
        assert runs[0]["asset"] == "api.example.com"
        assert runs[0]["policy_text_hash"]
        assert runs[0]["hypothesis_count"] == len(body["hypotheses"])
        assert runs[0]["blocked_count"] == 1
        assert runs[0]["evidence_count"] == 1
        assert runs[0]["report_title"] == body["report_draft"]["title"]

        detail_response = client.get(f"/mythos/pipeline/runs/{body['run_id']}")
        assert detail_response.status_code == 200
        detail = detail_response.json()
        serialized_detail = str(detail)
        assert detail["payload"]["artifact_kind"] == "postman"
        assert "SECRET POLICY" not in serialized_detail
        assert "policy_text" not in detail["payload"]
    finally:
        app.dependency_overrides.clear()
