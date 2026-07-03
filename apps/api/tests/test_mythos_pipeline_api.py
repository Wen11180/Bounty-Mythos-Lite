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


def test_mythos_pipeline_dry_run_links_artifact_and_validation_gate():
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
                                "header": [{"key": "Authorization", "value": "Bearer live-token"}],
                            }
                        }
                    ]
                },
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["artifact"]["artifact_id"].startswith("artifact_")
        assert body["artifact"]["kind"] == "postman"
        assert body["artifact"]["source_type"] == "dry_run_inline"
        assert body["artifact"]["evidence_count"] == 1
        assert body["validation_gate"]["status"] == "awaiting_approval"
        assert body["validation_gate"]["approval_required"] is True
        assert body["validation_workspace"]["allowed_to_execute"] is False
        assert body["validation_workspace"]["test_accounts_only"] is True
        assert body["validation_workspace"]["no_real_user_data"] is True
        assert body["validation_workspace"]["non_destructive_only"] is True

        runs_response = client.get("/mythos/pipeline/runs")
        assert runs_response.status_code == 200
        run = runs_response.json()[0]
        assert run["artifact"]["artifact_id"] == body["artifact"]["artifact_id"]
        assert run["validation_gate"]["status"] == "awaiting_approval"
        assert run["timeline"][0]["name"] == "policy_ingestion"

        artifacts_response = client.get("/mythos/artifacts")
        assert artifacts_response.status_code == 200
        artifact = artifacts_response.json()[0]
        serialized_artifact = str(artifact)
        assert artifact["id"] == body["artifact"]["artifact_id"]
        assert artifact["payload_summary"]["path_count"] == 1
        assert "live-token" not in serialized_artifact
        assert "SECRET POLICY" not in serialized_artifact

        artifact_detail_response = client.get(f"/mythos/artifacts/{body['artifact']['artifact_id']}")
        assert artifact_detail_response.status_code == 200
        assert artifact_detail_response.json()["source_hash"] == artifact["source_hash"]
    finally:
        app.dependency_overrides.clear()
