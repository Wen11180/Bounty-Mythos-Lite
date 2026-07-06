from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_session
from app.main import app
from app.repository import seed_sample_data


client = TestClient(app)


def override_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with testing_session() as session:
        seed_sample_data(session)

    def _override_get_session():
        with testing_session() as session:
            yield session

    return _override_get_session


def test_approval_records_api_creates_decides_and_lists_audit_records():
    app.dependency_overrides[get_session] = override_session()
    try:
        create_response = client.post(
            "/mythos/approval-records",
            json={
                "run_id": "pipeline_run_1",
                "program_id": "program_example",
                "asset": "api.example.com",
                "validation_mode": "two_account_authorization_check",
                "plan_digest": "plan_sha256_1",
                "requester": "lead_reviewer",
                "reason": "Need approval; Authorization: Bearer live-token.",
            },
        )

        assert create_response.status_code == 200
        created = create_response.json()
        assert created["id"].startswith("approval_")
        assert created["status"] == "requested"
        assert created["reason"] == "[REDACTED]"
        assert "live-token" not in str(created)

        decision_response = client.post(
            f"/mythos/approval-records/{created['id']}/decisions",
            json={
                "decision": "approved",
                "actor": "lead_reviewer",
                "reason": "Approved for test accounts only; cookie: live-cookie.",
            },
        )

        assert decision_response.status_code == 200
        decided = decision_response.json()
        assert decided["status"] == "approved"
        assert decided["decided_by"] == "lead_reviewer"
        assert decided["decision_reason"] == "[REDACTED]"
        assert "live-cookie" not in str(decided)

        list_response = client.get(
            "/mythos/approval-records",
            params={"run_id": "pipeline_run_1"},
        )

        assert list_response.status_code == 200
        assert [item["id"] for item in list_response.json()] == [created["id"]]
    finally:
        app.dependency_overrides.clear()


def test_canonical_approval_decision_api_reuses_durable_approval_records():
    app.dependency_overrides[get_session] = override_session()
    try:
        create_response = client.post(
            "/mythos/approval-records",
            json={
                "run_id": "pipeline_run_1",
                "program_id": "program_example",
                "asset": "api.example.com",
                "validation_mode": "two_account_authorization_check",
                "plan_digest": "plan_sha256_1",
                "requester": "lead_reviewer",
                "reason": "Need approval; Authorization: Bearer live-token.",
            },
        )
        assert create_response.status_code == 200
        approval_id = create_response.json()["id"]

        decision_response = client.post(
            f"/mythos/approvals/{approval_id}/decisions",
            json={
                "decision": "denied",
                "actor": "lead_reviewer",
                "reason": "Deny until cookie: live-cookie is removed.",
            },
        )

        assert decision_response.status_code == 200
        decided = decision_response.json()
        assert decided["id"] == approval_id
        assert decided["status"] == "denied"
        assert decided["decided_by"] == "lead_reviewer"
        assert decided["decision_reason"] == "[REDACTED]"
        assert "live-cookie" not in str(decided)
    finally:
        app.dependency_overrides.clear()


def test_approval_decision_api_rejects_approving_expired_record():
    app.dependency_overrides[get_session] = override_session()
    try:
        create_response = client.post(
            "/mythos/approval-records",
            json={
                "run_id": "pipeline_run_1",
                "program_id": "program_example",
                "asset": "api.example.com",
                "validation_mode": "two_account_authorization_check",
                "plan_digest": "plan_sha256_1",
                "expires_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
                "requester": "lead_reviewer",
                "reason": "Approval window already elapsed.",
            },
        )
        assert create_response.status_code == 200
        approval_id = create_response.json()["id"]

        decision_response = client.post(
            f"/mythos/approvals/{approval_id}/decisions",
            json={
                "decision": "approved",
                "actor": "lead_reviewer",
                "reason": "Trying to approve after expiry.",
            },
        )

        assert decision_response.status_code == 409
        assert decision_response.json()["detail"] == "Approval record expired"

        list_response = client.get(
            "/mythos/approval-records",
            params={"run_id": "pipeline_run_1"},
        )
        assert list_response.status_code == 200
        listed = next(item for item in list_response.json() if item["id"] == approval_id)
        assert listed["status"] == "requested"
        assert listed["decided_at"] is None
    finally:
        app.dependency_overrides.clear()


def test_approval_decision_api_rejects_reapproving_terminal_record():
    app.dependency_overrides[get_session] = override_session()
    try:
        create_response = client.post(
            "/mythos/approval-records",
            json={
                "run_id": "pipeline_run_1",
                "program_id": "program_example",
                "asset": "api.example.com",
                "validation_mode": "two_account_authorization_check",
                "plan_digest": "plan_sha256_1",
                "requester": "lead_reviewer",
                "reason": "Need approval for test-account validation.",
            },
        )
        assert create_response.status_code == 200
        approval_id = create_response.json()["id"]

        deny_response = client.post(
            f"/mythos/approvals/{approval_id}/decisions",
            json={
                "decision": "denied",
                "actor": "lead_reviewer",
                "reason": "Denied until scope evidence is clearer.",
            },
        )
        assert deny_response.status_code == 200

        approve_response = client.post(
            f"/mythos/approvals/{approval_id}/decisions",
            json={
                "decision": "approved",
                "actor": "lead_reviewer",
                "reason": "Trying to revive a terminal approval.",
            },
        )

        assert approve_response.status_code == 409
        assert approve_response.json()["detail"] == "Approval record already terminal"

        list_response = client.get(
            "/mythos/approval-records",
            params={"run_id": "pipeline_run_1"},
        )
        assert list_response.status_code == 200
        listed = next(item for item in list_response.json() if item["id"] == approval_id)
        assert listed["status"] == "denied"
        assert listed["decided_by"] == "lead_reviewer"
        assert listed["decision_reason"] == "Denied until scope evidence is clearer."
    finally:
        app.dependency_overrides.clear()
