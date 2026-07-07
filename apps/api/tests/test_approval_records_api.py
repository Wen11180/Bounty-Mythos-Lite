from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_session
from app.db_models import ProgramRecord
from app.main import app
from app.repository import DatabaseRepository, seed_sample_data


client = TestClient(app)


def override_session():
    testing_session, override_get_session = build_testing_session_override()
    return override_get_session


def build_testing_session_override():
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

    return testing_session, _override_get_session


def create_pipeline_run(testing_session) -> str:
    with testing_session() as session:
        repository = DatabaseRepository(session)
        run = repository.save_pipeline_run(
            program_id="program_example",
            asset="api.example.com",
            policy_text="Testing allowed.",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title="Approval test run",
            payload={"report_draft": {"title": "Approval test run"}},
        )
        return run.id


def test_approval_records_api_creates_decides_and_lists_audit_records():
    testing_session, override_get_session = build_testing_session_override()
    run_id = create_pipeline_run(testing_session)
    app.dependency_overrides[get_session] = override_get_session
    try:
        create_response = client.post(
            "/mythos/approval-records",
            json={
                "run_id": run_id,
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
            params={"run_id": run_id},
        )

        assert list_response.status_code == 200
        assert [item["id"] for item in list_response.json()] == [created["id"]]
    finally:
        app.dependency_overrides.clear()


def test_approval_records_api_blocks_creation_for_out_of_scope_program():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with testing_session() as session:
        seed_sample_data(session)
        program = session.get(ProgramRecord, "program_example")
        program.scope_status = "out_of_scope"
        session.add(program)
        session.commit()

    def _override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = _override_get_session
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
                "reason": "Should not queue approval outside current scope.",
            },
        )

        assert create_response.status_code == 409
        assert create_response.json()["detail"] == "scope_not_in_scope"

        with testing_session() as session:
            repository = DatabaseRepository(session)
            assert repository.list_approval_records(run_id="pipeline_run_1") == []
    finally:
        app.dependency_overrides.clear()


def test_approval_records_api_blocks_creation_for_out_of_scope_campaign_run():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with testing_session() as session:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        run = repository.save_pipeline_run(
            program_id="program_example",
            asset="api.example.com",
            policy_text="Testing allowed.",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title="Queued approval run",
            payload={"report_draft": {"title": "Queued approval run"}},
        )
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Out-of-scope approval run campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="out_of_scope",
            policy_text="Testing is currently out of scope.",
            default_asset="api.example.com",
            created_by="operator",
        )
        repository.save_pipeline_stage(
            pipeline_run_id=run.id,
            campaign_id=campaign.id,
            task_id=None,
            stage_key="campaign_report_preview",
            stage_order=0,
            status="preview_ready",
            input_refs=[f"pipeline_run:{run.id}"],
            output_refs=[],
            safety_gate_state="manual_review_required",
            stop_reason=None,
            payload={"raw_payload_processed": False},
        )
        run_id = run.id

    def _override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = _override_get_session
    try:
        create_response = client.post(
            "/mythos/approval-records",
            json={
                "run_id": run_id,
                "asset": "api.example.com",
                "validation_mode": "two_account_authorization_check",
                "plan_digest": "plan_sha256_1",
                "requester": "lead_reviewer",
                "reason": "Should not queue approval for an out-of-scope campaign run.",
            },
        )

        assert create_response.status_code == 409
        assert create_response.json()["detail"] == "scope_not_in_scope"

        with testing_session() as session:
            repository = DatabaseRepository(session)
            assert repository.list_approval_records(run_id=run_id) == []
    finally:
        app.dependency_overrides.clear()


def test_approval_records_api_blocks_creation_for_out_of_scope_pipeline_run():
    testing_session, override_get_session = build_testing_session_override()
    with testing_session() as session:
        repository = DatabaseRepository(session)
        run = repository.save_pipeline_run(
            program_id="program_example",
            asset="api.example.com",
            policy_text="Testing is no longer allowed.",
            scope_status="out_of_scope",
            hypothesis_count=1,
            blocked_count=1,
            report_title="Out of scope approval test run",
            payload={"report_draft": {"title": "Out of scope approval test run"}},
        )
        run_id = run.id

    app.dependency_overrides[get_session] = override_get_session
    try:
        create_response = client.post(
            "/mythos/approval-records",
            json={
                "run_id": run_id,
                "asset": "api.example.com",
                "validation_mode": "two_account_authorization_check",
                "plan_digest": "plan_sha256_1",
                "requester": "lead_reviewer",
                "reason": "Should not queue approval for an out-of-scope run.",
            },
        )

        assert create_response.status_code == 409
        assert create_response.json()["detail"] == "scope_not_in_scope"

        with testing_session() as session:
            repository = DatabaseRepository(session)
            assert repository.list_approval_records(run_id=run_id) == []
    finally:
        app.dependency_overrides.clear()


def test_canonical_approval_decision_api_reuses_durable_approval_records():
    testing_session, override_get_session = build_testing_session_override()
    run_id = create_pipeline_run(testing_session)
    app.dependency_overrides[get_session] = override_get_session
    try:
        create_response = client.post(
            "/mythos/approval-records",
            json={
                "run_id": run_id,
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
    testing_session, override_get_session = build_testing_session_override()
    run_id = create_pipeline_run(testing_session)
    app.dependency_overrides[get_session] = override_get_session
    try:
        create_response = client.post(
            "/mythos/approval-records",
            json={
                "run_id": run_id,
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
            params={"run_id": run_id},
        )
        assert list_response.status_code == 200
        listed = next(item for item in list_response.json() if item["id"] == approval_id)
        assert listed["status"] == "requested"
        assert listed["decided_at"] is None
    finally:
        app.dependency_overrides.clear()


def test_approval_decision_blocks_when_program_goes_out_of_scope_after_request():
    testing_session, override_get_session = build_testing_session_override()
    run_id = create_pipeline_run(testing_session)
    app.dependency_overrides[get_session] = override_get_session
    try:
        create_response = client.post(
            "/mythos/approval-records",
            json={
                "run_id": run_id,
                "program_id": "program_example",
                "asset": "api.example.com",
                "validation_mode": "two_account_authorization_check",
                "plan_digest": "plan_sha256_1",
                "requester": "lead_reviewer",
                "reason": "Need approval while scope is active.",
            },
        )
        assert create_response.status_code == 200
        approval_id = create_response.json()["id"]

        with testing_session() as session:
            program = session.get(ProgramRecord, "program_example")
            program.scope_status = "out_of_scope"
            session.add(program)
            session.commit()

        decision_response = client.post(
            f"/mythos/approvals/{approval_id}/decisions",
            json={
                "decision": "approved",
                "actor": "lead_reviewer",
                "reason": "Trying to approve after scope changed.",
            },
        )

        assert decision_response.status_code == 409
        assert decision_response.json()["detail"] == "scope_not_in_scope"

        list_response = client.get(
            "/mythos/approval-records",
            params={"run_id": run_id},
        )
        assert list_response.status_code == 200
        listed = next(item for item in list_response.json() if item["id"] == approval_id)
        assert listed["status"] == "requested"
        assert listed["decided_at"] is None
    finally:
        app.dependency_overrides.clear()


def test_approval_decision_api_rejects_reapproving_terminal_record():
    testing_session, override_get_session = build_testing_session_override()
    run_id = create_pipeline_run(testing_session)
    app.dependency_overrides[get_session] = override_get_session
    try:
        create_response = client.post(
            "/mythos/approval-records",
            json={
                "run_id": run_id,
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
            params={"run_id": run_id},
        )
        assert list_response.status_code == 200
        listed = next(item for item in list_response.json() if item["id"] == approval_id)
        assert listed["status"] == "denied"
        assert listed["decided_by"] == "lead_reviewer"
        assert listed["decision_reason"] == "Denied until scope evidence is clearer."
    finally:
        app.dependency_overrides.clear()
