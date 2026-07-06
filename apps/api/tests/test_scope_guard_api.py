from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_session
from app.main import app
from app.repository import DatabaseRepository, seed_sample_data


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


def approved_validation_request(plan_digest: str = "plan_sha256_1") -> dict:
    return {
        "asset": "api.example.com",
        "validation_type": "two_account_authorization_check",
        "human_approved": True,
        "plan_digest": plan_digest,
    }


def validation_rule() -> dict:
    return {
        "asset": "api.example.com",
        "scope_status": "in_scope",
        "automation": "limited",
        "allowed_validation": ["two_account_authorization_check"],
        "forbidden": ["DoS"],
        "human_approval_required": True,
    }


def create_approved_record(*, asset: str, validation_mode: str, plan_digest: str) -> str:
    create_response = client.post(
        "/mythos/approval-records",
        json={
            "run_id": "pipeline_run_1",
            "program_id": "program_example",
            "asset": asset,
            "validation_mode": validation_mode,
            "plan_digest": plan_digest,
            "requester": "lead_reviewer",
            "reason": "Approve scoped validation.",
        },
    )
    assert create_response.status_code == 200
    approval_id = create_response.json()["id"]

    decision_response = client.post(
        f"/mythos/approval-records/{approval_id}/decisions",
        json={
            "decision": "approved",
            "actor": "lead_reviewer",
            "reason": "Approved for test accounts only.",
        },
    )
    assert decision_response.status_code == 200
    return approval_id


def test_scope_guard_api_ignores_caller_human_approved_without_durable_record():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/scope-guard/evaluate",
            json={
                "rule": validation_rule(),
                "request": approved_validation_request(),
            },
        )

        assert response.status_code == 200
        assert response.json() == {"allowed": False, "reason": "approval_record_required"}
    finally:
        app.dependency_overrides.clear()


def test_scope_guard_api_allows_validation_with_matching_durable_approval():
    app.dependency_overrides[get_session] = override_session()
    try:
        create_approved_record(
            asset="api.example.com",
            validation_mode="two_account_authorization_check",
            plan_digest="plan_sha256_1",
        )

        response = client.post(
            "/scope-guard/evaluate",
            json={
                "rule": validation_rule(),
                "request": approved_validation_request(),
            },
        )

        assert response.status_code == 200
        assert response.json() == {"allowed": True, "reason": "approved_validation_record"}
    finally:
        app.dependency_overrides.clear()


def test_scope_guard_api_blocks_mismatched_durable_approval_record():
    app.dependency_overrides[get_session] = override_session()
    try:
        create_approved_record(
            asset="api.example.com",
            validation_mode="two_account_authorization_check",
            plan_digest="different_plan",
        )

        response = client.post(
            "/scope-guard/evaluate",
            json={
                "rule": validation_rule(),
                "request": approved_validation_request(),
            },
        )

        assert response.status_code == 200
        assert response.json() == {"allowed": False, "reason": "approval_record_required"}
    finally:
        app.dependency_overrides.clear()


def test_scope_guard_api_rejects_cross_campaign_approval_when_bound():
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
        source_campaign = repository.create_campaign(
            program_id="program_example",
            name="Source approval campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        target_campaign = repository.create_campaign(
            program_id="program_example",
            name="Target approval campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        source_task = repository.create_campaign_task(
            campaign_id=source_campaign.id,
            task_type="report_chain_review",
            agent_type="report_agent",
            title="Review source validation",
            input_refs=[f"campaign:{source_campaign.id}"],
        )
        approval = repository.create_approval_record(
            campaign_id=source_campaign.id,
            task_id=source_task.id,
            program_id=source_campaign.program_id,
            approval_type="validation_batch",
            actor="operator",
            reason="Approve source campaign only.",
            requested_action="two_account_authorization_check",
            asset="api.example.com",
            validation_mode="two_account_authorization_check",
            plan_digest="shared_plan_digest",
            autonomy_level=source_campaign.autonomy_level,
            safety_gate_state="awaiting_approval",
        )
        repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Approved for source campaign only.",
        )
        target_campaign_id = target_campaign.id

    def _override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = _override_get_session
    try:
        response = client.post(
            "/scope-guard/evaluate",
            json={
                "campaign_id": target_campaign_id,
                "rule": validation_rule(),
                "request": approved_validation_request(plan_digest="shared_plan_digest"),
            },
        )

        assert response.status_code == 200
        assert response.json() == {"allowed": False, "reason": "approval_record_required"}
    finally:
        app.dependency_overrides.clear()


def test_scope_guard_api_blocks_unlisted_validation_even_with_durable_approval():
    app.dependency_overrides[get_session] = override_session()
    try:
        create_approved_record(
            asset="api.example.com",
            validation_mode="unsafe_live_probe",
            plan_digest="plan_sha256_1",
        )

        response = client.post(
            "/scope-guard/evaluate",
            json={
                "rule": validation_rule(),
                "request": {
                    **approved_validation_request(),
                    "validation_type": "unsafe_live_probe",
                },
            },
        )

        assert response.status_code == 200
        assert response.json() == {"allowed": False, "reason": "validation_not_allowed"}
    finally:
        app.dependency_overrides.clear()


def test_scope_guard_api_blocks_forbidden_validation():
    response = client.post(
        "/scope-guard/evaluate",
        json={
            "rule": {
                "asset": "api.example.com",
                "scope_status": "in_scope",
                "automation": "limited",
                "allowed_validation": ["two_account_authorization_check"],
                "forbidden": ["DoS"],
                "human_approval_required": False,
            },
            "request": {
                "asset": "api.example.com",
                "validation_type": "DoS",
                "human_approved": False,
            },
        },
    )

    assert response.status_code == 200
    assert response.json() == {"allowed": False, "reason": "forbidden_validation"}
