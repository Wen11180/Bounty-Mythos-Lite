from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main
from app.db import Base, get_session
from app.repository import DatabaseRepository


client = TestClient(main.app)


def _lease_preview_payload(**updates):
    payload = {
        "active_origin": "http://127.0.0.1:43110",
        "sessions": [
            {
                "session_alias": "session_a",
                "account_alias": "account_a",
                "role_alias": "member",
                "ready": True,
            },
            {
                "session_alias": "session_b",
                "account_alias": "account_b",
                "role_alias": "member",
                "ready": True,
            },
        ],
        "workflows": [
            {
                "workflow_alias": "read_widget_a",
                "session_alias": "session_a",
                "origin": "http://127.0.0.1:43110",
                "route_template": "/widgets/{object}",
                "method": "GET",
                "action": "read_only_replay",
                "object_aliases": ["widget_a"],
            }
        ],
    }
    payload.update(updates)
    return payload


def test_studio_black_box_lab_lease_preview_is_local_review_only():
    request = main.StudioBlackBoxLabLeasePreviewRequest(
        **_lease_preview_payload()
    )

    preview = main.build_studio_black_box_lab_lease_preview(request)

    assert preview.model_dump(mode="json") == {
        "profile": "local_lab",
        "active_origin": "http://127.0.0.1:43110",
        "session_aliases": ["session_a", "session_b"],
        "workflow_aliases": ["read_widget_a"],
        "sessions_ready": True,
        "trace_review_required": True,
        "human_approval_required": True,
        "execution_allowed": False,
        "persist_session_state": False,
        "blocked_actions": [
            "remote_origin",
            "credential_input",
            "session_persistence",
            "automatic_report_submission",
        ],
    }


def test_studio_black_box_lab_lease_preview_endpoint_returns_no_execution_grant():
    response = client.post(
        "/mythos/studio/black-box-lab/leases/preview",
        json=_lease_preview_payload(),
    )

    assert response.status_code == 200
    assert response.json()["profile"] == "local_lab"
    assert response.json()["execution_allowed"] is False
    assert response.json()["persist_session_state"] is False


def test_studio_black_box_lab_lease_preview_rejects_remote_or_credential_input():
    with pytest.raises(ValidationError, match="loopback_origin_required"):
        main.StudioBlackBoxLabLeasePreviewRequest(
            **_lease_preview_payload(active_origin="https://api.example.test")
        )

    with pytest.raises(ValidationError):
        main.StudioBlackBoxLabLeasePreviewRequest(
            **(_lease_preview_payload() | {"credential": "synthetic-value"})
        )


def test_studio_black_box_lab_rejects_concrete_routes_and_uppercase_fingerprints():
    concrete_workflow = _lease_preview_payload()["workflows"][0] | {
        "route_template": "/widgets/concrete-123"
    }
    with pytest.raises(ValidationError, match="normalized_route_template_required"):
        main.StudioBlackBoxLabLeasePreviewRequest(
            **(_lease_preview_payload() | {"workflows": [concrete_workflow]})
        )

    with pytest.raises(ValidationError, match="safe_trace_fingerprint_required"):
        main.StudioBlackBoxLabTraceReviewRequest(
            workflow_alias="read_widget_a",
            session_alias="session_a",
            route_template="/widgets/{object}",
            response_schema_fingerprint=f"sha256:{'A' * 64}",
            redacted=True,
        )


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("sessions", [], "exactly_two_lab_sessions_required"),
        ("workflows", [], "one_to_three_lab_workflows_required"),
        (
            "workflows",
            _lease_preview_payload()["workflows"] * 4,
            "one_to_three_lab_workflows_required",
        ),
    ],
)
def test_studio_black_box_lab_lease_preview_enforces_bounded_shape(
    field,
    value,
    reason,
):
    with pytest.raises(ValidationError, match=reason):
        main.StudioBlackBoxLabLeasePreviewRequest(
            **(_lease_preview_payload() | {field: value})
        )


@pytest.fixture
def approved_lab_validation_run():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    with testing_session() as session:
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id=None,
            name="Local black-box lab",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Authorized loopback differential validation only.",
            default_asset="127.0.0.1:43110",
            target_classes=["local_lab"],
            allowed_tools=["black_box_differential"],
            created_by="operator",
        )
        plan_digest = "plan_sha256_local_lab"
        approval = repository.create_approval_record(
            campaign_id=campaign.id,
            task_id=None,
            approval_type="validation_batch",
            actor="operator",
            reason="Approve one bounded local-lab run.",
            asset=campaign.default_asset,
            validation_mode="black_box_differential",
            plan_digest=plan_digest,
            autonomy_level=campaign.autonomy_level,
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
            payload={"allowed_accounts": ["account_a", "account_b"]},
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=None,
            approval_id=approval.id,
            validation_mode="black_box_differential",
            target_ref=f"campaign:{campaign.id}",
            status="awaiting_approval",
            safety_gate_state="awaiting_approval",
            plan_digest=plan_digest,
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Awaiting local-lab approval.",
            payload={"allowed_accounts": ["account_a", "account_b"]},
        )
        assert repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="operator",
            reason="Local lab reviewed.",
        ) is not None
        assert repository.record_validation_run_preflight(
            validation_run.id,
            allowed=True,
            reason="approved_validation_record",
        ) is not None
        validation_run_id = validation_run.id
        approval_id = approval.id

    def _override_get_session():
        with testing_session() as session:
            yield session

    main.app.dependency_overrides[get_session] = _override_get_session
    try:
        yield validation_run_id, approval_id
    finally:
        main.app.dependency_overrides.pop(get_session, None)
        engine.dispose()


def _run_approval_payload(validation_run_id: str, **updates):
    payload = {
        "validation_run_id": validation_run_id,
        "lease_preview": _lease_preview_payload(),
        "trace_review": [
            {
                "workflow_alias": "read_widget_a",
                "session_alias": "session_a",
                "route_template": "/widgets/{object}",
                "response_schema_fingerprint": f"sha256:{'a' * 64}",
                "redacted": True,
            }
        ],
        "operator_confirmed": True,
    }
    payload.update(updates)
    return payload


def test_studio_black_box_lab_run_approval_binds_durable_preflight(
    approved_lab_validation_run,
):
    validation_run_id, approval_id = approved_lab_validation_run

    response = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=_run_approval_payload(validation_run_id),
    )

    assert response.status_code == 200
    assert response.json() == {
        "approval_status": "approved",
        "validation_run_id": validation_run_id,
        "approval_id": approval_id,
        "lease_digest": response.json()["lease_digest"],
        "local_runner_dispatch_allowed": True,
        "execution_allowed": False,
        "report_submission_allowed": False,
        "reason": "bounded_local_lab_run_approved",
    }
    assert response.json()["lease_digest"].startswith("sha256:")


def test_studio_black_box_lab_run_approval_requires_operator_confirmation(
    approved_lab_validation_run,
):
    validation_run_id, _ = approved_lab_validation_run

    response = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=_run_approval_payload(validation_run_id, operator_confirmed=False),
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "operator_confirmation_required"}


def test_studio_black_box_lab_run_approval_requires_matching_redacted_trace(
    approved_lab_validation_run,
):
    validation_run_id, _ = approved_lab_validation_run
    mismatched_trace = _run_approval_payload(validation_run_id)["trace_review"]
    mismatched_trace[0]["workflow_alias"] = "different_workflow"

    response = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=_run_approval_payload(
            validation_run_id,
            trace_review=mismatched_trace,
        ),
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "reviewed_trace_set_required"}
