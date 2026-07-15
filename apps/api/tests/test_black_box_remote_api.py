from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main
from app.db import Base, get_session
from app.db_models import ApprovalRecord, CampaignRecord, ValidationRunRecord
from app.repository import DatabaseRepository


client = TestClient(main.app)


def _lease_request_payload(validation_run_id="validation_pending", **updates):
    payload = {
        "validation_run_id": validation_run_id,
        "active_origin": "https://api.example.test",
        "passive_origins": ["https://static.example.test"],
        "account_aliases": ["account_a", "account_b"],
        "role_aliases": ["member"],
        "allowed_actions": ["read_only_replay"],
        "request_budget_per_workflow": 2,
        "duration_seconds": 300,
        "min_interval_seconds": 3,
        "workflows": [
            {
                "workflow_index": 1,
                "workflow_alias": "read_widget_a",
                "source_account_alias": "account_a",
                "source_role_alias": "member",
                "origin": "https://api.example.test",
                "route_template": "/v1/widgets/{object}",
                "method": "GET",
                "action": "read_only_replay",
                "object_alias": "widget_a",
                "object_owner_alias": "account_a",
                "object_state": "active",
                "object_reversible": True,
                "rollback_ready": True,
                "allowed_trial_classes": ["cross_account_object_swap"],
            }
        ],
        "operator_confirmed": True,
    }
    payload.update(updates)
    return payload


def _authorize_payload(**updates):
    payload = {
        "workflow_alias": "read_widget_a",
        "trial_class": "cross_account_object_swap",
        "target_account_alias": "account_b",
        "target_role_alias": "member",
        "object_alias": "widget_a",
        "session_generation": "session_generation_a",
    }
    payload.update(updates)
    return payload


def test_remote_profile_is_default_disabled_and_returns_only_safe_status():
    response = client.get("/mythos/studio/black-box-remote/status")

    assert response.status_code == 200, response.json()
    assert response.json() == {
        "profile": "remote_human_lease",
        "enabled": False,
        "state": "disabled",
        "expires_at": None,
        "relogin_required": True,
        "stop_reason": "remote_profile_disabled",
        "report_submission_allowed": False,
        "human_confirmation_allowed": False,
    }
    serialized = response.text.lower()
    assert not any(marker in serialized for marker in ("cookie", "authorization", "password", "token"))

    issue = client.post(
        "/mythos/studio/black-box-remote/leases",
        json=_lease_request_payload(),
    )
    assert issue.status_code == 409
    assert issue.json() == {"detail": "remote_human_lease_profile_disabled"}


@pytest.fixture
def remote_api_context(monkeypatch):
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    clock = [datetime.now(UTC)]

    with testing_session() as session:
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id=None,
            name="Remote black-box profile",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="api.example.test is in scope. Limited black-box differential validation is allowed.",
            default_asset="api.example.test",
            target_classes=["remote_web_api"],
            allowed_tools=["black_box_differential"],
            created_by="operator",
            payload={
                "scope_guard_rule": {
                    "asset": "api.example.test",
                    "scope_status": "in_scope",
                    "automation": "limited",
                    "allowed_validation": ["black_box_differential"],
                    "forbidden": [],
                    "human_approval_required": True,
                }
            },
        )
        request = main.StudioBlackBoxRemoteLeaseIssueRequest(
            **_lease_request_payload()
        )
        policy_digest = main._studio_black_box_remote_policy_digest(campaign)
        scope_digest = main._studio_black_box_remote_scope_digest(campaign)
        plan_digest = main._studio_black_box_remote_plan_digest(request)
        authority_payload = {
            "remote_human_lease": True,
            "policy_digest": policy_digest,
            "scope_digest": scope_digest,
            "allowed_accounts": ["account_a", "account_b"],
            "allowed_actions": ["read_only_replay"],
            "recorded_workflow_plan_digest": plan_digest,
        }
        approval = repository.create_approval_record(
            campaign_id=campaign.id,
            task_id=None,
            approval_type="black_box_remote_lease",
            actor="operator",
            reason="Approve one remote human-lease run.",
            requested_action="remote_black_box_differential",
            asset=campaign.default_asset,
            validation_mode="black_box_differential",
            plan_digest=plan_digest,
            autonomy_level=campaign.autonomy_level,
            expires_at=clock[0] + timedelta(minutes=20),
            payload=authority_payload,
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
            summary="Awaiting remote human approval.",
            payload=authority_payload,
        )
        assert repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="operator",
            reason="Remote lease reviewed now.",
        ) is not None
        assert repository.record_validation_run_preflight(
            validation_run.id,
            allowed=True,
            reason="approved_validation_record",
        ) is not None
        clock[0] = datetime.now(UTC)
        validation_run_id = validation_run.id
        approval_id = approval.id
        campaign_id = campaign.id

    def _override_get_session():
        with testing_session() as session:
            yield session

    main.app.dependency_overrides[get_session] = _override_get_session
    monkeypatch.setattr(
        main,
        "get_settings",
        lambda: SimpleNamespace(black_box_remote_profile_enabled=True),
    )
    monkeypatch.setattr(main, "_studio_black_box_remote_now", lambda: clock[0])
    main._studio_black_box_remote_reset_for_tests()
    try:
        yield SimpleNamespace(
            approval_id=approval_id,
            campaign_id=campaign_id,
            clock=clock,
            request=_lease_request_payload(validation_run_id),
            testing_session=testing_session,
            validation_run_id=validation_run_id,
        )
    finally:
        main._studio_black_box_remote_reset_for_tests()
        main.app.dependency_overrides.pop(get_session, None)
        engine.dispose()


def test_remote_lease_issue_requires_dedicated_current_authority_and_persists_summary_only(
    remote_api_context,
):
    response = client.post(
        "/mythos/studio/black-box-remote/leases",
        json=remote_api_context.request,
    )

    assert response.status_code == 200, response.json()
    body = response.json()
    assert body["profile"] == "remote_human_lease"
    assert body["lease_digest"].startswith("sha256:")
    assert body["lease"]["active_origins"] == ["https://api.example.test"]
    assert body["lease"]["request_budget_per_workflow"] == 2
    assert body["remote_runner_dispatch_allowed"] is True
    assert body["report_submission_allowed"] is False
    assert body["human_confirmation_allowed"] is False
    assert body["relogin_required"] is False
    serialized = response.text.lower()
    assert not any(marker in serialized for marker in ("cookie", "authorization", "password", "token"))

    with remote_api_context.testing_session() as session:
        record = session.get(ValidationRunRecord, remote_api_context.validation_run_id)
        summary = record.payload["remote_human_lease_summary"]
        assert summary == {
            "profile": "remote_human_lease",
            "lease_digest": body["lease_digest"],
            "approval_id": remote_api_context.approval_id,
            "issued_at": body["lease"]["issued_at"],
            "expires_at": body["lease"]["expires_at"],
        }
        assert "lease" not in summary
        assert "workflows" not in summary

    duplicate = client.post(
        "/mythos/studio/black-box-remote/leases",
        json=remote_api_context.request,
    )
    assert duplicate.status_code == 409
    assert duplicate.json() == {"detail": "single_run_remote_lease_already_issued"}


def test_remote_lease_issue_is_single_run_under_concurrent_requests(
    remote_api_context,
    monkeypatch,
):
    barrier = Barrier(2)
    original = main.get_settings

    def synchronized_settings():
        result = original()
        barrier.wait(timeout=5)
        return result

    monkeypatch.setattr(main, "get_settings", synchronized_settings)
    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(
            executor.map(
                lambda _: client.post(
                    "/mythos/studio/black-box-remote/leases",
                    json=remote_api_context.request,
                ),
                range(2),
            )
        )

    assert sorted(response.status_code for response in responses) == [200, 409]
    rejected = next(response for response in responses if response.status_code == 409)
    assert rejected.json() == {"detail": "single_run_remote_lease_already_issued"}


def test_remote_lease_issue_rejects_non_dedicated_or_stale_approval(remote_api_context):
    with remote_api_context.testing_session() as session:
        approval = session.get(ApprovalRecord, remote_api_context.approval_id)
        approval.approval_type = "validation_batch"
        session.add(approval)
        session.commit()

    response = client.post(
        "/mythos/studio/black-box-remote/leases",
        json=remote_api_context.request,
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "fresh_dedicated_remote_approval_required"}


def test_remote_request_rechecks_current_policy_scope_and_never_retries(remote_api_context):
    issued = client.post(
        "/mythos/studio/black-box-remote/leases",
        json=remote_api_context.request,
    ).json()

    with remote_api_context.testing_session() as session:
        campaign = session.get(CampaignRecord, remote_api_context.campaign_id)
        campaign.policy_text_hash = "d" * 64
        session.add(campaign)
        session.commit()

    first = client.post(
        f"/mythos/studio/black-box-remote/leases/{issued['lease_digest']}/authorize",
        json=_authorize_payload(),
    )
    second = client.post(
        f"/mythos/studio/black-box-remote/leases/{issued['lease_digest']}/authorize",
        json=_authorize_payload(),
    )

    assert first.status_code == 200
    assert first.json()["allowed"] is False
    assert first.json()["reason"] == "policy_or_scope_changed"
    assert first.json()["request_grant_id"] is None
    assert second.json()["reason"] == "policy_or_scope_changed"


def test_remote_request_rechecks_approval_and_status_exposes_relogin_only(remote_api_context):
    issued = client.post(
        "/mythos/studio/black-box-remote/leases",
        json=remote_api_context.request,
    ).json()

    with remote_api_context.testing_session() as session:
        approval = session.get(ApprovalRecord, remote_api_context.approval_id)
        approval.status = "revoked"
        session.add(approval)
        session.commit()

    decision = client.post(
        f"/mythos/studio/black-box-remote/leases/{issued['lease_digest']}/authorize",
        json=_authorize_payload(),
    )
    status = client.get(
        f"/mythos/studio/black-box-remote/leases/{issued['lease_digest']}/status"
    )

    assert decision.status_code == 200
    assert decision.json()["reason"] == "approval_preflight_changed"
    assert status.status_code == 200
    assert status.json()["state"] == "stopped"
    assert status.json()["relogin_required"] is True
    assert status.json()["stop_reason"] == "approval_preflight_changed"
    assert "approval_id" not in status.json()
    assert "lease" not in status.json()


def test_remote_status_expires_without_exposing_runtime_state(remote_api_context):
    issued = client.post(
        "/mythos/studio/black-box-remote/leases",
        json=remote_api_context.request,
    ).json()
    remote_api_context.clock[0] += timedelta(minutes=31)

    status = client.get(
        f"/mythos/studio/black-box-remote/leases/{issued['lease_digest']}/status"
    )

    assert status.status_code == 200
    assert status.json()["state"] == "expired"
    assert status.json()["relogin_required"] is True
    assert status.json()["report_submission_allowed"] is False
    assert status.json()["human_confirmation_allowed"] is False


def test_remote_global_status_tracks_active_and_expired_lease(remote_api_context):
    issued = client.post(
        "/mythos/studio/black-box-remote/leases",
        json=remote_api_context.request,
    ).json()

    active = client.get("/mythos/studio/black-box-remote/status")
    remote_api_context.clock[0] += timedelta(minutes=31)
    expired = client.get("/mythos/studio/black-box-remote/status")

    assert active.json() == {
        "profile": "remote_human_lease",
        "enabled": True,
        "state": "active",
        "expires_at": issued["lease"]["expires_at"],
        "relogin_required": False,
        "stop_reason": None,
        "report_submission_allowed": False,
        "human_confirmation_allowed": False,
    }
    assert expired.json()["state"] == "expired"
    assert expired.json()["relogin_required"] is True


def test_remote_request_grant_completes_without_exposing_capability(remote_api_context):
    issued = client.post(
        "/mythos/studio/black-box-remote/leases",
        json=remote_api_context.request,
    ).json()
    authorized = client.post(
        f"/mythos/studio/black-box-remote/leases/{issued['lease_digest']}/authorize",
        json=_authorize_payload(),
    )

    assert authorized.status_code == 200
    assert authorized.json()["allowed"] is True
    grant_id = authorized.json()["request_grant_id"]
    assert grant_id.startswith("remote_grant_")
    completed = client.post(
        f"/mythos/studio/black-box-remote/leases/{issued['lease_digest']}/complete",
        json={"request_grant_id": grant_id, "outcome": "success"},
    )

    assert completed.status_code == 200
    assert completed.json() == {
        "allowed": True,
        "reason": "remote_request_completed",
        "request_grant_id": None,
        "stop": None,
        "report_submission_allowed": False,
        "human_confirmation_allowed": False,
    }


def test_remote_terminal_completion_clears_execution_and_persists_safe_stop_only(
    remote_api_context,
):
    issued = client.post(
        "/mythos/studio/black-box-remote/leases",
        json=remote_api_context.request,
    ).json()
    authorized = client.post(
        f"/mythos/studio/black-box-remote/leases/{issued['lease_digest']}/authorize",
        json=_authorize_payload(),
    ).json()

    stopped = client.post(
        f"/mythos/studio/black-box-remote/leases/{issued['lease_digest']}/complete",
        json={
            "request_grant_id": authorized["request_grant_id"],
            "outcome": "rate_limited",
        },
    )
    retried = client.post(
        f"/mythos/studio/black-box-remote/leases/{issued['lease_digest']}/authorize",
        json=_authorize_payload(),
    )

    assert stopped.status_code == 200
    assert stopped.json()["reason"] == "rate_limited"
    assert retried.json()["reason"] == "rate_limited"
    assert issued["lease_digest"] not in main._STUDIO_BLACK_BOX_REMOTE_RUNTIMES
    with remote_api_context.testing_session() as session:
        record = session.get(ValidationRunRecord, remote_api_context.validation_run_id)
        assert record.allowed_to_execute is False
        assert record.status == "blocked"
        assert record.payload["remote_human_lease_stop_summary"] == {
            "lease_digest": issued["lease_digest"],
            "reason": "rate_limited",
            "stopped_at": record.finished_at.replace(tzinfo=UTC).isoformat(),
        }
        serialized = str(record.payload["remote_human_lease_stop_summary"]).lower()
        assert not any(
            marker in serialized
            for marker in ("header", "cookie", "authorization", "body", "response", "object_id")
        )


def test_remote_operator_stop_is_terminal_and_clears_execution(remote_api_context):
    issued = client.post(
        "/mythos/studio/black-box-remote/leases",
        json=remote_api_context.request,
    ).json()
    endpoint = (
        f"/mythos/studio/black-box-remote/leases/{issued['lease_digest']}/stop"
    )

    stopped = client.post(endpoint, json={"reason": "operator_stop"})
    repeated = client.post(endpoint, json={"reason": "operator_stop"})
    retried = client.post(
        f"/mythos/studio/black-box-remote/leases/{issued['lease_digest']}/authorize",
        json=_authorize_payload(),
    )

    assert stopped.status_code == 200
    assert stopped.json()["reason"] == "operator_stop"
    assert repeated.json()["reason"] == "operator_stop"
    assert retried.json()["reason"] == "operator_stop"
    assert issued["lease_digest"] not in main._STUDIO_BLACK_BOX_REMOTE_RUNTIMES
