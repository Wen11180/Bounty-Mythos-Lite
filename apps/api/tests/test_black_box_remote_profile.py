from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier, BrokenBarrierError

import pytest
from pydantic import ValidationError

from app import black_box_hunter
from app.black_box_hunter import remote_profile
from app.black_box_hunter.remote_profile import (
    RemoteLeaseRuntime,
    RemoteRequestAuthorization,
    RemoteWorkflowLease,
    issue_remote_human_lease,
)
from app.scope_guard import ScopeGuardRule


NOW = datetime(2026, 7, 15, 12, tzinfo=timezone.utc)


def _execution_lease(**updates):
    payload = {
        "lease_id": "remote_lease_123",
        "asset": "api.example.test",
        "policy_digest": f"sha256:{'a' * 64}",
        "scope_digest": f"sha256:{'b' * 64}",
        "plan_digest": f"sha256:{'c' * 64}",
        "active_origins": ["https://api.example.test"],
        "passive_origins": ["https://static.example.test"],
        "account_aliases": ["account_a", "account_b"],
        "role_aliases": ["member"],
        "allowed_actions": ["read_only_replay", "reversible_update"],
        "rollback_required": True,
        "workflow_budget": 1,
        "request_budget_per_workflow": 2,
        "duration_seconds": 1800,
        "min_interval_seconds": 3,
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=30),
    }
    payload.update(updates)
    return black_box_hunter.BlackBoxExecutionLease(**payload)


def _approval(lease=None, **updates):
    lease = lease or _execution_lease()
    payload = {
        "approval_id": "approval_remote_123",
        "preflight_id": "validation_remote_123",
        "lease_id": lease.lease_id,
        "asset": lease.asset,
        "policy_digest": lease.policy_digest,
        "scope_digest": lease.scope_digest,
        "plan_digest": lease.plan_digest,
        "validation_mode": "black_box_differential",
        "approval_status": "approved",
        "preflight_status": "preflight_passed",
        "expires_at": NOW + timedelta(minutes=30),
    }
    payload.update(updates)
    return black_box_hunter.LeaseApproval(**payload)


def _workflow(**updates):
    payload = {
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
    payload.update(updates)
    return RemoteWorkflowLease(**payload)


def _remote_lease(*, lease=None, approval=None, workflows=None, approved_at=None):
    lease = lease or _execution_lease()
    approval = approval or _approval(lease)
    return issue_remote_human_lease(
        lease=lease,
        approval=approval,
        approved_at=approved_at or NOW,
        workflows=workflows or [_workflow()],
        now=NOW,
    )


def _rule():
    return ScopeGuardRule(
        asset="api.example.test",
        scope_status="in_scope",
        automation="limited",
        allowed_validation=["black_box_differential"],
        forbidden=[],
        human_approval_required=True,
    )


def _request(**updates):
    payload = {
        "workflow_alias": "read_widget_a",
        "trial_class": "cross_account_object_swap",
        "target_account_alias": "account_b",
        "target_role_alias": "member",
        "object_alias": "widget_a",
        "session_generation": "session_generation_a",
    }
    payload.update(updates)
    return RemoteRequestAuthorization(**payload)


def _authorize(runtime, *, now=NOW, request=None, approval=None, **updates):
    remote_lease = runtime.remote_lease
    payload = {
        "rule": _rule(),
        "approval": approval or _approval(remote_lease.lease),
        "request": request or _request(),
        "current_policy_digest": remote_lease.lease.policy_digest,
        "current_scope_digest": remote_lease.lease.scope_digest,
        "current_plan_digest": remote_lease.lease.plan_digest,
        "lease_digest": remote_lease.lease_digest,
        "now": now,
    }
    payload.update(updates)
    return runtime.authorize(**payload)


def test_remote_human_lease_digest_binds_all_authority_and_is_immutable():
    remote_lease = _remote_lease()

    assert remote_lease.profile == "remote_human_lease"
    assert remote_lease.lease_digest.startswith("sha256:")
    assert remote_lease.report_submission_allowed is False
    assert remote_lease.human_confirmation_allowed is False
    with pytest.raises(ValidationError):
        remote_lease.lease_digest = f"sha256:{'f' * 64}"

    changed = _remote_lease(
        lease=_execution_lease(request_budget_per_workflow=1),
        approval=_approval(_execution_lease(request_budget_per_workflow=1)),
    )
    assert changed.lease_digest != remote_lease.lease_digest


@pytest.mark.parametrize(
    ("workflow_updates", "reason"),
    [
        ({"origin": "https://other.example.test"}, "active_origin_not_lease_approved"),
        ({"route_template": "/"}, "recorded_non_root_workflow_required"),
        ({"route_template": "/v1/工具/{object}"}, "ascii_remote_route_required"),
        (
            {"route_template": "/v1/{object}/widgets/{object}"},
            "single_remote_object_route_required",
        ),
        ({"object_owner_alias": "account_b"}, "source_owned_remote_object_required"),
        ({"object_owner_alias": "account_c"}, "leased_test_object_owner_required"),
        ({"action": "reversible_update", "method": "DELETE"}, "safe_workflow_action_required"),
    ],
)
def test_remote_human_lease_accepts_only_recorded_owned_safe_workflows(
    workflow_updates,
    reason,
):
    with pytest.raises(ValidationError, match=reason):
        _remote_lease(workflows=[_workflow(**workflow_updates)])


def test_remote_human_lease_requires_one_exact_https_origin_and_fresh_approval():
    with pytest.raises(ValidationError, match="single_remote_active_origin_required"):
        _remote_lease(
            lease=_execution_lease(
                active_origins=[
                    "https://api.example.test",
                    "https://other.example.test",
                ]
            )
        )

    with pytest.raises(ValidationError, match="exact_https_remote_origin_required"):
        _remote_lease(
            lease=_execution_lease(active_origins=["http://api.example.test"])
        )

    with pytest.raises(ValidationError, match="exact_https_remote_origin_required"):
        _remote_lease(
            lease=_execution_lease(active_origins=["https://例子.example.test"])
        )

    with pytest.raises(ValueError, match="fresh_remote_approval_required"):
        _remote_lease(approved_at=NOW - timedelta(minutes=30, seconds=1))


def test_remote_runtime_rechecks_scope_approval_digests_and_session_generation():
    runtime = RemoteLeaseRuntime(_remote_lease())

    decision = _authorize(
        runtime,
        current_policy_digest=f"sha256:{'d' * 64}",
    )
    assert decision.allowed is False
    assert decision.reason == "policy_or_scope_changed"
    assert decision.stop is not None
    assert _authorize(runtime).reason == "policy_or_scope_changed"

    runtime = RemoteLeaseRuntime(_remote_lease())
    granted = _authorize(runtime)
    assert granted.allowed is True
    assert granted.request_grant_id
    runtime.complete(granted.request_grant_id, outcome="success", now=NOW)

    changed_session = _authorize(
        runtime,
        now=NOW + timedelta(seconds=3),
        request=_request(session_generation="session_generation_b"),
    )
    assert changed_session.reason == "session_changed"
    assert changed_session.stop is not None


def test_remote_runtime_uses_server_side_concurrency_rate_request_and_time_budgets():
    runtime = RemoteLeaseRuntime(_remote_lease())
    first = _authorize(runtime)
    assert first.allowed is True

    concurrent = _authorize(runtime)
    assert concurrent.reason == "concurrency_limit"
    assert concurrent.stop is not None

    runtime = RemoteLeaseRuntime(_remote_lease())
    first = _authorize(runtime)
    runtime.complete(first.request_grant_id, outcome="success", now=NOW)
    early = _authorize(runtime, now=NOW + timedelta(seconds=2))
    assert early.reason == "rate_limit"
    assert early.stop is not None

    runtime = RemoteLeaseRuntime(_remote_lease())
    first = _authorize(runtime)
    runtime.complete(first.request_grant_id, outcome="success", now=NOW)
    second = _authorize(runtime, now=NOW + timedelta(seconds=3))
    runtime.complete(second.request_grant_id, outcome="success", now=NOW + timedelta(seconds=3))
    exhausted = _authorize(runtime, now=NOW + timedelta(seconds=6))
    assert exhausted.reason == "request_budget_exhausted"
    assert exhausted.stop is not None

    runtime = RemoteLeaseRuntime(_remote_lease())
    expired = _authorize(runtime, now=NOW + timedelta(minutes=30))
    assert expired.reason in {"duration_budget_exhausted", "lease_or_approval_expired"}
    assert expired.stop is not None


def test_remote_runtime_serializes_concurrent_authorization(monkeypatch):
    runtime = RemoteLeaseRuntime(_remote_lease())
    barrier = Barrier(2)
    original_validate = remote_profile.validate_black_box_trial

    def synchronized_validate(*args, **kwargs):
        try:
            barrier.wait(timeout=0.2)
        except BrokenBarrierError:
            pass
        return original_validate(*args, **kwargs)

    monkeypatch.setattr(
        remote_profile,
        "validate_black_box_trial",
        synchronized_validate,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        decisions = list(executor.map(lambda _: _authorize(runtime), range(2)))

    assert sum(decision.allowed for decision in decisions) == 1
    assert {decision.reason for decision in decisions} == {
        "remote_request_authorized",
        "concurrency_limit",
    }


@pytest.mark.parametrize(
    "reason",
    [
        "rate_limited",
        "captcha_or_waf_detected",
        "off_origin_redirect",
        "third_party_data_detected",
        "test_owned_object_required",
        "ambiguous_authority",
        "rollback_failed",
        "server_error",
        "session_expired",
    ],
)
def test_remote_runtime_stop_is_terminal_and_never_retries(reason):
    runtime = RemoteLeaseRuntime(_remote_lease())
    granted = _authorize(runtime)

    stopped = runtime.complete(granted.request_grant_id, outcome=reason, now=NOW)

    assert stopped.allowed is False
    assert stopped.reason == reason
    assert stopped.stop is not None
    assert _authorize(runtime, now=NOW + timedelta(minutes=1)).reason == reason


def test_remote_contract_has_no_discovery_submission_or_human_confirmation_input():
    with pytest.raises(ValidationError):
        RemoteRequestAuthorization(
            **(
                _request().model_dump()
                | {
                    "root_url": "https://api.example.test",
                    "submit_report": True,
                    "human_confirmed": True,
                }
            )
        )
