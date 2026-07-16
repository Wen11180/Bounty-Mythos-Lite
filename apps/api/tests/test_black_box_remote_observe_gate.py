from datetime import datetime, timedelta, timezone

import pytest

from app import black_box_hunter
from app.black_box_hunter.remote_observe_gate import (
    assess_remote_observe_gate,
    run_browser_demo_remote_fail_closed_pipeline,
    run_har_remote_fail_closed_pipeline,
)
from app.black_box_hunter.remote_profile import (
    RemoteLeaseRuntime,
    RemoteRequestAuthorization,
    RemoteWorkflowLease,
    issue_remote_human_lease,
)
from app.cli import main
from app.scope_guard import ScopeGuardRule

NOW = datetime(2026, 7, 15, 12, tzinfo=timezone.utc)


def _har_entry(object_id: str) -> dict:
    return {
        "request": {
            "method": "GET",
            "url": f"http://127.0.0.1/widgets/{object_id}",
            "headers": [{"name": "Cookie", "value": "session=SECRET"}],
            "queryString": [],
        },
        "response": {
            "status": 200,
            "headers": [],
            "content": {"mimeType": "application/json", "text": "{}"},
        },
    }


def _role_hars() -> dict[str, dict]:
    return {
        "role_a": {"log": {"version": "1.2", "entries": [_har_entry("101")]}},
        "role_b": {"log": {"version": "1.2", "entries": [_har_entry("202")]}},
    }


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


def _runtime() -> RemoteLeaseRuntime:
    lease = _execution_lease()
    remote = issue_remote_human_lease(
        lease=lease,
        approval=_approval(lease),
        approved_at=NOW,
        workflows=[_workflow()],
        now=NOW,
    )
    return RemoteLeaseRuntime(remote)


def _rule():
    return ScopeGuardRule(
        asset="api.example.test",
        scope_status="in_scope",
        automation="limited",
        allowed_validation=["black_box_differential"],
        forbidden=[],
        human_approval_required=True,
    )


def test_gate_defaults_to_plan_only_when_profile_disabled():
    gate = assess_remote_observe_gate(profile_enabled=False, now=NOW)
    assert gate["mode"] == "plan_only"
    assert gate["observe_allowed"] is False
    assert gate["reason"] == "remote_profile_disabled"
    assert gate["execution_allowed"] is False
    assert gate["report_submission_allowed"] is False
    assert gate["http_requests_attempted"] == 0


def test_gate_requires_runtime_and_two_sessions():
    runtime = _runtime()
    missing_runtime = assess_remote_observe_gate(
        profile_enabled=True,
        runtime=None,
        live_session_refs=["session_a", "session_b"],
        now=NOW,
    )
    assert missing_runtime["reason"] == "remote_lease_runtime_required"
    assert missing_runtime["mode"] == "plan_only"

    one_session = assess_remote_observe_gate(
        profile_enabled=True,
        runtime=runtime,
        live_session_refs=["session_a"],
        now=NOW,
    )
    assert one_session["reason"] == "two_live_sessions_required"
    assert one_session["observe_allowed"] is False


def test_gate_eligible_still_blocks_auto_execution():
    gate = assess_remote_observe_gate(
        profile_enabled=True,
        runtime=_runtime(),
        live_session_refs=["session_a", "session_b"],
        now=NOW,
    )
    assert gate["mode"] == "lease_bound_observe_eligible"
    assert gate["observe_allowed"] is True
    assert gate["execution_allowed"] is False
    assert gate["validation_allowed"] is False
    assert gate["report_submission_allowed"] is False


def test_gate_expired_lease_is_plan_only():
    runtime = _runtime()
    gate = assess_remote_observe_gate(
        profile_enabled=True,
        runtime=runtime,
        live_session_refs=["session_a", "session_b"],
        now=NOW + timedelta(hours=2),
    )
    assert gate["mode"] == "plan_only"
    assert gate["reason"] == "remote_lease_expired"
    assert gate["observe_allowed"] is False


def test_gate_stop_is_terminal_plan_only():
    runtime = _runtime()
    runtime.stop("operator_stop")
    gate = assess_remote_observe_gate(
        profile_enabled=True,
        runtime=runtime,
        live_session_refs=["session_a", "session_b"],
        now=NOW,
    )
    assert gate["mode"] == "plan_only"
    assert gate["reason"] == "remote_lease_stopped:operator_stop"
    assert gate["observe_allowed"] is False


def test_runtime_not_picklable_through_gate_path():
    import pickle

    runtime = _runtime()
    with pytest.raises(TypeError, match="not_serializable"):
        pickle.dumps(runtime)


def test_har_pipeline_fail_closed_without_lease_and_strips_secrets():
    import json

    result = run_har_remote_fail_closed_pipeline(
        _role_hars(),
        profile_enabled=False,
        account_aliases={"role_a": "account_a", "role_b": "account_b"},
        role_aliases={"role_a": "member", "role_b": "viewer"},
        role_ranks={"role_a": 10, "role_b": 1},
        now=NOW,
    )
    assert result["schema_version"] == "remote_fail_closed_pipeline_v1"
    assert result["source"] == "har"
    assert result["mode"] == "plan_only"
    assert result["gate"]["reason"] == "remote_profile_disabled"
    assert result["http_requests_attempted"] == 0
    assert result["execution_allowed"] is False
    assert result["report_submission_allowed"] is False
    assert result["candidates"]
    assert any(
        card["plan_trial_class"] == "cross_account_object_swap"
        for card in result["candidates"]
    )
    blob = json.dumps(result)
    assert "SECRET" not in blob


def test_browser_demo_pipeline_fail_closed_without_sessions():
    demo_a = {
        "account_alias": "account_a",
        "role_alias": "member",
        "role_rank": 10,
        "auth_headers": {"Cookie": "session=SECRET_A"},
        "events": [{"method": "GET", "url": "http://127.0.0.1/widgets/101", "status": 200}],
    }
    demo_b = {
        "account_alias": "account_b",
        "role_alias": "viewer",
        "role_rank": 1,
        "events": [{"method": "GET", "url": "http://127.0.0.1/widgets/202", "status": 200}],
    }
    result = run_browser_demo_remote_fail_closed_pipeline(
        demo_a,
        demo_b,
        profile_enabled=True,
        runtime=_runtime(),
        live_session_refs=[],
        now=NOW,
    )
    assert result["source"] == "browser_demo"
    assert result["mode"] == "plan_only"
    assert result["gate"]["reason"] == "two_live_sessions_required"
    assert result["authorize_dry_run"] is None
    assert "SECRET" not in str(result)


def test_eligible_dry_run_authorize_without_http():
    runtime = _runtime()
    lease = runtime.remote_lease.lease
    result = run_har_remote_fail_closed_pipeline(
        _role_hars(),
        profile_enabled=True,
        runtime=runtime,
        live_session_refs=["session_a", "session_b"],
        account_aliases={"role_a": "account_a", "role_b": "account_b"},
        role_aliases={"role_a": "member", "role_b": "viewer"},
        role_ranks={"role_a": 10, "role_b": 1},
        now=NOW,
        dry_run={
            "rule": _rule(),
            "approval": _approval(lease),
            "request": RemoteRequestAuthorization(
                workflow_alias="read_widget_a",
                trial_class="cross_account_object_swap",
                target_account_alias="account_b",
                target_role_alias="member",
                object_alias="widget_a",
                session_generation="session_generation_a",
            ),
            "current_policy_digest": lease.policy_digest,
            "current_scope_digest": lease.scope_digest,
            "current_plan_digest": lease.plan_digest,
            "lease_digest": runtime.remote_lease.lease_digest,
            "now": NOW,
        },
    )
    assert result["mode"] == "lease_bound_observe_eligible"
    assert result["gate"]["observe_allowed"] is True
    assert result["authorize_dry_run"]["allowed"] is True
    assert result["authorize_dry_run"]["request_grant_id"]
    assert result["authorize_dry_run"]["report_submission_allowed"] is False
    assert result["http_requests_attempted"] == 0
    assert result["execution_allowed"] is False


def test_dry_run_blocked_when_gate_closed():
    runtime = _runtime()
    lease = runtime.remote_lease.lease
    result = run_har_remote_fail_closed_pipeline(
        _role_hars(),
        profile_enabled=False,
        runtime=runtime,
        live_session_refs=["session_a", "session_b"],
        account_aliases={"role_a": "account_a", "role_b": "account_b"},
        now=NOW,
        dry_run={
            "rule": _rule(),
            "approval": _approval(lease),
            "request": RemoteRequestAuthorization(
                workflow_alias="read_widget_a",
                trial_class="cross_account_object_swap",
                target_account_alias="account_b",
                target_role_alias="member",
                object_alias="widget_a",
                session_generation="session_generation_a",
            ),
            "current_policy_digest": lease.policy_digest,
            "current_scope_digest": lease.scope_digest,
            "current_plan_digest": lease.plan_digest,
            "lease_digest": runtime.remote_lease.lease_digest,
            "now": NOW,
        },
    )
    assert result["authorize_dry_run"]["allowed"] is False
    assert result["authorize_dry_run"]["reason"] == "gate_blocks_authorize"


def test_cli_remote_gate_plan_only(tmp_path, capsys):
    import json

    har_a = tmp_path / "a.har"
    har_b = tmp_path / "b.har"
    out = tmp_path / "gate.json"
    har_a.write_text(json.dumps(_role_hars()["role_a"]), encoding="utf-8")
    har_b.write_text(json.dumps(_role_hars()["role_b"]), encoding="utf-8")

    code = main(
        [
            "black-box-remote-gate",
            "--har-a",
            str(har_a),
            "--har-b",
            str(har_b),
            "--out",
            str(out),
        ]
    )
    assert code == 0
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["mode"] == "plan_only"
    assert result["gate"]["reason"] == "remote_profile_disabled"
    assert result["http_requests_attempted"] == 0
    assert "SECRET" not in out.read_text(encoding="utf-8")
    captured = capsys.readouterr()
    assert "mode=plan_only" in captured.out


def test_cli_remote_gate_demo_source(tmp_path):
    import json

    demo_a = tmp_path / "a.json"
    demo_b = tmp_path / "b.json"
    out = tmp_path / "gate.json"
    demo_a.write_text(
        json.dumps(
            {
                "account_alias": "account_a",
                "role_alias": "member",
                "role_rank": 10,
                "events": [
                    {
                        "method": "GET",
                        "url": "http://127.0.0.1/widgets/101",
                        "status": 200,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    demo_b.write_text(
        json.dumps(
            {
                "account_alias": "account_b",
                "role_alias": "viewer",
                "role_rank": 1,
                "events": [
                    {
                        "method": "GET",
                        "url": "http://127.0.0.1/widgets/202",
                        "status": 200,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    code = main(
        [
            "black-box-remote-gate",
            "--demo-a",
            str(demo_a),
            "--demo-b",
            str(demo_b),
            "--out",
            str(out),
        ]
    )
    assert code == 0
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["source"] == "browser_demo"
    assert result["mode"] == "plan_only"
