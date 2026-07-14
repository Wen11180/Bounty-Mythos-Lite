from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import pickle

import pytest
from pydantic import ValidationError

from app import black_box_hunter
from app.black_box_hunter import BlackBoxExecutionLease
from app.scope_guard import ScopeGuardRule


NOW = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)


@dataclass(frozen=True)
class TrialContext:
    rule: ScopeGuardRule
    lease: BlackBoxExecutionLease
    approval: black_box_hunter.LeaseApproval
    trial: black_box_hunter.DifferentialTrial
    now: datetime


def _lease_payload(**updates):
    payload = {
        "lease_id": "lease_123",
        "asset": "api.example.com",
        "policy_digest": "policy_sha256_123",
        "scope_digest": "scope_sha256_123",
        "plan_digest": "plan_sha256_123",
        "active_origins": ["https://api.example.com"],
        "passive_origins": [],
        "account_aliases": ["account_a", "account_b"],
        "role_aliases": ["member"],
        "allowed_actions": ["read_only_replay"],
        "rollback_required": True,
        "workflow_budget": 1,
        "request_budget_per_workflow": 10,
        "duration_seconds": 300,
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
    }
    payload.update(updates)
    return payload


def _lease(**updates):
    return BlackBoxExecutionLease(**_lease_payload(**updates))


def _updated(model, **updates):
    payload = model.model_dump()
    payload.update(updates)
    return type(model)(**payload)


def _valid_context() -> TrialContext:
    rule = ScopeGuardRule(
        asset="api.example.com",
        scope_status="in_scope",
        automation="limited",
        allowed_validation=["black_box_differential"],
        forbidden=[],
        human_approval_required=True,
    )
    lease = _lease()
    approval = black_box_hunter.LeaseApproval(
        approval_id="approval_123",
        preflight_id="validation_123",
        lease_id=lease.lease_id,
        asset=lease.asset,
        policy_digest=lease.policy_digest,
        scope_digest=lease.scope_digest,
        plan_digest=lease.plan_digest,
        validation_mode="black_box_differential",
        approval_status="approved",
        preflight_status="preflight_passed",
        expires_at=NOW + timedelta(minutes=5),
    )
    trial = black_box_hunter.DifferentialTrial(
        workflow=black_box_hunter.WorkflowStep(
            workflow_index=1,
            origin="https://api.example.com",
            route_template="/v1/widgets/{object}",
            method="GET",
            action="read_only_replay",
            state="active",
        ),
        session=black_box_hunter.SessionAlias(
            account_alias="account_b",
            role_alias="member",
            active=True,
        ),
        test_object=black_box_hunter.TestObjectAlias(
            alias="widget_a",
            owner_alias="account_a",
            test_owned=True,
            reversible=True,
            state="active",
        ),
        generated_requests_in_workflow=0,
        active_generated_requests=0,
        elapsed_seconds=0,
        seconds_since_last_generated_request=3,
        requires_rollback=False,
        rollback_ready=False,
    )
    return TrialContext(rule, lease, approval, trial, NOW)


def _decision(context: TrialContext):
    return black_box_hunter.validate_black_box_trial(
        context.rule,
        context.lease,
        context.approval,
        context.trial,
        now=context.now,
    )


def _assert_blocked(context: TrialContext, reason: str) -> None:
    decision = _decision(context)
    assert decision.allowed is False
    assert decision.reason == reason
    assert decision.stop is not None


def _with_lease(context: TrialContext, **updates) -> TrialContext:
    return replace(context, lease=_updated(context.lease, **updates))


def _with_rule(context: TrialContext, **updates) -> TrialContext:
    return replace(context, rule=_updated(context.rule, **updates))


def _with_approval(context: TrialContext, **updates) -> TrialContext:
    return replace(context, approval=_updated(context.approval, **updates))


def _with_trial(context: TrialContext, **updates) -> TrialContext:
    return replace(context, trial=_updated(context.trial, **updates))


def _with_workflow(context: TrialContext, **updates) -> TrialContext:
    return _with_trial(context, workflow=_updated(context.trial.workflow, **updates))


def _with_session(context: TrialContext, **updates) -> TrialContext:
    return _with_trial(context, session=_updated(context.trial.session, **updates))


def _with_object(context: TrialContext, **updates) -> TrialContext:
    return _with_trial(context, test_object=_updated(context.trial.test_object, **updates))


def test_execution_lease_persists_only_safe_authority_metadata():
    lease = _lease(
        passive_origins=["https://static.example.com"],
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )

    assert lease.safe_projection() == {
        "lease_id": "lease_123",
        "asset": "api.example.com",
        "policy_digest": "policy_sha256_123",
        "scope_digest": "scope_sha256_123",
        "plan_digest": "plan_sha256_123",
        "active_origins": ["https://api.example.com"],
        "passive_origins": ["https://static.example.com"],
        "account_aliases": ["account_a", "account_b"],
        "role_aliases": ["member"],
        "allowed_actions": ["read_only_replay"],
        "rollback_required": True,
        "workflow_budget": 1,
        "request_budget_per_workflow": 10,
        "duration_seconds": 300,
        "min_interval_seconds": 3,
        "issued_at": "2026-07-14T12:00:00Z",
        "expires_at": "2026-07-14T12:05:00Z",
    }

    with pytest.raises(ValidationError):
        _lease(policy_digest="Bearer secret-value")


def test_execution_lease_requires_an_expiry():
    payload = _lease_payload()
    del payload["expires_at"]

    with pytest.raises(ValidationError):
        BlackBoxExecutionLease(**payload)


def test_runtime_session_registry_exposes_only_aliases_to_safe_projection():
    registry = black_box_hunter.RuntimeSessionRegistry()
    session_handle = object()

    registry.register_session("account_a", session_handle)
    registry.register_object("object_a", "concrete-object-id")

    assert registry.session_handle("account_a") is session_handle
    assert registry.object_id("object_a") == "concrete-object-id"
    assert registry.safe_projection() == {
        "session_aliases": ["account_a"],
        "object_aliases": ["object_a"],
    }


def test_runtime_session_registry_cannot_be_serialized():
    registry = black_box_hunter.RuntimeSessionRegistry()
    registry.register_session("account_a", "ephemeral-session-handle")

    with pytest.raises(TypeError, match="runtime_session_registry_not_serializable"):
        pickle.dumps(registry)


def test_allows_trial_only_after_scope_guard_matching_approval_and_preflight():
    decision = _decision(_valid_context())

    assert decision.allowed is True
    assert decision.reason == "trial_allowed"


def test_blocks_reversible_updates_without_rollback_readiness():
    context = _with_lease(_valid_context(), allowed_actions=["reversible_update"])
    context = _with_workflow(context, action="reversible_update", method="PATCH")
    context = _with_trial(context, requires_rollback=False, rollback_ready=False)

    _assert_blocked(context, "rollback_required")


def test_workflow_step_rejects_raw_query_values():
    with pytest.raises(ValidationError):
        black_box_hunter.WorkflowStep(
            workflow_index=1,
            origin="https://api.example.com",
            route_template="/v1/widgets?object_id=concrete-object-id",
            method="GET",
            action="read_only_replay",
            state="active",
        )


@pytest.mark.parametrize(
    "origin",
    [
        "https://api.example.com/v1",
        "https://api.example.com?token=secret-value",
    ],
)
def test_workflow_step_requires_an_exact_origin(origin):
    with pytest.raises(ValidationError):
        black_box_hunter.WorkflowStep(
            workflow_index=1,
            origin=origin,
            route_template="/v1/widgets/{object}",
            method="GET",
            action="read_only_replay",
            state="active",
        )


@pytest.mark.parametrize(
    ("updates", "reason"),
    [
        ({"passive_origins": ["https://api.example.com"]}, "overlap"),
        ({"issued_at": NOW + timedelta(minutes=5)}, "expiry"),
        ({"active_origins": ["https://*.example.com"]}, "wildcard"),
        ({"allowed_actions": ["delete"]}, "irreversible"),
    ],
)
def test_execution_lease_rejects_unsafe_configuration(updates, reason):
    if reason == "expiry":
        updates = {**updates, "expires_at": NOW + timedelta(minutes=5)}

    with pytest.raises(ValidationError):
        _lease(**updates)


def test_lease_approval_rejects_secret_like_metadata_and_naive_expiry():
    context = _valid_context()

    with pytest.raises(ValidationError):
        _with_approval(context, preflight_id="Bearer secret-value")
    with pytest.raises(ValidationError):
        _with_approval(context, expires_at=datetime(2026, 7, 14, 12, 5))


def test_trial_observation_rejects_raw_or_secret_response_data():
    observation = black_box_hunter.TrialObservation(
        status_class="2xx",
        response_schema_fingerprint="schema_sha256_123",
        timing_bucket="under_500ms",
        canary_match=True,
        redacted=True,
    )

    assert observation.model_dump()["state_effect"] is None
    for updates in (
        {"raw_response": "sensitive response body"},
        {"response_schema_fingerprint": "Bearer secret-value"},
    ):
        payload = {
            "status_class": "2xx",
            "response_schema_fingerprint": "schema_sha256_123",
            "timing_bucket": "under_500ms",
            "redacted": True,
        }
        payload.update(updates)
        with pytest.raises(ValidationError):
            black_box_hunter.TrialObservation(**payload)


@pytest.mark.parametrize(
    ("constructor", "kwargs"),
    [
        (
            black_box_hunter.SessionAlias,
            {
                "account_alias": "Bearer secret-value",
                "role_alias": "member",
                "active": True,
            },
        ),
        (
            black_box_hunter.TestObjectAlias,
            {
                "alias": "widget_a",
                "owner_alias": "token=secret-value",
                "test_owned": True,
                "reversible": True,
                "state": "active",
            },
        ),
        (
            black_box_hunter.TestObjectAlias,
            {
                "alias": "widget_a",
                "owner_alias": "account_a",
                "test_owned": True,
                "reversible": True,
                "state": "token=secret-value",
            },
        ),
        (
            black_box_hunter.WorkflowStep,
            {
                "workflow_index": 1,
                "origin": "https://api.example.com",
                "route_template": "/v1/widgets/{object}",
                "method": "GET",
                "action": "read_only_replay",
                "state": "token=secret-value",
            },
        ),
    ],
)
def test_safe_aliases_and_states_reject_secret_like_values(constructor, kwargs):
    with pytest.raises(ValidationError):
        constructor(**kwargs)


@pytest.mark.parametrize(
    ("context", "reason"),
    [
        (
            _with_workflow(_valid_context(), route_template="/"),
            "root_route_not_trialable",
        ),
        (
            _with_workflow(_valid_context(), method="DELETE"),
            "method_action_mismatch",
        ),
        (
            _with_rule(_valid_context(), scope_status="out_of_scope"),
            "out_of_scope",
        ),
        (
            _with_approval(_valid_context(), plan_digest="plan_sha256_other"),
            "approval_preflight_mismatch",
        ),
        (
            _with_object(_valid_context(), test_owned=False),
            "test_owned_object_required",
        ),
        (
            _with_session(_valid_context(), active=False),
            "session_inactive",
        ),
        (
            _with_workflow(_valid_context(), origin="https://static.example.com"),
            "active_origin_required",
        ),
        (
            _with_session(_valid_context(), role_alias="administrator"),
            "role_not_leased",
        ),
    ],
)
def test_trial_gate_stops_for_unsafe_authority_or_target(context, reason):
    _assert_blocked(context, reason)


@pytest.mark.parametrize(
    ("updates", "reason"),
    [
        ({"issued_at": NOW - timedelta(seconds=301)}, "duration_budget_exhausted"),
        (
            {
                "issued_at": NOW + timedelta(seconds=1),
                "expires_at": NOW + timedelta(minutes=5, seconds=1),
            },
            "lease_not_active",
        ),
    ],
)
def test_trial_gate_enforces_lease_timing(updates, reason):
    _assert_blocked(_with_lease(_valid_context(), **updates), reason)


def test_trial_gate_does_not_accept_a_caller_approval_boolean():
    context = _valid_context()

    with pytest.raises(TypeError):
        black_box_hunter.validate_black_box_trial(
            context.rule,
            context.lease,
            context.approval,
            context.trial,
            now=context.now,
            human_approved=True,
        )


def test_lease_approval_rejects_allowed_to_execute_as_an_authority_substitute():
    with pytest.raises(ValidationError):
        _with_approval(_valid_context(), allowed_to_execute=True)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("workflow_budget", 4),
        ("request_budget_per_workflow", 51),
        ("duration_seconds", 1801),
        ("min_interval_seconds", 2),
    ],
)
def test_execution_lease_does_not_relax_remote_preset(field, value):
    with pytest.raises(ValidationError):
        _lease(**{field: value})


@pytest.mark.parametrize(
    ("updates", "reason"),
    [
        ({"generated_requests_in_workflow": 10}, "request_budget_exhausted"),
        ({"active_generated_requests": 1}, "concurrency_limit"),
        ({"elapsed_seconds": 300}, "duration_budget_exhausted"),
        ({"seconds_since_last_generated_request": 2}, "rate_limit"),
        ({"workflow": {"workflow_index": 2}}, "workflow_budget_exhausted"),
    ],
)
def test_trial_gate_enforces_bounded_runtime_limits(updates, reason):
    context = _valid_context()
    if "workflow" in updates:
        context = _with_workflow(context, **updates["workflow"])
    else:
        context = _with_trial(context, **updates)

    _assert_blocked(context, reason)
