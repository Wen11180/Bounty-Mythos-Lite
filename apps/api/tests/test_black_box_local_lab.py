import pytest
from pydantic import ValidationError

from app import black_box_hunter


VALID_FINGERPRINT = f"sha256:{'a' * 64}"


def test_observed_workflow_model_keeps_only_safe_alias_provenance():
    workflow = black_box_hunter.ObservedWorkflow(
        workflow_alias="create_widget_a",
        session=black_box_hunter.SessionAlias(
            account_alias="account_a",
            role_alias="member",
            active=True,
        ),
        steps=[
            black_box_hunter.WorkflowStep(
                workflow_index=1,
                origin="http://127.0.0.1",
                route_template="/widgets/{object}",
                method="POST",
                action="test_object_create",
                state="draft",
            )
        ],
        objects=[
            black_box_hunter.ObservedTestObject(
                alias="widget_a",
                owner_alias="account_a",
                state="draft",
                reversible=True,
                provenance="demonstrated_normal_flow",
            )
        ],
        baseline_stable=True,
        rollback_ready=True,
    )

    projection = black_box_hunter.ObservedWorkflowModel(
        workflows=[workflow]
    ).safe_projection()

    assert projection == {
        "workflows": [
            {
                "workflow_alias": "create_widget_a",
                "account_alias": "account_a",
                "role_alias": "member",
                "baseline_stable": True,
                "rollback_ready": True,
                "steps": [
                    {
                        "workflow_index": 1,
                        "origin": "http://127.0.0.1",
                        "route_template": "/widgets/{object}",
                        "method": "POST",
                        "action": "test_object_create",
                        "state": "draft",
                    }
                ],
                "objects": [
                    {
                        "alias": "widget_a",
                        "owner_alias": "account_a",
                        "state": "draft",
                        "reversible": True,
                        "provenance": "demonstrated_normal_flow",
                    }
                ],
            }
        ]
    }


def _planning_model():
    workflow_a = black_box_hunter.ObservedWorkflow(
        workflow_alias="workflow_a",
        session=black_box_hunter.SessionAlias(
            account_alias="account_a",
            role_alias="member",
            active=True,
        ),
        role_rank=2,
        steps=[
            black_box_hunter.WorkflowStep(
                workflow_index=1,
                origin="http://127.0.0.1",
                route_template="/widgets/{object}",
                method="GET",
                action="read_only_replay",
                state="active",
            ),
            black_box_hunter.WorkflowStep(
                workflow_index=2,
                origin="http://127.0.0.1",
                route_template="/widgets/{object}/state",
                method="PATCH",
                action="reversible_update",
                state="active",
            ),
        ],
        objects=[
            black_box_hunter.ObservedTestObject(
                alias="parent_a",
                owner_alias="account_a",
                state="active",
                reversible=True,
                provenance="demonstrated_normal_flow",
            ),
            black_box_hunter.ObservedTestObject(
                alias="parent_a_alternate",
                owner_alias="account_a",
                state="active",
                reversible=True,
                provenance="demonstrated_normal_flow",
            ),
            black_box_hunter.ObservedTestObject(
                alias="child_a",
                owner_alias="account_a",
                parent_alias="parent_a",
                state="active",
                reversible=True,
                provenance="demonstrated_normal_flow",
            ),
        ],
        baseline_stable=True,
        rollback_ready=True,
    )
    workflow_b = black_box_hunter.ObservedWorkflow(
        workflow_alias="workflow_b",
        session=black_box_hunter.SessionAlias(
            account_alias="account_b",
            role_alias="viewer",
            active=True,
        ),
        role_rank=1,
        steps=[
            black_box_hunter.WorkflowStep(
                workflow_index=1,
                origin="http://127.0.0.1",
                route_template="/widgets/{object}",
                method="GET",
                action="read_only_replay",
                state="active",
            )
        ],
        objects=[
            black_box_hunter.ObservedTestObject(
                alias="parent_b",
                owner_alias="account_b",
                state="active",
                reversible=True,
                provenance="demonstrated_normal_flow",
            )
        ],
        baseline_stable=True,
        rollback_ready=True,
    )
    return black_box_hunter.ObservedWorkflowModel(
        workflows=[workflow_a, workflow_b]
    )


def test_planner_emits_only_the_five_approved_single_variable_trials():
    plans = black_box_hunter.plan_differential_trials(_planning_model())

    assert {plan.trial_class for plan in plans} == {
        "cross_account_object_swap",
        "lower_role_replay",
        "unauthenticated_read_only_replay",
        "owned_parent_child_swap",
        "reversible_out_of_order_state_transition",
    }
    assert all(
        [
            plan.baseline.phase,
            plan.trial.phase,
            plan.owner_control.phase,
            plan.session_control.phase,
            plan.repeat.phase,
        ]
        == ["baseline", "trial", "owner_control", "session_control", "repeat"]
        for plan in plans
    )
    assert all(plan.trial.changed_variable in {"object", "role", "session", "parent", "state"} for plan in plans)
    assert next(
        plan
        for plan in plans
        if plan.trial_class == "reversible_out_of_order_state_transition"
    ).rollback is not None


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("baseline_stable", False, "stable_baseline_required"),
        ("role_rank", None, "role_rank_required"),
        ("rollback_ready", False, "rollback_ready_required"),
    ],
)
def test_planner_refuses_missing_operational_preconditions(field, value, reason):
    model = _planning_model()
    changed_workflow = model.workflows[0].model_copy(update={field: value})
    incomplete_model = model.model_copy(
        update={"workflows": [changed_workflow, model.workflows[1]]}
    )

    with pytest.raises(ValueError, match=reason):
        black_box_hunter.plan_differential_trials(incomplete_model)


def test_observed_object_rejects_missing_provenance_or_state():
    observed_object = _planning_model().workflows[0].objects[0]

    with pytest.raises(ValidationError):
        black_box_hunter.ObservedTestObject.model_validate(
            observed_object.model_dump(exclude={"provenance"})
        )
    with pytest.raises(ValidationError):
        black_box_hunter.ObservedTestObject.model_validate(
            observed_object.model_dump() | {"state": ""}
        )


def _local_trial(*, account_alias="account_b", object_alias="widget_a", method="GET"):
    return black_box_hunter.DifferentialTrial(
        workflow=black_box_hunter.WorkflowStep(
            workflow_index=1,
            origin="http://127.0.0.1",
            route_template=(
                "/widgets/{object}/state" if method == "PATCH" else "/widgets/{object}"
            ),
            method=method,
            action=("reversible_update" if method == "PATCH" else "read_only_replay"),
            state="active",
        ),
        session=black_box_hunter.SessionAlias(
            account_alias=account_alias,
            role_alias="member",
            active=True,
        ),
        test_object=black_box_hunter.TestObjectAlias(
            alias=object_alias,
            owner_alias="account_a",
            test_owned=True,
            reversible=True,
            state="active",
        ),
        generated_requests_in_workflow=0,
        active_generated_requests=0,
        elapsed_seconds=0,
        seconds_since_last_generated_request=3,
        requires_rollback=method == "PATCH",
        rollback_ready=method == "PATCH",
    )


def test_loopback_bola_transport_returns_only_sanitized_evidence():
    from app.black_box_hunter.local_lab import LocalLabTransport

    observation = LocalLabTransport(mode="bola").execute(_local_trial())

    assert observation.status_class == "2xx"
    assert observation.canary_match is True
    assert observation.structural_identity_match is True
    assert observation.state_effect is False
    assert observation.redacted is True
    assert observation.stop is None
    serialized = observation.model_dump_json()
    assert "widget_a" not in serialized
    assert "account_a" not in serialized


def test_local_lab_refuses_trial_without_test_owned_object():
    from app.black_box_hunter.local_lab import LocalLabTransport

    unsafe_trial = _local_trial().model_copy(
        update={
            "test_object": black_box_hunter.TestObjectAlias(
                alias="widget_a",
                owner_alias="account_a",
                test_owned=False,
                reversible=True,
                state="active",
            )
        }
    )

    observation = LocalLabTransport(mode="bola").execute(unsafe_trial)

    assert observation.stop is not None
    assert observation.stop.reason == "test_owned_object_required"


def test_local_lab_never_executes_non_loopback_origin():
    from app.black_box_hunter.local_lab import LocalLabTransport

    remote_workflow = black_box_hunter.WorkflowStep(
        workflow_index=1,
        origin="https://api.example.com",
        route_template="/widgets/{object}",
        method="GET",
        action="read_only_replay",
        state="active",
    )
    remote_trial = _local_trial().model_copy(update={"workflow": remote_workflow})

    observation = LocalLabTransport(mode="bola").execute(remote_trial)

    assert observation.status_class == "network_error"
    assert observation.stop is not None
    assert observation.stop.reason == "loopback_origin_required"


@pytest.mark.parametrize(
    ("mode", "method", "object_alias", "status_class", "stop_reason", "intended_sharing"),
    [
        ("guarded", "GET", "widget_a", "4xx", None, False),
        ("shared", "GET", "widget_a", "2xx", None, True),
        ("expired_session", "GET", "widget_a", "4xx", "expired_session", False),
        ("unstable", "GET", "widget_a", "2xx", "unstable_response", False),
        ("rate_limited", "GET", "widget_a", "4xx", "rate_limited", False),
        ("server_error", "GET", "widget_a", "5xx", "server_error", False),
        ("rollback_failure", "PATCH", "widget_a", "4xx", "rollback_failed", False),
        ("off_origin_redirect", "GET", "widget_a", "3xx", "off_origin_redirect", False),
        ("third_party_data", "GET", "widget_a", "2xx", "third_party_data_detected", False),
        ("guarded", "GET", "unknown_object", "4xx", "unknown_test_object", False),
    ],
)
def test_loopback_lab_models_safe_stops_without_preserving_response_data(
    mode,
    method,
    object_alias,
    status_class,
    stop_reason,
    intended_sharing,
):
    from app.black_box_hunter.local_lab import LocalLabTransport

    transport = LocalLabTransport(mode=mode)
    try:
        observation = transport.execute(
            _local_trial(
                account_alias="account_a" if mode == "unstable" else "account_b",
                method=method,
                object_alias=object_alias,
            )
        )
    finally:
        transport.close()

    assert observation.status_class == status_class
    assert observation.intended_sharing is intended_sharing
    assert (observation.stop.reason if observation.stop else None) == stop_reason
    assert object_alias not in observation.model_dump_json()


def _observation(**updates):
    payload = {
        "status_class": "2xx",
        "response_schema_fingerprint": VALID_FINGERPRINT,
        "timing_bucket": "synthetic",
        "canary_match": None,
        "structural_identity_match": None,
        "state_effect": False,
        "redacted": True,
    }
    payload.update(updates)
    return black_box_hunter.TrialObservation(**payload)


def test_oracle_rejects_status_only_and_requires_controls_repeat_for_review():
    status_only = black_box_hunter.DifferentialEvidenceBundle(
        baseline_a=_observation(structural_identity_match=True),
        baseline_b=_observation(structural_identity_match=True),
        trial=_observation(),
        owner_control=_observation(structural_identity_match=True),
        session_control=_observation(structural_identity_match=True),
        repeat=_observation(),
        independent_repeat=True,
        rollback_required=False,
    )
    observed_once = status_only.model_copy(
        update={
            "trial": _observation(
                canary_match=True,
                structural_identity_match=True,
            ),
            "repeat": None,
        }
    )
    review_ready = observed_once.model_copy(
        update={
            "repeat": _observation(
                canary_match=True,
                structural_identity_match=True,
            )
        }
    )

    assert black_box_hunter.evaluate_differential_evidence(status_only).status == "inconclusive"
    assert black_box_hunter.evaluate_differential_evidence(observed_once).status == "observed"
    assert black_box_hunter.evaluate_differential_evidence(review_ready).status == "review_ready"


def test_oracle_distinguishes_hypothesis_reproduced_refuted_and_safe_stop():
    complete_bundle = black_box_hunter.DifferentialEvidenceBundle(
        baseline_a=_observation(structural_identity_match=True),
        baseline_b=_observation(structural_identity_match=True),
        trial=_observation(canary_match=True, structural_identity_match=True),
        owner_control=_observation(structural_identity_match=True),
        session_control=_observation(structural_identity_match=True),
        repeat=_observation(canary_match=True, structural_identity_match=True),
        independent_repeat=True,
        rollback_required=True,
    )
    with_rollback = complete_bundle.model_copy(
        update={"rollback": _observation(state_effect=True)}
    )
    intended_sharing = complete_bundle.model_copy(
        update={
            "trial": _observation(
                canary_match=True,
                structural_identity_match=True,
                intended_sharing=True,
            )
        }
    )
    terminal_stop = complete_bundle.model_copy(
        update={
            "trial": _observation(
                canary_match=True,
                stop=black_box_hunter.BlackBoxStop(reason="third_party_data_detected"),
            )
        }
    )

    assert black_box_hunter.evaluate_differential_evidence(
        complete_bundle.model_copy(
            update={"owner_control": None, "session_control": None}
        )
    ).status == "hypothesis"
    assert black_box_hunter.evaluate_differential_evidence(complete_bundle).status == "reproduced"
    assert black_box_hunter.evaluate_differential_evidence(with_rollback).status == "review_ready"
    assert black_box_hunter.evaluate_differential_evidence(intended_sharing).status == "refuted"
    assert black_box_hunter.evaluate_differential_evidence(terminal_stop).status == "inconclusive"
