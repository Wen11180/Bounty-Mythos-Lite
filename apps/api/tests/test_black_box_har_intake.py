import json

from app.black_box_hunter import plan_differential_trials
from app.black_box_hunter.har_intake import (
    build_observed_workflow_model_from_role_hars,
    redact_har_document,
    run_har_plan_only_pipeline,
)


def _entry(method: str, url: str, *, cookie: str = "session=SECRET", auth: str = "Bearer SECRET") -> dict:
    return {
        "request": {
            "method": method,
            "url": url,
            "headers": [
                {"name": "Cookie", "value": cookie},
                {"name": "Authorization", "value": auth},
                {"name": "Accept", "value": "application/json"},
            ],
            "queryString": [
                {"name": "access_token", "value": "leak-me"},
                {"name": "page", "value": "1"},
            ],
        },
        "response": {
            "status": 200,
            "headers": [{"name": "Set-Cookie", "value": "session=SECRET"}],
            "content": {
                "mimeType": "application/json",
                "text": '{"password":"nope","id":1}',
            },
        },
    }


def _har(entries: list[dict]) -> dict:
    return {"log": {"version": "1.2", "entries": entries}}


def test_redact_har_strips_secrets_and_bodies():
    raw = _har(
        [
            _entry("GET", "http://127.0.0.1/widgets/101?access_token=leak-me"),
        ]
    )
    redacted = redact_har_document(raw)
    blob = json.dumps(redacted)
    assert "SECRET" not in blob
    assert "leak-me" not in blob
    assert "password" not in blob
    assert "[REDACTED]" in blob
    assert redacted["log"]["entries"][0]["response"]["content"]["text"] == ""


def test_role_hars_build_model_with_aliases_not_raw_ids():
    role_hars = {
        "role_a": _har(
            [
                _entry("GET", "http://127.0.0.1/widgets/101"),
                _entry("POST", "http://127.0.0.1/widgets"),
            ]
        ),
        "role_b": _har(
            [
                _entry("GET", "http://127.0.0.1/widgets/202"),
            ]
        ),
    }
    model = build_observed_workflow_model_from_role_hars(
        role_hars,
        account_aliases={"role_a": "account_a", "role_b": "account_b"},
        role_aliases={"role_a": "member", "role_b": "viewer"},
        role_ranks={"role_a": 10, "role_b": 1},
    )
    projection = model.safe_projection()
    blob = json.dumps(projection)
    assert "101" not in blob
    assert "202" not in blob
    assert "SECRET" not in blob
    assert "Bearer" not in blob
    assert len(projection["workflows"]) == 2
    assert all(workflow["baseline_stable"] for workflow in projection["workflows"])
    routes = {
        step["route_template"]
        for workflow in projection["workflows"]
        for step in workflow["steps"]
    }
    assert "/widgets/{object}" in routes


def test_har_plan_only_pipeline_emits_cross_account_without_execution():
    role_hars = {
        "role_a": _har([_entry("GET", "http://127.0.0.1/widgets/101")]),
        "role_b": _har([_entry("GET", "http://127.0.0.1/widgets/202")]),
    }
    result = run_har_plan_only_pipeline(
        role_hars,
        account_aliases={"role_a": "account_a", "role_b": "account_b"},
        role_aliases={"role_a": "member", "role_b": "viewer"},
        role_ranks={"role_a": 10, "role_b": 1},
    )
    assert result["mode"] == "plan_only"
    assert result["execution_allowed"] is False
    assert result["validation_allowed"] is False
    assert result["report_submission_allowed"] is False
    assert result["raw_secrets_persisted"] is False
    assert "cross_account_object_swap" in result["plan_classes"]
    assert result["plan_count"] >= 3
    # Parent/child and state transition are optional for sparse HARs.
    assert "owned_parent_child_swap" not in result["plan_classes"]
    assert result["candidates"]
    top = result["candidates"][0]
    assert top["decision"] == "needs_evidence"
    assert top["execution_allowed"] is False
    assert "lease_bound_or_local_lab_observation_required" in top["evidence_gaps"]
    blob = json.dumps(result)
    assert "SECRET" not in blob
    assert "Bearer" not in blob


def test_require_all_classes_still_enforced_for_full_planner_default():
    role_hars = {
        "role_a": _har([_entry("GET", "http://127.0.0.1/widgets/101")]),
        "role_b": _har([_entry("GET", "http://127.0.0.1/widgets/202")]),
    }
    model = build_observed_workflow_model_from_role_hars(
        role_hars,
        account_aliases={"role_a": "account_a", "role_b": "account_b"},
        role_aliases={"role_a": "member", "role_b": "viewer"},
        role_ranks={"role_a": 10, "role_b": 1},
    )
    try:
        plan_differential_trials(model, require_all_classes=True)
        raised = False
    except ValueError as exc:
        raised = True
        assert "owned_parent_child_relationship_required" in str(exc)
    assert raised is True


def test_nested_har_binds_parent_alias_and_plans_parent_child():
    role_hars = {
        "role_a": _har(
            [
                _entry("GET", "http://127.0.0.1/widgets/101/items/301"),
                _entry("GET", "http://127.0.0.1/widgets/102"),
            ]
        ),
        "role_b": _har(
            [
                _entry("GET", "http://127.0.0.1/widgets/202"),
            ]
        ),
    }
    model = build_observed_workflow_model_from_role_hars(
        role_hars,
        account_aliases={"role_a": "account_a", "role_b": "account_b"},
        role_aliases={"role_a": "member", "role_b": "viewer"},
        role_ranks={"role_a": 10, "role_b": 1},
    )
    source = max(model.workflows, key=lambda workflow: workflow.role_rank or 0)
    children = [obj for obj in source.objects if obj.parent_alias is not None]
    assert len(children) == 1
    parents = [obj for obj in source.objects if obj.parent_alias is None]
    assert len(parents) >= 2
    plans = plan_differential_trials(model, require_all_classes=False)
    assert any(plan.trial_class == "owned_parent_child_swap" for plan in plans)
    routes = {
        step.route_template
        for workflow in model.workflows
        for step in workflow.steps
    }
    assert any("/items/{object}" in route for route in routes)
    blob = model.safe_projection()
    assert "101" not in json.dumps(blob)
    assert "301" not in json.dumps(blob)
