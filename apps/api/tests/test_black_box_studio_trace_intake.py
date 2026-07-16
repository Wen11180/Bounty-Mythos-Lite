"""Studio Playwright recording export -> dual-intake pipelines."""

import json

import pytest

from app.black_box_hunter.studio_trace_intake import (
    build_observed_workflow_model_from_studio_export,
    run_studio_trace_local_lab_pipeline,
    run_studio_trace_plan_only_pipeline,
)
from app.cli import main


def _trace(
    *,
    account: str,
    role: str,
    session: str,
    workflow: str,
    object_alias: str,
    method: str = "GET",
    route: str = "/widgets/{object}",
    param_name: str = "widget_id",
) -> dict:
    return {
        "method": method,
        "route_template": route,
        "parameters": [
            {"location": "path", "name": param_name, "value_type": "object_alias"},
        ],
        "aliases": {
            "account_alias": account,
            "object_aliases": [object_alias],
            "role_alias": role,
            "session_alias": session,
            "workflow_alias": workflow,
        },
        "status_class": "2xx",
        "response_schema_fingerprint": "sha256:" + ("a" * 64),
        "timing_bucket": "under_100ms",
    }


def _export(*, origin: str = "http://127.0.0.1:4100") -> dict:
    return {
        "schema_version": "studio_recording_export_v1",
        "source": "studio_playwright",
        "origin": origin,
        "traces": [
            _trace(
                account="account_a",
                role="member",
                session="session_a",
                workflow="workflow_a",
                object_alias="widget_a",
            ),
            _trace(
                account="account_b",
                role="viewer",
                session="session_b",
                workflow="workflow_b",
                object_alias="widget_b",
            ),
        ],
        "role_ranks": {"account_a": 10, "account_b": 1},
    }


def test_build_model_from_studio_export_aliases_and_routes():
    model = build_observed_workflow_model_from_studio_export(_export())
    accounts = {wf.session.account_alias for wf in model.workflows}
    assert accounts == {"account_a", "account_b"}
    assert all(wf.steps[0].route_template == "/widgets/{object}" for wf in model.workflows)
    assert all(wf.steps[0].origin == "http://127.0.0.1:4100" for wf in model.workflows)
    objects = {
        obj.alias
        for wf in model.workflows
        for obj in wf.objects
    }
    assert objects == {"widget_a", "widget_b"}
    proj = json.dumps(model.safe_projection())
    assert "Authorization" not in proj
    assert "Cookie" not in proj
    assert "507f1f77" not in proj


def test_rejects_secret_keys_in_export():
    export = _export()
    export["traces"][0]["headers"] = [{"name": "Cookie", "value": "x"}]
    with pytest.raises(ValueError, match="studio_export_secret_key_forbidden"):
        build_observed_workflow_model_from_studio_export(export)


def test_requires_two_accounts():
    export = _export()
    export["traces"] = [export["traces"][0]]
    with pytest.raises(ValueError, match="two_account_aliases_required"):
        build_observed_workflow_model_from_studio_export(export)


def test_plan_only_pipeline_blocks_execution():
    result = run_studio_trace_plan_only_pipeline(_export())
    assert result["source"] == "studio_playwright"
    assert result["schema_version"] == "studio_plan_only_pipeline_v1"
    assert result["mode"] == "plan_only"
    assert result["execution_allowed"] is False
    assert result["dispatch_allowed"] is False
    assert result["validation_allowed"] is False
    assert result["candidate_promotion_allowed"] is False
    assert result["report_submission_allowed"] is False
    assert result["raw_secrets_persisted"] is False
    assert result["plan_count"] >= 1
    assert "cross_account_object_swap" in result["plan_classes"]
    blob = json.dumps(result)
    assert "SECRET" not in blob
    assert "Bearer" not in blob


def test_local_lab_bola_retains_cross_account():
    result = run_studio_trace_local_lab_pipeline(
        _export(),
        mode="bola",
        local_lab=True,
        trial_classes={"cross_account_object_swap"},
    )
    assert result["source"] == "studio_playwright"
    assert result["schema_version"] == "studio_local_lab_pipeline_v1"
    assert result["mode"] == "local_lab_observe"
    assert result["execution_allowed"] is False
    assert result["report_submission_allowed"] is False
    retained = result["retained_candidates"]
    assert len(retained) == 1
    assert retained[0]["decision"] == "retained"
    assert retained[0]["plan_trial_class"] == "cross_account_object_swap"


def test_local_lab_guarded_suppresses():
    result = run_studio_trace_local_lab_pipeline(
        _export(),
        mode="guarded",
        local_lab=True,
        trial_classes={"cross_account_object_swap"},
    )
    assert result["execution_allowed"] is False
    decisions = {c["decision"] for c in result["candidates"]}
    assert "retained" not in decisions
    assert decisions & {"suppressed", "refuted", "needs_evidence"}


def test_cli_plan_only(tmp_path):
    recording = tmp_path / "recording.json"
    out = tmp_path / "out.json"
    recording.write_text(json.dumps(_export()), encoding="utf-8")
    code = main(
        [
            "black-box-studio-traces",
            "--recording",
            str(recording),
            "--plan-only",
            "--out",
            str(out),
        ]
    )
    assert code == 0
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["source"] == "studio_playwright"
    assert result["mode"] == "plan_only"
    assert result["execution_allowed"] is False


def test_cli_local_lab(tmp_path):
    recording = tmp_path / "recording.json"
    out = tmp_path / "out.json"
    recording.write_text(json.dumps(_export()), encoding="utf-8")
    code = main(
        [
            "black-box-studio-traces",
            "--recording",
            str(recording),
            "--mode",
            "bola",
            "--out",
            str(out),
        ]
    )
    assert code == 0
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["source"] == "studio_playwright"
    assert result["lab_mode"] == "bola"
    assert result["execution_allowed"] is False
    assert len(result["retained_candidates"]) == 1
