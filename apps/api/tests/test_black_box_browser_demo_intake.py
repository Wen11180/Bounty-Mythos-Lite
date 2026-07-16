import json
import pickle

import pytest

from app.black_box_hunter.browser_demo_intake import (
    EphemeralSessionBroker,
    EphemeralSessionHandle,
    build_observed_workflow_model_from_broker,
    build_observed_workflow_model_from_browser_demo,
    run_browser_demo_local_lab_pipeline,
    run_browser_demo_plan_only_pipeline,
)
from app.cli import main


def _demo(
    *,
    account: str,
    role: str,
    rank: int,
    object_id: str,
    secret: bool = True,
) -> dict:
    package = {
        "account_alias": account,
        "role_alias": role,
        "role_rank": rank,
        "events": [
            {
                "method": "GET",
                "url": f"http://127.0.0.1/widgets/{object_id}?token=SHOULD_STRIP",
                "status": 200,
            }
        ],
    }
    if secret:
        package["auth_headers"] = {
            "Cookie": "session=SECRET_COOKIE",
            "Authorization": "Bearer SECRET_TOKEN",
        }
        package["auth_cookies"] = {"session": "SECRET_COOKIE"}
    return package


def test_session_handle_refuses_pickle_and_hides_auth():
    handle = EphemeralSessionHandle(
        session_ref="session_a",
        account_alias="account_a",
        role_alias="member",
        auth_headers={"Authorization": "Bearer SECRET_TOKEN"},
    )
    handle.record_demo_request(
        method="GET",
        url="http://127.0.0.1/widgets/101?access_token=SECRET",
        status=200,
    )
    with pytest.raises(TypeError, match="not_serializable"):
        pickle.dumps(handle)

    projection = handle.safe_projection()
    assert projection["has_auth_material"] is True
    assert projection["auth_material_exported"] is False
    blob = json.dumps(projection)
    assert "SECRET" not in blob
    assert "Bearer" not in blob

    har = handle.to_redacted_har()
    har_blob = json.dumps(har)
    assert "SECRET" not in har_blob
    assert "token=" not in har_blob
    assert har["log"]["entries"][0]["request"]["headers"] == []
    assert har["log"]["entries"][0]["request"]["url"] == "http://127.0.0.1/widgets/101"


def test_broker_dual_session_builds_same_workflow_model_shape():
    broker = EphemeralSessionBroker()
    with pytest.raises(TypeError, match="not_serializable"):
        pickle.dumps(broker)

    a = broker.open_session(
        session_ref="session_a",
        account_alias="account_a",
        role_alias="member",
        role_rank=10,
        auth_headers={"Cookie": "session=SECRET_A"},
    )
    b = broker.open_session(
        session_ref="session_b",
        account_alias="account_b",
        role_alias="viewer",
        role_rank=1,
        auth_headers={"Cookie": "session=SECRET_B"},
    )
    a.record_demo_request(method="GET", url="http://127.0.0.1/widgets/101")
    b.record_demo_request(method="GET", url="http://127.0.0.1/widgets/202")

    model = build_observed_workflow_model_from_broker(broker)
    accounts = {wf.session.account_alias for wf in model.workflows}
    assert accounts == {"account_a", "account_b"}
    assert all(wf.steps[0].route_template == "/widgets/{object}" for wf in model.workflows)

    proj = json.dumps(model.safe_projection())
    assert "SECRET" not in proj
    assert "101" not in proj  # raw ids aliased
    assert "202" not in proj

    broker.destroy_all()
    assert broker.active_session_refs() == []


def test_login_traffic_rejected():
    handle = EphemeralSessionHandle(
        session_ref="session_a",
        account_alias="account_a",
        role_alias="member",
    )
    with pytest.raises(ValueError, match="login_traffic_not_recordable"):
        handle.record_demo_request(
            method="POST",
            url="http://127.0.0.1/login",
            status=200,
        )


def test_event_payload_must_not_carry_headers():
    with pytest.raises(ValueError, match="demo_event_must_not_carry_secrets"):
        build_observed_workflow_model_from_browser_demo(
            {
                "account_alias": "account_a",
                "role_alias": "member",
                "events": [
                    {
                        "method": "GET",
                        "url": "http://127.0.0.1/widgets/101",
                        "headers": [{"name": "Cookie", "value": "x"}],
                    }
                ],
            },
            _demo(account="account_b", role="viewer", rank=1, object_id="202", secret=False),
        )


def test_plan_only_pipeline_blocks_execution_and_strips_secrets():
    result = run_browser_demo_plan_only_pipeline(
        _demo(account="account_a", role="member", rank=10, object_id="101"),
        _demo(account="account_b", role="viewer", rank=1, object_id="202"),
    )
    assert result["source"] == "browser_demo"
    assert result["schema_version"] == "browser_demo_plan_only_pipeline_v1"
    assert result["execution_allowed"] is False
    assert result["validation_allowed"] is False
    assert result["report_submission_allowed"] is False
    assert result["raw_secrets_persisted"] is False
    assert result["auth_material_exported"] is False
    assert any(
        c["plan_trial_class"] == "cross_account_object_swap"
        for c in result["candidates"]
    )
    blob = json.dumps(result)
    assert "SECRET" not in blob
    assert "Bearer" not in blob
    assert "SHOULD_STRIP" not in blob


def test_local_lab_bola_retains_from_browser_demo():
    result = run_browser_demo_local_lab_pipeline(
        _demo(account="account_a", role="member", rank=10, object_id="101"),
        _demo(account="account_b", role="viewer", rank=1, object_id="202"),
        mode="bola",
        local_lab=True,
    )
    assert result["source"] == "browser_demo"
    assert result["lab_mode"] == "bola"
    assert len(result["retained_candidates"]) == 1
    assert result["retained_candidates"][0]["decision"] == "retained"
    assert result["execution_allowed"] is False
    assert result["report_submission_allowed"] is False
    assert "SECRET" not in json.dumps(result)


def test_local_lab_guarded_and_shared_from_browser_demo():
    guarded = run_browser_demo_local_lab_pipeline(
        _demo(account="account_a", role="member", rank=10, object_id="101", secret=False),
        _demo(account="account_b", role="viewer", rank=1, object_id="202", secret=False),
        mode="guarded",
    )
    assert guarded["retained_candidates"] == []
    assert guarded["candidates"][0]["decision"] == "suppressed"

    shared = run_browser_demo_local_lab_pipeline(
        _demo(account="account_a", role="member", rank=10, object_id="101", secret=False),
        _demo(account="account_b", role="viewer", rank=1, object_id="202", secret=False),
        mode="shared",
    )
    assert shared["retained_candidates"] == []
    assert shared["candidates"][0]["decision"] == "refuted"


def test_local_lab_flag_required():
    with pytest.raises(ValueError, match="local_lab_flag_required"):
        run_browser_demo_local_lab_pipeline(
            _demo(account="account_a", role="member", rank=10, object_id="101", secret=False),
            _demo(account="account_b", role="viewer", rank=1, object_id="202", secret=False),
            local_lab=False,
        )


def test_black_box_demo_cli_bola(tmp_path, capsys):
    demo_a = tmp_path / "demo_a.json"
    demo_b = tmp_path / "demo_b.json"
    out = tmp_path / "out.json"
    demo_a.write_text(
        json.dumps(_demo(account="account_a", role="member", rank=10, object_id="101")),
        encoding="utf-8",
    )
    demo_b.write_text(
        json.dumps(_demo(account="account_b", role="viewer", rank=1, object_id="202")),
        encoding="utf-8",
    )

    code = main(
        [
            "black-box-demo",
            "--demo-a",
            str(demo_a),
            "--demo-b",
            str(demo_b),
            "--mode",
            "bola",
            "--out",
            str(out),
        ]
    )
    assert code == 0
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["source"] == "browser_demo"
    assert len(result["retained_candidates"]) == 1
    assert "SECRET" not in out.read_text(encoding="utf-8")
    captured = capsys.readouterr()
    assert "retained=1/" in captured.out


def test_black_box_demo_cli_plan_only(tmp_path):
    demo_a = tmp_path / "demo_a.json"
    demo_b = tmp_path / "demo_b.json"
    out = tmp_path / "plan.json"
    demo_a.write_text(
        json.dumps(
            _demo(account="account_a", role="member", rank=10, object_id="101", secret=False)
        ),
        encoding="utf-8",
    )
    demo_b.write_text(
        json.dumps(
            _demo(account="account_b", role="viewer", rank=1, object_id="202", secret=False)
        ),
        encoding="utf-8",
    )
    code = main(
        [
            "black-box-demo",
            "--demo-a",
            str(demo_a),
            "--demo-b",
            str(demo_b),
            "--plan-only",
            "--out",
            str(out),
        ]
    )
    assert code == 0
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["schema_version"] == "browser_demo_plan_only_pipeline_v1"
    assert result["execution_allowed"] is False
    assert all(c["decision"] == "needs_evidence" for c in result["candidates"])
