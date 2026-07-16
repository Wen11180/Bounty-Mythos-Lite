import json

import pytest

from app.black_box_hunter.local_lab_pipeline import run_har_local_lab_pipeline


def _entry(method: str, url: str) -> dict:
    return {
        "request": {
            "method": method,
            "url": url,
            "headers": [
                {"name": "Cookie", "value": "session=SECRET"},
                {"name": "Authorization", "value": "Bearer SECRET"},
            ],
            "queryString": [],
        },
        "response": {
            "status": 200,
            "headers": [],
            "content": {"mimeType": "application/json", "text": "{\"id\":1}"},
        },
    }


def _har(entries: list[dict]) -> dict:
    return {"log": {"version": "1.2", "entries": entries}}


def _role_hars() -> dict[str, dict]:
    return {
        "role_a": _har([_entry("GET", "http://127.0.0.1/widgets/101")]),
        "role_b": _har([_entry("GET", "http://127.0.0.1/widgets/202")]),
    }


def _run(mode: str, **kwargs):
    return run_har_local_lab_pipeline(
        _role_hars(),
        mode=mode,
        local_lab=True,
        trial_classes={"cross_account_object_swap"},
        account_aliases={"role_a": "account_a", "role_b": "account_b"},
        role_aliases={"role_a": "member", "role_b": "viewer"},
        role_ranks={"role_a": 10, "role_b": 1},
        **kwargs,
    )


def test_local_lab_flag_required():
    with pytest.raises(ValueError, match="local_lab_flag_required"):
        run_har_local_lab_pipeline(_role_hars(), local_lab=False)


def test_bola_lab_retains_cross_account_candidate():
    result = _run("bola")
    assert result["mode"] == "local_lab_observe"
    assert result["execution_allowed"] is False
    assert result["report_submission_allowed"] is False
    assert result["raw_secrets_persisted"] is False

    obs = result["observations"][0]
    assert obs["plan_trial_class"] == "cross_account_object_swap"
    assert obs["evidence_status"] == "review_ready"
    assert obs["decision"] == "retained"

    retained = result["retained_candidates"]
    assert len(retained) == 1
    assert retained[0]["decision"] == "retained"
    assert "local_lab_controls_and_repeat_passed" in retained[0]["why_alive"]

    blob = json.dumps(result)
    assert "SECRET" not in blob
    assert "Bearer" not in blob


def test_guarded_lab_suppresses_non_vulnerable_cross_account():
    result = _run("guarded")
    obs = result["observations"][0]
    assert obs["evidence_status"] == "inconclusive"
    assert obs["decision"] == "suppressed"
    assert result["retained_candidates"] == []
    card = result["candidates"][0]
    assert card["decision"] == "suppressed"
    assert any("status_only" in item for item in card["why_dead_or_weak"])


def test_shared_lab_refutes_intended_sharing():
    result = _run("shared")
    obs = result["observations"][0]
    assert obs["evidence_status"] == "refuted"
    assert obs["decision"] == "refuted"
    assert result["retained_candidates"] == []
