from __future__ import annotations

import json

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
            "content": {"mimeType": "application/json", "text": '{"id":1}'},
        },
    }


def _har(entries: list[dict]) -> dict:
    return {"log": {"version": "1.2", "entries": entries}}


def _role_hars() -> dict[str, dict]:
    return {
        "role_a": _har([_entry("GET", "http://127.0.0.1/widgets/101")]),
        "role_b": _har([_entry("GET", "http://127.0.0.1/widgets/202")]),
    }


def _run(mode: str, trial_classes: set[str] | None = None) -> dict:
    return run_har_local_lab_pipeline(
        _role_hars(),
        mode=mode,
        local_lab=True,
        trial_classes=trial_classes or {"cross_account_object_swap"},
        account_aliases={"role_a": "account_a", "role_b": "account_b"},
        role_aliases={"role_a": "member", "role_b": "viewer"},
        role_ranks={"role_a": 10, "role_b": 1},
    )


def test_bola_candidate_includes_survive_falsify_attempt():
    result = _run("bola")
    card = result["candidates"][0]
    assert card["decision"] == "retained"
    attempts = card["falsify_attempts"]
    assert len(attempts) >= 1
    assert all(item["outcome"] == "survive" for item in attempts)
    assert all(item["rule_id"].startswith("differential:") for item in attempts)
    assert attempts[-1]["evidence_refs"]
    assert card["decision_reason"]


def test_guarded_candidate_includes_kill_falsify_attempt():
    result = _run("guarded")
    card = result["candidates"][0]
    assert card["decision"] == "suppressed"
    attempts = card["falsify_attempts"]
    kills = [item for item in attempts if item["outcome"] == "kill"]
    assert kills
    assert any(
        "status_only" in item["rule_id"] or "status_only" in card["decision_reason"]
        for item in kills
    ) or "status_only" in card["decision_reason"]
    blob = json.dumps(result)
    assert "SECRET" not in blob


def test_shared_candidate_includes_intended_sharing_kill():
    result = _run("shared")
    card = result["candidates"][0]
    assert card["decision"] == "refuted"
    attempts = card["falsify_attempts"]
    kills = [item for item in attempts if item["outcome"] == "kill"]
    assert kills
    assert any("intended_sharing" in item["rule_id"] for item in kills)
    assert card["decision_reason"] == "intended_sharing_observed"
    blob = json.dumps(result)
    assert "SECRET" not in blob


def test_unauth_bola_retains_with_multi_step_survive():
    result = _run("bola", {"unauthenticated_read_only_replay"})
    card = result["candidates"][0]
    assert card["plan_trial_class"] == "unauthenticated_read_only_replay"
    assert card["decision"] == "retained"
    assert all(item["outcome"] == "survive" for item in card["falsify_attempts"])
    assert len(card["falsify_attempts"]) >= 3


def test_unauth_guarded_kills_weak_signal():
    result = _run("guarded", {"unauthenticated_read_only_replay"})
    card = result["candidates"][0]
    assert card["decision"] == "suppressed"
    assert any(item["outcome"] == "kill" for item in card["falsify_attempts"])


def test_multi_family_bola_ranks_retained_first():
    result = _run(
        "bola",
        {
            "cross_account_object_swap",
            "lower_role_replay",
            "unauthenticated_read_only_replay",
        },
    )
    assert len(result["candidates"]) == 3
    assert all(card["decision"] == "retained" for card in result["candidates"])
    ranks = [card["rank"] for card in result["candidates"]]
    assert ranks == sorted(ranks)
    assert ranks == [1, 2, 3]
