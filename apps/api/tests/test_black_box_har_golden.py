from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.cli import main
from app.intelligence_benchmark.black_box_har_golden import (
    BlackBoxHarGoldenError,
    assert_intake_isomorphism,
    assert_safe_pipeline_result,
    default_fixture_root,
    evaluate_har_golden,
    list_golden_packages,
    run_all_har_golden_packages,
    run_har_golden_package,
)


FIXTURE_ROOT = default_fixture_root()
EXPECTED_PACKAGES = {
    "retain_bola_widgets",
    "retain_lower_role_widgets",
    "retain_unauth_widgets",
    "retain_multi_family_bola",
    "retain_parent_child_bola",
    "retain_state_transition_bola",
    "refute_guarded_widgets",
    "refute_shared_widgets",
    "refute_lower_role_guarded_widgets",
    "refute_unauth_guarded_widgets",
    "refute_parent_child_guarded",
    "refute_state_transition_rollback",
}


def test_default_fixture_root_contains_multi_family_packages():
    packages = list_golden_packages(FIXTURE_ROOT)
    ids = {path.name for path in packages}
    assert ids == EXPECTED_PACKAGES


def test_retain_bola_package_gate_passes_with_falsify_attempts():
    package = FIXTURE_ROOT / "retain_bola_widgets"
    result = run_har_golden_package(package)

    assert result["schema_version"] == "black_box_har_golden_result_v1"
    assert result["package_id"] == "retain_bola_widgets"
    assert result["lab_mode"] == "bola"
    assert result["execution_allowed"] is False
    assert result["report_submission_allowed"] is False
    assert result["gate"]["passed"] is True
    assert result["safety"]["safe"] is True
    assert result["gate"]["observed_statuses"] == ["retained"]

    top = result["top_candidates"]
    assert top
    assert top[0]["decision"] == "retained"
    assert top[0]["plan_trial_class"] == "cross_account_object_swap"
    assert top[0]["falsify_attempts"]
    assert all(item["outcome"] == "survive" for item in top[0]["falsify_attempts"])
    assert top[0]["falsify_attempts"][0]["rule_id"].startswith("differential:")

    blob = json.dumps(result)
    assert "SECRET" not in blob
    assert "Bearer" not in blob
    assert "leak-me" not in blob


def test_retain_lower_role_and_unauth_packages_gate_pass():
    for package_id, trial_class in (
        ("retain_lower_role_widgets", "lower_role_replay"),
        ("retain_unauth_widgets", "unauthenticated_read_only_replay"),
    ):
        result = run_har_golden_package(FIXTURE_ROOT / package_id)
        assert result["gate"]["passed"] is True, package_id
        assert result["safety"]["safe"] is True, package_id
        matching = [
            card
            for card in result["top_candidates"]
            if card.get("plan_trial_class") == trial_class
        ]
        assert matching
        assert matching[0]["decision"] == "retained"
        assert all(item["outcome"] == "survive" for item in matching[0]["falsify_attempts"])


def test_retain_multi_family_bola_package_retains_three_classes():
    result = run_har_golden_package(FIXTURE_ROOT / "retain_multi_family_bola")
    assert result["gate"]["passed"] is True
    retained = {
        card["plan_trial_class"]
        for card in result["top_candidates"]
        if card.get("decision") == "retained"
    }
    assert retained >= {
        "cross_account_object_swap",
        "lower_role_replay",
        "unauthenticated_read_only_replay",
    }
    # retained should rank ahead of any non-retained
    ranks = {card["plan_trial_class"]: card["rank"] for card in result["top_candidates"]}
    assert ranks["cross_account_object_swap"] <= 3


def test_refute_guarded_package_gate_passes_and_kills():
    package = FIXTURE_ROOT / "refute_guarded_widgets"
    result = run_har_golden_package(package)

    assert result["package_id"] == "refute_guarded_widgets"
    assert result["lab_mode"] == "guarded"
    assert result["gate"]["passed"] is True
    assert result["safety"]["safe"] is True
    assert result["retained_candidates"] == []

    matching = [
        card
        for card in result["top_candidates"]
        if card.get("plan_trial_class") == "cross_account_object_swap"
    ]
    assert matching
    assert matching[0]["decision"] == "suppressed"
    assert matching[0]["falsify_attempts"]
    kills = [
        item for item in matching[0]["falsify_attempts"] if item["outcome"] == "kill"
    ]
    assert kills

    blob = json.dumps(result)
    assert "SECRET" not in blob
    assert "Bearer" not in blob


def test_refute_shared_package_gate_passes_and_refutes():
    package = FIXTURE_ROOT / "refute_shared_widgets"
    result = run_har_golden_package(package)

    assert result["package_id"] == "refute_shared_widgets"
    assert result["lab_mode"] == "shared"
    assert result["gate"]["passed"] is True
    assert result["safety"]["safe"] is True
    assert result["retained_candidates"] == []

    matching = [
        card
        for card in result["top_candidates"]
        if card.get("plan_trial_class") == "cross_account_object_swap"
    ]
    assert matching
    assert matching[0]["decision"] == "refuted"
    assert matching[0]["decision_reason"] == "intended_sharing_observed"
    kills = [
        item for item in matching[0]["falsify_attempts"] if item["outcome"] == "kill"
    ]
    assert kills
    assert any("intended_sharing" in item["rule_id"] for item in kills)

    blob = json.dumps(result)
    assert "SECRET" not in blob
    assert "Bearer" not in blob


def test_refute_family_guarded_packages_kill():
    for package_id, trial_class in (
        ("refute_lower_role_guarded_widgets", "lower_role_replay"),
        ("refute_unauth_guarded_widgets", "unauthenticated_read_only_replay"),
    ):
        result = run_har_golden_package(FIXTURE_ROOT / package_id)
        assert result["gate"]["passed"] is True, package_id
        matching = [
            card
            for card in result["top_candidates"]
            if card.get("plan_trial_class") == trial_class
        ]
        assert matching
        assert matching[0]["decision"] == "suppressed"
        assert any(
            item["outcome"] == "kill" for item in matching[0]["falsify_attempts"]
        )


def test_retain_parent_child_and_state_packages_gate_pass():
    for package_id, trial_class in (
        ("retain_parent_child_bola", "owned_parent_child_swap"),
        ("retain_state_transition_bola", "reversible_out_of_order_state_transition"),
    ):
        result = run_har_golden_package(FIXTURE_ROOT / package_id)
        assert result["gate"]["passed"] is True, package_id
        assert result["safety"]["safe"] is True, package_id
        matching = [
            card
            for card in result["top_candidates"]
            if card.get("plan_trial_class") == trial_class
        ]
        assert matching
        assert any(card.get("decision") == "retained" for card in matching)


def test_refute_parent_child_and_state_packages_kill():
    for package_id, trial_class in (
        ("refute_parent_child_guarded", "owned_parent_child_swap"),
        ("refute_state_transition_rollback", "reversible_out_of_order_state_transition"),
    ):
        result = run_har_golden_package(FIXTURE_ROOT / package_id)
        assert result["gate"]["passed"] is True, package_id
        matching = [
            card
            for card in result["top_candidates"]
            if card.get("plan_trial_class") == trial_class
        ]
        assert matching
        assert all(card.get("decision") != "retained" for card in matching)


def test_all_golden_packages_gate_passes():
    summary = run_all_har_golden_packages(FIXTURE_ROOT)
    assert summary["schema_version"] == "black_box_har_golden_gate_v1"
    assert summary["package_count"] == len(EXPECTED_PACKAGES)
    assert summary["passed"] is True
    assert summary["failed_packages"] == []
    assert summary["execution_allowed"] is False
    assert summary["report_submission_allowed"] is False


def test_evaluate_har_golden_fails_when_retain_missing():
    pipeline = {
        "execution_allowed": False,
        "report_submission_allowed": False,
        "raw_secrets_persisted": False,
        "candidates": [
            {
                "candidate_id": "x",
                "plan_trial_class": "cross_account_object_swap",
                "decision": "suppressed",
                "falsify_attempts": [{"attempt_id": "a", "rule_id": "r", "outcome": "kill"}],
            }
        ],
    }
    manifest = {
        "package_id": "x",
        "expected_status": "retained",
        "expected_trial_class": "cross_account_object_swap",
        "top_n": 5,
    }
    gate = evaluate_har_golden(pipeline, manifest)
    assert gate["passed"] is False
    assert any("expected_retained_missing" in item for item in gate["failures"])


def test_dual_intake_isomorphism_for_retain_package():
    result = assert_intake_isomorphism(FIXTURE_ROOT / "retain_bola_widgets")
    assert result["passed"] is True
    assert "cross_account_object_swap" in result["har_plan_classes"]
    assert result["har_plan_classes"] == result["demo_plan_classes"]
    assert result["har_routes"] == result["demo_routes"]
    assert result["failures"] == []


def test_dual_intake_isomorphism_for_refute_package():
    result = assert_intake_isomorphism(FIXTURE_ROOT / "refute_guarded_widgets")
    assert result["passed"] is True
    assert result["har_plan_classes"] == result["demo_plan_classes"]


def test_dual_intake_isomorphism_for_shared_package():
    result = assert_intake_isomorphism(FIXTURE_ROOT / "refute_shared_widgets")
    assert result["passed"] is True
    assert result["har_plan_classes"] == result["demo_plan_classes"]


def test_missing_package_dir_raises():
    with pytest.raises(BlackBoxHarGoldenError, match="package_dir_required"):
        run_har_golden_package(FIXTURE_ROOT / "does_not_exist")


def test_cli_black_box_golden_package_writes_safe_json(tmp_path, capsys):
    out = tmp_path / "retain.json"
    code = main(
        [
            "black-box-golden",
            "--package",
            str(FIXTURE_ROOT / "retain_bola_widgets"),
            "--out",
            str(out),
        ]
    )
    assert code == 0
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["gate"]["passed"] is True
    assert result["safety"]["safe"] is True
    blob = out.read_text(encoding="utf-8")
    assert "SECRET" not in blob
    assert "Bearer" not in blob
    captured = capsys.readouterr()
    assert "gate_passed=True" in captured.out


def test_cli_black_box_golden_all_writes_summary(tmp_path, capsys):
    out_dir = tmp_path / "all"
    code = main(
        [
            "black-box-golden",
            "--all",
            "--root",
            str(FIXTURE_ROOT),
            "--out-dir",
            str(out_dir),
        ]
    )
    assert code == 0
    summary = json.loads((out_dir / "gate-summary.json").read_text(encoding="utf-8"))
    assert summary["passed"] is True
    assert summary["package_count"] == len(EXPECTED_PACKAGES)
    for package_id in EXPECTED_PACKAGES:
        assert (out_dir / f"{package_id}.json").is_file()
    captured = capsys.readouterr()
    assert "passed=True" in captured.out


def test_cli_black_box_golden_requires_package_or_all(capsys):
    code = main(["black-box-golden", "--out", "x.json"])
    assert code == 2
    captured = capsys.readouterr()
    assert "black-box-golden" in captured.err


def test_assert_safe_pipeline_result_detects_secret_leak():
    safety = assert_safe_pipeline_result({"raw": "Bearer SECRET", "execution_allowed": False})
    assert safety["safe"] is False
    assert safety["high_risk_marker_count"] >= 1
