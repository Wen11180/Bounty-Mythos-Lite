from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from app.intelligence_benchmark.black_box_release_v1 import (
    METRIC_THRESHOLDS,
    evaluate_black_box_release_v1,
)
from app.intelligence_benchmark.black_box_release_runner import (
    DEFAULT_FIXTURE_ROOT,
    BlackBoxReleaseFixtureError,
    capture_black_box_release_inputs,
    load_black_box_release_gold,
    load_black_box_release_inputs,
    run_black_box_release_suite,
)
import app.intelligence_benchmark.black_box_release_runner as runner_module


TRIAL_CLASSES = (
    "cross_account_object_swap",
    "lower_role_replay",
    "unauthenticated_read_only_replay",
    "owned_parent_child_swap",
    "reversible_out_of_order_state_transition",
)


def _observation_set(*, rollback: bool = False) -> dict:
    observations = {
        "baseline_a": {
            "schema_ref": "shape_a",
            "status_class": "2xx",
            "structural_identity_match": True,
        },
        "baseline_b": {
            "schema_ref": "shape_a",
            "status_class": "2xx",
            "structural_identity_match": True,
        },
        "trial": {
            "canary_match": True,
            "schema_ref": "shape_b",
            "status_class": "2xx",
            "structural_identity_match": True,
        },
        "owner_control": {
            "schema_ref": "shape_c",
            "status_class": "2xx",
            "structural_identity_match": True,
        },
        "session_control": {
            "schema_ref": "shape_c",
            "status_class": "2xx",
            "structural_identity_match": True,
        },
        "repeat": {
            "canary_match": True,
            "schema_ref": "shape_b",
            "status_class": "2xx",
            "structural_identity_match": True,
        },
    }
    if rollback:
        observations["rollback"] = {
            "schema_ref": "shape_d",
            "state_effect": True,
            "status_class": "2xx",
        }
    return {
        "independent_repeat": True,
        "observations": observations,
        "rollback_required": rollback,
    }


def _input_document(split: str = "development") -> dict:
    return {
        "version": "black_box_release_inputs_v1",
        "split": split,
        "evidence_sets": {
            "set_a1": _observation_set(),
            "set_b2": _observation_set(rollback=True),
        },
        "cases": [
            {
                "case_id": f"opaque-{index:02d}",
                "evidence_set": "set_b2" if index == 4 else "set_a1",
                "priority_score": 100 - index,
                "route_template": f"/{noun}/{{object}}",
                "trial_class": trial_class,
            }
            for index, (trial_class, noun) in enumerate(
                zip(
                    TRIAL_CLASSES,
                    ("records", "entries", "items", "documents", "transitions"),
                    strict=True,
                )
            )
        ],
    }


def _gold_for(captured: list[dict], split: str = "development") -> dict:
    return {
        "version": "black_box_release_gold_v1",
        "split": split,
        "cases": [
            {
                "case_id": case["case_id"],
                "expected_status": case["decision"]["status"],
                "scenario_class": (
                    "retain"
                    if case["decision"]["status"] == "review_ready"
                    else "bounded_negative"
                ),
                "trial_class": case["trial_class"],
            }
            for case in captured
        ],
    }


def test_runner_builds_review_ready_candidates_from_all_five_trial_classes():
    captured = capture_black_box_release_inputs(_input_document())

    assert len(captured) == 5
    assert {case["trial_class"] for case in captured} == set(TRIAL_CLASSES)
    assert {case["decision"]["status"] for case in captured} == {"review_ready"}
    assert all(case["candidate"] is not None for case in captured)
    assert all(case["candidate"]["independent_reproduction"] for case in captured)
    assert all(case["safety"]["origin_class"] == "loopback" for case in captured)


def test_runner_refutes_intended_sharing_without_emitting_a_candidate():
    document = _input_document()
    document["evidence_sets"]["set_a1"]["observations"]["trial"][
        "intended_sharing"
    ] = True

    captured = capture_black_box_release_inputs(document)

    assert captured[0]["decision"] == {
        "reason": "intended_sharing_observed",
        "status": "refuted",
    }
    assert captured[0]["candidate"] is None


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (
            lambda document: document["cases"][0].update(
                {"expected_status": "review_ready"}
            ),
            "verdict_fields_forbidden",
        ),
        (
            lambda document: document["cases"][0].update(
                {"case_id": "vulnerable-record"}
            ),
            "case_id_must_be_opaque",
        ),
        (
            lambda document: document["cases"][0].update(
                {"route_template": "/safe-records/{object}"}
            ),
            "route_template_must_be_opaque",
        ),
    ],
)
def test_staged_inputs_reject_verdict_or_semantic_label_leakage(mutate, reason):
    document = _input_document()
    mutate(document)

    with pytest.raises(BlackBoxReleaseFixtureError, match=reason):
        capture_black_box_release_inputs(document)


def test_suite_captures_both_splits_before_loading_any_gold(monkeypatch, tmp_path: Path):
    events: list[str] = []
    documents = {
        "development_inputs.json": _input_document("development"),
        "held_out_inputs.json": _input_document("held_out"),
    }

    def load_inputs(path: Path):
        return documents[path.name]

    original_capture = runner_module.capture_black_box_release_inputs

    def capture(document):
        events.append(f"capture:{document['split']}")
        return original_capture(document)

    def load_gold(path: Path):
        events.append(f"gold:{path.name}")
        split = "development" if path.name.startswith("development") else "held_out"
        captured = original_capture(documents[f"{split}_inputs.json"])
        return _gold_for(captured, split)

    monkeypatch.setattr(runner_module, "load_black_box_release_inputs", load_inputs)
    monkeypatch.setattr(runner_module, "capture_black_box_release_inputs", capture)
    monkeypatch.setattr(runner_module, "load_black_box_release_gold", load_gold)

    result = run_black_box_release_suite(tmp_path)

    assert events == [
        "capture:development",
        "capture:held_out",
        "gold:development_gold.json",
        "gold:held_out_gold.json",
    ]
    assert result["events"] == ["all_candidates_captured", "gold_loaded"]


def test_opaque_id_order_route_and_schema_ref_perturbations_preserve_metrics():
    original_inputs = _input_document("held_out")
    original_capture = capture_black_box_release_inputs(original_inputs)
    original_gold = _gold_for(original_capture, "held_out")
    original = evaluate_black_box_release_v1(original_capture, original_gold)

    perturbed_inputs = copy.deepcopy(original_inputs)
    perturbed_inputs["cases"].reverse()
    id_map = {}
    for index, case in enumerate(perturbed_inputs["cases"]):
        old_id = case["case_id"]
        new_id = f"random-{index:02d}"
        id_map[old_id] = new_id
        case["case_id"] = new_id
        case["route_template"] = f"/units-{index}/{{object}}"
    for evidence in perturbed_inputs["evidence_sets"].values():
        for observation in evidence["observations"].values():
            observation["schema_ref"] = f"renamed-{observation['schema_ref']}"
    perturbed_gold = copy.deepcopy(original_gold)
    for case in perturbed_gold["cases"]:
        case["case_id"] = id_map[case["case_id"]]

    perturbed_capture = capture_black_box_release_inputs(perturbed_inputs)
    perturbed = evaluate_black_box_release_v1(perturbed_capture, perturbed_gold)

    assert perturbed["status"] == original["status"] == "passed"
    assert perturbed["metrics"] == original["metrics"]


def test_checked_in_release_corpus_passes_the_held_out_top_10_gate():
    result = run_black_box_release_suite(DEFAULT_FIXTURE_ROOT)

    assert result["events"] == ["all_candidates_captured", "gold_loaded"]
    assert result["held_out"]["evaluation"]["status"] == "passed"
    assert len(result["held_out"]["evaluation"]["top_10_candidate_ids"]) == 10
    for name, threshold in METRIC_THRESHOLDS.items():
        assert result["held_out"]["evaluation"]["metrics"][name]["value"] >= threshold
    assert result["development"]["trial_class_coverage"] == sorted(TRIAL_CLASSES)
    assert result["held_out"]["trial_class_coverage"] == sorted(TRIAL_CLASSES)


def test_checked_in_gold_covers_every_required_benign_negative():
    gold = load_black_box_release_gold(DEFAULT_FIXTURE_ROOT / "held_out_gold.json")
    negative_scenarios = {
        case["scenario_class"]
        for case in gold["cases"]
        if case["expected_status"] != "review_ready"
    }

    assert negative_scenarios == {
        "cache_difference",
        "correct_authorization",
        "csrf_rotation",
        "intended_sharing",
        "public_test_data",
        "rate_limit",
        "rollback_failure",
        "session_expiry",
    }
    assert {
        case["expected_status"]
        for case in gold["cases"]
        if case["scenario_class"] != "retain"
    } <= {"refuted", "inconclusive"}


def test_checked_in_inputs_are_gold_free_and_load_without_hidden_labels():
    for split in ("development", "held_out"):
        path = DEFAULT_FIXTURE_ROOT / f"{split}_inputs.json"
        source = path.read_text(encoding="utf-8")
        document = load_black_box_release_inputs(path)

        assert document["split"] == split
        assert "expected_status" not in source
        assert "scenario_class" not in source
        assert '"label"' not in source
        assert '"verdict"' not in source
        assert '"gold"' not in source
