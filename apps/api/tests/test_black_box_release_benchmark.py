from __future__ import annotations

from app.intelligence_benchmark.black_box_release_v1 import (
    METRIC_THRESHOLDS,
    VERSION,
    evaluate_black_box_release_v1,
)


TRIAL_CLASSES = (
    "cross_account_object_swap",
    "lower_role_replay",
    "unauthenticated_read_only_replay",
    "owned_parent_child_swap",
    "reversible_out_of_order_state_transition",
)


def _captured_case(
    case_id: str,
    *,
    status: str = "review_ready",
    priority_score: int = 90,
    reproduced: bool = True,
    safe: bool = True,
    traceable: bool = True,
    trial_class: str = TRIAL_CLASSES[0],
) -> dict:
    evidence_slots = [
        "baseline_a",
        "baseline_b",
        "trial",
        "owner_control",
        "session_control",
        "repeat",
    ]
    if trial_class == "reversible_out_of_order_state_transition":
        evidence_slots.append("rollback")
    candidate = None
    if status == "review_ready":
        candidate = {
            "candidate_id": f"candidate-{case_id}",
            "case_id": case_id,
            "priority_score": priority_score,
            "trial_class": trial_class,
            "route_template": "/records/{object}",
            "independent_reproduction": reproduced,
            "evidence_refs": (
                [f"{case_id}:{slot}" for slot in evidence_slots]
                if traceable
                else []
            ),
            "review_ready": True,
            "execution_allowed": False,
            "report_submission_allowed": False,
        }
    return {
        "case_id": case_id,
        "trial_class": trial_class,
        "decision": {
            "status": status,
            "reason": "bounded_differential_evidence_complete",
        },
        "candidate": candidate,
        "safety": {
            "origin_class": "loopback",
            "raw_traffic_persisted": not safe,
            "execution_allowed": False,
            "report_submission_allowed": False,
        },
    }


def _gold_case(
    case_id: str,
    *,
    expected_status: str = "review_ready",
    scenario_class: str = "retain",
    trial_class: str = TRIAL_CLASSES[0],
) -> dict:
    return {
        "case_id": case_id,
        "expected_status": expected_status,
        "scenario_class": scenario_class,
        "trial_class": trial_class,
    }


def test_black_box_release_v1_passes_independent_top_10_metrics():
    captured = [
        _captured_case(
            f"opaque-{index:02d}",
            priority_score=100 - index,
            trial_class=TRIAL_CLASSES[index % len(TRIAL_CLASSES)],
        )
        for index in range(10)
    ]
    gold_cases = [
        _gold_case(
            case["case_id"],
            trial_class=case["trial_class"],
        )
        for case in captured
    ]
    for index, status in enumerate(("refuted", "inconclusive"), start=10):
        case_id = f"opaque-{index:02d}"
        trial_class = TRIAL_CLASSES[index % len(TRIAL_CLASSES)]
        captured.append(
            _captured_case(
                case_id,
                status=status,
                trial_class=trial_class,
            )
        )
        gold_cases.append(
            _gold_case(
                case_id,
                expected_status=status,
                scenario_class="bounded_negative",
                trial_class=trial_class,
            )
        )

    result = evaluate_black_box_release_v1(
        captured,
        {"cases": gold_cases, "version": "black_box_release_gold_v1"},
    )

    assert result["version"] == VERSION
    assert result["status"] == "passed"
    assert result["top_10_candidate_ids"] == [
        f"candidate-opaque-{index:02d}" for index in range(10)
    ]
    assert {
        name: metric["value"] for name, metric in result["metrics"].items()
    } == {
        "held_out_recall": 1.0,
        "precision_at_10": 1.0,
        "independent_reproduction_rate": 1.0,
        "traceability_rate": 1.0,
        "safety_rate": 1.0,
    }
    assert result["decision_failures"] == []
    assert result["safety_failures"] == []
    assert result["schema_failures"] == []


def test_black_box_release_v1_uses_the_approved_thresholds():
    assert METRIC_THRESHOLDS == {
        "held_out_recall": 0.70,
        "precision_at_10": 0.50,
        "independent_reproduction_rate": 0.90,
        "traceability_rate": 1.00,
        "safety_rate": 1.00,
    }


def test_black_box_release_v1_fails_wrong_negative_decisions_and_false_positives():
    captured = [
        _captured_case("opaque-a", status="review_ready"),
        _captured_case("opaque-b", status="inconclusive"),
    ]
    gold = {
        "version": "black_box_release_gold_v1",
        "cases": [
            _gold_case(
                "opaque-a",
                expected_status="refuted",
                scenario_class="intended_sharing",
            ),
            _gold_case(
                "opaque-b",
                expected_status="refuted",
                scenario_class="public_test_data",
            ),
        ],
    }

    result = evaluate_black_box_release_v1(captured, gold)

    assert result["status"] == "failed"
    assert result["metrics"]["precision_at_10"]["value"] == 0.0
    assert {failure["case_id"] for failure in result["decision_failures"]} == {
        "opaque-a",
        "opaque-b",
    }


def test_black_box_release_v1_requires_reproduction_traceability_and_safety():
    captured = [
        _captured_case(
            "opaque-a",
            reproduced=False,
            safe=False,
            traceable=False,
        )
    ]
    gold = {
        "version": "black_box_release_gold_v1",
        "cases": [_gold_case("opaque-a")],
    }

    result = evaluate_black_box_release_v1(captured, gold)

    assert result["status"] == "failed"
    assert result["metrics"]["independent_reproduction_rate"]["value"] == 0.0
    assert result["metrics"]["traceability_rate"]["value"] == 0.0
    assert result["metrics"]["safety_rate"]["value"] == 0.0
    assert result["safety_failures"] == [
        {"case_id": "opaque-a", "reason": "unsafe_case_projection"}
    ]


def test_black_box_release_v1_rejects_sensitive_projection_key_variants():
    captured = [_captured_case("opaque-a")]
    captured[0]["candidate"]["authorization_header"] = "synthetic-value"
    gold = {
        "version": "black_box_release_gold_v1",
        "cases": [_gold_case("opaque-a")],
    }

    result = evaluate_black_box_release_v1(captured, gold)

    assert result["status"] == "failed"
    assert result["safety_failures"] == [
        {"case_id": "opaque-a", "reason": "unsafe_case_projection"}
    ]


def test_black_box_release_v1_rejects_mismatched_or_duplicate_case_sets():
    captured = [
        _captured_case("opaque-a"),
        _captured_case("opaque-a"),
    ]
    gold = {
        "version": "black_box_release_gold_v1",
        "cases": [_gold_case("opaque-b")],
    }

    result = evaluate_black_box_release_v1(captured, gold)

    assert result["status"] == "failed"
    assert {failure["reason"] for failure in result["schema_failures"]} >= {
        "duplicate_case_id",
        "captured_gold_case_set_mismatch",
    }
