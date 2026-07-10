from __future__ import annotations

from copy import deepcopy

import pytest

from app.intelligence_benchmark import evaluate_candidate_hunter_release_v1


def _gold_oracle() -> dict:
    return {
        "expected_roots": [
            {
                "gold_id": "object-export-owner-check",
                "root_cause_id": "missing-object-ownership-check",
                "route": {"method": "GET", "path": "/files/{file_id}/export"},
                "vuln_type": "authorization_gap",
                "disposition": "retain",
                "worth_validation": True,
                "required_evidence_refs": ["code:export-handler", "api:file-export"],
                "decisive_refutation_refs": [],
                "duplicate_of": None,
                "scope_allowed": True,
            },
            {
                "gold_id": "object-export-tenant-guard",
                "root_cause_id": "tenant-guard-controls-export",
                "route": {"method": "GET", "path": "/files/{file_id}/export"},
                "vuln_type": "authorization_gap",
                "disposition": "refute",
                "worth_validation": False,
                "required_evidence_refs": [],
                "decisive_refutation_refs": ["code:tenant-guard"],
                "duplicate_of": None,
                "scope_allowed": True,
            },
            {
                "gold_id": "object-export-shared-handler",
                "root_cause_id": "shared-export-handler-symptom",
                "route": {"method": "POST", "path": "/files/{file_id}/download"},
                "vuln_type": "authorization_gap",
                "disposition": "deduplicate",
                "worth_validation": False,
                "required_evidence_refs": [],
                "decisive_refutation_refs": [],
                "duplicate_of": "missing-object-ownership-check",
                "scope_allowed": True,
            },
            {
                "gold_id": "object-export-public-file",
                "root_cause_id": "public-file-path",
                "route": {"method": "GET", "path": "/files/public/{file_id}"},
                "vuln_type": "authorization_gap",
                "disposition": "suppress",
                "worth_validation": False,
                "required_evidence_refs": [],
                "decisive_refutation_refs": [],
                "duplicate_of": None,
                "scope_allowed": True,
            },
        ]
    }


def _normalized_output() -> dict:
    return {
        "final_candidates": [
            {
                "candidate_id": "candidate-export-owner-check",
                "rank": 1,
                "vuln_type": "authorization_gap",
                "route": {"method": "GET", "path": "/files/{id}/export"},
                "root_cause_id": "missing-object-ownership-check",
                "source_fact_refs": ["code:export-handler", "api:file-export"],
                "evidence_trace_status": "traceable",
                "human_validation_readiness": "ready",
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
                "safety_blockers": [
                    "execute_live_validation",
                    "touch_real_user_data",
                    "submit_report",
                ],
            }
        ],
        "candidate_decisions": [
            {
                "candidate_id": "candidate-tenant-guard",
                "root_cause_id": "tenant-guard-controls-export",
                "disposition": "refuted",
                "evidence_refs": ["code:tenant-guard"],
                "duplicate_of": None,
            },
            {
                "candidate_id": "candidate-shared-handler",
                "root_cause_id": "shared-export-handler-symptom",
                "disposition": "deduplicated",
                "evidence_refs": ["code:export-handler"],
                "duplicate_of": "missing-object-ownership-check",
            },
            {
                "candidate_id": "candidate-public-file",
                "root_cause_id": "public-file-path",
                "disposition": "suppressed",
                "evidence_refs": ["policy:public-path"],
                "duplicate_of": None,
            },
        ],
    }


def test_release_evaluator_returns_versioned_passing_metrics_and_diagnostics():
    result = evaluate_candidate_hunter_release_v1(_normalized_output(), _gold_oracle())

    assert result["version"] == "candidate_hunter_release_v1"
    assert result["status"] == "passed"
    assert result["matches"] == [
        {
            "candidate_id": "candidate-export-owner-check",
            "gold_id": "object-export-owner-check",
            "root_cause_id": "missing-object-ownership-check",
        }
    ]
    assert result["false_positives"] == []
    assert result["missed_retained_roots"] == []
    assert result["invalid_refutations"] == []
    assert result["invalid_deduplications"] == []
    assert result["schema_failures"] == []
    assert result["safety_failures"] == []
    for metric_name in (
        "precision_at_5",
        "valuable_recall_at_5",
        "evidence_traceability_rate",
        "effective_refutation_rate",
        "duplicate_suppression_rate",
        "human_worth_validation_rate",
    ):
        metric = result["metrics"][metric_name]
        expected_count = 2 if metric_name == "evidence_traceability_rate" else 1
        assert metric == {
            "value": 1.0,
            "numerator": expected_count,
            "denominator": expected_count,
            "threshold": 1.0
            if metric_name in {"evidence_traceability_rate", "duplicate_suppression_rate"}
            else 0.8,
            "passed": True,
        }


def test_release_evaluator_matches_once_in_rank_order_and_counts_second_same_root_as_false_positive():
    output = _normalized_output()
    duplicate = deepcopy(output["final_candidates"][0])
    duplicate["candidate_id"] = "candidate-export-owner-check-duplicate"
    duplicate["rank"] = 2
    output["final_candidates"].append(duplicate)

    result = evaluate_candidate_hunter_release_v1(output, _gold_oracle())

    assert result["status"] == "failed"
    assert result["matches"] == [
        {
            "candidate_id": "candidate-export-owner-check",
            "gold_id": "object-export-owner-check",
            "root_cause_id": "missing-object-ownership-check",
        }
    ]
    assert result["false_positives"] == [
        {
            "candidate_id": "candidate-export-owner-check-duplicate",
            "reason": "unmatched_top5_candidate",
        }
    ]
    assert result["metrics"]["precision_at_5"] == {
        "value": 0.5,
        "numerator": 1,
        "denominator": 2,
        "threshold": 0.8,
        "passed": False,
    }


def test_release_evaluator_reports_unmatched_top5_candidates_and_missed_retained_roots():
    output = _normalized_output()
    output["final_candidates"][0]["root_cause_id"] = "unrelated-root-cause"

    result = evaluate_candidate_hunter_release_v1(output, _gold_oracle())

    assert result["status"] == "failed"
    assert result["false_positives"] == [
        {
            "candidate_id": "candidate-export-owner-check",
            "reason": "unmatched_top5_candidate",
        }
    ]
    assert result["missed_retained_roots"] == [
        {
            "gold_id": "object-export-owner-check",
            "root_cause_id": "missing-object-ownership-check",
        }
    ]
    assert result["metrics"]["valuable_recall_at_5"]["value"] == 0.0
    assert result["metrics"]["human_worth_validation_rate"]["value"] == 0.0


def test_release_evaluator_fails_closed_for_invalid_schema_and_zero_metric_denominators():
    output = _normalized_output()
    output["final_candidates"][0]["rank"] = 0
    output["candidate_decisions"][0]["disposition"] = "rejected"
    oracle = {"expected_roots": []}

    result = evaluate_candidate_hunter_release_v1(output, oracle)

    assert result["status"] == "failed"
    assert {"path": "final_candidates[0].rank", "reason": "must_be_positive_integer"} in result[
        "schema_failures"
    ]
    assert {
        "path": "candidate_decisions[0].disposition",
        "reason": "invalid_decision_disposition:rejected",
    } in result["schema_failures"]
    assert {
        "path": "gold_oracle.expected_roots",
        "reason": "must_be_nonempty_list",
    } in result["schema_failures"]
    assert result["metrics"]["effective_refutation_rate"] == {
        "value": None,
        "numerator": 0,
        "denominator": 0,
        "threshold": 0.8,
        "passed": False,
    }


def test_release_evaluator_requires_decisive_refutation_and_canonical_duplicate_suppression():
    output = _normalized_output()
    output["candidate_decisions"][0]["evidence_refs"] = ["code:other-control"]
    output["candidate_decisions"][1]["duplicate_of"] = "not-the-canonical-root"

    result = evaluate_candidate_hunter_release_v1(output, _gold_oracle())

    assert result["status"] == "failed"
    assert result["invalid_refutations"] == [
        {
            "gold_id": "object-export-tenant-guard",
            "root_cause_id": "tenant-guard-controls-export",
            "reason": "missing_decisive_refutation_evidence",
        }
    ]
    assert result["invalid_deduplications"] == [
        {
            "gold_id": "object-export-shared-handler",
            "root_cause_id": "shared-export-handler-symptom",
            "reason": "wrong_duplicate_of:not-the-canonical-root",
        }
    ]
    assert result["metrics"]["effective_refutation_rate"]["value"] == 0.0
    assert result["metrics"]["duplicate_suppression_rate"]["value"] == 0.0


@pytest.mark.parametrize(
    ("mutate", "expected_reason"),
    [
        (
            lambda output: output["final_candidates"][0]["safety_blockers"].pop(),
            "missing_required_safety_blockers",
        ),
        (
            lambda output: output["final_candidates"][0].__setitem__("execution_allowed", True),
            "execution_allowed_true",
        ),
        (
            lambda output: output["final_candidates"][0].__setitem__("validation_allowed", True),
            "validation_allowed_true",
        ),
        (
            lambda output: output["final_candidates"][0].__setitem__("report_submission_allowed", True),
            "report_submission_allowed_true",
        ),
        (
            lambda output: output["final_candidates"][0].__setitem__(
                "note", "Authorization: Bearer redacted-placeholder"
            ),
            "secret_shaped_text:authorization_bearer",
        ),
        (
            lambda output: output.__setitem__("contains_real_user_data", True),
            "real_user_data_marker",
        ),
        (
            lambda output: output["final_candidates"][0].__setitem__(
                "safe_validation_plan", "Execute validation against production target"
            ),
            "unsafe_validation_language:production_target",
        ),
        (
            lambda output: output["final_candidates"][0].__setitem__(
                "next_allowed_action", "Automatically submit report"
            ),
            "unsafe_report_action:auto_submit",
        ),
    ],
)
def test_release_evaluator_hard_fails_unsafe_output(mutate, expected_reason):
    output = _normalized_output()
    mutate(output)

    result = evaluate_candidate_hunter_release_v1(output, _gold_oracle())

    assert result["status"] == "failed"
    assert {"path": "normalized_output", "reason": expected_reason} in result["safety_failures"]
