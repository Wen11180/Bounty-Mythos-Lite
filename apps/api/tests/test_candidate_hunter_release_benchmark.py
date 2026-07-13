from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from app.cli import main as cli_main
from app.intelligence_benchmark import (
    evaluate_candidate_hunter_release_suite_v1,
    evaluate_candidate_hunter_release_v1,
)


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
                "candidate_promotion_allowed": False,
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
                "candidate_id": "candidate-export-owner-check",
                "root_cause_id": "missing-object-ownership-check",
                "disposition": "retained",
                "evidence_refs": ["code:export-handler", "api:file-export"],
                "duplicate_of": None,
            },
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
    output["candidate_decisions"][1]["evidence_refs"] = ["code:other-control"]
    output["candidate_decisions"][2]["duplicate_of"] = "not-the-canonical-root"

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
            lambda output: output["final_candidates"][0].__setitem__(
                "candidate_promotion_allowed", True
            ),
            "candidate_promotion_allowed_true",
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


@pytest.mark.parametrize(
    ("mutate", "expected_reason"),
    [
        (
            lambda output: output["final_candidates"][0].pop("execution_allowed"),
            "execution_allowed_not_false",
        ),
        (
            lambda output: output["final_candidates"][0].__setitem__(
                "validation_allowed", "false"
            ),
            "validation_allowed_not_false",
        ),
        (
            lambda output: output["final_candidates"][0].pop(
                "candidate_promotion_allowed"
            ),
            "candidate_promotion_allowed_not_false",
        ),
        (
            lambda output: output["final_candidates"][0].__setitem__(
                "candidate_promotion_allowed", None
            ),
            "candidate_promotion_allowed_not_false",
        ),
        (
            lambda output: output["final_candidates"][0].__setitem__(
                "candidate_promotion_allowed", "false"
            ),
            "candidate_promotion_allowed_not_false",
        ),
        (
            lambda output: output["final_candidates"][0].__setitem__(
                "report_submission_allowed", None
            ),
            "report_submission_allowed_not_false",
        ),
        (
            lambda output: output["final_candidates"][0].__setitem__(
                "safe_validation_plan", ["Execute validation against production target"]
            ),
            "unsafe_validation_language:production_target",
        ),
        (
            lambda output: output["final_candidates"][0].__setitem__(
                "next_allowed_action", ["Automatically submit report"]
            ),
            "unsafe_report_action:auto_submit",
        ),
    ],
)
def test_release_evaluator_fails_closed_for_missing_or_non_scalar_safety_fields(
    mutate, expected_reason
):
    output = _normalized_output()
    mutate(output)

    result = evaluate_candidate_hunter_release_v1(output, _gold_oracle())

    assert result["status"] == "failed"
    assert {"path": "normalized_output", "reason": expected_reason} in result["safety_failures"]


@pytest.mark.parametrize(
    ("field", "value", "expected_reason"),
    [
        ("headers", {"Authorization": "Bearer synthetic-placeholder"}, "authorization"),
        ("headers", {"Cookie": "session=synthetic-placeholder"}, "cookie"),
        ("credentials", {"password": "synthetic-placeholder"}, "password"),
        ("credentials", {"apiKey": "synthetic-placeholder"}, "api_key"),
    ],
)
def test_release_evaluator_rejects_structured_sensitive_values(
    field, value, expected_reason
):
    output = _normalized_output()
    output["final_candidates"][0][field] = value

    result = evaluate_candidate_hunter_release_v1(output, _gold_oracle())

    assert result["status"] == "failed"
    assert {
        "path": "normalized_output",
        "reason": f"secret_shaped_text:{expected_reason}",
    } in result["safety_failures"]


def test_release_evaluator_requires_in_scope_gold_and_canonical_deduplication_ids():
    output = _normalized_output()
    oracle = _gold_oracle()
    oracle["expected_roots"][0]["scope_allowed"] = False
    oracle["expected_roots"][2]["duplicate_of"] = None
    output["candidate_decisions"][2]["duplicate_of"] = None

    result = evaluate_candidate_hunter_release_v1(output, oracle)

    assert result["status"] == "failed"
    assert {
        "path": "gold_oracle.expected_roots[0].scope_allowed",
        "reason": "must_be_true",
    } in result["schema_failures"]
    assert {
        "path": "gold_oracle.expected_roots[2].duplicate_of",
        "reason": "must_be_nonempty_string",
    } in result["schema_failures"]
    assert {
        "path": "candidate_decisions[2].duplicate_of",
        "reason": "must_be_nonempty_string",
    } in result["schema_failures"]


def test_release_evaluator_rejects_ambiguous_decisions_and_missing_suppression():
    output = _normalized_output()
    conflicting_decision = deepcopy(output["candidate_decisions"][0])
    conflicting_decision["disposition"] = "suppressed"
    output["candidate_decisions"].append(conflicting_decision)
    output["candidate_decisions"] = [
        decision
        for decision in output["candidate_decisions"]
        if decision["disposition"] != "suppressed" or decision is conflicting_decision
    ]

    result = evaluate_candidate_hunter_release_v1(output, _gold_oracle())

    assert result["status"] == "failed"
    assert {
        "path": "candidate_decisions[3].root_cause_id",
        "reason": "must_be_unique",
    } in result["schema_failures"]
    assert result["invalid_suppressions"] == [
        {
            "gold_id": "object-export-public-file",
            "root_cause_id": "public-file-path",
            "reason": "suppressed_decision_missing",
        }
    ]


@pytest.mark.parametrize(
    ("mutate", "expected_reason"),
    [
        (
            lambda output: output["candidate_decisions"][0].__setitem__(
                "execution_allowed", True
            ),
            "execution_allowed_true",
        ),
        (
            lambda output: output["candidate_decisions"][0].__setitem__(
                "safe_validation_plan", ["Send live outbound request against production target"]
            ),
            "unsafe_validation_language:production_target",
        ),
        (
            lambda output: output.__setitem__("contains_real_user_data", "true"),
            "real_user_data_marker",
        ),
        (
            lambda output: output["final_candidates"][0].__setitem__(
                "metadata", {"Authorization": 7}
            ),
            "secret_shaped_text:authorization",
        ),
        (
            lambda output: output["final_candidates"][0].__setitem__(
                "evidence_trace_status", "not_traceable"
            ),
            "evidence_trace_not_traceable",
        ),
    ],
)
def test_release_evaluator_scans_all_output_records_and_requires_traceability(
    mutate, expected_reason
):
    output = _normalized_output()
    mutate(output)

    result = evaluate_candidate_hunter_release_v1(output, _gold_oracle())

    assert result["status"] == "failed"
    assert {"path": "normalized_output", "reason": expected_reason} in result["safety_failures"]


def test_release_evaluator_rejects_terminal_roots_in_final_candidates():
    output = _normalized_output()
    output["final_candidates"][0]["root_cause_id"] = "public-file-path"
    output["final_candidates"][0]["route"] = {
        "method": "GET",
        "path": "/files/public/{file_id}",
    }

    result = evaluate_candidate_hunter_release_v1(output, _gold_oracle())

    assert result["status"] == "failed"
    assert result["invalid_suppressions"] == [
        {
            "gold_id": "object-export-public-file",
            "root_cause_id": "public-file-path",
            "reason": "suppressed_root_present_in_final_candidates",
        }
    ]


def test_release_evaluator_requires_retained_non_self_canonical_duplicate_root():
    output = _normalized_output()
    oracle = _gold_oracle()
    oracle["expected_roots"][2]["duplicate_of"] = "tenant-guard-controls-export"
    output["candidate_decisions"][2]["duplicate_of"] = "tenant-guard-controls-export"

    result = evaluate_candidate_hunter_release_v1(output, oracle)

    assert result["status"] == "failed"
    assert {
        "path": "gold_oracle.expected_roots[2].duplicate_of",
        "reason": "canonical_root_must_retain",
    } in result["schema_failures"]

    oracle = _gold_oracle()
    oracle["expected_roots"][2]["duplicate_of"] = "shared-export-handler-symptom"
    output = _normalized_output()
    output["candidate_decisions"][2]["duplicate_of"] = "shared-export-handler-symptom"

    result = evaluate_candidate_hunter_release_v1(output, oracle)

    assert result["status"] == "failed"
    assert {
        "path": "gold_oracle.expected_roots[2].duplicate_of",
        "reason": "canonical_root_must_differ",
    } in result["schema_failures"]


def test_release_evaluator_rejects_candidate_template_over_literal_gold_segment():
    output = _normalized_output()
    output["final_candidates"][0]["route"]["path"] = "/files/{anything}/{anything}"

    result = evaluate_candidate_hunter_release_v1(output, _gold_oracle())

    assert result["status"] == "failed"
    assert result["matches"] == []
    assert result["missed_retained_roots"] == [
        {
            "gold_id": "object-export-owner-check",
            "root_cause_id": "missing-object-ownership-check",
        }
    ]


def test_release_evaluator_rejects_duplicate_gold_roots_and_non_string_references():
    oracle = _gold_oracle()
    duplicate_root = deepcopy(oracle["expected_roots"][1])
    duplicate_root["gold_id"] = "duplicate-refutation-root"
    oracle["expected_roots"].append(duplicate_root)
    output = _normalized_output()
    output["final_candidates"][0]["source_fact_refs"].append({"ref": "code:bad"})
    oracle["expected_roots"][0]["required_evidence_refs"].append({"ref": "api:bad"})

    result = evaluate_candidate_hunter_release_v1(output, oracle)

    assert result["status"] == "failed"
    assert {
        "path": "gold_oracle.expected_roots[4].root_cause_id",
        "reason": "must_be_unique",
    } in result["schema_failures"]
    assert {
        "path": "final_candidates[0].source_fact_refs",
        "reason": "must_contain_nonempty_strings_only",
    } in result["schema_failures"]
    assert {
        "path": "gold_oracle.expected_roots[0].required_evidence_refs",
        "reason": "must_contain_nonempty_strings_only",
    } in result["schema_failures"]


def test_release_evaluator_rejects_unstructured_bearer_values_without_rejecting_safe_refs():
    output = _normalized_output()
    output["final_candidates"][0]["source_fact_refs"].append(
        "code:access_token_helper"
    )

    safe_result = evaluate_candidate_hunter_release_v1(output, _gold_oracle())

    assert safe_result["status"] == "passed"
    assert safe_result["safety_failures"] == []

    output["candidate_decisions"][0]["review_note"] = (
        "Authorization: Bearer synthetic-placeholder"
    )
    unsafe_result = evaluate_candidate_hunter_release_v1(output, _gold_oracle())

    assert unsafe_result["status"] == "failed"
    assert {
        "path": "normalized_output",
        "reason": "secret_shaped_text:authorization_bearer",
    } in unsafe_result["safety_failures"]


def test_release_evaluator_distinguishes_token_count_from_a_token_value():
    output = _normalized_output()
    output["final_candidates"][0]["metadata"] = {"token_count": 1}

    safe_result = evaluate_candidate_hunter_release_v1(output, _gold_oracle())

    assert safe_result["status"] == "passed"
    output["final_candidates"][0]["metadata"] = {
        "summary": {"Token": "synthetic-placeholder"}
    }
    unsafe_result = evaluate_candidate_hunter_release_v1(output, _gold_oracle())

    assert unsafe_result["status"] == "failed"
    assert {
        "path": "normalized_output",
        "reason": "secret_shaped_text:token",
    } in unsafe_result["safety_failures"]


def test_release_evaluator_cli_writes_versioned_passing_result(tmp_path: Path):
    output_path = tmp_path / "hunter-output.json"
    gold_path = tmp_path / "gold.json"
    result_path = tmp_path / "result.json"
    output_path.write_text(json.dumps(_normalized_output()), encoding="utf-8")
    gold_path.write_text(json.dumps(_gold_oracle()), encoding="utf-8")

    exit_code = cli_main(
        [
            "candidate-hunter-release-eval",
            "--hunter-output",
            str(output_path),
            "--gold",
            str(gold_path),
            "--output",
            str(result_path),
        ]
    )

    assert exit_code == 0
    result = json.loads(result_path.read_text(encoding="utf-8"))
    assert result["version"] == "candidate_hunter_release_v1"
    assert result["status"] == "passed"


def test_release_evaluator_cli_returns_nonzero_for_failed_gate(tmp_path: Path):
    output = _normalized_output()
    output["final_candidates"][0]["execution_allowed"] = True
    output_path = tmp_path / "hunter-output.json"
    gold_path = tmp_path / "gold.json"
    result_path = tmp_path / "result.json"
    output_path.write_text(json.dumps(output), encoding="utf-8")
    gold_path.write_text(json.dumps(_gold_oracle()), encoding="utf-8")

    exit_code = cli_main(
        [
            "candidate-hunter-release-eval",
            "--hunter-output",
            str(output_path),
            "--gold",
            str(gold_path),
            "--output",
            str(result_path),
        ]
    )

    assert exit_code == 1
    assert json.loads(result_path.read_text(encoding="utf-8"))["status"] == "failed"


def test_release_suite_evaluator_aggregates_independent_case_metrics():
    result = evaluate_candidate_hunter_release_suite_v1(
        [
            {
                "case_id": "release-case-one",
                "normalized_output": _normalized_output(),
                "gold_oracle": _gold_oracle(),
            },
            {
                "case_id": "release-case-two",
                "normalized_output": _normalized_output(),
                "gold_oracle": _gold_oracle(),
            },
        ]
    )

    assert result["version"] == "candidate_hunter_release_suite_v1"
    assert result["status"] == "passed"
    assert result["metrics"]["precision_at_5"] == {
        "value": 1.0,
        "numerator": 2,
        "denominator": 2,
        "threshold": 0.8,
        "passed": True,
    }
    assert result["case_diagnostics"] == [
        {"case_id": "release-case-one", "status": "passed"},
        {"case_id": "release-case-two", "status": "passed"},
    ]
    assert result["matches"] == [
        {
            "case_id": "release-case-one",
            "candidate_id": "candidate-export-owner-check",
            "gold_id": "object-export-owner-check",
            "root_cause_id": "missing-object-ownership-check",
        },
        {
            "case_id": "release-case-two",
            "candidate_id": "candidate-export-owner-check",
            "gold_id": "object-export-owner-check",
            "root_cause_id": "missing-object-ownership-check",
        },
    ]
    assert result["false_positives"] == []
    assert result["missed_retained_roots"] == []


def test_release_suite_evaluator_keeps_zero_denominators_as_suite_failures():
    retain_only_oracle = {"expected_roots": [_gold_oracle()["expected_roots"][0]]}

    result = evaluate_candidate_hunter_release_suite_v1(
        [
            {
                "case_id": "retain-only",
                "normalized_output": _normalized_output(),
                "gold_oracle": retain_only_oracle,
            }
        ]
    )

    assert result["status"] == "failed"
    assert {
        "path": "metrics.effective_refutation_rate",
        "reason": "zero_denominator",
    } in result["schema_failures"]
    assert result["case_diagnostics"] == [
        {"case_id": "retain-only", "status": "passed"}
    ]

def test_release_evaluator_rejects_final_candidates_without_retained_decisions():
    output = _normalized_output()
    output["candidate_decisions"] = [
        decision
        for decision in output["candidate_decisions"]
        if decision["disposition"] != "retained"
    ]

    result = evaluate_candidate_hunter_release_v1(output, _gold_oracle())

    assert result["status"] == "failed"
    assert {
        "path": "final_candidates[0].candidate_id",
        "reason": "missing_retained_decision",
    } in result["schema_failures"]


def test_release_evaluator_rejects_empty_decisions_when_final_candidates_exist():
    output = _normalized_output()
    output["candidate_decisions"] = []

    result = evaluate_candidate_hunter_release_v1(output, _gold_oracle())

    assert result["status"] == "failed"
    assert {
        "path": "final_candidates[0].candidate_id",
        "reason": "missing_retained_decision",
    } in result["schema_failures"]
