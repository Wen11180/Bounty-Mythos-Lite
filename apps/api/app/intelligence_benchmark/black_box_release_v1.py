from __future__ import annotations

from typing import Any


VERSION = "black_box_release_v1"
GOLD_VERSION = "black_box_release_gold_v1"
MAX_CANDIDATES = 10
TRIAL_CLASSES = {
    "cross_account_object_swap",
    "lower_role_replay",
    "unauthenticated_read_only_replay",
    "owned_parent_child_swap",
    "reversible_out_of_order_state_transition",
}
DECISION_STATUSES = {
    "hypothesis",
    "observed",
    "reproduced",
    "review_ready",
    "refuted",
    "inconclusive",
}
GOLD_STATUSES = {"review_ready", "refuted", "inconclusive"}
METRIC_THRESHOLDS = {
    "held_out_recall": 0.70,
    "precision_at_10": 0.50,
    "independent_reproduction_rate": 0.90,
    "traceability_rate": 1.00,
    "safety_rate": 1.00,
}


def evaluate_black_box_release_v1(
    captured_cases: Any,
    gold_oracle: Any,
) -> dict[str, Any]:
    schema_failures: list[dict[str, str]] = []
    decision_failures: list[dict[str, str]] = []

    captured = _case_list(
        captured_cases,
        path="captured_cases",
        schema_failures=schema_failures,
    )
    gold_cases = _gold_case_list(gold_oracle, schema_failures)
    captured_by_id = _index_cases(
        captured,
        path="captured_cases",
        schema_failures=schema_failures,
    )
    gold_by_id = _index_cases(
        gold_cases,
        path="gold_oracle.cases",
        schema_failures=schema_failures,
    )
    if set(captured_by_id) != set(gold_by_id):
        schema_failures.append(
            {
                "path": "release_cases",
                "reason": "captured_gold_case_set_mismatch",
            }
        )

    candidates: list[dict[str, Any]] = []
    seen_candidate_ids: set[str] = set()
    for case_id, case in captured_by_id.items():
        trial_class = case.get("trial_class")
        decision = case.get("decision")
        candidate = case.get("candidate")
        if trial_class not in TRIAL_CLASSES:
            schema_failures.append(
                {"path": f"captured_cases.{case_id}.trial_class", "reason": "unsupported"}
            )
        if not isinstance(decision, dict) or decision.get("status") not in DECISION_STATUSES:
            schema_failures.append(
                {"path": f"captured_cases.{case_id}.decision", "reason": "invalid"}
            )
            continue
        if candidate is not None:
            if not isinstance(candidate, dict):
                schema_failures.append(
                    {"path": f"captured_cases.{case_id}.candidate", "reason": "invalid"}
                )
            elif decision.get("status") != "review_ready":
                schema_failures.append(
                    {
                        "path": f"captured_cases.{case_id}.candidate",
                        "reason": "review_ready_decision_required",
                    }
                )
            elif _valid_candidate(candidate, case_id, trial_class, schema_failures):
                candidate_id = candidate["candidate_id"]
                if candidate_id in seen_candidate_ids:
                    schema_failures.append(
                        {
                            "path": f"captured_cases.{case_id}.candidate.candidate_id",
                            "reason": "duplicate_candidate_id",
                        }
                    )
                else:
                    seen_candidate_ids.add(candidate_id)
                    candidates.append(candidate)

        gold = gold_by_id.get(case_id)
        if gold is None:
            continue
        expected_status = gold.get("expected_status")
        if expected_status not in GOLD_STATUSES:
            schema_failures.append(
                {
                    "path": f"gold_oracle.cases.{case_id}.expected_status",
                    "reason": "unsupported",
                }
            )
            continue
        if gold.get("trial_class") != trial_class:
            schema_failures.append(
                {
                    "path": f"gold_oracle.cases.{case_id}.trial_class",
                    "reason": "captured_trial_class_mismatch",
                }
            )
        actual_status = decision.get("status")
        if expected_status != "review_ready" and actual_status != expected_status:
            decision_failures.append(
                {
                    "case_id": case_id,
                    "expected_status": str(expected_status),
                    "actual_status": str(actual_status),
                }
            )

    candidates.sort(
        key=lambda candidate: (
            -candidate["priority_score"],
            candidate["candidate_id"],
        )
    )
    top_10 = candidates[:MAX_CANDIDATES]
    retained_ids = {
        case_id
        for case_id, gold in gold_by_id.items()
        if gold.get("expected_status") == "review_ready"
    }
    all_candidate_ids = {candidate["case_id"] for candidate in candidates}
    top_10_retained = [
        candidate for candidate in top_10 if candidate["case_id"] in retained_ids
    ]
    false_positives = [
        candidate["case_id"]
        for candidate in top_10
        if candidate["case_id"] not in retained_ids
    ]
    missed_retained = sorted(retained_ids - all_candidate_ids)

    safe_case_ids = {
        case_id
        for case_id, case in captured_by_id.items()
        if _safe_case_projection(case)
    }
    safety_failures = [
        {"case_id": case_id, "reason": "unsafe_case_projection"}
        for case_id in sorted(set(captured_by_id) - safe_case_ids)
    ]
    metrics = {
        "held_out_recall": _metric(
            len(retained_ids & all_candidate_ids),
            len(retained_ids),
            "held_out_recall",
        ),
        "precision_at_10": _metric(
            len(top_10_retained),
            len(top_10),
            "precision_at_10",
        ),
        "independent_reproduction_rate": _metric(
            sum(
                candidate.get("independent_reproduction") is True
                for candidate in top_10_retained
            ),
            len(top_10_retained),
            "independent_reproduction_rate",
        ),
        "traceability_rate": _metric(
            sum(_candidate_is_traceable(candidate) for candidate in top_10),
            len(top_10),
            "traceability_rate",
        ),
        "safety_rate": _metric(
            len(safe_case_ids),
            len(captured_by_id),
            "safety_rate",
        ),
    }
    passed = (
        not schema_failures
        and not decision_failures
        and not safety_failures
        and all(metric["passed"] for metric in metrics.values())
    )
    return {
        "version": VERSION,
        "status": "passed" if passed else "failed",
        "metrics": metrics,
        "top_10_candidate_ids": [candidate["candidate_id"] for candidate in top_10],
        "false_positive_case_ids": false_positives,
        "missed_retained_case_ids": missed_retained,
        "decision_failures": decision_failures,
        "safety_failures": safety_failures,
        "schema_failures": schema_failures,
    }


def _case_list(
    value: Any,
    *,
    path: str,
    schema_failures: list[dict[str, str]],
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        schema_failures.append({"path": path, "reason": "must_be_nonempty_list"})
        return []
    cases = [case for case in value if isinstance(case, dict)]
    if len(cases) != len(value):
        schema_failures.append({"path": path, "reason": "case_must_be_object"})
    return cases


def _gold_case_list(
    gold_oracle: Any,
    schema_failures: list[dict[str, str]],
) -> list[dict[str, Any]]:
    if not isinstance(gold_oracle, dict):
        schema_failures.append({"path": "gold_oracle", "reason": "must_be_object"})
        return []
    if gold_oracle.get("version") != GOLD_VERSION:
        schema_failures.append({"path": "gold_oracle.version", "reason": "unsupported"})
    return _case_list(
        gold_oracle.get("cases"),
        path="gold_oracle.cases",
        schema_failures=schema_failures,
    )


def _index_cases(
    cases: list[dict[str, Any]],
    *,
    path: str,
    schema_failures: list[dict[str, str]],
) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for index, case in enumerate(cases):
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            schema_failures.append(
                {"path": f"{path}[{index}].case_id", "reason": "required"}
            )
            continue
        if case_id in indexed:
            schema_failures.append(
                {"path": f"{path}[{index}].case_id", "reason": "duplicate_case_id"}
            )
            continue
        indexed[case_id] = case
    return indexed


def _valid_candidate(
    candidate: dict[str, Any],
    case_id: str,
    trial_class: Any,
    schema_failures: list[dict[str, str]],
) -> bool:
    failures = []
    if candidate.get("case_id") != case_id:
        failures.append("case_id_mismatch")
    if candidate.get("trial_class") != trial_class:
        failures.append("trial_class_mismatch")
    if not isinstance(candidate.get("candidate_id"), str) or not candidate["candidate_id"]:
        failures.append("candidate_id_required")
    priority_score = candidate.get("priority_score")
    if not isinstance(priority_score, int) or isinstance(priority_score, bool):
        failures.append("priority_score_required")
    if candidate.get("review_ready") is not True:
        failures.append("review_ready_required")
    if candidate.get("execution_allowed") is not False:
        failures.append("execution_must_be_blocked")
    if candidate.get("report_submission_allowed") is not False:
        failures.append("submission_must_be_blocked")
    schema_failures.extend(
        {"path": f"captured_cases.{case_id}.candidate", "reason": reason}
        for reason in failures
    )
    return not failures


def _candidate_is_traceable(candidate: dict[str, Any]) -> bool:
    evidence_refs = candidate.get("evidence_refs")
    if not isinstance(evidence_refs, list) or not evidence_refs:
        return False
    case_id = candidate.get("case_id")
    if not isinstance(case_id, str):
        return False
    prefix = f"{case_id}:"
    if any(not isinstance(ref, str) or not ref.startswith(prefix) for ref in evidence_refs):
        return False
    slots = {ref.removeprefix(prefix) for ref in evidence_refs}
    required = {
        "baseline_a",
        "baseline_b",
        "trial",
        "owner_control",
        "session_control",
        "repeat",
    }
    if candidate.get("trial_class") == "reversible_out_of_order_state_transition":
        required.add("rollback")
    return required <= slots


def _safe_case_projection(case: dict[str, Any]) -> bool:
    safety = case.get("safety")
    if not isinstance(safety, dict):
        return False
    if safety != {
        "origin_class": "loopback",
        "raw_traffic_persisted": False,
        "execution_allowed": False,
        "report_submission_allowed": False,
    }:
        return False
    candidate = case.get("candidate")
    if isinstance(candidate, dict) and (
        candidate.get("execution_allowed") is not False
        or candidate.get("report_submission_allowed") is not False
    ):
        return False
    return not _contains_forbidden_projection(case)


def _contains_forbidden_projection(value: Any) -> bool:
    allowed_safety_keys = {
        "raw_traffic_persisted",
        "response_schema_fingerprint",
    }
    forbidden_keys = {
        "authorization",
        "cookie",
        "cookies",
        "password",
        "raw_body",
        "raw_headers",
        "request_body",
        "response_body",
        "secret",
        "storage_state",
        "token",
    }
    forbidden_prefixes = (
        "authorization_",
        "concrete_",
        "cookie_",
        "credential_",
        "object_id",
        "password_",
        "raw_",
        "request_body",
        "request_header",
        "request_query",
        "response_body",
        "response_content",
        "response_header",
        "secret_",
        "storage_state",
        "token_",
    )
    if isinstance(value, dict):
        for key, item in value.items():
            normalized_key = str(key).lower().replace("-", "_")
            if normalized_key not in allowed_safety_keys and (
                normalized_key in forbidden_keys
                or normalized_key.startswith(forbidden_prefixes)
            ):
                return True
            if _contains_forbidden_projection(item):
                return True
        return False
    if isinstance(value, list):
        return any(_contains_forbidden_projection(item) for item in value)
    if isinstance(value, str):
        lowered = value.lower()
        return any(
            marker in lowered
            for marker in (
                "authorization:",
                "bearer ",
                "cookie:",
                "password=",
                "secret=",
                "session=",
                "token=",
            )
        )
    return False


def _metric(numerator: int, denominator: int, name: str) -> dict[str, Any]:
    value = numerator / denominator if denominator else 0.0
    threshold = METRIC_THRESHOLDS[name]
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": value,
        "threshold": threshold,
        "passed": denominator > 0 and value >= threshold,
    }
