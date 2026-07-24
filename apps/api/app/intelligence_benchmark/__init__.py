from __future__ import annotations

import json
import re
from typing import Any


REQUIRED_SAFETY_BLOCKERS = {
    "execute_live_validation",
    "touch_real_user_data",
    "submit_report",
}
ADVISORY_ARTIFACT_FACT_TYPES = {
    "sarif": "scanner_signal",
    "sbom": "dependency_signal",
    "fuzzing": "fuzzing_signal",
    "strategy": "strategy_signal",
}
DEFAULT_FORBIDDEN_TEXT = [
    "Authorization: Bearer",
    "Cookie",
    "access_token",
    "secret-token",
]
REQUIRED_STUDIO_ARTIFACTS = ["scope", "policy", "code", "api", "har"]
UNSAFE_VALIDATION_PLAN_PATTERNS = {
    "live_outbound_request": ["send live outbound", "execute live outbound"],
    "production_target": ["against production", "production target"],
    "real_user_data": ["inspect real user data", "collect real user data"],
}
UNSAFE_REPORT_NEXT_ACTION_PATTERNS = {
    "submit_report": ["submit the report", "auto submit", "automatically submit"],
    "execute_validation": ["execute validation", "run validation"],
}


def build_studio_expectations_template(candidates_payload: Any) -> dict:
    candidates = _candidate_list(candidates_payload)[:5]
    expected_candidates = []
    for candidate in candidates:
        route = _first_candidate_route(candidate)
        if not route:
            continue
        expected: dict[str, Any] = {
            "name": _expectation_name(candidate, route),
            "route_method": route.get("route_method", ""),
            "route_path": route.get("route_path", ""),
            "vuln_type": _candidate_vuln_type(candidate),
            "required_artifacts": _candidate_artifact_kinds(candidate),
            "require_code_path": True,
            "require_refutation_status": True,
            "require_security_invariant": True,
            "require_impact_rationale": True,
            "require_repair_guidance": True,
            "require_regression_test": True,
            "require_policy_risk": True,
            "require_policy_review": True,
            "require_evidence_review": True,
            "require_provenance_review": True,
            "require_deduplication_review": True,
            "require_refutation_review": True,
            "require_validation_review": True,
            "max_duplicate_risk_score": 49,
            "max_policy_risk_score": 49,
        }
        code_path = _candidate_code_path(candidate)
        if code_path:
            expected["code_path"] = code_path
        expected_candidates.append(expected)
    return {
        "draft_review_required": True,
        "max_candidates": 5,
        "expected_candidates": expected_candidates,
        "forbidden_text": list(DEFAULT_FORBIDDEN_TEXT),
        "notes": [
            "Generated from current Studio candidates as a draft benchmark template.",
            "Review and edit expected candidates before using this as a quality gate.",
        ],
    }

MAX_STUDIO_CANDIDATES = 5


def evaluate_studio_candidates(candidates_payload: Any, expectations: Any) -> dict:
    candidates = _candidate_list(candidates_payload)
    expected_candidates = _expected_candidate_list(expectations)
    forbidden_text = _string_list(
        expectations.get("forbidden_text", []) if isinstance(expectations, dict) else []
    )
    max_candidates = _max_candidates(expectations)
    forbidden_text_present = _forbidden_text_present(candidates_payload, forbidden_text)
    failures: list[dict[str, str]] = []
    evidence_gaps: list[dict[str, str]] = []
    matched = 0

    if not expected_candidates:
        failures.append({"name": "benchmark", "reason": "no_expected_candidates"})

    if len(candidates) > max_candidates:
        failures.append(
            {
                "name": "candidate_set",
                "reason": f"too_many_candidates:{len(candidates)}",
            }
        )
    if len(expected_candidates) > max_candidates:
        failures.append(
            {
                "name": "expected_candidate_set",
                "reason": f"too_many_expected_candidates:{len(expected_candidates)}",
            }
        )

    for expected in expected_candidates:
        candidate = _matching_candidate(candidates, expected)
        name = _expected_name(expected)
        if candidate is None:
            failures.append({"name": name, "reason": "expected_candidate_not_found"})
            continue
        candidate_failures = _candidate_quality_failures(candidate, expected)
        evidence_gaps.extend(_candidate_evidence_gaps(candidate, expected, name))
        if candidate_failures:
            failures.extend({"name": name, "reason": reason} for reason in candidate_failures)
        else:
            matched += 1

    if forbidden_text_present:
        failures.append({"name": "safety", "reason": "forbidden_text_present"})

    status = "passed" if not failures else "failed"
    return {
        "status": status,
        "candidate_count": len(candidates),
        "expected_count": len(expected_candidates),
        "matched": matched,
        "failures": failures,
        "evidence_gaps": evidence_gaps,
        "safety": {
            "forbidden_text_present": forbidden_text_present,
        },
    }


def _candidate_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        value = value.get("candidates", [])
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _expected_candidate_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        return []
    expected = value.get("expected_candidates", [])
    if not isinstance(expected, list):
        return []
    return [item for item in expected if isinstance(item, dict)]


def _matching_candidate(
    candidates: list[dict[str, Any]],
    expected: dict[str, Any],
) -> dict[str, Any] | None:
    for candidate in candidates:
        if _candidate_vuln_type(candidate) != _text(expected.get("vuln_type")):
            continue
        if _candidate_matches_route(candidate, expected):
            return candidate
    return None


def _first_candidate_route(candidate: dict[str, Any]) -> dict[str, str] | None:
    routes = _candidate_routes(candidate)
    return routes[0] if routes else None


def _expectation_name(candidate: dict[str, Any], route: dict[str, str]) -> str:
    vuln_type = _candidate_vuln_type(candidate) or "candidate"
    route_method = _text(route.get("route_method"))
    route_path = _text(route.get("route_path"))
    route_label = f"{route_method} {route_path}".strip()
    return f"{vuln_type} at {route_label}" if route_label else vuln_type


def _candidate_matches_route(candidate: dict[str, Any], expected: dict[str, Any]) -> bool:
    expected_method = _text(expected.get("route_method")).upper()
    expected_path = _text(expected.get("route_path"))
    if not expected_path:
        return True
    for route in _candidate_routes(candidate):
        method = _text(route.get("route_method")).upper()
        path = _text(route.get("route_path"))
        if expected_method and method and method != expected_method:
            continue
        if _route_paths_match(expected_path, path):
            return True
    return False


def _candidate_routes(candidate: dict[str, Any]) -> list[dict[str, str]]:
    routes: list[dict[str, str]] = []
    location_route = _route_from_location(candidate.get("location"))
    if location_route:
        routes.append(location_route)
    source_facts = candidate.get("source_facts", [])
    if isinstance(source_facts, list):
        for fact in source_facts:
            if not isinstance(fact, dict):
                continue
            route_path = _text(fact.get("route_path"))
            if route_path:
                routes.append(
                    {
                        "route_method": _text(fact.get("route_method")),
                        "route_path": route_path,
                    }
                )
    return routes


def _route_from_location(value: Any) -> dict[str, str] | None:
    location = _text(value)
    if not location:
        return None
    parts = location.split(maxsplit=1)
    if len(parts) == 2 and parts[1].startswith("/"):
        return {"route_method": parts[0], "route_path": parts[1]}
    if location.startswith("/"):
        return {"route_method": "", "route_path": location}
    return None


def _candidate_quality_failures(
    candidate: dict[str, Any],
    expected: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    if not _string_list(candidate.get("evidence_needed")):
        failures.append("missing_evidence_needed")
    if not _string_list(candidate.get("false_positive_checks")):
        failures.append("missing_false_positive_checks")
    for keyword in _missing_required_keywords(
        candidate,
        "evidence_needed",
        expected,
        "required_evidence_keywords",
    ):
        failures.append(f"missing_evidence_keyword:{keyword}")
    for keyword in _missing_required_keywords(
        candidate,
        "false_positive_checks",
        expected,
        "required_false_positive_keywords",
    ):
        failures.append(f"missing_false_positive_keyword:{keyword}")
    if not _string_list(candidate.get("safe_validation_plan")):
        failures.append("missing_safe_validation_plan")
    for reason in _unsafe_validation_plan_reasons(candidate):
        failures.append(f"unsafe_validation_plan:{reason}")
    missing_artifacts = _missing_required_artifacts(candidate, expected)
    if missing_artifacts:
        failures.append("missing_required_artifacts:" + ",".join(missing_artifacts))
    missing_advisory_signals = _missing_advisory_signals(candidate, expected)
    for artifact_kind in missing_advisory_signals:
        failures.append(f"missing_advisory_signal:{artifact_kind}")
    expected_code_path = _text(expected.get("code_path"))
    if expected_code_path and not _candidate_has_code_path(candidate, expected_code_path):
        failures.append(f"missing_code_path:{expected_code_path}")
    if expected.get("require_code_path") is True and not _candidate_has_any_code_path(candidate):
        failures.append("missing_code_path")
    if expected.get("require_refutation_status") is True and not _candidate_refutation_status(candidate):
        failures.append("missing_refutation_status")
    if expected.get("require_security_invariant") is True and not _candidate_security_invariant(candidate):
        failures.append("missing_security_invariant")
    if expected.get("require_impact_rationale") is True and not _candidate_impact_rationale(candidate):
        failures.append("missing_impact_rationale")
    if expected.get("require_repair_guidance") is True and not _candidate_repair_guidance(candidate):
        failures.append("missing_repair_guidance")
    if expected.get("require_regression_test") is True and not _candidate_regression_test(candidate):
        failures.append("missing_regression_test")
    if expected.get("require_policy_risk") is True and not _candidate_policy_risk(candidate):
        failures.append("missing_policy_risk")
    if expected.get("require_policy_review") is True and not _candidate_policy_review_gate(candidate):
        failures.append("missing_policy_review")
    if expected.get("require_evidence_review") is True and not _candidate_evidence_review_gate(candidate):
        failures.append("missing_evidence_review")
    if expected.get("require_provenance_review") is True and not _candidate_provenance_review_gate(candidate):
        failures.append("missing_provenance_review")
    if expected.get("require_deduplication_review") is True and not _candidate_deduplication_review_gate(candidate):
        failures.append("missing_deduplication_review")
    if expected.get("require_refutation_review") is True and not _candidate_refutation_review_gate(candidate):
        failures.append("missing_refutation_review")
    if expected.get("require_validation_review") is True and not _candidate_validation_review_gate(candidate):
        failures.append("missing_validation_review")
    max_duplicate_risk_score = expected.get("max_duplicate_risk_score")
    if isinstance(max_duplicate_risk_score, int):
        duplicate_risk_score = _candidate_duplicate_risk_score(candidate)
        if duplicate_risk_score is None:
            failures.append("missing_duplicate_risk_score")
        elif duplicate_risk_score > max_duplicate_risk_score:
            failures.append(f"duplicate_risk_too_high:{duplicate_risk_score}")
    max_policy_risk_score = expected.get("max_policy_risk_score")
    if isinstance(max_policy_risk_score, int):
        policy_risk_score = _candidate_policy_risk_score(candidate)
        if policy_risk_score is None:
            failures.append("missing_policy_risk_score")
        elif policy_risk_score > max_policy_risk_score:
            failures.append(f"policy_risk_too_high:{policy_risk_score}")
    report_readiness = candidate.get("report_readiness")
    if not isinstance(report_readiness, dict):
        failures.append("missing_report_readiness")
    else:
        if report_readiness.get("status") != "submission_blocked":
            failures.append("report_not_submission_blocked")
        if report_readiness.get("report_submission_allowed") is not False:
            failures.append("report_submission_allowed")
        if not _text(report_readiness.get("next_allowed_action")):
            failures.append("missing_report_next_allowed_action")
        for reason in _unsafe_report_next_action_reasons(report_readiness):
            failures.append(f"unsafe_report_next_allowed_action:{reason}")
    blockers = set(_string_list(candidate.get("safety_blockers")))
    if not REQUIRED_SAFETY_BLOCKERS.issubset(blockers):
        failures.append("missing_safety_blockers")
    return failures


def _missing_required_artifacts(
    candidate: dict[str, Any],
    expected: dict[str, Any],
) -> list[str]:
    required = _string_list(expected.get("required_artifacts"))
    if not required:
        return []
    source_facts = candidate.get("source_facts", [])
    artifact_kinds = {
        _text(fact.get("artifact_kind"))
        for fact in source_facts
        if isinstance(fact, dict)
    }
    return [kind for kind in required if kind not in artifact_kinds]


def _missing_advisory_signals(
    candidate: dict[str, Any],
    expected: dict[str, Any],
) -> list[str]:
    required = _string_list(expected.get("required_artifacts"))
    source_facts = candidate.get("source_facts", [])
    if not isinstance(source_facts, list):
        source_facts = []
    missing = []
    for artifact_kind, fact_type in ADVISORY_ARTIFACT_FACT_TYPES.items():
        if artifact_kind not in required:
            continue
        if not any(
            isinstance(fact, dict)
            and _text(fact.get("artifact_kind")) == artifact_kind
            and _text(fact.get("fact_type")) == fact_type
            and _text(fact.get("advisory_only")).lower() == "true"
            for fact in source_facts
        ):
            missing.append(artifact_kind)
    return missing


def _missing_required_keywords(
    candidate: dict[str, Any],
    candidate_field: str,
    expected: dict[str, Any],
    expected_field: str,
) -> list[str]:
    required = _string_list(expected.get(expected_field))
    if not required:
        return []
    candidate_text = _normalized_keyword_text(
        " ".join(_string_list(candidate.get(candidate_field)))
    )
    return [
        keyword
        for keyword in required
        if _normalized_keyword_text(keyword) not in candidate_text
    ]


def _normalized_keyword_text(value: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9]+", " ", value.lower()).split())


def _candidate_evidence_gaps(
    candidate: dict[str, Any],
    expected: dict[str, Any],
    name: str,
) -> list[dict[str, str]]:
    gaps: list[dict[str, str]] = []
    for artifact_kind in _missing_required_artifacts(candidate, expected):
        gaps.append(
            {
                "name": name,
                "artifact_kind": artifact_kind,
                "reason": "missing_required_artifact",
            }
        )
    for artifact_kind in _missing_advisory_signals(candidate, expected):
        gaps.append(
            {
                "name": name,
                "artifact_kind": artifact_kind,
                "reason": "missing_advisory_signal",
            }
        )
    expected_code_path = _text(expected.get("code_path"))
    if expected_code_path and not _candidate_has_code_path(candidate, expected_code_path):
        gaps.append(
            {
                "name": name,
                "artifact_kind": "code",
                "reason": "missing_code_path",
            }
        )
    if expected.get("require_code_path") is True and not _candidate_has_any_code_path(candidate):
        gaps.append(
            {
                "name": name,
                "artifact_kind": "code",
                "reason": "missing_code_path",
            }
        )
    for keyword in _missing_required_keywords(
        candidate,
        "evidence_needed",
        expected,
        "required_evidence_keywords",
    ):
        gaps.append(
            {
                "name": name,
                "artifact_kind": "evidence_needed",
                "reason": "missing_required_keyword",
                "keyword": keyword,
            }
        )
    for keyword in _missing_required_keywords(
        candidate,
        "false_positive_checks",
        expected,
        "required_false_positive_keywords",
    ):
        gaps.append(
            {
                "name": name,
                "artifact_kind": "false_positive_checks",
                "reason": "missing_required_keyword",
                "keyword": keyword,
            }
        )
    return gaps


def _candidate_artifact_kinds(candidate: dict[str, Any]) -> list[str]:
    source_facts = candidate.get("source_facts", [])
    if not isinstance(source_facts, list):
        return list(REQUIRED_STUDIO_ARTIFACTS)
    benchmark_artifacts = {
        *REQUIRED_STUDIO_ARTIFACTS,
        "sarif",
        "sbom",
        "fuzzing",
    }
    kinds = {
        kind
        for fact in source_facts
        if isinstance(fact, dict)
        and (kind := _text(fact.get("artifact_kind")))
        and kind in benchmark_artifacts
    }
    kinds.update(REQUIRED_STUDIO_ARTIFACTS)
    ordered = [
        kind
        for kind in (
            "scope",
            "policy",
            "code",
            "api",
            "har",
            "sarif",
            "sbom",
            "fuzzing",
        )
        if kind in kinds
    ]
    return ordered + sorted(kinds.difference(ordered))


def _candidate_has_code_path(candidate: dict[str, Any], expected_code_path: str) -> bool:
    expected_path, expected_symbol = _split_expected_code_path(expected_code_path)
    source_facts = candidate.get("source_facts", [])
    if not isinstance(source_facts, list):
        return False
    for fact in source_facts:
        if not isinstance(fact, dict):
            continue
        if _text(fact.get("artifact_kind")) != "code":
            continue
        source_path = _normalized_path(_text(fact.get("source_path")))
        if source_path != expected_path and not source_path.endswith("/" + expected_path):
            continue
        if expected_symbol and _text(fact.get("symbol_name")) != expected_symbol:
            continue
        if source_path:
            return True
    return False


def _candidate_has_any_code_path(candidate: dict[str, Any]) -> bool:
    source_facts = candidate.get("source_facts", [])
    if not isinstance(source_facts, list):
        return False
    return any(
        isinstance(fact, dict)
        and _text(fact.get("artifact_kind")) == "code"
        and bool(_normalized_path(_text(fact.get("source_path"))))
        for fact in source_facts
    )


def _candidate_refutation_status(candidate: dict[str, Any]) -> str:
    return _text(candidate.get("refutation_status"))


def _candidate_duplicate_risk_score(candidate: dict[str, Any]) -> int | None:
    value = candidate.get("duplicate_risk_score")
    if not isinstance(value, int):
        return None
    return max(0, min(100, value))


def _candidate_policy_risk(candidate: dict[str, Any]) -> str:
    return _text(candidate.get("policy_risk"))


def _candidate_policy_risk_score(candidate: dict[str, Any]) -> int | None:
    value = candidate.get("policy_risk_score")
    if not isinstance(value, int):
        return None
    return max(0, min(100, value))


def _candidate_policy_review_gate(candidate: dict[str, Any]) -> bool:
    review = candidate.get("policy_review")
    if not isinstance(review, dict):
        return False
    return bool(_text(review.get("status"))) and bool(_string_list(review.get("review_items")))


def _candidate_evidence_review_gate(candidate: dict[str, Any]) -> bool:
    evidence_review = candidate.get("evidence_review")
    if not isinstance(evidence_review, dict):
        return False
    required_items = _string_list(evidence_review.get("required_items"))
    if (
        _text(evidence_review.get("status"))
        in {"required", "needs_review", "needs_human_review"}
        and required_items
    ):
        return True
    return (
        _text(evidence_review.get("status")) in {"required", "needs_review"}
        and evidence_review.get("human_review_required") is True
        and evidence_review.get("redaction_required") is True
        and evidence_review.get("provenance_required") is True
    )


def _candidate_provenance_review_gate(candidate: dict[str, Any]) -> bool:
    review = candidate.get("provenance_review")
    if not isinstance(review, dict):
        return False
    return (
        bool(_text(review.get("status")))
        and bool(_string_list(review.get("artifact_kinds")))
        and bool(_string_list(review.get("review_items")))
    )


def _candidate_deduplication_review_gate(candidate: dict[str, Any]) -> bool:
    review = candidate.get("deduplication_review")
    if not isinstance(review, dict):
        return False
    return bool(_text(review.get("status"))) and bool(_string_list(review.get("review_items")))


def _candidate_refutation_review_gate(candidate: dict[str, Any]) -> bool:
    review = candidate.get("refutation_review")
    if not isinstance(review, dict):
        return False
    return bool(_text(review.get("status"))) and bool(_string_list(review.get("questions")))


def _candidate_validation_review_gate(candidate: dict[str, Any]) -> bool:
    review = candidate.get("validation_review")
    if not isinstance(review, dict):
        return False
    return (
        bool(_text(review.get("status")))
        and review.get("execution_allowed") is False
        and bool(_string_list(review.get("review_items")))
    )


def _candidate_security_invariant(candidate: dict[str, Any]) -> str:
    return (
        _text(candidate.get("broken_invariant"))
        or _text(candidate.get("security_invariant"))
        or _text(candidate.get("invariant"))
    )


def _candidate_impact_rationale(candidate: dict[str, Any]) -> str:
    explicit = _text(candidate.get("impact_rationale")) or _text(candidate.get("impact"))
    if explicit:
        return explicit
    for reason in _string_list(candidate.get("ranking_reasons")):
        if reason.lower().startswith("impact:"):
            return reason
    return ""


def _candidate_repair_guidance(candidate: dict[str, Any]) -> str:
    return (
        _text(candidate.get("repair_guidance"))
        or _text(candidate.get("suggested_fix"))
        or _text(candidate.get("remediation"))
        or _first_string(candidate.get("repair_steps"))
    )


def _candidate_regression_test(candidate: dict[str, Any]) -> str:
    return (
        _text(candidate.get("regression_test"))
        or _first_string(candidate.get("regression_tests"))
        or _first_string(candidate.get("test_recommendations"))
    )


def _unsafe_validation_plan_reasons(candidate: dict[str, Any]) -> list[str]:
    plan_text = " ".join(_string_list(candidate.get("safe_validation_plan"))).lower()
    if not plan_text:
        return []
    return [
        reason
        for reason, patterns in UNSAFE_VALIDATION_PLAN_PATTERNS.items()
        if any(pattern in plan_text for pattern in patterns)
    ]


def _unsafe_report_next_action_reasons(report_readiness: dict[str, Any]) -> list[str]:
    action_text = _text(report_readiness.get("next_allowed_action")).lower()
    if not action_text:
        return []
    return [
        reason
        for reason, patterns in UNSAFE_REPORT_NEXT_ACTION_PATTERNS.items()
        if any(pattern in action_text for pattern in patterns)
    ]


def _candidate_code_path(candidate: dict[str, Any]) -> str:
    source_facts = candidate.get("source_facts", [])
    if not isinstance(source_facts, list):
        return ""
    for fact in source_facts:
        if not isinstance(fact, dict) or _text(fact.get("artifact_kind")) != "code":
            continue
        source_path = _normalized_path(_text(fact.get("source_path")))
        if not source_path:
            continue
        source_name = source_path.rsplit("/", 1)[-1]
        symbol = _text(fact.get("symbol_name"))
        return f"{source_name}:{symbol}" if symbol else source_name
    return ""


def _split_expected_code_path(value: str) -> tuple[str, str]:
    path, separator, symbol = value.rpartition(":")
    if separator and path:
        return _normalized_path(path), symbol.strip()
    return _normalized_path(value), ""


def _forbidden_text_present(payload: Any, forbidden_text: list[str]) -> list[str]:
    if not forbidden_text:
        return []
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    serialized_lower = serialized.lower()
    return [text for text in forbidden_text if text and text.lower() in serialized_lower]


def _max_candidates(expectations: Any) -> int:
    if not isinstance(expectations, dict):
        return MAX_STUDIO_CANDIDATES
    value = expectations.get("max_candidates", MAX_STUDIO_CANDIDATES)
    if not isinstance(value, int) or value <= 0:
        return MAX_STUDIO_CANDIDATES
    return min(value, MAX_STUDIO_CANDIDATES)


def _route_paths_match(expected_path: str, candidate_path: str) -> bool:
    expected_segments = _route_segments(expected_path)
    candidate_segments = _route_segments(candidate_path)
    if len(expected_segments) != len(candidate_segments):
        return False
    return all(
        _route_segment_matches(expected, candidate)
        or _route_segment_matches(candidate, expected)
        for expected, candidate in zip(expected_segments, candidate_segments, strict=True)
    )


def _route_segments(route_path: str) -> list[str]:
    return [segment for segment in route_path.strip("/").split("/") if segment]


def _route_segment_matches(pattern: str, value: str) -> bool:
    if pattern == value:
        return True
    return (
        pattern.startswith("{")
        and pattern.endswith("}")
        or pattern.startswith("<")
        and pattern.endswith(">")
        or pattern.startswith(":")
    )


def _candidate_vuln_type(candidate: dict[str, Any]) -> str:
    return _text(candidate.get("vuln_type"))


def _normalized_path(value: str) -> str:
    return value.replace("\\", "/").strip("/").lower()


def _expected_name(expected: dict[str, Any]) -> str:
    return _text(expected.get("name")) or _text(expected.get("route_path")) or "expected"


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [text for item in value if (text := _text(item))]


def _first_string(value: Any) -> str:
    values = _string_list(value)
    return values[0] if values else ""


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


from app.intelligence_benchmark.release_v1 import (
    evaluate_candidate_hunter_authorized_lab_v1,
    evaluate_candidate_hunter_release_suite_v1,
    evaluate_candidate_hunter_release_v1,
)


__all__ = [
    "build_studio_expectations_template",
    "evaluate_candidate_hunter_authorized_lab_v1",
    "evaluate_candidate_hunter_release_suite_v1",
    "evaluate_candidate_hunter_release_v1",
    "evaluate_studio_candidates",
]
