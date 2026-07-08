from __future__ import annotations

import json
from typing import Any


REQUIRED_SAFETY_BLOCKERS = {
    "execute_live_validation",
    "touch_real_user_data",
    "submit_report",
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
    matched = 0

    if len(candidates) > max_candidates:
        failures.append(
            {
                "name": "candidate_set",
                "reason": f"too_many_candidates:{len(candidates)}",
            }
        )

    for expected in expected_candidates:
        candidate = _matching_candidate(candidates, expected)
        name = _expected_name(expected)
        if candidate is None:
            failures.append({"name": name, "reason": "expected_candidate_not_found"})
            continue
        candidate_failures = _candidate_quality_failures(candidate, expected)
        if candidate_failures:
            failures.extend({"name": name, "reason": reason} for reason in candidate_failures)
        else:
            matched += 1

    if forbidden_text_present:
        failures.append({"name": "safety", "reason": "forbidden_text_present"})
    if len(candidates) > MAX_STUDIO_CANDIDATES:
        failures.append(
            {"name": "candidate_set", "reason": f"too_many_candidates:{len(candidates)}"}
        )

    status = "passed" if not failures else "failed"
    return {
        "status": status,
        "candidate_count": len(candidates),
        "expected_count": len(expected_candidates),
        "matched": matched,
        "failures": failures,
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
    if not _string_list(candidate.get("safe_validation_plan")):
        failures.append("missing_safe_validation_plan")
    missing_artifacts = _missing_required_artifacts(candidate, expected)
    if missing_artifacts:
        failures.append("missing_required_artifacts:" + ",".join(missing_artifacts))
    expected_code_path = _text(expected.get("code_path"))
    if expected_code_path and not _candidate_has_code_path(candidate, expected_code_path):
        failures.append(f"missing_code_path:{expected_code_path}")
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
        return 5
    value = expectations.get("max_candidates", 5)
    return value if isinstance(value, int) and value > 0 else 5


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


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


__all__ = ["evaluate_studio_candidates"]
