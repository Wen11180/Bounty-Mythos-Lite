from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any

from app.black_box_hunter import (
    BlackBoxStop,
    DifferentialEvidenceBundle,
    TrialObservation,
    evaluate_differential_evidence,
)
from app.intelligence_benchmark.black_box_release_v1 import (
    GOLD_STATUSES,
    GOLD_VERSION,
    TRIAL_CLASSES,
    evaluate_black_box_release_v1,
)


INPUT_VERSION = "black_box_release_inputs_v1"
DEFAULT_FIXTURE_ROOT = (
    Path(__file__).resolve().parents[2]
    / "tests"
    / "fixtures"
    / "black_box_differential_release"
)
OBSERVATION_SLOTS = (
    "baseline_a",
    "baseline_b",
    "trial",
    "owner_control",
    "session_control",
    "repeat",
    "rollback",
)
REQUIRED_NEGATIVE_SCENARIOS = {
    "cache_difference",
    "correct_authorization",
    "csrf_rotation",
    "intended_sharing",
    "public_test_data",
    "rate_limit",
    "rollback_failure",
    "session_expiry",
}
_RESERVED_INPUT_KEYS = {
    "disposition",
    "expected_status",
    "gold",
    "label",
    "scenario_class",
    "verdict",
}
_SEMANTIC_LABEL_MARKERS = {
    "bola",
    "cache",
    "csrf",
    "expired",
    "guarded",
    "negative",
    "positive",
    "public",
    "rate",
    "refuted",
    "retain",
    "rollback",
    "safe",
    "shared",
    "vulnerable",
}
_CASE_KEYS = {
    "case_id",
    "evidence_set",
    "priority_score",
    "route_template",
    "trial_class",
}
_EVIDENCE_KEYS = {"independent_repeat", "observations", "rollback_required"}
_OBSERVATION_KEYS = {
    "canary_match",
    "intended_sharing",
    "schema_ref",
    "state_effect",
    "status_class",
    "stop_reason",
    "structural_identity_match",
}


class BlackBoxReleaseFixtureError(ValueError):
    pass


def load_black_box_release_inputs(path: Path) -> dict[str, Any]:
    return _load_json(path, kind="inputs")


def load_black_box_release_gold(path: Path) -> dict[str, Any]:
    document = _load_json(path, kind="gold")
    if set(document) != {"cases", "split", "version"}:
        raise BlackBoxReleaseFixtureError("gold:unexpected_keys")
    if document.get("version") != GOLD_VERSION:
        raise BlackBoxReleaseFixtureError("gold:unsupported_version")
    if document.get("split") not in {"development", "held_out"}:
        raise BlackBoxReleaseFixtureError("gold:unsupported_split")
    cases = document.get("cases")
    if not isinstance(cases, list) or not cases:
        raise BlackBoxReleaseFixtureError("gold:cases_required")
    seen: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict) or set(case) != {
            "case_id",
            "expected_status",
            "scenario_class",
            "trial_class",
        }:
            raise BlackBoxReleaseFixtureError(f"gold:cases[{index}]:invalid")
        case_id = case.get("case_id")
        if not _opaque_identifier(case_id):
            raise BlackBoxReleaseFixtureError(f"gold:cases[{index}]:case_id_must_be_opaque")
        if case_id in seen:
            raise BlackBoxReleaseFixtureError(f"gold:cases[{index}]:duplicate_case_id")
        seen.add(case_id)
        if case.get("expected_status") not in GOLD_STATUSES:
            raise BlackBoxReleaseFixtureError(f"gold:cases[{index}]:expected_status_invalid")
        if case.get("trial_class") not in TRIAL_CLASSES:
            raise BlackBoxReleaseFixtureError(f"gold:cases[{index}]:trial_class_invalid")
        if not isinstance(case.get("scenario_class"), str) or not case["scenario_class"]:
            raise BlackBoxReleaseFixtureError(f"gold:cases[{index}]:scenario_class_invalid")
    if document["split"] == "held_out":
        scenarios = {
            case["scenario_class"]
            for case in cases
            if case["expected_status"] != "review_ready"
        }
        if scenarios != REQUIRED_NEGATIVE_SCENARIOS:
            raise BlackBoxReleaseFixtureError("gold:held_out_negative_matrix_incomplete")
    return document


def capture_black_box_release_inputs(document: Any) -> list[dict[str, Any]]:
    _validate_input_document(document)
    evidence_sets = document["evidence_sets"]
    return [
        _capture_case(case, evidence_sets[case["evidence_set"]])
        for case in document["cases"]
    ]


def run_black_box_release_suite(fixture_root: Path) -> dict[str, Any]:
    development_inputs = load_black_box_release_inputs(
        fixture_root / "development_inputs.json"
    )
    held_out_inputs = load_black_box_release_inputs(
        fixture_root / "held_out_inputs.json"
    )
    if development_inputs.get("split") != "development":
        raise BlackBoxReleaseFixtureError("development:split_mismatch")
    if held_out_inputs.get("split") != "held_out":
        raise BlackBoxReleaseFixtureError("held_out:split_mismatch")

    development_capture = capture_black_box_release_inputs(development_inputs)
    held_out_capture = capture_black_box_release_inputs(held_out_inputs)
    events = ["all_candidates_captured"]

    development_gold = load_black_box_release_gold(
        fixture_root / "development_gold.json"
    )
    held_out_gold = load_black_box_release_gold(fixture_root / "held_out_gold.json")
    events.append("gold_loaded")
    development_evaluation = evaluate_black_box_release_v1(
        development_capture,
        development_gold,
    )
    held_out_evaluation = evaluate_black_box_release_v1(
        held_out_capture,
        held_out_gold,
    )
    return {
        "version": "black_box_release_suite_v1",
        "events": events,
        "development": {
            "captured_cases": development_capture,
            "evaluation": development_evaluation,
            "trial_class_coverage": sorted(
                {case["trial_class"] for case in development_capture}
            ),
        },
        "held_out": {
            "captured_cases": held_out_capture,
            "evaluation": held_out_evaluation,
            "trial_class_coverage": sorted(
                {case["trial_class"] for case in held_out_capture}
            ),
        },
    }


def _validate_input_document(document: Any) -> None:
    if not isinstance(document, dict):
        raise BlackBoxReleaseFixtureError("inputs:must_be_object")
    if _contains_reserved_input_key(document):
        raise BlackBoxReleaseFixtureError("inputs:verdict_fields_forbidden")
    if set(document) != {"cases", "evidence_sets", "split", "version"}:
        raise BlackBoxReleaseFixtureError("inputs:unexpected_keys")
    if document.get("version") != INPUT_VERSION:
        raise BlackBoxReleaseFixtureError("inputs:unsupported_version")
    if document.get("split") not in {"development", "held_out"}:
        raise BlackBoxReleaseFixtureError("inputs:unsupported_split")
    evidence_sets = document.get("evidence_sets")
    cases = document.get("cases")
    if not isinstance(evidence_sets, dict) or not evidence_sets:
        raise BlackBoxReleaseFixtureError("inputs:evidence_sets_required")
    if not isinstance(cases, list) or not cases:
        raise BlackBoxReleaseFixtureError("inputs:cases_required")

    for evidence_id, evidence in evidence_sets.items():
        if not _opaque_identifier(evidence_id):
            raise BlackBoxReleaseFixtureError("inputs:evidence_set_id_must_be_opaque")
        _validate_evidence_set(evidence_id, evidence)

    seen_case_ids: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict) or set(case) != _CASE_KEYS:
            raise BlackBoxReleaseFixtureError(f"inputs:cases[{index}]:invalid")
        case_id = case.get("case_id")
        if not _opaque_identifier(case_id):
            raise BlackBoxReleaseFixtureError("inputs:case_id_must_be_opaque")
        if case_id in seen_case_ids:
            raise BlackBoxReleaseFixtureError("inputs:duplicate_case_id")
        seen_case_ids.add(case_id)
        if case.get("evidence_set") not in evidence_sets:
            raise BlackBoxReleaseFixtureError("inputs:unknown_evidence_set")
        if case.get("trial_class") not in TRIAL_CLASSES:
            raise BlackBoxReleaseFixtureError("inputs:trial_class_invalid")
        priority_score = case.get("priority_score")
        if (
            not isinstance(priority_score, int)
            or isinstance(priority_score, bool)
            or not 0 <= priority_score <= 100
        ):
            raise BlackBoxReleaseFixtureError("inputs:priority_score_invalid")
        if not _opaque_route_template(case.get("route_template")):
            raise BlackBoxReleaseFixtureError("inputs:route_template_must_be_opaque")
    if {case["trial_class"] for case in cases} != TRIAL_CLASSES:
        raise BlackBoxReleaseFixtureError("inputs:trial_class_matrix_incomplete")


def _validate_evidence_set(evidence_id: str, evidence: Any) -> None:
    if not isinstance(evidence, dict) or set(evidence) != _EVIDENCE_KEYS:
        raise BlackBoxReleaseFixtureError(f"inputs:{evidence_id}:invalid")
    if not isinstance(evidence.get("independent_repeat"), bool):
        raise BlackBoxReleaseFixtureError(f"inputs:{evidence_id}:repeat_flag_invalid")
    if not isinstance(evidence.get("rollback_required"), bool):
        raise BlackBoxReleaseFixtureError(f"inputs:{evidence_id}:rollback_flag_invalid")
    observations = evidence.get("observations")
    if not isinstance(observations, dict) or "trial" not in observations:
        raise BlackBoxReleaseFixtureError(f"inputs:{evidence_id}:trial_required")
    if not set(observations) <= set(OBSERVATION_SLOTS):
        raise BlackBoxReleaseFixtureError(f"inputs:{evidence_id}:observation_slot_invalid")
    for slot, observation in observations.items():
        if not isinstance(observation, dict) or not set(observation) <= _OBSERVATION_KEYS:
            raise BlackBoxReleaseFixtureError(
                f"inputs:{evidence_id}:{slot}:observation_invalid"
            )
        if observation.get("status_class") not in {
            "2xx",
            "3xx",
            "4xx",
            "5xx",
            "network_error",
        }:
            raise BlackBoxReleaseFixtureError(
                f"inputs:{evidence_id}:{slot}:status_class_invalid"
            )
        if not _opaque_identifier(observation.get("schema_ref")):
            raise BlackBoxReleaseFixtureError(
                f"inputs:{evidence_id}:{slot}:schema_ref_must_be_opaque"
            )
        for key in (
            "canary_match",
            "intended_sharing",
            "state_effect",
            "structural_identity_match",
        ):
            if key in observation and not isinstance(observation[key], bool):
                raise BlackBoxReleaseFixtureError(
                    f"inputs:{evidence_id}:{slot}:{key}_invalid"
                )


def _capture_case(case: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    observations = evidence["observations"]
    bundle = DifferentialEvidenceBundle(
        **{
            slot: _build_observation(observations[slot])
            for slot in OBSERVATION_SLOTS
            if slot in observations
        },
        independent_repeat=evidence["independent_repeat"],
        rollback_required=evidence["rollback_required"],
    )
    decision = evaluate_differential_evidence(bundle)
    candidate = None
    if decision.status == "review_ready":
        evidence_refs = [
            f"{case['case_id']}:{slot}"
            for slot in OBSERVATION_SLOTS
            if slot in observations
        ]
        candidate = {
            "candidate_id": f"candidate-{case['case_id']}",
            "case_id": case["case_id"],
            "priority_score": case["priority_score"],
            "trial_class": case["trial_class"],
            "route_template": case["route_template"],
            "independent_reproduction": (
                evidence["independent_repeat"] and "repeat" in observations
            ),
            "evidence_refs": evidence_refs,
            "review_ready": True,
            "execution_allowed": False,
            "report_submission_allowed": False,
        }
    return {
        "case_id": case["case_id"],
        "trial_class": case["trial_class"],
        "decision": decision.model_dump(mode="json"),
        "candidate": candidate,
        "safety": {
            "origin_class": "loopback",
            "raw_traffic_persisted": False,
            "execution_allowed": False,
            "report_submission_allowed": False,
        },
    }


def _build_observation(observation: dict[str, Any]) -> TrialObservation:
    schema_digest = sha256(observation["schema_ref"].encode("utf-8")).hexdigest()
    payload = {
        "status_class": observation["status_class"],
        "response_schema_fingerprint": f"sha256:{schema_digest}",
        "timing_bucket": "synthetic",
        "redacted": True,
        **{
            key: observation[key]
            for key in (
                "canary_match",
                "intended_sharing",
                "state_effect",
                "structural_identity_match",
            )
            if key in observation
        },
    }
    if stop_reason := observation.get("stop_reason"):
        payload["stop"] = BlackBoxStop(reason=stop_reason)
    return TrialObservation(**payload)


def _load_json(path: Path, *, kind: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BlackBoxReleaseFixtureError(f"{kind}:unreadable") from exc
    if not isinstance(value, dict):
        raise BlackBoxReleaseFixtureError(f"{kind}:must_be_object")
    return value


def _contains_reserved_input_key(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            str(key).lower() in _RESERVED_INPUT_KEYS
            or _contains_reserved_input_key(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_reserved_input_key(item) for item in value)
    return False


def _opaque_identifier(value: Any) -> bool:
    if not isinstance(value, str) or re.fullmatch(r"[a-z][a-z0-9_-]{2,63}", value) is None:
        return False
    words = set(re.findall(r"[a-z]+", value.lower()))
    return not words & _SEMANTIC_LABEL_MARKERS


def _opaque_route_template(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"/[a-z][a-z0-9_-]*/\{object\}(?:/[a-z][a-z0-9_-]*)?", value)
        is None
    ):
        return False
    words = set(re.findall(r"[a-z]+", value.lower()))
    return not words & _SEMANTIC_LABEL_MARKERS
