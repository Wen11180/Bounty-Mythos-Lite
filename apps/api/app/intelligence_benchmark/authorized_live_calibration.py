"""Authorized live-program calibration infrastructure (no auto-attack).

Claim scope: schema + redaction + human-confirmed outcome logging for authorized
programs only. Does NOT claim live bounty superiority, XBOW ranking, remote
auto-attack, or auto-submission.

This module exists so Mythos-Lite can accumulate a lawful live track record:
authorized program intake -> human-reviewed outcomes -> redacted metrics.
Execution and report submission remain blocked.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.intelligence_benchmark.human_hour_calibration import (
    FORBIDDEN_MARKERS,
    HumanHourCalibrationError,
)

REQUIRED_METRICS = (
    "log_schema_valid_rate",
    "redaction_safe_rate",
    "authorized_program_rate",
    "human_confirmed_rate",
    "measured_precision_at_confirmed",
    "measured_fp_kill_rate",
    "safety_rate",
)

ALLOWED_OUTCOMES = frozenset(
    {
        "human_confirmed_valid",
        "human_confirmed_fp",
        "human_needs_more_evidence",
        "human_rejected_out_of_scope",
        "human_deduplicated",
        "not_submitted",
    }
)


class AuthorizedLiveCalibrationError(ValueError):
    """Raised when authorized live calibration inputs are invalid."""


def _rate(num: float, den: float) -> float:
    if den <= 0:
        return 1.0
    return round(float(num) / float(den), 4)


def _blob_safe(payload: object) -> bool:
    text = json.dumps(payload, default=str)
    lowered = text.lower()
    if "secret" in lowered and "SECRET" in text:
        return False
    for marker in FORBIDDEN_MARKERS:
        if marker.lower() in lowered:
            if marker.lower() in {"bearer ", "cookie=", "authorization:"}:
                return False
            if marker in text:
                return False
    if "bearer " in lowered or "cookie=" in lowered or "authorization:" in lowered:
        return False
    return True


def validate_live_log_entry(entry: dict[str, Any]) -> list[str]:
    """Return schema errors for one redacted authorized live outcome entry."""
    errors: list[str] = []
    if not isinstance(entry, dict):
        return ["entry_not_object"]
    if not str(entry.get("entry_id") or "").strip():
        errors.append("entry_id_missing")
    if not str(entry.get("program_handle") or "").strip():
        errors.append("program_handle_missing")
    if entry.get("authorized") is not True:
        errors.append("authorized_not_true")
    outcome = str(entry.get("outcome") or "").strip()
    if outcome not in ALLOWED_OUTCOMES:
        errors.append("outcome_invalid")
    if entry.get("human_confirmed") is not True:
        errors.append("human_confirmed_not_true")
    if entry.get("execution_allowed") is True:
        errors.append("execution_allowed_true")
    if entry.get("report_submission_allowed") is True:
        errors.append("report_submission_allowed_true")
    if entry.get("auto_submitted") is True:
        errors.append("auto_submitted_true")
    if "wall_clock_minutes" in entry and entry.get("wall_clock_minutes") is not None:
        try:
            wall = float(entry.get("wall_clock_minutes"))
            if wall < 0:
                errors.append("wall_clock_minutes_negative")
        except (TypeError, ValueError):
            errors.append("wall_clock_minutes_invalid")
    for key in (
        "program_handle",
        "package_label",
        "notes",
        "hypothesis_class",
        "language_family",
        "vuln_family",
    ):
        value = entry.get(key)
        if value is not None and not isinstance(value, str):
            errors.append(f"{key}_not_string")
    if "candidate_rank" in entry:
        rank = entry.get("candidate_rank")
        if isinstance(rank, bool) or not isinstance(rank, int) or rank < 1:
            errors.append("candidate_rank_invalid")
    for key in ("report_ready", "report_valid"):
        if key in entry and not isinstance(entry.get(key), bool):
            errors.append(f"{key}_not_boolean")
    return errors


def synthetic_authorized_live_fixture() -> list[dict[str, Any]]:
    """Synthetic authorized-program outcome rows (not a real live claim).

    Demonstrates the lawful track-record pipeline shape: human-confirmed only,
    redacted, submission blocked.
    """
    base = {
        "authorized": True,
        "human_confirmed": True,
        "execution_allowed": False,
        "report_submission_allowed": False,
        "auto_submitted": False,
        "program_handle": "synthetic-authorized-program",
        "hypothesis_class": "authorization",
        "vuln_family": "idor",
    }
    return [
        {
            **base,
            "entry_id": "live-valid-1",
            "package_label": "unguarded-object-read",
            "outcome": "human_confirmed_valid",
            "language_family": "python",
            "notes": "Human confirmed review-ready IDOR candidate; not auto-submitted.",
        },
        {
            **base,
            "entry_id": "live-valid-2",
            "package_label": "guard-after-sink",
            "outcome": "human_confirmed_valid",
            "language_family": "typescript",
        },
        {
            **base,
            "entry_id": "live-fp-1",
            "package_label": "service-layer-ownership",
            "outcome": "human_confirmed_fp",
            "language_family": "java",
            "notes": "Human confirmed ownership control; FP killed.",
        },
        {
            **base,
            "entry_id": "live-fp-2",
            "package_label": "middleware-ownership",
            "outcome": "human_confirmed_fp",
            "language_family": "go",
        },
        {
            **base,
            "entry_id": "live-fp-3",
            "package_label": "before-action-ownership",
            "outcome": "human_confirmed_fp",
            "language_family": "rails",
        },
        {
            **base,
            "entry_id": "live-needs-1",
            "package_label": "api-only-surface",
            "outcome": "human_needs_more_evidence",
            "language_family": "php",
        },
        {
            **base,
            "entry_id": "live-oos-1",
            "package_label": "out-of-scope-asset",
            "outcome": "human_rejected_out_of_scope",
            "language_family": "csharp",
        },
        {
            **base,
            "entry_id": "live-dedupe-1",
            "package_label": "shared-root-cause",
            "outcome": "human_deduplicated",
            "language_family": "python",
        },
        {
            **base,
            "entry_id": "live-not-submitted-1",
            "package_label": "valid-but-held",
            "outcome": "not_submitted",
            "language_family": "typescript",
            "notes": "Human confirmed candidate held for manual report drafting.",
        },
        {
            **base,
            "entry_id": "live-kotlin-fp-1",
            "package_label": "kotlin-spring-ownership",
            "outcome": "human_confirmed_fp",
            "language_family": "kotlin",
            "notes": "Authorized lab-shaped: ownership guard correctly refuted candidate.",
            "wall_clock_minutes": 18.0,
        },
        {
            **base,
            "entry_id": "live-csharp-valid-1",
            "package_label": "csharp-service-unguarded",
            "outcome": "not_submitted",
            "language_family": "csharp",
            "notes": "Human-confirmed valid-shaped candidate held for manual report draft.",
            "wall_clock_minutes": 42.0,
        },
        {
            **base,
            "entry_id": "live-rust-fp-1",
            "package_label": "rust-ownership",
            "outcome": "human_confirmed_fp",
            "language_family": "rust",
            "notes": "Authorized lab-shaped: Rust ownership guard correctly refuted candidate.",
        },
        {
            **base,
            "entry_id": "live-scala-fp-1",
            "package_label": "scala-ownership",
            "outcome": "human_confirmed_fp",
            "language_family": "scala",
            "notes": "Authorized lab-shaped: Scala ownership guard correctly refuted candidate.",
        },
    ]


COMMITTED_LIVE_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "authorized_live_outcomes.json"
)


def load_live_outcome_package(
    path: Path | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load live outcome entries plus package metadata (source_kind, auth refs)."""
    if path is None:
        if COMMITTED_LIVE_FIXTURE.is_file():
            path = COMMITTED_LIVE_FIXTURE
        else:
            return synthetic_authorized_live_fixture(), {
                "source_kind": "synthetic",
                "fixture_kind": "synthetic_authorized_live_fixture",
            }
    log_path = Path(path)
    if not log_path.is_file():
        raise AuthorizedLiveCalibrationError(f"live_log_missing:{log_path}")
    raw = log_path.read_text(encoding="utf-8")
    if log_path.suffix.lower() == ".jsonl":
        entries: list[dict[str, Any]] = []
        for line_no, line in enumerate(raw.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                item = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise AuthorizedLiveCalibrationError(
                    f"live_log_jsonl_invalid_line:{line_no}"
                ) from exc
            if isinstance(item, dict):
                entries.append(item)
        if not entries:
            raise AuthorizedLiveCalibrationError("live_log_empty")
        return entries, {"source_kind": package_source_kind(None, entries)}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AuthorizedLiveCalibrationError("live_log_json_invalid") from exc
    if isinstance(payload, dict) and isinstance(payload.get("entries"), list):
        entries = [e for e in payload["entries"] if isinstance(e, dict)]
        meta = {
            k: payload.get(k)
            for k in (
                "source_kind",
                "fixture_kind",
                "program_authorization_id",
                "authorization_ref",
                "schema_version",
                "claim_scope",
                "description",
                "evaluation_top_k",
                "attestation_status",
                "independent_verification",
            )
            if k in payload
        }
        if "source_kind" not in meta and "fixture_kind" not in meta:
            meta["source_kind"] = package_source_kind(payload, entries)
        return entries, meta
    if isinstance(payload, list):
        entries = [e for e in payload if isinstance(e, dict)]
        return entries, {"source_kind": package_source_kind(None, entries)}
    raise AuthorizedLiveCalibrationError("live_log_must_be_list_or_entries_object")


def load_live_outcome_logs(path: Path | None = None) -> list[dict[str, Any]]:
    entries, _meta = load_live_outcome_package(path)
    return entries


def compute_live_calibration_metrics(
    entries: list[dict[str, Any]],
    *,
    package_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not entries:
        raise AuthorizedLiveCalibrationError("live_log_empty")

    schema_ok = 0
    safe_ok = 0
    authorized_ok = 0
    human_ok = 0
    valid_expected = 0
    valid_hit = 0
    kill_expected = 0
    kill_hit = 0
    row_errors: list[dict[str, Any]] = []
    language_families: set[str] = set()

    for entry in entries:
        errors = validate_live_log_entry(entry)
        safe = _blob_safe(entry)
        if not errors:
            schema_ok += 1
        else:
            row_errors.append(
                {"entry_id": str(entry.get("entry_id") or ""), "errors": errors}
            )
        if safe:
            safe_ok += 1
        if entry.get("authorized") is True:
            authorized_ok += 1
        if entry.get("human_confirmed") is True:
            human_ok += 1
        lang = str(entry.get("language_family") or "").strip().lower()
        if lang:
            language_families.add(lang)
        outcome = str(entry.get("outcome") or "")
        if outcome in {"human_confirmed_valid", "not_submitted"}:
            valid_expected += 1
            if not errors and safe:
                valid_hit += 1
        elif outcome == "human_confirmed_fp":
            kill_expected += 1
            if not errors and safe:
                kill_hit += 1

    outcome_counts: dict[str, int] = {}
    wall_clock_total = 0.0
    wall_clock_n = 0
    for entry in entries:
        oc = str(entry.get("outcome") or "").strip() or "unknown"
        outcome_counts[oc] = outcome_counts.get(oc, 0) + 1
        if entry.get("wall_clock_minutes") is not None:
            try:
                wall_clock_total += float(entry.get("wall_clock_minutes"))
                wall_clock_n += 1
            except (TypeError, ValueError):
                pass
    source_kind = package_source_kind(package_meta, entries)
    real_signals = detect_real_track_record_signals(
        entries=entries,
        source_kind=source_kind,
        package_meta=package_meta,
    )
    outcome_metrics = _compute_outcome_metrics(
        entries=entries,
        package_meta=package_meta,
        is_operator_attested=bool(real_signals["is_operator_attested"]),
        data_complete=not row_errors and safe_ok == len(entries),
    )
    track_record_summary = {
        "outcome_counts": dict(sorted(outcome_counts.items())),
        "language_families": sorted(language_families),
        "wall_clock_entries": wall_clock_n,
        "wall_clock_minutes_total": round(wall_clock_total, 4) if wall_clock_n else 0.0,
        "source_kind": source_kind,
        "program_authorization_id": real_signals.get("program_authorization_id"),
        "attestation_status": real_signals.get("attestation_status"),
        "independent_verification": False,
        "non_real_provenance_markers": real_signals.get(
            "non_real_provenance_markers"
        )
        or [],
        "has_real_wall_clock_logs": bool(real_signals["has_real_wall_clock_logs"]),
        "has_real_live_valid_report_outcomes": bool(
            real_signals["has_real_live_valid_report_outcomes"]
        ),
        "wall_clock_real_entry_count": real_signals["wall_clock_real_entry_count"],
        "valid_report_real_entry_count": real_signals["valid_report_real_entry_count"],
        "outcome_metrics": outcome_metrics,
        "note": (
            "Operator-attested authorized redacted package detected; independent verification is not provided."
            if real_signals["is_operator_attested"]
            else (
                "Synthetic/template/unverified package only. "
                "Attach source_kind=authorized_redacted_real with program_authorization_id, "
                "non-synthetic inputs, wall_clock_minutes, and report_outcome_ref "
                "to close live market gaps."
            )
        ),
    }
    return {
        "entry_count": len(entries),
        "schema_ok": schema_ok,
        "safe_ok": safe_ok,
        "row_errors": row_errors,
        "language_families": sorted(language_families),
        "track_record_summary": track_record_summary,
        "metrics": {
            "log_schema_valid_rate": _rate(schema_ok, len(entries)),
            "redaction_safe_rate": _rate(safe_ok, len(entries)),
            "authorized_program_rate": _rate(authorized_ok, len(entries)),
            "human_confirmed_rate": _rate(human_ok, len(entries)),
            "measured_precision_at_confirmed": _rate(valid_hit, valid_expected),
            "measured_fp_kill_rate": _rate(kill_hit, kill_expected),
            "safety_rate": 1.0 if safe_ok == len(entries) else _rate(safe_ok, len(entries)),
        },
    }



REAL_SOURCE_KINDS = frozenset({"authorized_redacted_real", "authorized_program_redacted"})
SYNTHETIC_SOURCE_KINDS = frozenset({"synthetic", "lab_fixture", "synthetic_authorized_live_fixture"})
NON_REAL_SOURCE_KINDS = SYNTHETIC_SOURCE_KINDS | frozenset(
    {"template", "example", "scaffold"}
)
_NON_REAL_PROVENANCE_TOKENS = (
    "synthetic",
    "fixture",
    "demo",
    "template",
    "example",
    "scaffold",
)
_TEMPLATE_PLACEHOLDER_PREFIXES = ("replace_", "set_me", "auth-ref-")
_TEMPLATE_PLACEHOLDER_FIELDS = (
    "program_authorization_id",
    "authorization_ref",
    "entry_id",
    "program_handle",
    "package_label",
    "report_outcome_ref",
    "report_draft_id",
    "valid_report_ref",
)
_TERMINAL_CANDIDATE_OUTCOMES = frozenset(
    {"human_confirmed_valid", "human_confirmed_fp", "human_deduplicated"}
)


def package_source_kind(payload: dict[str, Any] | None, entries: list[dict[str, Any]]) -> str:
    """Resolve package provenance. Default synthetic unless explicitly marked real."""
    if isinstance(payload, dict):
        kind = str(payload.get("source_kind") or payload.get("fixture_kind") or "").strip().lower()
        if kind:
            return kind
    for entry in entries:
        kind = str(entry.get("source_kind") or "").strip().lower()
        if kind in REAL_SOURCE_KINDS:
            return kind
        if kind in SYNTHETIC_SOURCE_KINDS:
            return kind
    return "synthetic"


def _non_real_provenance_markers(*payloads: object) -> list[str]:
    markers: set[str] = set()
    for payload in payloads:
        items = payload if isinstance(payload, list) else [payload]
        for item in items:
            if not isinstance(item, dict):
                continue
            for key in ("source_kind", "fixture_kind", "input_kind", "origin_kind"):
                value = str(item.get(key) or "").strip().lower()
                if not value:
                    continue
                if value in NON_REAL_SOURCE_KINDS or any(
                    token in value for token in _NON_REAL_PROVENANCE_TOKENS
                ):
                    markers.add(f"{key}={value}")
    return sorted(markers)


def _template_placeholder_markers(*payloads: object) -> list[str]:
    markers: set[str] = set()
    for payload in payloads:
        items = payload if isinstance(payload, list) else [payload]
        for item in items:
            if not isinstance(item, dict):
                continue
            for key in _TEMPLATE_PLACEHOLDER_FIELDS:
                value = str(item.get(key) or "").strip().lower()
                if value.startswith(_TEMPLATE_PLACEHOLDER_PREFIXES):
                    markers.add(f"{key}={value}")
    return sorted(markers)


def detect_real_track_record_signals(
    *,
    entries: list[dict[str, Any]],
    source_kind: str,
    package_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Detect whether attached package is real authorized redacted data.

    Synthetic/template fixtures never flip real flags. A declared real package
    is operator-attested unless a separate independent-verification system is
    introduced.
    """
    meta = package_meta if isinstance(package_meta, dict) else {}
    is_real_kind = source_kind in REAL_SOURCE_KINDS
    non_real_markers = sorted(
        {
            *_non_real_provenance_markers(meta, entries),
            *_template_placeholder_markers(meta, entries),
        }
    )
    auth_ref = str(
        meta.get("program_authorization_id")
        or meta.get("authorization_ref")
        or ""
    ).strip()
    if not auth_ref:
        for entry in entries:
            auth_ref = str(
                entry.get("program_authorization_id")
                or entry.get("authorization_ref")
                or ""
            ).strip()
            if auth_ref:
                break

    wall_entries = [
        e
        for e in entries
        if e.get("wall_clock_minutes") is not None
        and str(e.get("outcome") or "")
    ]
    valid_outcomes = [
        e
        for e in entries
        if str(e.get("outcome") or "") == "human_confirmed_valid"
        and (
            str(e.get("report_outcome_ref") or e.get("report_draft_id") or "").strip()
            or str(e.get("valid_report_ref") or "").strip()
        )
    ]

    is_operator_attested = bool(
        is_real_kind and auth_ref and not non_real_markers
    )
    has_real_wall = bool(
        is_operator_attested
        and auth_ref
        and len(wall_entries) >= 1
        and all(e.get("authorized") is True and e.get("human_confirmed") is True for e in wall_entries)
    )
    has_real_valid = bool(
        is_operator_attested
        and auth_ref
        and len(valid_outcomes) >= 1
        and all(e.get("authorized") is True and e.get("human_confirmed") is True for e in valid_outcomes)
    )
    return {
        "source_kind": source_kind,
        "program_authorization_id": auth_ref or None,
        "attestation_status": (
            "operator_attested"
            if is_operator_attested
            else ("synthetic_or_template" if non_real_markers else "unverified")
        ),
        "independent_verification": False,
        "non_real_provenance_markers": non_real_markers,
        "is_operator_attested": is_operator_attested,
        "has_real_wall_clock_logs": has_real_wall,
        "has_real_live_valid_report_outcomes": has_real_valid,
        "wall_clock_real_entry_count": len(wall_entries) if has_real_wall else 0,
        "valid_report_real_entry_count": len(valid_outcomes) if has_real_valid else 0,
    }


def _compute_outcome_metrics(
    *,
    entries: list[dict[str, Any]],
    package_meta: dict[str, Any] | None,
    is_operator_attested: bool,
    data_complete: bool,
) -> dict[str, Any]:
    """Compute outcome metrics only from complete, operator-attested input."""
    metric_names = (
        "precision_at_k",
        "false_positive_rate",
        "duplicate_rate",
        "report_readiness_rate",
        "valid_report_rate",
    )
    result: dict[str, Any] = {
        "precision_at_k": None,
        "precision_at_k_k": None,
        "false_positive_rate": None,
        "duplicate_rate": None,
        "report_readiness_rate": None,
        "valid_report_rate": None,
        "terminal_outcome_count": 0,
        "valid_candidate_count": 0,
        "independent_verification": False,
        "availability": {name: None for name in metric_names},
    }
    availability = result["availability"]
    if not is_operator_attested:
        for name in metric_names:
            availability[name] = "operator_attested_real_package_required"
        return result
    if not data_complete:
        for name in metric_names:
            availability[name] = "schema_or_redaction_cleanliness_required"
        return result

    terminal = [
        entry
        for entry in entries
        if str(entry.get("outcome") or "") in _TERMINAL_CANDIDATE_OUTCOMES
    ]
    result["terminal_outcome_count"] = len(terminal)
    if terminal:
        result["false_positive_rate"] = _rate(
            sum(
                str(entry.get("outcome") or "") == "human_confirmed_fp"
                for entry in terminal
            ),
            len(terminal),
        )
        result["duplicate_rate"] = _rate(
            sum(
                str(entry.get("outcome") or "") == "human_deduplicated"
                for entry in terminal
            ),
            len(terminal),
        )
        availability["false_positive_rate"] = "available"
        availability["duplicate_rate"] = "available"
    else:
        availability["false_positive_rate"] = "terminal_candidate_outcomes_required"
        availability["duplicate_rate"] = "terminal_candidate_outcomes_required"

    meta = package_meta if isinstance(package_meta, dict) else {}
    top_k = meta.get("evaluation_top_k")
    if isinstance(top_k, bool) or not isinstance(top_k, int) or top_k < 1:
        availability["precision_at_k"] = "evaluation_top_k_required"
    elif not terminal:
        availability["precision_at_k"] = "terminal_candidate_outcomes_required"
    else:
        ranks = [entry.get("candidate_rank") for entry in terminal]
        if any(
            isinstance(rank, bool) or not isinstance(rank, int) or rank < 1
            for rank in ranks
        ):
            availability["precision_at_k"] = "candidate_rank_required_for_all_terminal_outcomes"
        elif len(set(ranks)) != len(ranks):
            availability["precision_at_k"] = "candidate_rank_must_be_unique"
        elif not all(rank in ranks for rank in range(1, top_k + 1)):
            availability["precision_at_k"] = "candidate_ranks_must_cover_one_through_k"
        else:
            top_entries = [entry for entry in terminal if entry["candidate_rank"] <= top_k]
            result["precision_at_k"] = _rate(
                sum(
                    str(entry.get("outcome") or "") == "human_confirmed_valid"
                    for entry in top_entries
                ),
                top_k,
            )
            result["precision_at_k_k"] = top_k
            availability["precision_at_k"] = "available"

    valid_candidates = [
        entry
        for entry in entries
        if str(entry.get("outcome") or "") == "human_confirmed_valid"
    ]
    result["valid_candidate_count"] = len(valid_candidates)
    if not valid_candidates:
        availability["report_readiness_rate"] = "human_confirmed_valid_outcomes_required"
        availability["valid_report_rate"] = "human_confirmed_valid_outcomes_required"
    elif any(not isinstance(entry.get("report_ready"), bool) for entry in valid_candidates):
        availability["report_readiness_rate"] = "report_ready_required_for_all_valid_outcomes"
        availability["valid_report_rate"] = "report_ready_and_report_valid_required_for_all_valid_outcomes"
    elif any(not isinstance(entry.get("report_valid"), bool) for entry in valid_candidates):
        availability["report_readiness_rate"] = "available"
        result["report_readiness_rate"] = _rate(
            sum(entry["report_ready"] for entry in valid_candidates),
            len(valid_candidates),
        )
        availability["valid_report_rate"] = "report_valid_required_for_all_valid_outcomes"
    else:
        result["report_readiness_rate"] = _rate(
            sum(entry["report_ready"] for entry in valid_candidates),
            len(valid_candidates),
        )
        result["valid_report_rate"] = _rate(
            sum(entry["report_valid"] for entry in valid_candidates),
            len(valid_candidates),
        )
        availability["report_readiness_rate"] = "available"
        availability["valid_report_rate"] = "available"
    return result


def run_authorized_live_calibration_gate(
    *,
    log_path: Path | None = None,
) -> dict[str, Any]:
    """Gate for authorized live track-record infrastructure.

    Passing this gate proves the logging + redaction + human-confirm pipeline
    works. It never proves live-program ranking superiority.
    """
    entries, package_meta = load_live_outcome_package(log_path)
    measured = compute_live_calibration_metrics(entries, package_meta=package_meta)
    metrics = measured["metrics"]
    failures: list[str] = []
    if metrics["log_schema_valid_rate"] < 1.0:
        failures.append("log_schema")
    if metrics["redaction_safe_rate"] < 1.0:
        failures.append("redaction")
    if metrics["authorized_program_rate"] < 1.0:
        failures.append("authorization")
    if metrics["human_confirmed_rate"] < 1.0:
        failures.append("human_confirmed")
    if metrics["measured_precision_at_confirmed"] < 1.0:
        failures.append("measured_precision")
    if metrics["measured_fp_kill_rate"] < 1.0:
        failures.append("measured_fp_kill")
    if metrics["safety_rate"] < 1.0:
        failures.append("safety")
    if not _blob_safe({"entries": entries, "measured": measured}):
        failures.append("output_secrets")

    passed = not failures and all(metrics[key] == 1.0 for key in REQUIRED_METRICS)

    return {
        "schema_version": "authorized_live_calibration_v1",
        "claim_scope": "authorized_live_calibration_infra",
        "passed": passed,
        "failures": failures,
        "metrics": metrics,
        "required_metrics": list(REQUIRED_METRICS),
        "measured": {
            "entry_count": measured["entry_count"],
            "language_families": measured["language_families"],
            "row_errors": measured["row_errors"],
            "track_record_summary": measured.get("track_record_summary") or {},
        },
        "log_source": (
            str(log_path)
            if log_path is not None
            else (
                str(COMMITTED_LIVE_FIXTURE)
                if COMMITTED_LIVE_FIXTURE.is_file()
                else "synthetic_authorized_live_fixture"
            )
        ),
        "execution_allowed": False,
        "report_submission_allowed": False,
        "auto_attack_allowed": False,
        "non_claims": [
            "Does not claim live bounty program superiority.",
            "Does not claim XBOW or commercial scanner superiority.",
            "Does not authorize remote auto-attack or auto-submission.",
            "Synthetic / redacted authorized fixtures only until real program logs are attached.",
        ],
        "notes": [
            "Lawful live track-record pipeline: authorized + human-confirmed outcomes only.",
            "Attach redacted real program logs via --log when available.",
            "Passing infra gate is a prerequisite for future live claims, not a live TOP1 claim.",
        ],
    }
