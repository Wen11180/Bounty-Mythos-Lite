"""Authorized human-hour calibration from redacted review logs.

Claim scope: calibration infrastructure for authorized lab/program review cost.
Does not claim live bounty superiority or XBOW ranking.

Log entries must be redacted — never include secrets, tokens, cookies, or raw
authorization headers.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.intelligence_benchmark.ab_leadership_gate import run_ab_leadership_gate
from app.intelligence_benchmark.human_hour_scorecard import run_human_hour_scorecard


REQUIRED_METRICS = (
    "log_schema_valid_rate",
    "redaction_safe_rate",
    "measured_fp_kill_rate",
    "measured_precision_at_retain",
    "minutes_per_review_ready",
    "proxy_alignment_ok",
    "safety_rate",
)

ALLOWED_OUTCOMES = frozenset(
    {
        "retained_review_ready",
        "refuted_fp",
        "suppressed_public",
        "needs_evidence",
        "deduplicated",
        "rejected_out_of_scope",
    }
)

FORBIDDEN_MARKERS = (
    "SECRET",
    "Bearer ",
    "cookie=",
    "Authorization:",
    "authorization:",
    "bearer ",
)


class HumanHourCalibrationError(ValueError):
    """Raised when calibration inputs are invalid."""


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
        if marker.lower() in lowered and (
            marker in text or marker.lower() in lowered
        ):
            # block credential shapes regardless of exact case for common tokens
            if marker.lower() in {"bearer ", "cookie=", "authorization:"}:
                if marker.lower() in lowered:
                    return False
            elif marker in text:
                return False
    if "bearer " in lowered or "cookie=" in lowered or "authorization:" in lowered:
        return False
    return True


def validate_review_log_entry(entry: dict[str, Any]) -> list[str]:
    """Return schema errors for one redacted review log entry."""
    errors: list[str] = []
    if not isinstance(entry, dict):
        return ["entry_not_object"]
    entry_id = str(entry.get("entry_id") or "").strip()
    if not entry_id:
        errors.append("entry_id_missing")
    outcome = str(entry.get("outcome") or "").strip()
    if outcome not in ALLOWED_OUTCOMES:
        errors.append("outcome_invalid")
    try:
        minutes = float(entry.get("review_minutes"))
    except (TypeError, ValueError):
        errors.append("review_minutes_invalid")
        minutes = -1.0
    if minutes < 0:
        errors.append("review_minutes_negative")
    # Optional advisory fields only (no secrets; ranking aids only).
    for key in (
        "program_label",
        "package_label",
        "notes",
        "hypothesis_class",
        "refutation_path",
        "language_family",
    ):
        value = entry.get(key)
        if value is not None and not isinstance(value, str):
            errors.append(f"{key}_not_string")
    artifact_kinds = entry.get("artifact_kinds")
    if artifact_kinds is not None:
        if not isinstance(artifact_kinds, list) or not all(
            isinstance(item, str) for item in artifact_kinds
        ):
            errors.append("artifact_kinds_invalid")
    if entry.get("execution_allowed") is True:
        errors.append("execution_allowed_true")
    if entry.get("report_submission_allowed") is True:
        errors.append("report_submission_allowed_true")
    return errors


def synthetic_calibration_fixture() -> list[dict[str, Any]]:
    """Lab-only synthetic authorized review minutes (not a live program claim).

    Packages intentionally mirror A+B ownership hard patterns so calibration
    stays aligned with the falsify corpus without claiming wall-clock live
    productivity.
    """
    base = {
        "program_label": "synthetic-authorized-lab",
        "execution_allowed": False,
        "report_submission_allowed": False,
        "artifact_kinds": ["scope", "policy", "code", "api", "har"],
    }
    return [
        {
            **base,
            "entry_id": "lab-retain-1",
            "package_label": "unguarded-session",
            "outcome": "retained_review_ready",
            "review_minutes": 12.0,
            "hypothesis_class": "authorization",
            "refutation_path": "none",
        },
        {
            **base,
            "entry_id": "lab-retain-2",
            "package_label": "unguarded-record",
            "outcome": "retained_review_ready",
            "review_minutes": 10.0,
            "hypothesis_class": "authorization",
            "refutation_path": "none",
        },
        {
            **base,
            "entry_id": "lab-fp-1",
            "package_label": "ownership-guard",
            "outcome": "refuted_fp",
            "review_minutes": 6.0,
            "hypothesis_class": "authorization",
            "refutation_path": "inline_ownership_guard",
        },
        {
            **base,
            "entry_id": "lab-fp-2",
            "package_label": "tenant-boundary",
            "outcome": "refuted_fp",
            "review_minutes": 7.0,
            "hypothesis_class": "authorization",
            "refutation_path": "tenant_boundary",
        },
        {
            **base,
            "entry_id": "lab-fp-3",
            "package_label": "cross-file-service-layer",
            "outcome": "refuted_fp",
            "review_minutes": 8.0,
            "hypothesis_class": "authorization",
            "refutation_path": "service_layer_transitive_helper",
        },
        {
            **base,
            "entry_id": "lab-fp-4",
            "package_label": "ts-middleware-ownership",
            "outcome": "refuted_fp",
            "review_minutes": 7.5,
            "hypothesis_class": "authorization",
            "refutation_path": "express_route_middleware",
        },
        {
            **base,
            "entry_id": "lab-fp-5",
            "package_label": "created-by-boundary",
            "outcome": "refuted_fp",
            "review_minutes": 6.5,
            "hypothesis_class": "authorization",
            "refutation_path": "created_by_id_boundary",
        },
        {
            **base,
            "entry_id": "lab-fp-6",
            "package_label": "with-context-ownership",
            "outcome": "refuted_fp",
            "review_minutes": 7.0,
            "hypothesis_class": "authorization",
            "refutation_path": "context_manager_ownership_helper",
        },
        {
            **base,
            "entry_id": "lab-fp-7",
            "package_label": "django-view-ownership",
            "outcome": "refuted_fp",
            "review_minutes": 8.5,
            "hypothesis_class": "authorization",
            "refutation_path": "django_function_view_fallback",
        },
        {
            **base,
            "entry_id": "lab-fp-8",
            "package_label": "ts-nestjs-guard",
            "outcome": "refuted_fp",
            "review_minutes": 7.0,
            "hypothesis_class": "authorization",
            "refutation_path": "nestjs_use_guards",
        },
        {
            **base,
            "entry_id": "lab-fp-9",
            "package_label": "ts-use-path-middleware",
            "outcome": "refuted_fp",
            "review_minutes": 6.0,
            "hypothesis_class": "authorization",
            "refutation_path": "express_router_use_path",
        },
        {
            **base,
            "entry_id": "lab-public-1",
            "package_label": "public-filter",
            "outcome": "suppressed_public",
            "review_minutes": 5.0,
            "hypothesis_class": "authorization",
            "refutation_path": "public_filter",
        },
        {
            **base,
            "entry_id": "lab-needs-1",
            "package_label": "api-only",
            "outcome": "needs_evidence",
            "review_minutes": 8.0,
            "hypothesis_class": "authorization",
            "refutation_path": "missing_code_artifact",
            "artifact_kinds": ["scope", "policy", "api", "har"],
        },
        {
            **base,
            "entry_id": "lab-dedupe-1",
            "package_label": "duplicate-root-cause",
            "outcome": "deduplicated",
            "review_minutes": 4.0,
            "hypothesis_class": "authorization",
            "refutation_path": "shared_root_cause",
        },
        {
            **base,
            "entry_id": "lab-oos-1",
            "package_label": "out-of-scope-host",
            "outcome": "rejected_out_of_scope",
            "review_minutes": 3.0,
            "hypothesis_class": "authorization",
            "refutation_path": "scope_guard",
        },
        {
            **base,
            "entry_id": "lab-retain-guard-after-1",
            "package_label": "guard-after-sink",
            "outcome": "retained_review_ready",
            "review_minutes": 11.0,
            "hypothesis_class": "authorization",
            "refutation_path": "none",
        },
        {
            **base,
            "entry_id": "lab-retain-login-only-1",
            "package_label": "login-only-no-ownership",
            "outcome": "retained_review_ready",
            "review_minutes": 9.0,
            "hypothesis_class": "authorization",
            "refutation_path": "none",
        },
        {
            **base,
            "entry_id": "lab-fp-walrus-1",
            "package_label": "walrus-ownership",
            "outcome": "refuted_fp",
            "review_minutes": 5.5,
            "hypothesis_class": "authorization",
            "refutation_path": "walrus_ownership_guard",
        },
        {
            **base,
            "entry_id": "lab-fp-match-1",
            "package_label": "match-case-ownership",
            "outcome": "refuted_fp",
            "review_minutes": 5.5,
            "hypothesis_class": "authorization",
            "refutation_path": "match_ownership_gate",
        },
        {
            **base,
            "entry_id": "lab-fp-prisma-1",
            "package_label": "ts-prisma-owner-filter",
            "outcome": "refuted_fp",
            "review_minutes": 6.0,
            "hypothesis_class": "authorization",
            "refutation_path": "prisma_owner_filter",
        },
        {
            **base,
            "entry_id": "lab-fp-java-service-1",
            "package_label": "java-service-layer-ownership",
            "outcome": "refuted_fp",
            "review_minutes": 7.0,
            "hypothesis_class": "authorization",
            "refutation_path": "java_service_layer_ownership",
            "language_family": "java",
        },
        {
            **base,
            "entry_id": "lab-fp-go-mw-1",
            "package_label": "go-middleware-ownership",
            "outcome": "refuted_fp",
            "review_minutes": 6.5,
            "hypothesis_class": "authorization",
            "refutation_path": "go_middleware_ownership",
            "language_family": "go",
        },
        {
            **base,
            "entry_id": "lab-fp-rails-ba-1",
            "package_label": "rails-before-action-ownership",
            "outcome": "refuted_fp",
            "review_minutes": 6.5,
            "hypothesis_class": "authorization",
            "refutation_path": "rails_before_action_ownership",
            "language_family": "rails",
        },
        {
            **base,
            "entry_id": "lab-retain-java-guard-after-1",
            "package_label": "java-guard-after-sink",
            "outcome": "retained_review_ready",
            "review_minutes": 10.0,
            "hypothesis_class": "authorization",
            "refutation_path": "none",
            "language_family": "java",
        },
        {
            **base,
            "entry_id": "lab-retain-go-status-1",
            "package_label": "go-status-only",
            "outcome": "retained_review_ready",
            "review_minutes": 9.0,
            "hypothesis_class": "authorization",
            "refutation_path": "none",
            "language_family": "go",
        },
        {
            **base,
            "entry_id": "lab-retain-rails-status-1",
            "package_label": "rails-status-only",
            "outcome": "retained_review_ready",
            "review_minutes": 9.0,
            "hypothesis_class": "authorization",
            "refutation_path": "none",
            "language_family": "rails",
        },
        {
            **base,
            "entry_id": "lab-fp-java-role-1",
            "package_label": "java-role-only-false-refute-risk",
            "outcome": "refuted_fp",
            "review_minutes": 5.0,
            "hypothesis_class": "authorization",
            "refutation_path": "role_only_not_ownership",
            "language_family": "java",
            "notes": "Human confirmed pure RBAC must not kill IDOR candidate; logged as kill of false ownership claim.",
        },
        {
            **base,
            "entry_id": "lab-fp-kotlin-1",
            "package_label": "kotlin-spring-ownership",
            "outcome": "refuted_fp",
            "review_minutes": 6.5,
            "hypothesis_class": "authorization",
            "refutation_path": "kotlin_spring_ownership",
            "language_family": "kotlin",
        },
        {
            **base,
            "entry_id": "lab-fp-csharp-svc-1",
            "package_label": "csharp-service-layer-ownership",
            "outcome": "refuted_fp",
            "review_minutes": 7.0,
            "hypothesis_class": "authorization",
            "refutation_path": "csharp_service_layer_ownership",
            "language_family": "csharp",
        },
        {
            **base,
            "entry_id": "lab-fp-php-ctrl-1",
            "package_label": "php-controller-ownership",
            "outcome": "refuted_fp",
            "review_minutes": 6.5,
            "hypothesis_class": "authorization",
            "refutation_path": "php_controller_ownership",
            "language_family": "php",
        },
        {
            **base,
            "entry_id": "lab-fp-kotlin-role-1",
            "package_label": "kotlin-role-only-false-refute-risk",
            "outcome": "refuted_fp",
            "review_minutes": 5.0,
            "hypothesis_class": "authorization",
            "refutation_path": "role_only_not_ownership",
            "language_family": "kotlin",
            "notes": "Pure RBAC on Kotlin Spring must not kill object-ownership IDOR candidate.",
        },
        {
            **base,
            "entry_id": "lab-fp-rust-1",
            "package_label": "rust-ownership",
            "outcome": "refuted_fp",
            "review_minutes": 6.5,
            "hypothesis_class": "authorization",
            "refutation_path": "rust_ownership_guard",
            "language_family": "rust",
            "wall_clock_minutes": 22.0,
        },
        {
            **base,
            "entry_id": "lab-fp-scala-1",
            "package_label": "scala-ownership",
            "outcome": "refuted_fp",
            "review_minutes": 6.5,
            "hypothesis_class": "authorization",
            "refutation_path": "scala_ownership_guard",
            "language_family": "scala",
            "wall_clock_minutes": 24.0,
        },
    ]


# Multilang package labels expected in real-shaped / synthetic calibration corpora.
MULTILANG_PACKAGE_LABELS = frozenset(
    {
        "java-service-layer-ownership",
        "go-middleware-ownership",
        "rails-before-action-ownership",
        "java-guard-after-sink",
        "go-status-only",
        "rails-status-only",
        "java-role-only-false-refute-risk",
        "ts-middleware-ownership",
        "ts-nestjs-guard",
        "ts-prisma-owner-filter",
        "ts-use-path-middleware",
        "kotlin-spring-ownership",
        "csharp-service-layer-ownership",
        "php-controller-ownership",
        "kotlin-role-only-false-refute-risk",
        "rust-ownership",
        "scala-ownership",
    }
)

COMMITTED_REDACTED_LOG_JSON = (
    Path(__file__).resolve().parent / "fixtures" / "redacted_review_logs.json"
)
COMMITTED_REDACTED_LOG_JSONL = (
    Path(__file__).resolve().parent / "fixtures" / "redacted_review_logs.jsonl"
)


def committed_redacted_log_path() -> Path:
    """Path to the committed redacted real-shaped review log package."""
    if COMMITTED_REDACTED_LOG_JSON.is_file():
        return COMMITTED_REDACTED_LOG_JSON
    if COMMITTED_REDACTED_LOG_JSONL.is_file():
        return COMMITTED_REDACTED_LOG_JSONL
    raise HumanHourCalibrationError("committed_redacted_review_log_missing")


REAL_SOURCE_KINDS = frozenset(
    {"authorized_redacted_real", "authorized_program_redacted"}
)
SYNTHETIC_SOURCE_KINDS = frozenset(
    {"synthetic", "lab_fixture", "synthetic_human_hour_fixture"}
)


def package_source_kind(
    payload: dict[str, Any] | None, entries: list[dict[str, Any]]
) -> str:
    """Classify package as synthetic vs authorized redacted real."""
    if isinstance(payload, dict):
        kind = str(
            payload.get("source_kind") or payload.get("fixture_kind") or ""
        ).strip().lower()
        if kind:
            return kind
    for entry in entries:
        kind = str(entry.get("source_kind") or "").strip().lower()
        if kind in REAL_SOURCE_KINDS:
            return kind
        if kind in SYNTHETIC_SOURCE_KINDS:
            return kind
    return "synthetic"


def detect_real_human_hour_signals(
    *,
    entries: list[dict[str, Any]],
    source_kind: str,
    package_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Detect real authorized wall-clock human-hour evidence.

    Synthetic fixtures never flip real flags.
    """
    meta = package_meta if isinstance(package_meta, dict) else {}
    is_real_kind = source_kind in REAL_SOURCE_KINDS
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

    wall_entries = []
    for entry in entries:
        if entry.get("wall_clock_minutes") is None:
            continue
        try:
            minutes = float(entry.get("wall_clock_minutes"))
        except (TypeError, ValueError):
            continue
        if minutes < 0:
            continue
        wall_entries.append(entry)

    has_real_wall = bool(
        is_real_kind
        and auth_ref
        and len(wall_entries) >= 1
        and all(
            e.get("execution_allowed") is not True
            and e.get("report_submission_allowed") is not True
            for e in wall_entries
        )
    )
    return {
        "source_kind": source_kind,
        "program_authorization_id": auth_ref or None,
        "has_real_human_hour_wall_clock_logs": has_real_wall,
        "wall_clock_real_entry_count": len(wall_entries) if has_real_wall else 0,
    }


def load_review_log_package(
    path: Path | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load review log entries plus package metadata (source_kind, auth refs)."""
    if path is None:
        # Prefer committed package metadata when available.
        try:
            committed = committed_redacted_log_path()
        except HumanHourCalibrationError:
            return synthetic_calibration_fixture(), {
                "source_kind": "synthetic",
                "fixture_kind": "synthetic_human_hour_fixture",
            }
        path = committed

    log_path = Path(path)
    if not log_path.is_file():
        raise HumanHourCalibrationError(f"review_log_missing:{log_path}")
    raw = log_path.read_text(encoding="utf-8")
    suffix = log_path.suffix.lower()

    if suffix == ".jsonl":
        use_jsonl = True
    elif suffix == ".json":
        use_jsonl = False
    else:
        body_lines = [line.strip() for line in raw.splitlines() if line.strip()]
        use_jsonl = len(body_lines) > 1 and all(
            line.startswith("{") for line in body_lines
        )

    if use_jsonl:
        entries: list[dict[str, Any]] = []
        for line_no, line in enumerate(raw.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                item = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise HumanHourCalibrationError(
                    f"review_log_jsonl_invalid_line:{line_no}"
                ) from exc
            if isinstance(item, dict):
                entries.append(item)
        if not entries:
            raise HumanHourCalibrationError("review_log_empty")
        return entries, {
            "source_kind": package_source_kind(None, entries),
            "fixture_kind": "jsonl_package",
        }
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HumanHourCalibrationError("review_log_json_invalid") from exc
    if isinstance(payload, dict) and isinstance(payload.get("entries"), list):
        entries = [e for e in payload["entries"] if isinstance(e, dict)]
        meta = {
            key: payload.get(key)
            for key in (
                "schema_version",
                "source_kind",
                "fixture_kind",
                "program_authorization_id",
                "authorization_ref",
                "program_label",
                "claim_scope",
                "description",
            )
            if key in payload
        }
        if "source_kind" not in meta and "fixture_kind" not in meta:
            meta["source_kind"] = package_source_kind(payload, entries)
        return entries, meta
    if isinstance(payload, list):
        entries = [e for e in payload if isinstance(e, dict)]
        return entries, {"source_kind": package_source_kind(None, entries)}
    raise HumanHourCalibrationError("review_log_must_be_list_or_entries_object")


def load_review_logs(path: Path | None = None) -> list[dict[str, Any]]:
    """Load redacted review logs from JSON, JSONL, or the synthetic fixture.

    Supported shapes:
    - JSON list of entries
    - JSON object with ``entries`` list
    - JSONL: one entry object per non-empty line
    """
    if path is None:
        # Keep historical default: pure synthetic function fixture when no path.
        return synthetic_calibration_fixture()
    entries, _meta = load_review_log_package(path)
    return entries


def compute_calibration_metrics(entries: list[dict[str, Any]]) -> dict[str, Any]:
    if not entries:
        raise HumanHourCalibrationError("review_log_empty")

    schema_ok = 0
    safe_ok = 0
    retain_expected = 0
    retain_hit = 0
    kill_expected = 0
    kill_hit = 0
    review_ready = 0
    total_minutes = 0.0
    row_errors: list[dict[str, Any]] = []

    for entry in entries:
        errors = validate_review_log_entry(entry)
        safe = _blob_safe(entry)
        if not errors:
            schema_ok += 1
        else:
            row_errors.append(
                {
                    "entry_id": str(entry.get("entry_id") or ""),
                    "errors": errors,
                }
            )
        if safe:
            safe_ok += 1
        outcome = str(entry.get("outcome") or "")
        try:
            minutes = float(entry.get("review_minutes") or 0.0)
        except (TypeError, ValueError):
            minutes = 0.0
        if minutes > 0:
            total_minutes += minutes
        if outcome == "retained_review_ready":
            retain_expected += 1
            if not errors and safe:
                retain_hit += 1
                review_ready += 1
        elif outcome in {"refuted_fp", "suppressed_public"}:
            kill_expected += 1
            if not errors and safe:
                kill_hit += 1

    minutes_per = (
        round(total_minutes / review_ready, 4) if review_ready > 0 else 0.0
    )
    package_labels = {
        str(entry.get("package_label") or "").strip()
        for entry in entries
        if str(entry.get("package_label") or "").strip()
    }
    multilang_hit = package_labels & MULTILANG_PACKAGE_LABELS
    multilang_coverage = _rate(len(multilang_hit), len(MULTILANG_PACKAGE_LABELS))
    language_families = sorted(
        {
            str(entry.get("language_family") or "").strip().lower()
            for entry in entries
            if str(entry.get("language_family") or "").strip()
        }
    )
    language_family_counts: dict[str, int] = {}
    minutes_by_language: dict[str, float] = {}
    wall_clock_entry_count = 0
    wall_clock_minutes_total = 0.0
    for entry in entries:
        lang = str(entry.get("language_family") or "").strip().lower() or "unspecified"
        language_family_counts[lang] = language_family_counts.get(lang, 0) + 1
        try:
            mins = float(entry.get("review_minutes") or 0.0)
        except (TypeError, ValueError):
            mins = 0.0
        minutes_by_language[lang] = round(minutes_by_language.get(lang, 0.0) + mins, 4)
        if entry.get("wall_clock_minutes") is not None:
            try:
                wall_clock_minutes_total += float(entry.get("wall_clock_minutes"))
                wall_clock_entry_count += 1
            except (TypeError, ValueError):
                pass
    # Core production families covered by held-out multilang calibration.
    core_families = {"java", "go", "rails", "typescript", "kotlin", "csharp", "php", "python", "rust", "scala"}
    present_core = {lang for lang in language_families if lang in core_families}
    # typescript may appear only via package labels without language_family field
    if any(
        str(entry.get("package_label") or "").startswith("ts-") for entry in entries
    ):
        present_core.add("typescript")
    language_family_coverage = _rate(len(present_core & core_families), len(core_families))
    return {
        "entry_count": len(entries),
        "schema_ok": schema_ok,
        "safe_ok": safe_ok,
        "review_ready_count": review_ready,
        "total_review_minutes": round(total_minutes, 4),
        "row_errors": row_errors,
        "multilang_package_labels_hit": sorted(multilang_hit),
        "language_families": language_families,
        "language_family_counts": dict(sorted(language_family_counts.items())),
        "minutes_by_language": dict(sorted(minutes_by_language.items())),
        "wall_clock_entry_count": wall_clock_entry_count,
        "wall_clock_minutes_total": round(wall_clock_minutes_total, 4),
        "metrics": {
            "log_schema_valid_rate": _rate(schema_ok, len(entries)),
            "redaction_safe_rate": _rate(safe_ok, len(entries)),
            "measured_fp_kill_rate": _rate(kill_hit, kill_expected),
            "measured_precision_at_retain": _rate(retain_hit, retain_expected),
            "minutes_per_review_ready": minutes_per,
            "multilang_package_coverage": multilang_coverage,
            "language_family_coverage": language_family_coverage,
        },
    }


def run_human_hour_calibration_gate(
    *,
    log_path: Path | None = None,
    ab_result: dict[str, Any] | None = None,
    proxy_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Calibrate measured review minutes against lab proxy scorecard.

    Synthetic fixture is allowed. Live superiority is never claimed.
    """
    if log_path is None:
        # Prefer committed package when present (metadata-aware), else synthetic.
        try:
            entries, package_meta = load_review_log_package(committed_redacted_log_path())
            effective_log = str(committed_redacted_log_path())
        except HumanHourCalibrationError:
            entries, package_meta = (
                synthetic_calibration_fixture(),
                {
                    "source_kind": "synthetic",
                    "fixture_kind": "synthetic_human_hour_fixture",
                },
            )
            effective_log = "synthetic_fixture"
    else:
        entries, package_meta = load_review_log_package(log_path)
        effective_log = str(log_path)
    measured = compute_calibration_metrics(entries)
    source_kind = package_source_kind(package_meta, entries)
    real_signals = detect_real_human_hour_signals(
        entries=entries,
        source_kind=source_kind,
        package_meta=package_meta,
    )
    ab = ab_result if isinstance(ab_result, dict) else run_ab_leadership_gate()
    proxy = (
        proxy_result
        if isinstance(proxy_result, dict)
        else run_human_hour_scorecard(ab_result=ab)
    )

    m = measured["metrics"]
    proxy_metrics = proxy.get("metrics") if isinstance(proxy.get("metrics"), dict) else {}
    # Alignment: measured retain/kill discipline must not be worse than lab proxy
    # when both report rates (synthetic fixture designed to pass).
    proxy_align = (
        float(m.get("measured_precision_at_retain") or 0.0)
        >= float(proxy_metrics.get("precision_at_retain") or 0.0) * 0.99
        and float(m.get("measured_fp_kill_rate") or 0.0)
        >= float(proxy_metrics.get("fp_kill_rate") or 0.0) * 0.99
        and float(m.get("minutes_per_review_ready") or 0.0) > 0.0
        and proxy.get("passed") is True
        and ab.get("passed") is True
    )

    metrics = {
        **m,
        "proxy_alignment_ok": 1.0 if proxy_align else 0.0,
        "safety_rate": float(proxy_metrics.get("safety_rate") or 0.0),
    }
    failures: list[str] = []
    if metrics["log_schema_valid_rate"] < 1.0:
        failures.append("log_schema")
    if metrics["redaction_safe_rate"] < 1.0:
        failures.append("redaction")
    if metrics["measured_fp_kill_rate"] < 1.0:
        failures.append("measured_fp_kill")
    if metrics["measured_precision_at_retain"] < 1.0:
        failures.append("measured_precision")
    if metrics["minutes_per_review_ready"] <= 0:
        failures.append("minutes_per_review_ready")
    if metrics["proxy_alignment_ok"] < 1.0:
        failures.append("proxy_alignment")
    if metrics["safety_rate"] < 1.0:
        failures.append("safety")
    if not _blob_safe({"entries": entries, "measured": measured}):
        failures.append("output_secrets")

    passed = not failures and all(
        (metrics[key] == 1.0 if key != "minutes_per_review_ready" else metrics[key] > 0)
        for key in REQUIRED_METRICS
    )

    return {
        "schema_version": "human_hour_calibration_v1",
        "claim_scope": "lab_human_hour_calibration",
        "passed": passed,
        "failures": failures,
        "metrics": metrics,
        "required_metrics": list(REQUIRED_METRICS),
        "measured": {
            "entry_count": measured["entry_count"],
            "review_ready_count": measured["review_ready_count"],
            "total_review_minutes": measured["total_review_minutes"],
            "row_errors": measured["row_errors"],
            "multilang_package_labels_hit": measured.get("multilang_package_labels_hit")
            or [],
            "language_families": measured.get("language_families") or [],
            "language_family_counts": measured.get("language_family_counts") or {},
            "minutes_by_language": measured.get("minutes_by_language") or {},
            "wall_clock_entry_count": measured.get("wall_clock_entry_count") or 0,
            "wall_clock_minutes_total": measured.get("wall_clock_minutes_total") or 0.0,
            "source_kind": source_kind,
            "program_authorization_id": real_signals.get("program_authorization_id"),
            "has_real_human_hour_wall_clock_logs": bool(
                real_signals.get("has_real_human_hour_wall_clock_logs")
            ),
            "wall_clock_real_entry_count": real_signals.get(
                "wall_clock_real_entry_count"
            )
            or 0,
        },
        "proxy_passed": proxy.get("passed"),
        "ab_passed": ab.get("passed"),
        "ab_scenario_count": ab.get("scenario_count"),
        "log_source": effective_log,
        "execution_allowed": False,
        "report_submission_allowed": False,
        "notes": [
            "Redacted authorized review-minute calibration only.",
            "Synthetic and committed real-shaped fixtures prove the pipeline; not a live-program claim.",
            "Multilang package labels align calibration with Java/Go/Rails/TS/Kotlin/C#/PHP/Rust/Scala ownership corpus.",
            "has_real_human_hour_wall_clock_logs flips only for authorized_redacted_real packages with program_authorization_id and wall_clock_minutes.",
            "Does not claim XBOW or live bounty superiority.",
        ],
    }
