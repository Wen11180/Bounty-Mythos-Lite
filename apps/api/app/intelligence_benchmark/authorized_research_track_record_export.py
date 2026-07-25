"""Export redacted research-session track records for live/HH calibration.

Builds packages compatible with:
- authorized-live-calibration --log
- human-hour-calibration --log

Safety:
- Never unlocks execution, validation, or report submission
- Never auto-submits reports
- source_kind becomes authorized_redacted_real only when caller both provides
  program_authorization_id and sets declare_real_package=True without a
  synthetic/template input marker
- Default / demo path remains synthetic and must not flip has_real_* flags
- Secret-like content is rejected (not written)
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.human_review_approvals import (
    APPROVAL_KIND_RESIDUAL,
    DECISION_STATUSES,
    resolve_human_review_approvals,
)
from app.intelligence_benchmark.authorized_live_calibration import (
    ALLOWED_OUTCOMES as LIVE_ALLOWED_OUTCOMES,
    detect_real_track_record_signals,
    package_source_kind as live_package_source_kind,
    validate_live_log_entry,
)
from app.intelligence_benchmark.human_hour_calibration import (
    ALLOWED_OUTCOMES as HH_ALLOWED_OUTCOMES,
    FORBIDDEN_MARKERS,
    detect_real_human_hour_signals,
    package_source_kind as hh_package_source_kind,
    validate_review_log_entry,
)

SCHEMA_VERSION = "authorized_research_track_record_export_v1"
LIVE_PACKAGE_SCHEMA = "authorized_live_outcomes_v1"
HH_PACKAGE_SCHEMA = "human_hour_review_logs_v1"

REAL_SOURCE_KINDS = frozenset(
    {"authorized_redacted_real", "authorized_program_redacted"}
)
SYNTHETIC_SOURCE_KIND = "synthetic"
_NON_REAL_SOURCE_MARKERS = frozenset(
    {
        "synthetic",
        "lab_fixture",
        "synthetic_authorized_live_fixture",
        "synthetic_human_hour_fixture",
        "template",
        "example",
        "scaffold",
    }
)

_SECRET_VALUE_RE = re.compile(
    r"(?i)(bearer\s+[a-z0-9._\-+=/]{8,}|api[_-]?key\s*[:=]\s*\S+|"
    r"password\s*[:=]\s*\S+|cookie\s*[:=]\s*\S+|authorization\s*:\s*\S+)"
)
_SECRET_KEY_RE = re.compile(
    r"(secret|token|cookie|password|authorization|api[_-]?key|credential|bearer)",
    re.IGNORECASE,
)

_STATUS_TO_LIVE: dict[str, str] = {
    "approved": "human_confirmed_valid",
    "rejected_fp": "human_confirmed_fp",
    "denied": "human_rejected_out_of_scope",
    "waived": "not_submitted",
    "expired": "human_needs_more_evidence",
    "revoked": "not_submitted",
}
_STATUS_TO_HH: dict[str, str] = {
    "approved": "retained_review_ready",
    "rejected_fp": "refuted_fp",
    "denied": "rejected_out_of_scope",
    "waived": "suppressed_public",
    "expired": "needs_evidence",
    "revoked": "suppressed_public",
}

_LIVE_OUTCOME_ALIASES = {
    "valid": "human_confirmed_valid",
    "confirmed_valid": "human_confirmed_valid",
    "human_confirmed_valid": "human_confirmed_valid",
    "fp": "human_confirmed_fp",
    "false_positive": "human_confirmed_fp",
    "human_confirmed_fp": "human_confirmed_fp",
    "needs_evidence": "human_needs_more_evidence",
    "human_needs_more_evidence": "human_needs_more_evidence",
    "out_of_scope": "human_rejected_out_of_scope",
    "human_rejected_out_of_scope": "human_rejected_out_of_scope",
    "deduplicated": "human_deduplicated",
    "human_deduplicated": "human_deduplicated",
    "not_submitted": "not_submitted",
}
_HH_OUTCOME_ALIASES = {
    "retain": "retained_review_ready",
    "retained": "retained_review_ready",
    "retained_review_ready": "retained_review_ready",
    "fp": "refuted_fp",
    "refuted_fp": "refuted_fp",
    "false_positive": "refuted_fp",
    "needs_evidence": "needs_evidence",
    "deduplicated": "deduplicated",
    "out_of_scope": "rejected_out_of_scope",
    "rejected_out_of_scope": "rejected_out_of_scope",
    "suppressed": "suppressed_public",
    "suppressed_public": "suppressed_public",
}


class TrackRecordExportError(ValueError):
    """Raised when track-record export inputs are invalid or unsafe."""

def export_research_track_record(
    *,
    approvals: list[dict[str, Any] | Any] | None = None,
    approvals_bundle: dict[str, Any] | None = None,
    package_root: str | Path | None = None,
    wall_clock_runner: dict[str, Any] | Any | None = None,
    session_notes: list[dict[str, Any]] | None = None,
    program_handle: str = "research-session",
    package_id: str = "",
    package_label: str = "",
    program_authorization_id: str | None = None,
    declare_real_package: bool = False,
    language_family: str = "unknown",
    hypothesis_class: str = "authorization",
    vuln_family: str = "idor",
    evaluation_top_k: int | None = None,
    human_allow_export_write: bool = False,
    out_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Build redacted live + human-hour packages from research-session artifacts.

    Real package flags only flip when declare_real_package is True, a non-empty
    program_authorization_id is provided, no input is marked synthetic/template,
    and entries carry the fields required by detect_real_* helpers.
    """
    handle = _safe_label(program_handle) or "research-session"
    pkg_id = _safe_label(package_id) or _safe_label(package_label) or "research-package"
    pkg_label = _safe_label(package_label) or pkg_id
    lang = _safe_label(language_family) or "unknown"
    hyp = _safe_label(hypothesis_class) or "authorization"
    vuln = _safe_label(vuln_family) or "idor"
    auth_ref = str(program_authorization_id or "").strip()
    if evaluation_top_k is not None and (
        isinstance(evaluation_top_k, bool)
        or not isinstance(evaluation_top_k, int)
        or evaluation_top_k < 1
    ):
        raise TrackRecordExportError("evaluation_top_k_invalid")

    if declare_real_package and not auth_ref:
        raise TrackRecordExportError(
            "declare_real_package_requires_program_authorization_id"
        )

    source_kind = (
        "authorized_redacted_real"
        if (declare_real_package and auth_ref)
        else SYNTHETIC_SOURCE_KIND
    )

    resolved = resolve_human_review_approvals(
        approvals=approvals,
        approvals_bundle=approvals_bundle,
        package_root=package_root,
    )
    residual_decisions = [
        a
        for a in resolved
        if str(a.get("approval_kind") or "") == APPROVAL_KIND_RESIDUAL
        and str(a.get("status") or "") in DECISION_STATUSES
    ]

    runner = _normalize_wall_clock_runner(wall_clock_runner)
    session_wall = _wall_clock_minutes_from_runner(runner)
    notes = [n for n in (session_notes or []) if isinstance(n, dict)]
    non_real_inputs = _non_real_input_contexts(
        session_notes=notes,
        residual_decisions=residual_decisions,
        approvals=approvals,
        approvals_bundle=approvals_bundle,
        wall_clock_runner=runner,
    )
    if declare_real_package and non_real_inputs:
        raise TrackRecordExportError(
            "declare_real_package_rejects_synthetic_input:"
            + ",".join(non_real_inputs)
        )

    live_entries: list[dict[str, Any]] = []
    hh_entries: list[dict[str, Any]] = []

    for idx, note in enumerate(notes, start=1):
        _reject_secret_payload(note, context=f"session_notes[{idx}]")
        live_entries.append(
            _live_entry_from_note(
                note,
                index=idx,
                program_handle=handle,
                package_label=pkg_label,
                auth_ref=auth_ref,
                source_kind=source_kind,
                language_family=lang,
                hypothesis_class=hyp,
                vuln_family=vuln,
                default_wall=session_wall,
            )
        )
        hh_entries.append(
            _hh_entry_from_note(
                note,
                index=idx,
                package_label=pkg_label,
                auth_ref=auth_ref,
                source_kind=source_kind,
                language_family=lang,
                hypothesis_class=hyp,
                default_wall=session_wall,
            )
        )

    for idx, approval in enumerate(residual_decisions, start=1):
        _reject_secret_payload(approval, context=f"approval[{idx}]")
        entry_index = len(live_entries) + 1
        live_entries.append(
            _live_entry_from_approval(
                approval,
                index=entry_index,
                program_handle=handle,
                package_label=pkg_label,
                auth_ref=auth_ref,
                source_kind=source_kind,
                language_family=lang,
                hypothesis_class=hyp,
                vuln_family=vuln,
                default_wall=session_wall,
            )
        )
        hh_entries.append(
            _hh_entry_from_approval(
                approval,
                index=entry_index,
                package_label=pkg_label,
                auth_ref=auth_ref,
                source_kind=source_kind,
                language_family=lang,
                hypothesis_class=hyp,
                default_wall=session_wall,
            )
        )

    if not live_entries and session_wall is not None and session_wall >= 0:
        live_entries.append(
            _blank_live_wall_entry(
                program_handle=handle,
                package_label=pkg_label,
                auth_ref=auth_ref,
                source_kind=source_kind,
                language_family=lang,
                hypothesis_class=hyp,
                vuln_family=vuln,
                wall_clock_minutes=session_wall,
            )
        )
        hh_entries.append(
            _blank_hh_wall_entry(
                package_label=pkg_label,
                auth_ref=auth_ref,
                source_kind=source_kind,
                language_family=lang,
                hypothesis_class=hyp,
                wall_clock_minutes=session_wall,
            )
        )

    if not live_entries and not hh_entries:
        raise TrackRecordExportError(
            "no_exportable_research_session_artifacts"
            ":provide_session_notes_or_residual_decisions_or_wall_clock_runner"
        )

    for entry in live_entries:
        _force_live_safety(entry)
        errors = validate_live_log_entry(entry)
        if errors:
            raise TrackRecordExportError(
                f"live_entry_invalid:{entry.get('entry_id')}:{','.join(errors)}"
            )
        if not _blob_safe(entry):
            raise TrackRecordExportError(
                f"live_entry_secret_like:{entry.get('entry_id')}"
            )

    for entry in hh_entries:
        _force_hh_safety(entry)
        errors = validate_review_log_entry(entry)
        if errors:
            raise TrackRecordExportError(
                f"hh_entry_invalid:{entry.get('entry_id')}:{','.join(errors)}"
            )
        if not _blob_safe(entry):
            raise TrackRecordExportError(
                f"hh_entry_secret_like:{entry.get('entry_id')}"
            )

    live_package: dict[str, Any] = {
        "schema_version": LIVE_PACKAGE_SCHEMA,
        "source_kind": source_kind,
        "claim_scope": (
            "authorized_live_calibration_real_package"
            if source_kind in REAL_SOURCE_KINDS
            else "synthetic_research_session_export"
        ),
        "description": (
            "Redacted research-session live outcomes exported by Mythos-Lite. "
            "No secrets; execution and submission blocked."
        ),
        "attestation_status": (
            "operator_attested" if source_kind in REAL_SOURCE_KINDS else "synthetic"
        ),
        "independent_verification": False,
        "execution_allowed": False,
        "report_submission_allowed": False,
        "auto_attack_allowed": False,
        "package_id": pkg_id,
        "entries": live_entries,
    }
    hh_package: dict[str, Any] = {
        "schema_version": HH_PACKAGE_SCHEMA,
        "source_kind": source_kind,
        "claim_scope": (
            "authorized_human_hour_real_package"
            if source_kind in REAL_SOURCE_KINDS
            else "synthetic_research_session_export"
        ),
        "description": (
            "Redacted research-session human-hour review logs exported by Mythos-Lite. "
            "No secrets; execution and submission blocked."
        ),
        "attestation_status": (
            "operator_attested" if source_kind in REAL_SOURCE_KINDS else "synthetic"
        ),
        "independent_verification": False,
        "execution_allowed": False,
        "report_submission_allowed": False,
        "package_id": pkg_id,
        "entries": hh_entries,
    }
    if auth_ref:
        live_package["program_authorization_id"] = auth_ref
        hh_package["program_authorization_id"] = auth_ref
    if evaluation_top_k is not None:
        live_package["evaluation_top_k"] = evaluation_top_k

    if not _blob_safe(live_package) or not _blob_safe(hh_package):
        raise TrackRecordExportError("exported_package_secret_like_content")

    live_kind = live_package_source_kind(live_package, live_entries)
    hh_kind = hh_package_source_kind(hh_package, hh_entries)
    live_signals = detect_real_track_record_signals(
        entries=live_entries,
        source_kind=live_kind,
        package_meta=live_package,
    )
    hh_signals = detect_real_human_hour_signals(
        entries=hh_entries,
        source_kind=hh_kind,
        package_meta=hh_package,
    )

    if source_kind not in REAL_SOURCE_KINDS:
        if live_signals.get("has_real_wall_clock_logs") or live_signals.get(
            "has_real_live_valid_report_outcomes"
        ):
            raise TrackRecordExportError("synthetic_export_flipped_live_real_flags")
        if hh_signals.get("has_real_human_hour_wall_clock_logs"):
            raise TrackRecordExportError("synthetic_export_flipped_hh_real_flags")

    written: dict[str, str | None] = {
        "live_path": None,
        "human_hour_path": None,
        "manifest_path": None,
    }
    export_written = False
    if out_dir is not None:
        if not human_allow_export_write:
            raise TrackRecordExportError(
                "human_allow_export_write_required_to_write_files"
            )
        root = Path(out_dir)
        root.mkdir(parents=True, exist_ok=True)
        live_path = root / "authorized_live_outcomes.export.json"
        hh_path = root / "human_hour_review_logs.export.json"
        manifest_path = root / "research_track_record_export.manifest.json"
        live_path.write_text(
            json.dumps(live_package, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        hh_path.write_text(
            json.dumps(hh_package, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        written["live_path"] = str(live_path)
        written["human_hour_path"] = str(hh_path)
        written["manifest_path"] = str(manifest_path)
        export_written = True

    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "stage": "authorized_research_track_record_export",
        "status": "exported" if export_written else "built_in_memory",
        "source_kind": source_kind,
        "declare_real_package": bool(declare_real_package),
        "program_authorization_id": auth_ref or None,
        "evaluation_top_k": evaluation_top_k,
        "attestation_status": live_package["attestation_status"],
        "independent_verification": False,
        "package_id": pkg_id,
        "package_label": pkg_label,
        "program_handle": handle,
        "live_package": live_package,
        "human_hour_package": hh_package,
        "live_entry_count": len(live_entries),
        "human_hour_entry_count": len(hh_entries),
        "residual_decision_count": len(residual_decisions),
        "session_note_count": len(notes),
        "wall_clock_minutes_from_runner": session_wall,
        "signals_preview": {
            "live": live_signals,
            "human_hour": hh_signals,
        },
        "paths": written,
        "export_written": export_written,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "auto_attack_allowed": False,
        "auto_submitted": False,
        "human_review_required": True,
        "safety_invariants": [
            "no_auto_attack",
            "no_auto_submit",
            "no_raw_secrets",
            "synthetic_or_template_inputs_cannot_be_declared_real",
            "real_flags_only_via_detect_real_helpers",
        ],
        "attach_protocol": {
            "live_cli": "authorized-live-calibration --log <live_path>",
            "human_hour_cli": "human-hour-calibration --log <human_hour_path>",
            "delivery_cli": (
                "delivery-readiness --live-log <live_path> --log <human_hour_path>"
            ),
            "real_package_requirements": [
                "--declare-real-package",
                "--program-authorization-id <auth-ref>",
                "replace all synthetic/template-marked input artifacts",
                "wall_clock_minutes on entries for wall-clock gap",
                "human_confirmed_valid + report_outcome_ref for valid-report gap",
                "no secrets/tokens/cookies",
            ],
        },
        "non_claims": [
            "Does not claim live bounty superiority.",
            "Does not claim XBOW ranking.",
            "Does not auto-attack or auto-submit.",
            "Synthetic exports never flip has_real_* flags.",
        ],
        "summary": (
            f"source_kind={source_kind} live={len(live_entries)} "
            f"hh={len(hh_entries)} real_wall="
            f"{live_signals.get('has_real_wall_clock_logs') or hh_signals.get('has_real_human_hour_wall_clock_logs')} "
            f"real_valid={live_signals.get('has_real_live_valid_report_outcomes')}"
        ),
    }

    if export_written and written["manifest_path"]:
        manifest = {
            k: v
            for k, v in result.items()
            if k not in {"live_package", "human_hour_package"}
        }
        Path(str(written["manifest_path"])).write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    return result


def build_demo_session_notes() -> list[dict[str, Any]]:
    """Synthetic demo notes for dry-run export (never real)."""
    return [
        {
            "entry_id": "demo-retain-1",
            "source_kind": SYNTHETIC_SOURCE_KIND,
            "fixture_kind": "synthetic_research_track_record_demo",
            "outcome": "retained_review_ready",
            "live_outcome": "human_confirmed_valid",
            "review_minutes": 14.0,
            "wall_clock_minutes": 48.0,
            "report_outcome_ref": "demo-report-draft-1",
            "package_label": "demo-unguarded-read",
            "language_family": "python",
            "hypothesis_class": "authorization",
            "vuln_family": "idor",
            "notes": "Synthetic demo only.",
        },
        {
            "entry_id": "demo-fp-1",
            "source_kind": SYNTHETIC_SOURCE_KIND,
            "fixture_kind": "synthetic_research_track_record_demo",
            "outcome": "refuted_fp",
            "live_outcome": "human_confirmed_fp",
            "review_minutes": 9.0,
            "wall_clock_minutes": 22.0,
            "package_label": "demo-owner-guarded",
            "language_family": "java",
            "hypothesis_class": "authorization",
            "vuln_family": "idor",
            "notes": "Synthetic demo FP kill.",
        },
    ]


def _non_real_input_contexts(
    *,
    session_notes: list[dict[str, Any]],
    residual_decisions: list[dict[str, Any]],
    approvals: list[dict[str, Any] | Any] | None,
    approvals_bundle: dict[str, Any] | None,
    wall_clock_runner: dict[str, Any],
) -> list[str]:
    """Return structured provenance markers that cannot support a real claim."""
    contexts: list[str] = []
    sources: tuple[tuple[str, Any], ...] = (
        ("session_notes", session_notes),
        ("residual_decisions", residual_decisions),
        ("approvals", approvals or []),
        ("approvals_bundle", approvals_bundle or {}),
        ("wall_clock_runner", wall_clock_runner),
    )
    for label, source in sources:
        items = source if isinstance(source, list) else [source]
        for index, item in enumerate(items, start=1):
            if not isinstance(item, dict):
                continue
            marker = _non_real_source_marker(item)
            if marker:
                suffix = f"[{index}]" if isinstance(source, list) else ""
                contexts.append(f"{label}{suffix}.{marker}")
    return contexts


def _non_real_source_marker(value: dict[str, Any]) -> str:
    for key in ("source_kind", "fixture_kind", "input_kind", "origin_kind"):
        marker = str(value.get(key) or "").strip().lower()
        if not marker:
            continue
        if marker in _NON_REAL_SOURCE_MARKERS:
            return f"{key}={marker}"
        if key in {"fixture_kind", "input_kind", "origin_kind"} and any(
            token in marker
            for token in (
                "synthetic",
                "fixture",
                "demo",
                "template",
                "example",
                "scaffold",
            )
        ):
            return f"{key}={marker}"
    return ""


def _normalize_wall_clock_runner(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return value
    if hasattr(value, "__dict__"):
        return dict(vars(value))
    raise TrackRecordExportError("wall_clock_runner_invalid")


def _wall_clock_minutes_from_runner(runner: dict[str, Any]) -> float | None:
    if not runner:
        return None
    schedule = runner.get("schedule") or []
    if isinstance(schedule, list) and schedule:
        total = 0.0
        for slot in schedule:
            if not isinstance(slot, dict):
                continue
            try:
                total += float(slot.get("budget_minutes") or 0)
            except (TypeError, ValueError):
                continue
        if total > 0:
            return round(total, 2)
    try:
        hours = float(runner.get("wall_clock_hours") or 0)
    except (TypeError, ValueError):
        hours = 0.0
    if hours > 0:
        return round(hours * 60.0, 2)
    return None


def _live_entry_from_note(
    note: dict[str, Any],
    *,
    index: int,
    program_handle: str,
    package_label: str,
    auth_ref: str,
    source_kind: str,
    language_family: str,
    hypothesis_class: str,
    vuln_family: str,
    default_wall: float | None,
) -> dict[str, Any]:
    outcome = _resolve_live_outcome(note)
    wall = _optional_float(note.get("wall_clock_minutes"), default=default_wall)
    entry: dict[str, Any] = {
        "entry_id": _safe_label(note.get("entry_id")) or f"session-live-{index}",
        "program_handle": _safe_label(note.get("program_handle")) or program_handle,
        "authorized": True,
        "human_confirmed": True,
        "outcome": outcome,
        "language_family": _safe_label(note.get("language_family")) or language_family,
        "hypothesis_class": _safe_label(note.get("hypothesis_class"))
        or hypothesis_class,
        "vuln_family": _safe_label(note.get("vuln_family")) or vuln_family,
        "package_label": _safe_label(note.get("package_label")) or package_label,
        "notes": _safe_text(note.get("notes") or "Redacted research-session note."),
        "execution_allowed": False,
        "report_submission_allowed": False,
        "auto_submitted": False,
        "source_kind": source_kind,
    }
    if wall is not None:
        entry["wall_clock_minutes"] = wall
    report_ref = _safe_label(
        note.get("report_outcome_ref")
        or note.get("report_draft_id")
        or note.get("valid_report_ref")
    )
    if report_ref:
        entry["report_outcome_ref"] = report_ref
    elif outcome == "human_confirmed_valid":
        entry["report_outcome_ref"] = f"draft-{entry['entry_id']}"
    if auth_ref:
        entry["program_authorization_id"] = auth_ref
    for key in ("candidate_rank", "report_ready", "report_valid"):
        if key in note:
            entry[key] = note[key]
    return entry


def _hh_entry_from_note(
    note: dict[str, Any],
    *,
    index: int,
    package_label: str,
    auth_ref: str,
    source_kind: str,
    language_family: str,
    hypothesis_class: str,
    default_wall: float | None,
) -> dict[str, Any]:
    outcome = _resolve_hh_outcome(note)
    review = _optional_float(note.get("review_minutes"), default=12.0)
    if review is None or review < 0:
        review = 12.0
    wall = _optional_float(note.get("wall_clock_minutes"), default=default_wall)
    entry: dict[str, Any] = {
        "entry_id": _safe_label(note.get("entry_id")) or f"session-hh-{index}",
        "outcome": outcome,
        "review_minutes": float(review),
        "package_label": _safe_label(note.get("package_label")) or package_label,
        "language_family": _safe_label(note.get("language_family")) or language_family,
        "hypothesis_class": _safe_label(note.get("hypothesis_class"))
        or hypothesis_class,
        "refutation_path": _safe_label(note.get("refutation_path"))
        or "research_session",
        "notes": _safe_text(note.get("notes") or "Redacted research-session review."),
        "execution_allowed": False,
        "report_submission_allowed": False,
        "source_kind": source_kind,
        "program_label": _safe_label(note.get("program_label")) or "research-session",
        "artifact_kinds": ["scope", "policy", "code", "api", "har"],
    }
    if wall is not None:
        entry["wall_clock_minutes"] = wall
    if auth_ref:
        entry["program_authorization_id"] = auth_ref
    return entry


def _live_entry_from_approval(
    approval: dict[str, Any],
    *,
    index: int,
    program_handle: str,
    package_label: str,
    auth_ref: str,
    source_kind: str,
    language_family: str,
    hypothesis_class: str,
    vuln_family: str,
    default_wall: float | None,
) -> dict[str, Any]:
    payload = (
        approval.get("payload") if isinstance(approval.get("payload"), dict) else {}
    )
    status = str(approval.get("status") or "").strip().lower()
    note = {
        "entry_id": _safe_label(approval.get("approval_id"))
        or f"approval-live-{index}",
        "outcome": payload.get("live_outcome") or payload.get("outcome"),
        "live_outcome": payload.get("live_outcome"),
        "wall_clock_minutes": payload.get("wall_clock_minutes"),
        "report_outcome_ref": payload.get("report_outcome_ref")
        or payload.get("report_draft_id")
        or (f"draft-{approval.get('approval_id')}" if status == "approved" else None),
        "package_label": approval.get("package_id") or package_label,
        "language_family": payload.get("language_family") or language_family,
        "hypothesis_class": payload.get("hypothesis_class") or hypothesis_class,
        "vuln_family": payload.get("vuln_family") or vuln_family,
        "notes": approval.get("decision_reason") or approval.get("reason") or "",
        "program_handle": payload.get("program_handle") or program_handle,
        "_status": status,
    }
    if not note.get("outcome") and not note.get("live_outcome"):
        note["live_outcome"] = _STATUS_TO_LIVE.get(status, "not_submitted")
    for key in ("candidate_rank", "report_ready", "report_valid"):
        if key in payload:
            note[key] = payload[key]
    return _live_entry_from_note(
        note,
        index=index,
        program_handle=program_handle,
        package_label=package_label,
        auth_ref=auth_ref,
        source_kind=source_kind,
        language_family=language_family,
        hypothesis_class=hypothesis_class,
        vuln_family=vuln_family,
        default_wall=default_wall,
    )


def _hh_entry_from_approval(
    approval: dict[str, Any],
    *,
    index: int,
    package_label: str,
    auth_ref: str,
    source_kind: str,
    language_family: str,
    hypothesis_class: str,
    default_wall: float | None,
) -> dict[str, Any]:
    payload = (
        approval.get("payload") if isinstance(approval.get("payload"), dict) else {}
    )
    status = str(approval.get("status") or "").strip().lower()
    note = {
        "entry_id": _safe_label(approval.get("approval_id")) or f"approval-hh-{index}",
        "outcome": payload.get("outcome")
        or _STATUS_TO_HH.get(status, "needs_evidence"),
        "review_minutes": payload.get("review_minutes"),
        "wall_clock_minutes": payload.get("wall_clock_minutes"),
        "package_label": approval.get("package_id") or package_label,
        "language_family": payload.get("language_family") or language_family,
        "hypothesis_class": payload.get("hypothesis_class") or hypothesis_class,
        "refutation_path": payload.get("refutation_path") or "human_residual_review",
        "notes": approval.get("decision_reason") or approval.get("reason") or "",
        "program_label": payload.get("program_label") or "research-session",
    }
    return _hh_entry_from_note(
        note,
        index=index,
        package_label=package_label,
        auth_ref=auth_ref,
        source_kind=source_kind,
        language_family=language_family,
        hypothesis_class=hypothesis_class,
        default_wall=default_wall,
    )


def _blank_live_wall_entry(
    *,
    program_handle: str,
    package_label: str,
    auth_ref: str,
    source_kind: str,
    language_family: str,
    hypothesis_class: str,
    vuln_family: str,
    wall_clock_minutes: float,
) -> dict[str, Any]:
    entry = {
        "entry_id": f"session-wall-{uuid4().hex[:10]}",
        "program_handle": program_handle,
        "authorized": True,
        "human_confirmed": True,
        "outcome": "not_submitted",
        "wall_clock_minutes": float(wall_clock_minutes),
        "language_family": language_family,
        "hypothesis_class": hypothesis_class,
        "vuln_family": vuln_family,
        "package_label": package_label,
        "notes": "Wall-clock session export without residual decision.",
        "execution_allowed": False,
        "report_submission_allowed": False,
        "auto_submitted": False,
        "source_kind": source_kind,
    }
    if auth_ref:
        entry["program_authorization_id"] = auth_ref
    return entry


def _blank_hh_wall_entry(
    *,
    package_label: str,
    auth_ref: str,
    source_kind: str,
    language_family: str,
    hypothesis_class: str,
    wall_clock_minutes: float,
) -> dict[str, Any]:
    entry = {
        "entry_id": f"session-hh-wall-{uuid4().hex[:10]}",
        "outcome": "needs_evidence",
        "review_minutes": 0.0,
        "wall_clock_minutes": float(wall_clock_minutes),
        "package_label": package_label,
        "language_family": language_family,
        "hypothesis_class": hypothesis_class,
        "refutation_path": "wall_clock_session",
        "notes": "Wall-clock session export without residual decision.",
        "execution_allowed": False,
        "report_submission_allowed": False,
        "source_kind": source_kind,
        "program_label": "research-session",
        "artifact_kinds": ["scope", "policy", "code", "api", "har"],
    }
    if auth_ref:
        entry["program_authorization_id"] = auth_ref
    return entry


def _resolve_live_outcome(note: dict[str, Any]) -> str:
    raw = (
        str(
            note.get("live_outcome")
            or note.get("outcome")
            or note.get("_status")
            or "not_submitted"
        )
        .strip()
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
    )
    if raw in _STATUS_TO_LIVE:
        return _STATUS_TO_LIVE[raw]
    mapped = _LIVE_OUTCOME_ALIASES.get(raw)
    if mapped and mapped in LIVE_ALLOWED_OUTCOMES:
        return mapped
    hh_to_live = {
        "retained_review_ready": "human_confirmed_valid",
        "refuted_fp": "human_confirmed_fp",
        "needs_evidence": "human_needs_more_evidence",
        "rejected_out_of_scope": "human_rejected_out_of_scope",
        "deduplicated": "human_deduplicated",
        "suppressed_public": "not_submitted",
    }
    if raw in hh_to_live:
        return hh_to_live[raw]
    if raw in LIVE_ALLOWED_OUTCOMES:
        return raw
    return "not_submitted"


def _resolve_hh_outcome(note: dict[str, Any]) -> str:
    raw = (
        str(note.get("outcome") or note.get("hh_outcome") or "needs_evidence")
        .strip()
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
    )
    if raw in _STATUS_TO_HH:
        return _STATUS_TO_HH[raw]
    mapped = _HH_OUTCOME_ALIASES.get(raw)
    if mapped and mapped in HH_ALLOWED_OUTCOMES:
        return mapped
    live_to_hh = {
        "human_confirmed_valid": "retained_review_ready",
        "human_confirmed_fp": "refuted_fp",
        "human_needs_more_evidence": "needs_evidence",
        "human_rejected_out_of_scope": "rejected_out_of_scope",
        "human_deduplicated": "deduplicated",
        "not_submitted": "suppressed_public",
    }
    if raw in live_to_hh:
        return live_to_hh[raw]
    if raw in HH_ALLOWED_OUTCOMES:
        return raw
    return "needs_evidence"


def _force_live_safety(entry: dict[str, Any]) -> None:
    entry["authorized"] = True
    entry["human_confirmed"] = True
    entry["execution_allowed"] = False
    entry["report_submission_allowed"] = False
    entry["auto_submitted"] = False
    for key in (
        "notes",
        "program_handle",
        "package_label",
        "hypothesis_class",
        "language_family",
        "vuln_family",
        "report_outcome_ref",
    ):
        if key in entry and entry[key] is not None:
            entry[key] = (
                _safe_text(entry[key]) if key == "notes" else _safe_label(entry[key])
            )


def _force_hh_safety(entry: dict[str, Any]) -> None:
    entry["execution_allowed"] = False
    entry["report_submission_allowed"] = False
    for key in (
        "notes",
        "package_label",
        "hypothesis_class",
        "language_family",
        "refutation_path",
        "program_label",
    ):
        if key in entry and entry[key] is not None:
            entry[key] = (
                _safe_text(entry[key]) if key == "notes" else _safe_label(entry[key])
            )


def _optional_float(value: Any, *, default: float | None = None) -> float | None:
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_label(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if _SECRET_VALUE_RE.search(text) or _looks_forbidden(text):
        raise TrackRecordExportError(f"secret_like_label_rejected:{text[:24]}")
    return re.sub(r"\s+", " ", text)[:200]


def _safe_text(value: Any) -> str:
    text = str(value or "")
    if _SECRET_VALUE_RE.search(text) or _looks_forbidden(text):
        raise TrackRecordExportError("secret_like_text_rejected")
    if _SECRET_KEY_RE.search(text) and len(text) > 40:
        raise TrackRecordExportError("secret_like_text_rejected")
    return text[:500]


def _reject_secret_payload(payload: object, *, context: str) -> None:
    if not _blob_safe(payload):
        raise TrackRecordExportError(f"secret_like_content_rejected:{context}")


def _looks_forbidden(text: str) -> bool:
    lowered = text.lower()
    if "secret" in lowered and "SECRET" in text:
        return True
    for marker in FORBIDDEN_MARKERS:
        if marker.lower() in lowered:
            if marker.lower() in {"bearer ", "cookie=", "authorization:"}:
                return True
            if marker in text:
                return True
    if "bearer " in lowered or "cookie=" in lowered or "authorization:" in lowered:
        return True
    return False


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


__all__ = [
    "SCHEMA_VERSION",
    "TrackRecordExportError",
    "build_demo_session_notes",
    "export_research_track_record",
]
