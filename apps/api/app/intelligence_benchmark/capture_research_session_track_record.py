"""Capture live/HH track-record packages from an authorized research package root.

Closes the last mile for market live + human-hour gaps:
  package residual approvals + wall-clock runner (+ optional session notes)
  -> export-research-track-record packages
  -> optional market/delivery score with attached logs

Never unlocks execution, auto-attack, or report submission.
has_real_* only flips when declare_real_package + program_authorization_id + real fields.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.intelligence_benchmark.authorized_live_calibration import (
    run_authorized_live_calibration_gate,
)
from app.intelligence_benchmark.authorized_research_track_record_export import (
    TrackRecordExportError,
    export_research_track_record,
)
from app.intelligence_benchmark.human_hour_calibration import (
    run_human_hour_calibration_gate,
)
from app.intelligence_benchmark.lab_leadership_rollup import run_lab_leadership_rollup
from app.intelligence_benchmark.multilang_production_breadth import (
    run_multilang_production_breadth_gate,
)
from app.intelligence_benchmark.track_record_path_resolver import (
    publish_track_record_exports_to_drop_dir,
)

SCHEMA_VERSION = "capture_research_session_track_record_v1"

_SESSION_NOTE_CANDIDATES = (
    "inputs/session_notes.json",
    "inputs/research_session_notes.json",
    "_export/session_notes.json",
    "SESSION_NOTES.json",
)

_WALL_CLOCK_CANDIDATES = (
    "inputs/wall_clock_runner.json",
    "inputs/wall_clock_multi_hour_runner.json",
    "_export/wall_clock_multi_hour_runner/latest.json",
)


class CaptureResearchSessionError(ValueError):
    """Raised when package capture inputs are invalid or unsafe."""


def capture_research_session_track_record(
    *,
    package_root: str | Path,
    out_dir: str | Path,
    program_authorization_id: str | None = None,
    declare_real_package: bool = False,
    program_handle: str = "",
    package_id: str = "",
    package_label: str = "",
    language_family: str = "unknown",
    hypothesis_class: str = "authorization",
    vuln_family: str = "idor",
    evaluation_top_k: int | None = None,
    human_allow_export_write: bool = False,
    rescore_market: bool = True,
    session_notes_path: str | Path | None = None,
    wall_clock_path: str | Path | None = None,
    publish_drop_dir: bool = False,
    drop_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Discover package artifacts, export live/HH packages, optionally re-score market."""
    if not human_allow_export_write:
        raise CaptureResearchSessionError(
            "human_allow_export_write_required_for_capture_write"
        )

    root = Path(package_root)
    if not root.is_dir():
        raise CaptureResearchSessionError(f"package_root_missing:{root}")

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    discovered = discover_package_capture_artifacts(
        package_root=root,
        session_notes_path=session_notes_path,
        wall_clock_path=wall_clock_path,
    )

    handle = (program_handle or "").strip() or root.name or "research-session"
    export = export_research_track_record(
        package_root=root,
        session_notes=discovered.get("session_notes") or None,
        wall_clock_runner=discovered.get("wall_clock_runner") or None,
        program_handle=handle,
        package_id=package_id or root.name,
        package_label=package_label or root.name,
        program_authorization_id=program_authorization_id,
        declare_real_package=declare_real_package,
        language_family=language_family,
        hypothesis_class=hypothesis_class,
        vuln_family=vuln_family,
        evaluation_top_k=evaluation_top_k,
        human_allow_export_write=True,
        out_dir=out,
    )

    live_path = (export.get("paths") or {}).get("live_path")
    hh_path = (export.get("paths") or {}).get("human_hour_path")

    market: dict[str, Any] | None = None
    if rescore_market:
        market = _score_market_with_packages(
            live_path=Path(live_path) if live_path else None,
            hh_path=Path(hh_path) if hh_path else None,
        )
        (out / "market_after_capture.json").write_text(
            json.dumps(market, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    published = None
    if publish_drop_dir:
        published = publish_track_record_exports_to_drop_dir(
            live_path=live_path,
            human_hour_path=hh_path,
            drop_dir=drop_dir,
            human_allow_write=True,
        )
        # Re-score using drop-dir attached packages when market requested
        if rescore_market and published:
            from app.intelligence_benchmark.track_record_path_resolver import (
                resolve_attached_track_record_paths,
            )
            attached = resolve_attached_track_record_paths(drop_dir=published.get("drop_dir"))
            live2 = attached.get("live_log")
            hh2 = attached.get("human_hour_log")
            market = _score_market_with_packages(
                live_path=Path(live2) if live2 else (Path(live_path) if live_path else None),
                hh_path=Path(hh2) if hh2 else (Path(hh_path) if hh_path else None),
            )
            (out / "market_after_capture.json").write_text(
                json.dumps(market, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

    remaining = (
        list(market.get("remaining_for_full_market_leadership") or [])
        if isinstance(market, dict)
        else []
    )
    closed = (
        list(market.get("closed_market_gaps") or [])
        if isinstance(market, dict)
        else []
    )
    signals_preview = export.get("signals_preview") or {}

    result = {
        "schema_version": SCHEMA_VERSION,
        "claim_scope": "research_session_capture_for_market_track_record",
        "passed": bool(export.get("export_written")),
        "package_root": str(root.resolve()),
        "out_dir": str(out.resolve()),
        "discovered": {
            "session_notes_path": discovered.get("session_notes_path"),
            "session_note_count": len(discovered.get("session_notes") or []),
            "wall_clock_path": discovered.get("wall_clock_path"),
            "wall_clock_present": bool(discovered.get("wall_clock_runner")),
            "approvals_via_package_root": True,
        },
        "export": {
            "source_kind": export.get("source_kind"),
            "declare_real_package": export.get("declare_real_package"),
            "program_authorization_id": export.get("program_authorization_id"),
            "live_entry_count": export.get("live_entry_count"),
            "human_hour_entry_count": export.get("human_hour_entry_count"),
            "residual_decision_count": export.get("residual_decision_count"),
            "session_note_count": export.get("session_note_count"),
            "wall_clock_minutes_from_runner": export.get("wall_clock_minutes_from_runner"),
            "paths": export.get("paths"),
            "signals_preview": signals_preview,
            "summary": export.get("summary"),
        },
        "market_after_capture": market,
        "published_drop_dir": published,
        "remaining_for_full_market_leadership": remaining,
        "closed_market_gaps": closed,
        "gap_closure": {
            "wall_clock_closed": (
                "real_authorized_program_wall_clock_logs" not in remaining
                if market is not None
                else None
            ),
            "valid_report_closed": (
                "real_live_valid_report_outcomes" not in remaining
                if market is not None
                else None
            ),
            "full_market_leadership": bool(market is not None and not remaining),
        },
        "missing_for_real_flags": _missing_for_real_flags(
            declare_real_package=declare_real_package,
            program_authorization_id=program_authorization_id,
            export=export,
            discovered=discovered,
        ),
        "execution_allowed": False,
        "report_submission_allowed": False,
        "auto_attack_allowed": False,
        "validation_allowed": False,
        "human_review_required": True,
        "non_claims": [
            "Does not fabricate authorized program outcomes.",
            "Does not flip has_real_* without declare + auth ref + real fields.",
            "Does not auto-attack or auto-submit.",
        ],
    }

    (out / "capture_manifest.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return result


def discover_package_capture_artifacts(
    *,
    package_root: str | Path,
    session_notes_path: str | Path | None = None,
    wall_clock_path: str | Path | None = None,
) -> dict[str, Any]:
    """Find session notes + wall-clock runner under an authorized package root."""
    root = Path(package_root)
    notes_path: Path | None = Path(session_notes_path) if session_notes_path else None
    if notes_path is None:
        notes_path = _first_existing(root, _SESSION_NOTE_CANDIDATES)
    wall_path: Path | None = Path(wall_clock_path) if wall_clock_path else None
    if wall_path is None:
        wall_path = _first_existing(root, _WALL_CLOCK_CANDIDATES)
    if wall_path is None:
        wall_path = _latest_wall_clock_export(root)

    session_notes: list[dict[str, Any]] = []
    if notes_path is not None and notes_path.is_file():
        session_notes = _load_session_notes(notes_path)

    wall_clock_runner: dict[str, Any] | None = None
    if wall_path is not None and wall_path.is_file():
        raw = json.loads(wall_path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            wall_clock_runner = raw
        else:
            raise CaptureResearchSessionError(
                f"wall_clock_json_must_be_object:{wall_path}"
            )

    return {
        "session_notes_path": str(notes_path) if notes_path else None,
        "session_notes": session_notes,
        "wall_clock_path": str(wall_path) if wall_path else None,
        "wall_clock_runner": wall_clock_runner,
    }


def _score_market_with_packages(
    *,
    live_path: Path | None,
    hh_path: Path | None,
) -> dict[str, Any]:
    lab = run_lab_leadership_rollup(calibration_log=hh_path)
    live = run_authorized_live_calibration_gate(log_path=live_path)
    breadth = run_multilang_production_breadth_gate()
    ab = (lab.get("component_results") or {}).get("ab_leadership") or {}
    hh = (lab.get("component_results") or {}).get("human_hour_calibration") or {}
    live_measured = live.get("measured") if isinstance(live.get("measured"), dict) else {}
    track = live_measured.get("track_record_summary") or {}

    has_real_live_wall = bool(track.get("has_real_wall_clock_logs"))
    has_real_hh_wall = bool(hh.get("has_real_human_hour_wall_clock_logs"))
    has_real_wall = has_real_live_wall or has_real_hh_wall
    has_real_valid = bool(track.get("has_real_live_valid_report_outcomes"))
    breadth_beyond = bool(breadth.get("beyond_held_out") and breadth.get("passed"))

    remaining: list[str] = []
    if not has_real_wall:
        remaining.append("real_authorized_program_wall_clock_logs")
    if not has_real_valid:
        remaining.append("real_live_valid_report_outcomes")
    if not breadth_beyond:
        remaining.append("production_multilang_sast_breadth_beyond_held_outs")

    closed: list[str] = []
    if breadth_beyond:
        closed.append("production_multilang_sast_breadth_beyond_held_outs")
    if has_real_wall:
        closed.append("real_authorized_program_wall_clock_logs")
    if has_real_valid:
        closed.append("real_live_valid_report_outcomes")
    if breadth_beyond and lab.get("passed") and live.get("passed"):
        closed.append("commercial_delivery_packaging")
        closed.append("anti_auto_exploit_narrative")

    return {
        "schema_version": "market_leadership_scoreboard_v1",
        "claim_scope": "honest_market_gap_scoreboard_after_capture",
        "passed": bool(lab.get("passed") and live.get("passed") and breadth.get("passed")),
        "lab_passed": lab.get("passed"),
        "live_infra_passed": live.get("passed"),
        "multilang_breadth_passed": breadth.get("passed"),
        "lab_scenario_count": ab.get("scenario_count"),
        "remaining_for_full_market_leadership": remaining,
        "closed_market_gaps": closed,
        "signals": {
            "has_real_wall_clock_logs": has_real_wall,
            "has_real_live_wall_clock_logs": has_real_live_wall,
            "has_real_human_hour_wall_clock_logs": has_real_hh_wall,
            "has_real_live_valid_report_outcomes": has_real_valid,
            "multilang_beyond_held_out": breadth_beyond,
        },
        "paths": {
            "live_log": str(live_path) if live_path else None,
            "human_hour_log": str(hh_path) if hh_path else None,
        },
        "execution_allowed": False,
        "report_submission_allowed": False,
        "auto_attack_allowed": False,
    }


def _missing_for_real_flags(
    *,
    declare_real_package: bool,
    program_authorization_id: str | None,
    export: dict[str, Any],
    discovered: dict[str, Any],
) -> list[str]:
    missing: list[str] = []
    if not declare_real_package:
        missing.append("declare_real_package")
    if not str(program_authorization_id or "").strip():
        missing.append("program_authorization_id")
    if not discovered.get("wall_clock_runner") and not (
        (export.get("signals_preview") or {}).get("live") or {}
    ).get("has_real_wall_clock_logs"):
        # wall clock may still come from session notes; only advisory
        if int(export.get("session_note_count") or 0) == 0 and int(
            export.get("residual_decision_count") or 0
        ) == 0:
            missing.append("session_notes_or_residual_approvals_or_wall_clock_runner")
    preview = (export.get("signals_preview") or {}).get("live") or {}
    if not preview.get("has_real_live_valid_report_outcomes"):
        missing.append(
            "human_confirmed_valid_entry_with_report_outcome_ref_for_valid_report_gap"
        )
    if not (
        preview.get("has_real_wall_clock_logs")
        or ((export.get("signals_preview") or {}).get("human_hour") or {}).get(
            "has_real_human_hour_wall_clock_logs"
        )
    ):
        missing.append("wall_clock_minutes_on_real_entries_for_wall_clock_gap")
    return missing


def _first_existing(root: Path, relatives: tuple[str, ...]) -> Path | None:
    for rel in relatives:
        path = root / rel
        if path.is_file():
            return path
    return None


def _latest_wall_clock_export(root: Path) -> Path | None:
    export_root = root / "_export" / "wall_clock_multi_hour_runner"
    if not export_root.is_dir():
        return None
    candidates: list[Path] = []
    for path in export_root.rglob("*.json"):
        name = path.name.lower()
        if name in {"result.json", "wall_clock_runner.json", "plan.json", "summary.json"}:
            candidates.append(path)
        elif "wall_clock" in name or name == "runner.json":
            candidates.append(path)
    if not candidates:
        # any json under export as last resort if named result
        candidates = [
            p
            for p in export_root.rglob("*.json")
            if p.is_file() and "result" in p.name.lower()
        ]
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]


def _load_session_notes(path: Path) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return [e for e in raw if isinstance(e, dict)]
    if isinstance(raw, dict):
        entries = raw.get("entries")
        if isinstance(entries, list):
            return [e for e in entries if isinstance(e, dict)]
        # single note object
        if any(k in raw for k in ("outcome", "notes", "wall_clock_minutes", "entry_id")):
            return [raw]
    raise CaptureResearchSessionError(f"session_notes_invalid:{path}")
