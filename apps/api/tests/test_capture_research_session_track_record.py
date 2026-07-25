"""Tests for package-root research-session capture -> live/HH track-record export."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.cli import main
from app.intelligence_benchmark.authorized_research_track_record_export import (
    TrackRecordExportError,
    build_demo_session_notes,
)
from app.intelligence_benchmark.capture_research_session_track_record import (
    CaptureResearchSessionError,
    capture_research_session_track_record,
    discover_package_capture_artifacts,
)
from app.intelligence_benchmark.authorized_live_calibration import (
    detect_real_track_record_signals,
    load_live_outcome_package,
    package_source_kind,
)


def _operator_attested_session_notes() -> list[dict]:
    return [
        {
            "entry_id": "attested-valid-1",
            "outcome": "retained_review_ready",
            "live_outcome": "human_confirmed_valid",
            "review_minutes": 14.0,
            "wall_clock_minutes": 48.0,
            "report_outcome_ref": "attested-report-1",
            "package_label": "attested-unguarded-read",
            "language_family": "python",
            "notes": "Redacted operator-attested outcome.",
        },
        {
            "entry_id": "attested-fp-1",
            "outcome": "refuted_fp",
            "live_outcome": "human_confirmed_fp",
            "review_minutes": 9.0,
            "wall_clock_minutes": 22.0,
            "package_label": "attested-owner-guarded",
            "language_family": "java",
            "notes": "Redacted operator-attested false positive.",
        },
    ]

def _write_pkg_with_session_notes(
    root: Path,
    notes: list[dict] | None = None,
    *,
    wall_clock: dict | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    inputs = root / "inputs"
    inputs.mkdir(exist_ok=True)
    (inputs / "session_notes.json").write_text(
        json.dumps(notes if notes is not None else build_demo_session_notes()),
        encoding="utf-8",
    )
    if wall_clock is not None:
        (inputs / "wall_clock_runner.json").write_text(
            json.dumps(wall_clock),
            encoding="utf-8",
        )
    return root


def test_discover_package_capture_artifacts_finds_session_notes(tmp_path: Path):
    pkg = _write_pkg_with_session_notes(tmp_path / "pkg")
    discovered = discover_package_capture_artifacts(package_root=pkg)
    assert discovered["session_notes_path"] is not None
    assert len(discovered["session_notes"]) == 2
    assert discovered["wall_clock_runner"] is None


def test_synthetic_capture_never_flips_real_flags(tmp_path: Path):
    pkg = _write_pkg_with_session_notes(tmp_path / "pkg")
    out = tmp_path / "out"
    result = capture_research_session_track_record(
        package_root=pkg,
        out_dir=out,
        human_allow_export_write=True,
        rescore_market=True,
    )
    assert result["passed"] is True
    assert result["export"]["source_kind"] == "synthetic"
    live = result["export"]["signals_preview"]["live"]
    hh = result["export"]["signals_preview"]["human_hour"]
    assert live["has_real_wall_clock_logs"] is False
    assert live["has_real_live_valid_report_outcomes"] is False
    assert hh["has_real_human_hour_wall_clock_logs"] is False
    assert "real_authorized_program_wall_clock_logs" in result[
        "remaining_for_full_market_leadership"
    ]
    assert "real_live_valid_report_outcomes" in result[
        "remaining_for_full_market_leadership"
    ]
    assert result["execution_allowed"] is False
    assert result["report_submission_allowed"] is False
    assert result["auto_attack_allowed"] is False
    assert (out / "capture_manifest.json").is_file()
    assert (out / "market_after_capture.json").is_file()


def test_operator_attested_capture_can_close_remaining(tmp_path: Path):
    pkg = _write_pkg_with_session_notes(
        tmp_path / "pkg", notes=_operator_attested_session_notes()
    )
    out = tmp_path / "out"
    result = capture_research_session_track_record(
        package_root=pkg,
        out_dir=out,
        human_allow_export_write=True,
        declare_real_package=True,
        program_authorization_id="auth-capture-001",
        program_handle="auth-program",
        rescore_market=True,
    )
    assert result["export"]["source_kind"] == "authorized_redacted_real"
    assert result["remaining_for_full_market_leadership"] == []
    assert result["gap_closure"]["full_market_leadership"] is True
    live = result["export"]["signals_preview"]["live"]
    assert live["has_real_wall_clock_logs"] is True
    assert live["has_real_live_valid_report_outcomes"] is True

    live_path = Path(result["export"]["paths"]["live_path"])
    entries, meta = load_live_outcome_package(live_path)
    kind = package_source_kind(meta, entries)
    signals = detect_real_track_record_signals(
        entries=entries, source_kind=kind, package_meta=meta
    )
    assert signals["has_real_wall_clock_logs"] is True
    assert signals["has_real_live_valid_report_outcomes"] is True


def test_write_requires_human_allow_export_write(tmp_path: Path):
    pkg = _write_pkg_with_session_notes(tmp_path / "pkg")
    with pytest.raises(
        CaptureResearchSessionError, match="human_allow_export_write"
    ):
        capture_research_session_track_record(
            package_root=pkg,
            out_dir=tmp_path / "out",
            human_allow_export_write=False,
        )


def test_declare_real_without_auth_ref_raises(tmp_path: Path):
    pkg = _write_pkg_with_session_notes(tmp_path / "pkg")
    with pytest.raises(TrackRecordExportError, match="program_authorization_id"):
        capture_research_session_track_record(
            package_root=pkg,
            out_dir=tmp_path / "out",
            human_allow_export_write=True,
            declare_real_package=True,
        )


def test_secret_like_session_notes_rejected(tmp_path: Path):
    pkg = _write_pkg_with_session_notes(
        tmp_path / "pkg",
        notes=[
            {
                "entry_id": "bad-1",
                "outcome": "refuted_fp",
                "review_minutes": 5,
                "notes": "Authorization: Bearer supersecrettokenvalue",
            }
        ],
    )
    with pytest.raises(TrackRecordExportError, match="secret_like"):
        capture_research_session_track_record(
            package_root=pkg,
            out_dir=tmp_path / "out",
            human_allow_export_write=True,
        )


def test_package_root_missing_raises(tmp_path: Path):
    with pytest.raises(CaptureResearchSessionError, match="package_root_missing"):
        capture_research_session_track_record(
            package_root=tmp_path / "no-such-pkg",
            out_dir=tmp_path / "out",
            human_allow_export_write=True,
        )


def test_cli_synthetic_capture_keeps_remaining(tmp_path: Path):
    pkg = _write_pkg_with_session_notes(tmp_path / "pkg")
    out = tmp_path / "out"
    manifest = tmp_path / "manifest.json"
    code = main(
        [
            "capture-research-session-track-record",
            "--package-root",
            str(pkg),
            "--out-dir",
            str(out),
            "--human-allow-export-write",
            "--out",
            str(manifest),
        ]
    )
    assert code == 0
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["export"]["source_kind"] == "synthetic"
    remaining = payload["remaining_for_full_market_leadership"]
    assert "real_authorized_program_wall_clock_logs" in remaining
    assert "real_live_valid_report_outcomes" in remaining
    assert payload["execution_allowed"] is False


def test_cli_declared_real_capture_rejects_scaffold_demo_notes(tmp_path: Path):
    pkg = _write_pkg_with_session_notes(tmp_path / "pkg")
    out = tmp_path / "out"
    manifest = tmp_path / "manifest.json"
    code = main(
        [
            "capture-research-session-track-record",
            "--package-root",
            str(pkg),
            "--out-dir",
            str(out),
            "--declare-real-package",
            "--program-authorization-id",
            "auth-cli-capture-001",
            "--program-handle",
            "cli-capture-program",
            "--human-allow-export-write",
            "--out",
            str(manifest),
        ]
    )
    assert code == 2
    assert not manifest.exists()
    assert not (out / "authorized_live_outcomes.export.json").exists()


def test_cli_requires_human_allow_export_write(tmp_path: Path):
    pkg = _write_pkg_with_session_notes(tmp_path / "pkg")
    code = main(
        [
            "capture-research-session-track-record",
            "--package-root",
            str(pkg),
            "--out-dir",
            str(tmp_path / "out"),
        ]
    )
    assert code == 2
