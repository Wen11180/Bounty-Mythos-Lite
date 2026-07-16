"""Tests for research-session -> redacted live/HH track-record export."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.cli import main
from app.human_review_approvals import (
    APPROVAL_KIND_RESIDUAL,
    STATUS_APPROVED,
    STATUS_REJECTED_FP,
    build_human_review_approval,
)
from app.intelligence_benchmark.authorized_live_calibration import (
    detect_real_track_record_signals,
    load_live_outcome_package,
    package_source_kind,
    run_authorized_live_calibration_gate,
)
from app.intelligence_benchmark.authorized_research_track_record_export import (
    TrackRecordExportError,
    build_demo_session_notes,
    export_research_track_record,
)
from app.intelligence_benchmark.human_hour_calibration import (
    detect_real_human_hour_signals,
    load_review_log_package,
    package_source_kind as hh_package_source_kind,
    run_human_hour_calibration_gate,
)
from app.wall_clock_multi_hour_runner import build_wall_clock_multi_hour_runner


def test_synthetic_demo_export_never_flips_real_flags():
    result = export_research_track_record(session_notes=build_demo_session_notes())
    assert result["source_kind"] == "synthetic"
    live = result["signals_preview"]["live"]
    hh = result["signals_preview"]["human_hour"]
    assert live["has_real_wall_clock_logs"] is False
    assert live["has_real_live_valid_report_outcomes"] is False
    assert hh["has_real_human_hour_wall_clock_logs"] is False
    assert result["execution_allowed"] is False
    assert result["report_submission_allowed"] is False
    assert result["auto_submitted"] is False


def test_authorized_export_flips_wall_clock_and_valid_flags():
    result = export_research_track_record(
        session_notes=build_demo_session_notes(),
        program_authorization_id="auth-export-001",
        declare_real_package=True,
        program_handle="auth-program",
        package_label="export-real-demo",
    )
    assert result["source_kind"] == "authorized_redacted_real"
    live = result["signals_preview"]["live"]
    hh = result["signals_preview"]["human_hour"]
    assert live["has_real_wall_clock_logs"] is True
    assert live["has_real_live_valid_report_outcomes"] is True
    assert hh["has_real_human_hour_wall_clock_logs"] is True


def test_declare_real_without_auth_ref_raises():
    with pytest.raises(TrackRecordExportError, match="program_authorization_id"):
        export_research_track_record(
            session_notes=build_demo_session_notes(),
            declare_real_package=True,
        )


def test_secret_like_session_notes_rejected():
    with pytest.raises(TrackRecordExportError, match="secret_like"):
        export_research_track_record(
            session_notes=[
                {
                    "entry_id": "bad-1",
                    "outcome": "refuted_fp",
                    "review_minutes": 5,
                    "notes": "Authorization: Bearer supersecrettokenvalue",
                }
            ]
        )


def test_export_from_residual_approvals_and_wall_clock_runner():
    approved = build_human_review_approval(
        approval_kind=APPROVAL_KIND_RESIDUAL,
        package_id="pkg-export-1",
        candidate_id="c-valid",
        actor="researcher",
        reason="residual review",
        status=STATUS_APPROVED,
        decision_reason="Human confirmed review-ready candidate",
        decided_by="researcher",
        payload={
            "wall_clock_minutes": 40,
            "review_minutes": 15,
            "report_outcome_ref": "draft-c-valid",
            "language_family": "python",
        },
    )
    rejected = build_human_review_approval(
        approval_kind=APPROVAL_KIND_RESIDUAL,
        package_id="pkg-export-1",
        candidate_id="c-fp",
        actor="researcher",
        reason="fp",
        status=STATUS_REJECTED_FP,
        decision_reason="Owner guard present",
        decided_by="researcher",
        payload={
            "wall_clock_minutes": 18,
            "review_minutes": 8,
            "language_family": "java",
        },
    )
    runner = build_wall_clock_multi_hour_runner(
        package_id="pkg-export-1",
        bridge_result={"package_id": "pkg-export-1", "candidates": []},
        human_allow_export_write=False,
    )
    result = export_research_track_record(
        approvals=[approved, rejected],
        wall_clock_runner=runner,
        program_handle="auth-program",
        package_id="pkg-export-1",
        program_authorization_id="auth-export-002",
        declare_real_package=True,
    )
    assert result["live_entry_count"] >= 2
    assert result["source_kind"] == "authorized_redacted_real"
    assert result["signals_preview"]["live"]["has_real_wall_clock_logs"] is True
    assert result["signals_preview"]["live"]["has_real_live_valid_report_outcomes"] is True


def test_write_requires_human_allow_export_write(tmp_path: Path):
    with pytest.raises(TrackRecordExportError, match="human_allow_export_write"):
        export_research_track_record(
            session_notes=build_demo_session_notes(),
            out_dir=tmp_path / "out",
            human_allow_export_write=False,
        )


def test_written_packages_load_through_calibration_gates(tmp_path: Path):
    out_dir = tmp_path / "export"
    result = export_research_track_record(
        session_notes=build_demo_session_notes(),
        program_authorization_id="auth-export-e2e",
        declare_real_package=True,
        program_handle="auth-program",
        human_allow_export_write=True,
        out_dir=out_dir,
    )
    assert result["export_written"] is True
    live_path = Path(result["paths"]["live_path"])
    hh_path = Path(result["paths"]["human_hour_path"])
    assert live_path.is_file()
    assert hh_path.is_file()

    entries, meta = load_live_outcome_package(live_path)
    kind = package_source_kind(meta, entries)
    signals = detect_real_track_record_signals(
        entries=entries, source_kind=kind, package_meta=meta
    )
    assert signals["has_real_wall_clock_logs"] is True
    assert signals["has_real_live_valid_report_outcomes"] is True

    hh_entries, hh_meta = load_review_log_package(hh_path)
    hh_kind = hh_package_source_kind(hh_meta, hh_entries)
    hh_signals = detect_real_human_hour_signals(
        entries=hh_entries, source_kind=hh_kind, package_meta=hh_meta
    )
    assert hh_signals["has_real_human_hour_wall_clock_logs"] is True

    live_gate = run_authorized_live_calibration_gate(log_path=live_path)
    assert live_gate["passed"] is True
    hh_gate = run_human_hour_calibration_gate(log_path=hh_path)
    assert hh_gate["passed"] is True


def test_cli_demo_export_and_delivery_remaining_with_declared_real(tmp_path: Path):
    out_dir = tmp_path / "cli-export"
    manifest = tmp_path / "manifest.json"
    code = main(
        [
            "export-research-track-record",
            "--demo",
            "--declare-real-package",
            "--program-authorization-id",
            "auth-cli-001",
            "--program-handle",
            "cli-program",
            "--human-allow-export-write",
            "--out-dir",
            str(out_dir),
            "--out",
            str(manifest),
        ]
    )
    assert code == 0
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["source_kind"] == "authorized_redacted_real"
    live_path = payload["paths"]["live_path"]
    delivery_out = tmp_path / "delivery.json"
    code2 = main(
        [
            "delivery-readiness",
            "--out",
            str(delivery_out),
            "--live-log",
            live_path,
        ]
    )
    assert code2 == 0
    delivery = json.loads(delivery_out.read_text(encoding="utf-8"))
    assert delivery["remaining_for_full_market_leadership"] == []


def test_cli_synthetic_demo_does_not_close_remaining(tmp_path: Path):
    out_dir = tmp_path / "cli-synth"
    manifest = tmp_path / "manifest.json"
    code = main(
        [
            "export-research-track-record",
            "--demo",
            "--human-allow-export-write",
            "--out-dir",
            str(out_dir),
            "--out",
            str(manifest),
        ]
    )
    assert code == 0
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["source_kind"] == "synthetic"
    live_path = payload["paths"]["live_path"]
    delivery_out = tmp_path / "delivery.json"
    code2 = main(
        [
            "delivery-readiness",
            "--out",
            str(delivery_out),
            "--live-log",
            live_path,
        ]
    )
    assert code2 == 0
    delivery = json.loads(delivery_out.read_text(encoding="utf-8"))
    remaining = delivery["remaining_for_full_market_leadership"]
    assert "real_authorized_program_wall_clock_logs" in remaining
    assert "real_live_valid_report_outcomes" in remaining