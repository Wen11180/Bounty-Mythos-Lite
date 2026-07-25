"""Tests for track-record path resolution, prepare scaffold, and drop-dir attach."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from app.cli import main
from app.intelligence_benchmark.authorized_research_track_record_export import (
    export_research_track_record,
)
from app.intelligence_benchmark.capture_research_session_track_record import (
    capture_research_session_track_record,
)
from app.intelligence_benchmark.prepare_research_session_package import (
    PrepareResearchSessionError,
    prepare_research_session_package,
)
from app.intelligence_benchmark.track_record_path_resolver import (
    ENV_DROP_DIR,
    ENV_HUMAN_HOUR,
    ENV_LIVE,
    default_drop_dir,
    publish_track_record_exports_to_drop_dir,
    resolve_attached_track_record_paths,
)


def _operator_attested_session_notes() -> list[dict]:
    return [
        {
            "entry_id": "attested-valid-1",
            "outcome": "retained_review_ready",
            "live_outcome": "human_confirmed_valid",
            "review_minutes": 12.0,
            "wall_clock_minutes": 40.0,
            "report_outcome_ref": "attested-report-1",
            "package_label": "attested-unguarded-read",
            "language_family": "python",
            "notes": "Redacted operator-attested outcome.",
        }
    ]

def test_resolve_prefers_cli_over_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    live_cli = tmp_path / "cli-live.json"
    live_env = tmp_path / "env-live.json"
    live_cli.write_text("{}", encoding="utf-8")
    live_env.write_text("{}", encoding="utf-8")
    monkeypatch.setenv(ENV_LIVE, str(live_env))
    resolved = resolve_attached_track_record_paths(
        live_log=live_cli,
        env=os.environ,
    )
    assert resolved["live_log"] == str(live_cli)
    assert resolved["sources"]["live"] == "cli"


def test_resolve_env_and_drop_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    drop = tmp_path / "authorized_track_records"
    drop.mkdir()
    live = drop / "authorized_live_outcomes.export.json"
    hh = drop / "human_hour_review_logs.export.json"
    live.write_text("{}", encoding="utf-8")
    hh.write_text("{}", encoding="utf-8")
    monkeypatch.delenv(ENV_LIVE, raising=False)
    monkeypatch.delenv(ENV_HUMAN_HOUR, raising=False)
    monkeypatch.setenv(ENV_DROP_DIR, str(drop))
    resolved = resolve_attached_track_record_paths(env=os.environ, start=tmp_path)
    assert resolved["live_log"] == str(live)
    assert resolved["human_hour_log"] == str(hh)
    assert resolved["sources"]["live"] == "drop_dir"
    assert resolved["sources"]["human_hour"] == "drop_dir"


def test_resolve_never_requires_committed_fixtures(tmp_path: Path):
    resolved = resolve_attached_track_record_paths(start=tmp_path, env={})
    assert resolved["live_log"] is None
    assert resolved["human_hour_log"] is None
    assert resolved["never_auto_selects_committed_synthetic_fixtures"] is True


def test_prepare_requires_human_allow_write(tmp_path: Path):
    with pytest.raises(PrepareResearchSessionError, match="human_allow_write"):
        prepare_research_session_package(
            package_root=tmp_path / "pkg",
            human_allow_write=False,
        )


def test_prepare_scaffolds_capture_ready_package(tmp_path: Path):
    pkg = tmp_path / "pkg"
    result = prepare_research_session_package(
        package_root=pkg,
        program_handle="demo-program",
        human_allow_write=True,
    )
    assert (pkg / "inputs" / "session_notes.json").is_file()
    assert (pkg / "CAPTURE_README.md").is_file()
    assert (pkg / "AUTHORIZATION_CHECKLIST.md").is_file()
    assert result["declare_real_package"] is False
    assert result["execution_allowed"] is False


def test_prepare_then_capture_synthetic_keeps_remaining(tmp_path: Path):
    pkg = tmp_path / "pkg"
    prepare_research_session_package(package_root=pkg, human_allow_write=True)
    out = tmp_path / "out"
    result = capture_research_session_track_record(
        package_root=pkg,
        out_dir=out,
        human_allow_export_write=True,
        rescore_market=True,
    )
    assert result["export"]["source_kind"] == "synthetic"
    remaining = result["remaining_for_full_market_leadership"]
    assert "real_authorized_program_wall_clock_logs" in remaining
    assert "real_live_valid_report_outcomes" in remaining


def test_publish_drop_dir_and_market_auto_attach(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # Build an operator-attested export, publish to drop dir, auto-attach via env drop dir.
    export_dir = tmp_path / "export"
    exported = export_research_track_record(
        session_notes=_operator_attested_session_notes(),
        program_authorization_id="auth-drop-001",
        declare_real_package=True,
        program_handle="drop-program",
        human_allow_export_write=True,
        out_dir=export_dir,
    )
    drop = tmp_path / "drop"
    published = publish_track_record_exports_to_drop_dir(
        live_path=exported["paths"]["live_path"],
        human_hour_path=exported["paths"]["human_hour_path"],
        drop_dir=drop,
        human_allow_write=True,
    )
    assert Path(published["written"]["live"]).is_file()

    monkeypatch.setenv(ENV_DROP_DIR, str(drop))
    market_out = tmp_path / "market.json"
    code = main(
        [
            "market-leadership-scoreboard",
            "--out",
            str(market_out),
        ]
    )
    assert code == 0
    market = json.loads(market_out.read_text(encoding="utf-8"))
    assert market["remaining_for_full_market_leadership"] == []
    assert market["signals"]["has_real_wall_clock_logs"] is True
    assert market["signals"]["has_real_live_valid_report_outcomes"] is True


def test_cli_prepare_scaffold_cannot_be_captured_as_real(tmp_path: Path):
    pkg = tmp_path / "pkg"
    drop = tmp_path / "drop"
    code = main(
        [
            "prepare-research-session-package",
            "--package-root",
            str(pkg),
            "--program-handle",
            "cli-prep",
            "--human-allow-write",
        ]
    )
    assert code == 0
    out = tmp_path / "out"
    code2 = main(
        [
            "capture-research-session-track-record",
            "--package-root",
            str(pkg),
            "--out-dir",
            str(out),
            "--declare-real-package",
            "--program-authorization-id",
            "auth-cli-prep-001",
            "--human-allow-export-write",
            "--publish-drop-dir",
            "--drop-dir",
            str(drop),
        ]
    )
    assert code2 == 2
    assert not (drop / "authorized_live_outcomes.export.json").exists()
    assert not (drop / "human_hour_review_logs.export.json").exists()


def test_default_drop_dir_name():
    path = default_drop_dir(start=Path.cwd())
    assert path.name == "authorized_track_records"
