from __future__ import annotations

import json
from pathlib import Path

from app.cli import main
from app.intelligence_benchmark.commercial_delivery_bundle import (
    build_commercial_delivery_bundle,
    evaluate_anti_auto_exploit_narrative,
)
from app.intelligence_benchmark.authorized_research_track_record_export import (
    export_research_track_record,
    build_demo_session_notes,
)


def test_anti_auto_exploit_proof_passes_with_locked_safety():
    proof = evaluate_anti_auto_exploit_narrative(
        payload={
            "execution_allowed": False,
            "report_submission_allowed": False,
            "auto_attack_allowed": False,
        }
    )
    assert proof["schema_version"] == "anti_auto_exploit_proof_v1"
    assert proof["passed"] is True
    assert proof["execution_allowed"] is False
    assert proof["report_submission_allowed"] is False
    assert proof["auto_attack_allowed"] is False
    assert "auto_exploit" in proof["positioning"]["do_not_claim"]


def test_anti_auto_exploit_proof_fails_if_execution_unlocked():
    proof = evaluate_anti_auto_exploit_narrative(
        payload={"execution_allowed": True, "auto_attack_allowed": False}
    )
    assert proof["passed"] is False
    assert proof["checks"]["safety_invariants_passed"] is False


def test_commercial_delivery_bundle_writes_artifacts(tmp_path):
    out_dir = tmp_path / "bundle"
    manifest = build_commercial_delivery_bundle(
        out_dir=out_dir,
        human_allow_write=True,
    )
    assert manifest["schema_version"] == "commercial_delivery_bundle_v1"
    assert manifest["passed"] is True
    assert manifest["execution_allowed"] is False
    assert manifest["report_submission_allowed"] is False
    assert manifest["auto_attack_allowed"] is False
    assert "commercial_delivery_packaging" in manifest["closed_market_gaps"]
    assert "anti_auto_exploit_narrative" in manifest["closed_market_gaps"]
    assert "production_multilang_sast_breadth_beyond_held_outs" in manifest["closed_market_gaps"]
    remaining = manifest["remaining_for_full_market_leadership"]
    assert "real_authorized_program_wall_clock_logs" in remaining
    assert "real_live_valid_report_outcomes" in remaining
    assert (out_dir / "manifest.json").is_file()
    assert (out_dir / "customer_brief.md").is_file()
    assert (out_dir / "market_scoreboard.json").is_file()
    assert (out_dir / "anti_auto_exploit.json").is_file()
    brief = (out_dir / "customer_brief.md").read_text(encoding="utf-8")
    assert "Anti auto-exploit" in brief or "anti-auto-exploit" in brief.lower()
    assert "SECRET" not in brief
    assert "Bearer" not in brief
    blob = (out_dir / "manifest.json").read_text(encoding="utf-8")
    assert "SECRET" not in blob


def test_commercial_delivery_bundle_requires_human_gate(tmp_path):
    try:
        build_commercial_delivery_bundle(out_dir=tmp_path / "x", human_allow_write=False)
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "human_allow_write" in str(exc)


def test_cli_commercial_delivery_bundle(tmp_path, capsys):
    out_dir = tmp_path / "cli-bundle"
    code = main(
        [
            "commercial-delivery-bundle",
            "--out-dir",
            str(out_dir),
            "--human-allow-write",
            "--out",
            str(out_dir / "manifest-copy.json"),
        ]
    )
    assert code == 0
    assert (out_dir / "manifest.json").is_file()
    payload = json.loads((out_dir / "manifest-copy.json").read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert payload["auto_attack_allowed"] is False
    captured = capsys.readouterr()
    assert "passed=True" in captured.out


def test_cli_commercial_delivery_bundle_requires_flag(tmp_path, capsys):
    code = main(["commercial-delivery-bundle", "--out-dir", str(tmp_path / "x")])
    assert code == 2
    captured = capsys.readouterr()
    assert "human-allow-write" in captured.err


def test_market_scoreboard_closes_packaging_and_anti(tmp_path, capsys):
    out = tmp_path / "market.json"
    code = main(["market-leadership-scoreboard", "--out", str(out)])
    assert code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    closed = payload["closed_market_gaps"]
    assert "production_multilang_sast_breadth_beyond_held_outs" in closed
    assert "commercial_delivery_packaging" in closed
    assert "anti_auto_exploit_narrative" in closed
    assert payload["signals"]["commercial_packaging_ready"] is True
    assert payload["signals"]["anti_auto_exploit_proven"] is True
    assert payload["anti_auto_exploit"]["passed"] is True
    remaining = payload["remaining_for_full_market_leadership"]
    assert remaining == [
        "real_authorized_program_wall_clock_logs",
        "real_live_valid_report_outcomes",
    ]
    assert payload["attach_protocol"]["bundle_command"] == "commercial-delivery-bundle"
    assert payload["execution_allowed"] is False
