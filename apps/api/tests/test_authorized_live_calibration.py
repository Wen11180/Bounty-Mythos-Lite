from __future__ import annotations

import json
from pathlib import Path

from app.cli import main
from app.intelligence_benchmark.authorized_live_calibration import (
    REQUIRED_METRICS,
    run_authorized_live_calibration_gate,
    synthetic_authorized_live_fixture,
    validate_live_log_entry,
)


def test_synthetic_live_entries_are_schema_valid():
    for entry in synthetic_authorized_live_fixture():
        assert validate_live_log_entry(entry) == []


def test_authorized_live_calibration_gate_passes():
    result = run_authorized_live_calibration_gate()
    assert result["schema_version"] == "authorized_live_calibration_v1"
    assert result["claim_scope"] == "authorized_live_calibration_infra"
    assert result["passed"] is True
    assert result["execution_allowed"] is False
    assert result["report_submission_allowed"] is False
    assert result["auto_attack_allowed"] is False
    assert "Does not claim live bounty program superiority." in result["non_claims"]
    for key in REQUIRED_METRICS:
        assert result["metrics"][key] == 1.0, key
    outcome_metrics = result["measured"]["track_record_summary"]["outcome_metrics"]
    assert outcome_metrics["precision_at_k"] is None
    assert outcome_metrics["false_positive_rate"] is None
    assert outcome_metrics["duplicate_rate"] is None
    assert outcome_metrics["report_readiness_rate"] is None
    assert outcome_metrics["valid_report_rate"] is None


def test_cli_authorized_live_calibration(tmp_path, capsys):
    out = tmp_path / "live.json"
    code = main(["authorized-live-calibration", "--out", str(out)])
    assert code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert "SECRET" not in out.read_text(encoding="utf-8")
    assert "passed=True" in capsys.readouterr().out


def test_cli_delivery_readiness(tmp_path, capsys):
    out = tmp_path / "delivery.json"
    code = main(["delivery-readiness", "--out", str(out)])
    assert code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert payload["lab_passed"] is True
    assert payload["live_infra_passed"] is True
    assert payload["auto_attack_allowed"] is False
    assert "auto_exploit" in payload["positioning"]["do_not_claim"]
    assert payload["lab_scenario_count"] == 90
    assert payload["multilang_breadth_passed"] is True
    assert "progress" in payload
    assert "kotlin_spring_ownership_held_out" in payload["progress"]["closed_this_wave"]
    assert "rust_axum_ownership_held_out" in payload["progress"]["closed_this_wave"]
    assert "scala_spring_ownership_held_out" in payload["progress"]["closed_this_wave"]
    assert "multilang_production_breadth_beyond_held_outs" in payload["progress"]["closed_this_wave"]
    assert payload["progress"]["multilang_production_breadth"]["beyond_held_out"] is True
    assert payload["positioning"].get("anti_auto_exploit")
    remaining = payload["remaining_for_full_market_leadership"]
    assert "real_authorized_program_wall_clock_logs" in remaining
    assert "real_live_valid_report_outcomes" in remaining
    assert "production_multilang_sast_breadth_beyond_held_outs" not in remaining
    assert len(remaining) == 2


def test_synthetic_package_does_not_claim_real_track_record():
    from app.intelligence_benchmark.authorized_live_calibration import (
        detect_real_track_record_signals,
        load_live_outcome_package,
        package_source_kind,
    )

    entries, meta = load_live_outcome_package()
    kind = package_source_kind(meta, entries)
    assert kind in {"synthetic", "lab_fixture", "synthetic_authorized_live_fixture"}
    signals = detect_real_track_record_signals(
        entries=entries,
        source_kind=kind,
        package_meta=meta,
    )
    assert signals["has_real_wall_clock_logs"] is False
    assert signals["has_real_live_valid_report_outcomes"] is False


def test_crafted_real_package_flips_track_record_flags(tmp_path):
    import json
    from app.intelligence_benchmark.authorized_live_calibration import (
        detect_real_track_record_signals,
        load_live_outcome_package,
        package_source_kind,
    )

    package = {
        "schema_version": "authorized_live_outcomes_v1",
        "source_kind": "authorized_redacted_real",
        "program_authorization_id": "auth-program-demo-001",
        "entries": [
            {
                "entry_id": "real-1",
                "program_handle": "demo-program",
                "program_authorization_id": "auth-program-demo-001",
                "authorized": True,
                "human_confirmed": True,
                "outcome": "human_confirmed_valid",
                "wall_clock_minutes": 42,
                "report_outcome_ref": "report-ref-001",
                "language_family": "python",
                "hypothesis_class": "authorization",
                "vuln_family": "idor",
                "package_label": "real-redacted-package",
                "notes": "Redacted human-confirmed outcome only.",
                "execution_allowed": False,
                "report_submission_allowed": False,
                "auto_submitted": False,
                "source_kind": "authorized_redacted_real",
            }
        ],
    }
    path = tmp_path / "real_package.json"
    path.write_text(json.dumps(package), encoding="utf-8")
    entries, meta = load_live_outcome_package(path)
    kind = package_source_kind(meta, entries)
    assert kind == "authorized_redacted_real"
    signals = detect_real_track_record_signals(
        entries=entries,
        source_kind=kind,
        package_meta=meta,
    )
    assert signals["has_real_wall_clock_logs"] is True
    assert signals["has_real_live_valid_report_outcomes"] is True
    summary = run_authorized_live_calibration_gate(log_path=path)["measured"][
        "track_record_summary"
    ]
    outcome_metrics = summary["outcome_metrics"]
    assert outcome_metrics["precision_at_k"] is None
    assert outcome_metrics["report_readiness_rate"] is None
    assert outcome_metrics["valid_report_rate"] is None


def test_operator_attested_package_reports_complete_outcome_metrics(tmp_path):
    package = {
        "schema_version": "authorized_live_outcomes_v1",
        "source_kind": "authorized_redacted_real",
        "program_authorization_id": "auth-program-metrics-001",
        "evaluation_top_k": 3,
        "entries": [
            {
                "entry_id": "metric-valid-1",
                "program_handle": "attested-program",
                "program_authorization_id": "auth-program-metrics-001",
                "authorized": True,
                "human_confirmed": True,
                "outcome": "human_confirmed_valid",
                "candidate_rank": 1,
                "report_ready": True,
                "report_valid": True,
                "wall_clock_minutes": 42,
                "report_outcome_ref": "report-metric-001",
                "language_family": "python",
                "hypothesis_class": "authorization",
                "vuln_family": "idor",
                "package_label": "attested-valid",
                "execution_allowed": False,
                "report_submission_allowed": False,
                "auto_submitted": False,
                "source_kind": "authorized_redacted_real",
            },
            {
                "entry_id": "metric-fp-1",
                "program_handle": "attested-program",
                "program_authorization_id": "auth-program-metrics-001",
                "authorized": True,
                "human_confirmed": True,
                "outcome": "human_confirmed_fp",
                "candidate_rank": 2,
                "wall_clock_minutes": 20,
                "language_family": "java",
                "hypothesis_class": "authorization",
                "vuln_family": "idor",
                "package_label": "attested-fp",
                "execution_allowed": False,
                "report_submission_allowed": False,
                "auto_submitted": False,
                "source_kind": "authorized_redacted_real",
            },
            {
                "entry_id": "metric-duplicate-1",
                "program_handle": "attested-program",
                "program_authorization_id": "auth-program-metrics-001",
                "authorized": True,
                "human_confirmed": True,
                "outcome": "human_deduplicated",
                "candidate_rank": 3,
                "wall_clock_minutes": 18,
                "language_family": "go",
                "hypothesis_class": "authorization",
                "vuln_family": "idor",
                "package_label": "attested-duplicate",
                "execution_allowed": False,
                "report_submission_allowed": False,
                "auto_submitted": False,
                "source_kind": "authorized_redacted_real",
            },
        ],
    }
    path = tmp_path / "operator_attested_metrics.json"
    path.write_text(json.dumps(package), encoding="utf-8")

    outcome_metrics = run_authorized_live_calibration_gate(log_path=path)["measured"][
        "track_record_summary"
    ]["outcome_metrics"]
    assert outcome_metrics["precision_at_k"] == 0.3333
    assert outcome_metrics["precision_at_k_k"] == 3
    assert outcome_metrics["false_positive_rate"] == 0.3333
    assert outcome_metrics["duplicate_rate"] == 0.3333
    assert outcome_metrics["report_readiness_rate"] == 1.0
    assert outcome_metrics["valid_report_rate"] == 1.0
    assert outcome_metrics["independent_verification"] is False


def test_template_package_cannot_flip_real_track_record_flags():
    template = (
        Path(__file__).resolve().parents[1]
        / "app"
        / "intelligence_benchmark"
        / "fixtures"
        / "templates"
        / "authorized_wall_clock_and_outcomes.template.json"
    )
    from app.intelligence_benchmark.authorized_live_calibration import (
        detect_real_track_record_signals,
        load_live_outcome_package,
        package_source_kind,
    )

    entries, meta = load_live_outcome_package(template)
    signals = detect_real_track_record_signals(
        entries=entries,
        source_kind=package_source_kind(meta, entries),
        package_meta=meta,
    )
    assert signals["has_real_wall_clock_logs"] is False
    assert signals["has_real_live_valid_report_outcomes"] is False

    meta["source_kind"] = "authorized_redacted_real"
    meta.pop("fixture_kind")
    for entry in entries:
        entry["source_kind"] = "authorized_redacted_real"
    relabeled_signals = detect_real_track_record_signals(
        entries=entries,
        source_kind=package_source_kind(meta, entries),
        package_meta=meta,
    )
    assert relabeled_signals["has_real_wall_clock_logs"] is False
    assert relabeled_signals["has_real_live_valid_report_outcomes"] is False


def test_delivery_readiness_remaining_empty_with_real_live_package(tmp_path):
    """Attaching a real authorized live package must drop both real-data remaining gaps."""
    package = {
        "schema_version": "authorized_live_outcomes_v1",
        "source_kind": "authorized_redacted_real",
        "program_authorization_id": "auth-program-e2e-001",
        "entries": [
            {
                "entry_id": "e2e-valid-1",
                "program_handle": "demo-program",
                "program_authorization_id": "auth-program-e2e-001",
                "authorized": True,
                "human_confirmed": True,
                "outcome": "human_confirmed_valid",
                "wall_clock_minutes": 55,
                "report_outcome_ref": "report-e2e-001",
                "language_family": "python",
                "hypothesis_class": "authorization",
                "vuln_family": "idor",
                "package_label": "e2e-real-valid",
                "notes": "Redacted human-confirmed outcome only.",
                "execution_allowed": False,
                "report_submission_allowed": False,
                "auto_submitted": False,
                "source_kind": "authorized_redacted_real",
            },
            {
                "entry_id": "e2e-fp-1",
                "program_handle": "demo-program",
                "program_authorization_id": "auth-program-e2e-001",
                "authorized": True,
                "human_confirmed": True,
                "outcome": "human_confirmed_fp",
                "wall_clock_minutes": 30,
                "language_family": "java",
                "hypothesis_class": "authorization",
                "vuln_family": "idor",
                "package_label": "e2e-real-fp",
                "execution_allowed": False,
                "report_submission_allowed": False,
                "auto_submitted": False,
                "source_kind": "authorized_redacted_real",
            },
        ],
    }
    live_path = tmp_path / "real_live.json"
    live_path.write_text(json.dumps(package), encoding="utf-8")
    out = tmp_path / "delivery.json"
    code = main(
        [
            "delivery-readiness",
            "--out",
            str(out),
            "--live-log",
            str(live_path),
        ]
    )
    assert code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert payload["remaining_for_full_market_leadership"] == []
    track = payload["progress"]["live_track_record_infra"]
    assert track["has_real_wall_clock_logs"] is True
    assert track["has_real_live_valid_report_outcomes"] is True


def test_market_leadership_scoreboard_cli(tmp_path, capsys):
    out = tmp_path / "market.json"
    code = main(["market-leadership-scoreboard", "--out", str(out)])
    assert code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "market_leadership_scoreboard_v1"
    assert payload["passed"] is True
    assert payload["auto_attack_allowed"] is False
    assert "auto_exploit" in payload["positioning"]["do_not_claim"]
    remaining = payload["remaining_for_full_market_leadership"]
    assert "real_authorized_program_wall_clock_logs" in remaining
    assert "real_live_valid_report_outcomes" in remaining
    assert "production_multilang_sast_breadth_beyond_held_outs" not in remaining
    assert "production_multilang_sast_breadth_beyond_held_outs" in payload["closed_market_gaps"]
    assert "passed=True" in capsys.readouterr().out
