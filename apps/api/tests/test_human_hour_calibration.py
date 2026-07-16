from __future__ import annotations

import json

from app.cli import main
from app.intelligence_benchmark.human_hour_calibration import (
    REQUIRED_METRICS,
    run_human_hour_calibration_gate,
    synthetic_calibration_fixture,
    validate_review_log_entry,
)


def test_synthetic_fixture_entries_are_schema_valid():
    for entry in synthetic_calibration_fixture():
        assert validate_review_log_entry(entry) == []


def test_human_hour_calibration_gate_passes_synthetic_fixture():
    result = run_human_hour_calibration_gate()
    assert result["schema_version"] == "human_hour_calibration_v1"
    assert result["claim_scope"] == "lab_human_hour_calibration"
    assert result["passed"] is True
    assert result["failures"] == []
    assert result["execution_allowed"] is False
    assert result["report_submission_allowed"] is False
    assert result["proxy_passed"] is True
    assert result["ab_passed"] is True
    for key in REQUIRED_METRICS:
        if key == "minutes_per_review_ready":
            assert result["metrics"][key] > 0
        else:
            assert result["metrics"][key] == 1.0, key


def test_cli_human_hour_calibration_writes_summary(tmp_path, capsys):
    out = tmp_path / "human-hour-calibration.json"
    code = main(
        [
            "human-hour-calibration",
            "--out",
            str(out),
        ]
    )
    assert code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert payload["metrics"]["proxy_alignment_ok"] == 1.0
    blob = out.read_text(encoding="utf-8")
    assert "SECRET" not in blob
    assert "Bearer" not in blob
    captured = capsys.readouterr()
    assert "passed=True" in captured.out


def test_cli_human_hour_calibration_rejects_secret_log(tmp_path):
    log = tmp_path / "bad-log.json"
    log.write_text(
        json.dumps(
            [
                {
                    "entry_id": "bad",
                    "outcome": "retained_review_ready",
                    "review_minutes": 5,
                    "notes": "Authorization: Bearer SECRET-token",
                    "execution_allowed": False,
                    "report_submission_allowed": False,
                }
            ]
        ),
        encoding="utf-8",
    )
    out = tmp_path / "out.json"
    code = main(
        [
            "human-hour-calibration",
            "--out",
            str(out),
            "--log",
            str(log),
        ]
    )
    assert code == 1
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["passed"] is False
    assert "redaction" in payload["failures"] or payload["metrics"]["redaction_safe_rate"] < 1.0


def test_committed_redacted_package_passes_calibration():
    from app.intelligence_benchmark.human_hour_calibration import (
        committed_redacted_log_path,
        load_review_logs,
        run_human_hour_calibration_gate,
    )

    path = committed_redacted_log_path()
    entries = load_review_logs(path)
    assert len(entries) >= 20
    result = run_human_hour_calibration_gate(log_path=path)
    assert result["passed"] is True
    assert result["metrics"]["multilang_package_coverage"] == 1.0
    assert set(result["measured"]["language_families"]) >= {"java", "go", "rails", "kotlin", "csharp", "php"}


def test_jsonl_review_log_load_and_gate():
    from app.intelligence_benchmark.human_hour_calibration import (
        COMMITTED_REDACTED_LOG_JSONL,
        load_review_logs,
        run_human_hour_calibration_gate,
    )

    assert COMMITTED_REDACTED_LOG_JSONL.is_file()
    entries = load_review_logs(COMMITTED_REDACTED_LOG_JSONL)
    assert len(entries) >= 20
    result = run_human_hour_calibration_gate(log_path=COMMITTED_REDACTED_LOG_JSONL)
    assert result["passed"] is True


def test_cli_human_hour_calibration_with_committed_log(tmp_path, capsys):
    from app.cli import main
    from app.intelligence_benchmark.human_hour_calibration import committed_redacted_log_path
    import json

    out = tmp_path / "cal.json"
    code = main(
        [
            "human-hour-calibration",
            "--out",
            str(out),
            "--log",
            str(committed_redacted_log_path()),
        ]
    )
    assert code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert "redacted_review_logs" in payload["log_source"]


def test_synthetic_human_hour_package_does_not_claim_real_wall_clock():
    from app.intelligence_benchmark.human_hour_calibration import (
        detect_real_human_hour_signals,
        load_review_log_package,
        package_source_kind,
        run_human_hour_calibration_gate,
    )

    result = run_human_hour_calibration_gate()
    assert result["measured"]["has_real_human_hour_wall_clock_logs"] is False
    entries, meta = load_review_log_package()
    kind = package_source_kind(meta, entries)
    assert kind in {"synthetic", "lab_fixture", "synthetic_human_hour_fixture"}
    signals = detect_real_human_hour_signals(
        entries=entries, source_kind=kind, package_meta=meta
    )
    assert signals["has_real_human_hour_wall_clock_logs"] is False


def test_crafted_real_human_hour_package_flips_wall_clock_flag(tmp_path):
    from app.intelligence_benchmark.human_hour_calibration import (
        detect_real_human_hour_signals,
        load_review_log_package,
        package_source_kind,
        run_human_hour_calibration_gate,
    )

    package = {
        "schema_version": "human_hour_review_logs_v1",
        "source_kind": "authorized_redacted_real",
        "program_authorization_id": "auth-hh-demo-001",
        "entries": [
            {
                "entry_id": "hh-real-1",
                "outcome": "refuted_fp",
                "review_minutes": 10.0,
                "wall_clock_minutes": 40.0,
                "program_authorization_id": "auth-hh-demo-001",
                "package_label": "java-service-layer-ownership",
                "language_family": "java",
                "hypothesis_class": "authorization",
                "refutation_path": "service_layer",
                "execution_allowed": False,
                "report_submission_allowed": False,
                "source_kind": "authorized_redacted_real",
            },
            {
                "entry_id": "hh-real-2",
                "outcome": "retained_review_ready",
                "review_minutes": 15.0,
                "wall_clock_minutes": 55.0,
                "program_authorization_id": "auth-hh-demo-001",
                "package_label": "go-middleware-ownership",
                "language_family": "go",
                "hypothesis_class": "authorization",
                "execution_allowed": False,
                "report_submission_allowed": False,
                "source_kind": "authorized_redacted_real",
            },
        ],
    }
    path = tmp_path / "hh_real.json"
    path.write_text(json.dumps(package), encoding="utf-8")
    entries, meta = load_review_log_package(path)
    kind = package_source_kind(meta, entries)
    assert kind == "authorized_redacted_real"
    signals = detect_real_human_hour_signals(
        entries=entries, source_kind=kind, package_meta=meta
    )
    assert signals["has_real_human_hour_wall_clock_logs"] is True
    # Gate may fail proxy alignment with only 2 entries; focus on real signal path via load.
    assert signals["wall_clock_real_entry_count"] == 2
