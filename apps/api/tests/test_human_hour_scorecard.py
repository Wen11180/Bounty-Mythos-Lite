from __future__ import annotations

import json

from app.cli import main
from app.intelligence_benchmark.human_hour_scorecard import (
    REQUIRED_METRICS,
    run_human_hour_scorecard,
)


def test_human_hour_scorecard_passes_on_ab_lab_corpus():
    result = run_human_hour_scorecard()
    assert result["schema_version"] == "human_hour_scorecard_v1"
    assert result["claim_scope"] == "lab_human_hour_quality_proxy"
    assert result["passed"] is True
    assert result["execution_allowed"] is False
    assert result["report_submission_allowed"] is False
    assert result["ab_passed"] is True
    assert result["review_ready_count"] > 0
    for key in REQUIRED_METRICS:
        if key == "review_ready_per_sim_hour":
            assert result["metrics"][key] > 0
        else:
            assert result["metrics"][key] == 1.0, key
    notes = " ".join(result.get("notes") or [])
    assert "XBOW" in notes or "live" in notes.lower()


def test_cli_human_hour_scorecard_writes_summary(tmp_path, capsys):
    out = tmp_path / "human-hour.json"
    code = main(
        [
            "human-hour-scorecard",
            "--out",
            str(out),
            "--simulated-hours",
            "1.0",
        ]
    )
    assert code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert payload["metrics"]["ab_gate_pass"] == 1.0
    assert payload["metrics"]["fp_kill_rate"] == 1.0
    blob = out.read_text(encoding="utf-8")
    assert "SECRET" not in blob
    assert "Bearer" not in blob
    captured = capsys.readouterr()
    assert "passed=True" in captured.out
