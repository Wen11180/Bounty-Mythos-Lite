from __future__ import annotations

import json

from app.cli import main
from app.intelligence_benchmark.lab_leadership_rollup import run_lab_leadership_rollup


def test_lab_leadership_rollup_passes_lab_gates():
    result = run_lab_leadership_rollup()
    assert result["schema_version"] == "lab_leadership_rollup_v1"
    assert result["claim_scope"] == "lab_quality_leadership"
    assert result["passed"] is True
    assert result["failures"] == []
    assert result["execution_allowed"] is False
    assert result["report_submission_allowed"] is False
    assert "Does not claim XBOW" in " ".join(result["non_claims"])
    names = {gate["name"] for gate in result["gates"]}
    assert names == {
        "black_box_leadership",
        "ab_leadership",
        "human_hour_scorecard",
        "human_hour_calibration",
        "multilang_production_breadth",
    }
    breadth = result["component_results"]["multilang_production_breadth"]
    assert breadth["passed"] is True
    assert breadth["beyond_held_out"] is True
    hh = result["component_results"]["human_hour_calibration"]
    assert hh["has_real_human_hour_wall_clock_logs"] is False
    ab = result["component_results"]["ab_leadership"]
    assert ab["passed"] is True
    assert ab["scenario_count"] == 90


def test_cli_lab_leadership_rollup_writes_summary(tmp_path, capsys):
    out = tmp_path / "lab-leadership.json"
    code = main(["lab-leadership-rollup", "--out", str(out)])
    assert code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert payload["schema_version"] == "lab_leadership_rollup_v1"
    blob = out.read_text(encoding="utf-8")
    assert "SECRET" not in blob
    assert "Bearer" not in blob
    captured = capsys.readouterr()
    assert "passed=True" in captured.out
