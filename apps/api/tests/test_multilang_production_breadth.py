from __future__ import annotations

import json

from app.cli import main
from app.intelligence_benchmark.multilang_production_breadth import (
    REQUIRED_METRICS,
    TARGET_LANGUAGES,
    run_multilang_production_breadth_gate,
)


def test_multilang_production_breadth_gate_passes_beyond_held_outs():
    result = run_multilang_production_breadth_gate()
    assert result["schema_version"] == "multilang_production_breadth_v1"
    assert result["claim_scope"] == "lab_multilang_pattern_breadth"
    assert result["passed"] is True
    assert result["beyond_held_out"] is True
    assert result["failures"] == []
    assert result["execution_allowed"] is False
    assert result["report_submission_allowed"] is False
    assert result["auto_attack_allowed"] is False
    for key in REQUIRED_METRICS:
        assert result["metrics"][key] >= 1.0 or (
            key == "multi_pattern_language_rate" and result["metrics"][key] >= 0.5
        ), key
    assert result["metrics"]["matrix_coverage_rate"] == 1.0
    assert result["metrics"]["safety_rate"] == 1.0
    for language in TARGET_LANGUAGES:
        assert language in result["languages_hit"]
    assert "rust" in result["languages_hit"]
    assert "scala" in result["languages_hit"]
    assert result["cells_ok"] == result["cells_total"]
    assert result["cells_total"] > 0
    for family in (
        "ssrf_refute",
        "ssrf_retain",
        "path_refute",
        "path_retain",
        "injection_refute",
        "injection_retain",
        "mass_assign_refute",
        "mass_assign_retain",
    ):
        assert family in result["patterns_hit"], family
    assert any("Not a full commercial" in note for note in result["non_claims"])


def test_cli_multilang_production_breadth(tmp_path, capsys):
    out = tmp_path / "breadth.json"
    code = main(["multilang-production-breadth", "--out", str(out)])
    assert code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert payload["beyond_held_out"] is True
    blob = out.read_text(encoding="utf-8")
    assert "SECRET" not in blob
    assert "Bearer" not in blob
    captured = capsys.readouterr()
    assert "passed=True" in captured.out
    assert "beyond_held_out=True" in captured.out
