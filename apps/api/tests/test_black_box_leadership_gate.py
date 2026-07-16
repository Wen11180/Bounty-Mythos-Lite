from __future__ import annotations

import json

from app.cli import main
from app.intelligence_benchmark.black_box_har_golden import default_fixture_root
from app.intelligence_benchmark.black_box_leadership_gate import (
    REQUIRED_FAMILIES,
    run_black_box_leadership_gate,
)


FIXTURE_ROOT = default_fixture_root()


def test_leadership_gate_passes_on_default_corpus():
    result = run_black_box_leadership_gate(FIXTURE_ROOT)
    assert result["schema_version"] == "black_box_leadership_gate_v1"
    assert result["package_count"] == 12
    assert result["passed"] is True
    assert result["failures"] == []
    assert result["execution_allowed"] is False
    assert result["report_submission_allowed"] is False
    assert result["claim_scope"] == "lab_quality_leadership"

    metrics = result["metrics"]
    for key in (
        "golden_pass_rate",
        "safety_rate",
        "iso_pass_rate",
        "falsify_coverage",
        "retain_hit",
        "refute_kill",
        "family_retain_coverage",
        "family_refute_coverage",
    ):
        assert metrics[key] == 1.0, key

    assert set(result["required_families"]) == set(REQUIRED_FAMILIES)
    assert set(result["families_with_retain"]) >= set(REQUIRED_FAMILIES)
    assert set(result["families_with_refute"]) >= set(REQUIRED_FAMILIES)


def test_cli_black_box_leadership_gate_writes_summary(tmp_path, capsys):
    out = tmp_path / "leadership.json"
    code = main(
        [
            "black-box-leadership-gate",
            "--root",
            str(FIXTURE_ROOT),
            "--out",
            str(out),
        ]
    )
    assert code == 0
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["passed"] is True
    assert result["metrics"]["family_retain_coverage"] == 1.0
    blob = out.read_text(encoding="utf-8")
    assert "SECRET" not in blob
    assert "Bearer" not in blob
    captured = capsys.readouterr()
    assert "passed=True" in captured.out


def test_leadership_gate_fails_when_package_missing(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    try:
        run_black_box_leadership_gate(empty)
        raised = False
    except Exception:
        raised = True
    assert raised
