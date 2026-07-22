from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "run_ab_operator_trial.py"


def _operator_trial_module():
    spec = importlib.util.spec_from_file_location("operator_trial_scorecard", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_scorecard_does_not_label_failed_lab_as_applicable_only():
    module = _operator_trial_module()
    summary = {
        "case_id": "lab-failed",
        "suite": "lab",
        "risk_family": "authorization",
        "expected_disposition": "retain",
        "evaluation_status": "failed",
        "evaluation_scope": "authorized_lab_package",
        "applicable_metrics": ["precision_at_5"],
        "not_applicable_metrics": ["effective_refutation_rate"],
        "loop_audit_status": "ready",
        "events": [],
        "final_candidates": [],
        "candidate_decisions": [],
        "gold_roots": [],
        "metrics": {},
        "false_positives": [],
        "missed_retained_roots": [],
        "invalid_refutations": [],
        "invalid_deduplications": [],
        "invalid_suppressions": [{"reason": "missing_suppression_evidence"}],
        "safety_failures": [],
        "schema_failures": [],
        "stage_audit_failures": [],
    }

    markdown = module._render_markdown(
        [summary],
        "2026-07-21T00:00:00Z",
        mode="authorized-lab-package",
    )
    trial_header = next(line for line in markdown.splitlines() if line.startswith("| Trial |"))
    trial_divider = next(
        line
        for line in markdown.splitlines()
        if line.startswith("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    )

    assert "authorized lab applicability recorded" not in markdown
    assert "inspect evaluator notes" in markdown
    assert "- invalid_suppressions: `[{\'reason\': \'missing_suppression_evidence\'}]`" in markdown
    assert trial_header.count("|") == trial_divider.count("|") == 11
