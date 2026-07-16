"""Unified lab leadership rollup (black-box + A+B + human-hour + multilang breadth).

Claim scope: authorized lab quality only.
Does not claim live-program or XBOW superiority.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.intelligence_benchmark.ab_leadership_gate import (
    AbLeadershipGateError,
    run_ab_leadership_gate,
)
from app.intelligence_benchmark.black_box_leadership_gate import (
    BlackBoxLeadershipGateError,
    run_black_box_leadership_gate,
)
from app.intelligence_benchmark.human_hour_calibration import (
    HumanHourCalibrationError,
    run_human_hour_calibration_gate,
)
from app.intelligence_benchmark.human_hour_scorecard import (
    HumanHourScorecardError,
    run_human_hour_scorecard,
)
from app.intelligence_benchmark.multilang_production_breadth import (
    run_multilang_production_breadth_gate,
)


class LabLeadershipRollupError(ValueError):
    """Raised when lab leadership rollup inputs fail."""


def _gate_summary(name: str, result: dict[str, Any]) -> dict[str, Any]:
    metrics = result.get("metrics") if isinstance(result.get("metrics"), dict) else {}
    return {
        "name": name,
        "passed": bool(result.get("passed")),
        "claim_scope": result.get("claim_scope"),
        "schema_version": result.get("schema_version"),
        "scenario_count": result.get("scenario_count"),
        "beyond_held_out": result.get("beyond_held_out"),
        "metric_keys": sorted(metrics.keys()),
        "headline_metrics": {
            key: metrics.get(key)
            for key in (
                "scenario_pass_rate",
                "safety_rate",
                "falsify_coverage",
                "review_ready_per_sim_hour",
                "minutes_per_review_ready",
                "golden_pass_rate",
                "matrix_coverage_rate",
                "language_count_rate",
                "service_or_middleware_rate",
            )
            if key in metrics
        },
    }


def run_lab_leadership_rollup(
    *,
    black_box_root: Path | None = None,
    simulated_human_hours: float = 1.0,
    calibration_log: Path | None = None,
) -> dict[str, Any]:
    """Aggregate black-box, A+B, human-hour, and multilang breadth lab leadership gates."""
    try:
        black_box = run_black_box_leadership_gate(black_box_root)
        ab = run_ab_leadership_gate()
        human_hour = run_human_hour_scorecard(
            simulated_human_hours=float(simulated_human_hours or 1.0),
        )
        calibration = run_human_hour_calibration_gate(log_path=calibration_log)
        multilang_breadth = run_multilang_production_breadth_gate()
    except (
        BlackBoxLeadershipGateError,
        AbLeadershipGateError,
        HumanHourScorecardError,
        HumanHourCalibrationError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
    ) as error:
        raise LabLeadershipRollupError(str(error)) from error

    gates = [
        _gate_summary("black_box_leadership", black_box),
        _gate_summary("ab_leadership", ab),
        _gate_summary("human_hour_scorecard", human_hour),
        _gate_summary("human_hour_calibration", calibration),
        _gate_summary("multilang_production_breadth", multilang_breadth),
    ]
    failures = [gate["name"] for gate in gates if not gate["passed"]]
    passed = not failures
    return {
        "schema_version": "lab_leadership_rollup_v1",
        "claim_scope": "lab_quality_leadership",
        "passed": passed,
        "failures": failures,
        "gates": gates,
        "execution_allowed": False,
        "report_submission_allowed": False,
        "non_claims": [
            "Does not claim live bounty program superiority.",
            "Does not claim XBOW or commercial scanner superiority.",
            "Lab synthetic / authorized fixture metrics only.",
            "Multilang breadth is not a full commercial multi-language SAST claim.",
        ],
        "notes": [
            "Unified rollup of black-box leadership, A+B falsify quality, "
            "human-hour proxy/calibration, and multilang production breadth gates.",
            "All component gates must pass for rollup pass.",
        ],
        "component_results": {
            "black_box_leadership": {
                "passed": black_box.get("passed"),
                "metrics": black_box.get("metrics"),
                "claim_scope": black_box.get("claim_scope"),
            },
            "ab_leadership": {
                "passed": ab.get("passed"),
                "scenario_count": ab.get("scenario_count"),
                "metrics": ab.get("metrics"),
                "claim_scope": ab.get("claim_scope"),
            },
            "human_hour_scorecard": {
                "passed": human_hour.get("passed"),
                "metrics": human_hour.get("metrics"),
                "claim_scope": human_hour.get("claim_scope"),
            },
            "human_hour_calibration": {
                "passed": calibration.get("passed"),
                "metrics": calibration.get("metrics"),
                "claim_scope": calibration.get("claim_scope"),
                "has_real_human_hour_wall_clock_logs": bool(
                    (calibration.get("measured") or {}).get(
                        "has_real_human_hour_wall_clock_logs"
                    )
                ),
                "source_kind": (calibration.get("measured") or {}).get("source_kind"),
                "wall_clock_entry_count": (calibration.get("measured") or {}).get(
                    "wall_clock_entry_count"
                ),
            },
            "multilang_production_breadth": {
                "passed": multilang_breadth.get("passed"),
                "beyond_held_out": multilang_breadth.get("beyond_held_out"),
                "metrics": multilang_breadth.get("metrics"),
                "languages_hit": multilang_breadth.get("languages_hit"),
                "patterns_hit": multilang_breadth.get("patterns_hit"),
                "claim_scope": multilang_breadth.get("claim_scope"),
            },
        },
    }
