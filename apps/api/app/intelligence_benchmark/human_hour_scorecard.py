"""Authorized lab human-hour quality scorecard (synthetic proxies only).

Claim scope: simulated authorized-lab research quality density proxies derived
from A+B (and optional black-box) leadership gates. Does not claim live bounty
program superiority or XBOW ranking.
"""

from __future__ import annotations

from typing import Any

from app.intelligence_benchmark.ab_leadership_gate import run_ab_leadership_gate


REQUIRED_METRICS = (
    "precision_at_retain",
    "fp_kill_rate",
    "needs_evidence_discipline",
    "review_ready_per_sim_hour",
    "safety_rate",
    "ab_gate_pass",
)

# Simulated human research hour budget for the lab hard corpus.
# Proxy only — not a measured wall-clock claim.
SIMULATED_HUMAN_HOURS = 1.0


class HumanHourScorecardError(ValueError):
    """Raised when human-hour scorecard inputs are invalid."""


def _rate(num: float, den: float) -> float:
    if den <= 0:
        return 1.0
    return round(float(num) / float(den), 4)


def run_human_hour_scorecard(
    *,
    ab_result: dict[str, Any] | None = None,
    simulated_human_hours: float = SIMULATED_HUMAN_HOURS,
) -> dict[str, Any]:
    """Compute human-hour quality proxies from the A+B leadership hard corpus."""
    if simulated_human_hours <= 0:
        raise HumanHourScorecardError("simulated_human_hours_must_be_positive")

    ab = ab_result if isinstance(ab_result, dict) else run_ab_leadership_gate()
    if not isinstance(ab, dict):
        raise HumanHourScorecardError("ab_result_invalid")

    metrics_ab = ab.get("metrics") if isinstance(ab.get("metrics"), dict) else {}
    scenarios = ab.get("scenarios") if isinstance(ab.get("scenarios"), list) else []

    retain_expected = 0
    retain_hit = 0
    kill_expected = 0
    kill_hit = 0
    needs_expected = 0
    needs_hit = 0
    review_ready = 0

    for row in scenarios:
        if not isinstance(row, dict):
            continue
        expected = str(row.get("expected") or "")
        ok = bool(
            row.get("disposition_ok")
            and row.get("has_falsification_card")
            and row.get("card_quality_ok")
            and row.get("safe")
        )
        if expected == "retained":
            retain_expected += 1
            if ok:
                retain_hit += 1
                review_ready += 1
        elif expected in {"refuted", "suppressed"}:
            kill_expected += 1
            if ok:
                kill_hit += 1
        elif expected == "needs_evidence":
            needs_expected += 1
            if ok:
                needs_hit += 1
        elif expected == "rank_order" and ok:
            # Rank-order scenario produces two review-ready retained finals.
            review_ready += 2
        elif expected == "multi" and ok:
            # One retained final after shared-root dedupe.
            review_ready += 1
        elif expected == "multi_engine_advisory" and ok:
            # Advisory consistency is not a review-ready candidate itself.
            pass

    precision_at_retain = _rate(retain_hit, retain_expected)
    fp_kill_rate = _rate(kill_hit, kill_expected)
    needs_discipline = _rate(needs_hit, needs_expected)
    safety_rate = float(metrics_ab.get("safety_rate") or 0.0)
    ab_gate_pass = 1.0 if ab.get("passed") is True else 0.0
    review_ready_per_sim_hour = round(review_ready / simulated_human_hours, 4)

    metrics = {
        "precision_at_retain": precision_at_retain,
        "fp_kill_rate": fp_kill_rate,
        "needs_evidence_discipline": needs_discipline,
        "review_ready_per_sim_hour": review_ready_per_sim_hour,
        "safety_rate": safety_rate,
        "ab_gate_pass": ab_gate_pass,
    }

    # Perfect lab proxy: all quality rates 1.0 and at least one review-ready unit.
    passed = (
        all(metrics[key] == 1.0 for key in (
            "precision_at_retain",
            "fp_kill_rate",
            "needs_evidence_discipline",
            "safety_rate",
            "ab_gate_pass",
        ))
        and review_ready_per_sim_hour > 0
        and float(metrics_ab.get("scenario_pass_rate") or 0.0) == 1.0
    )

    return {
        "schema_version": "human_hour_scorecard_v1",
        "claim_scope": "lab_human_hour_quality_proxy",
        "passed": passed,
        "simulated_human_hours": simulated_human_hours,
        "review_ready_count": review_ready,
        "ab_scenario_count": ab.get("scenario_count"),
        "ab_passed": ab.get("passed"),
        "metrics": metrics,
        "required_metrics": list(REQUIRED_METRICS),
        "ab_metrics": metrics_ab,
        "execution_allowed": False,
        "report_submission_allowed": False,
        "notes": [
            "Synthetic authorized lab proxies only.",
            "Does not claim live bounty program or XBOW superiority.",
            "review_ready_per_sim_hour uses a fixed simulated hour budget, not wall-clock measurement.",
        ],
    }
