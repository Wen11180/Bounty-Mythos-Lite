# Lab leadership rollup scoreboard

**Claim scope:** authorized lab quality only (black-box + A+B + human-hour).

**Not claimed:** live bounty program superiority, XBOW live-target ranking, remote auto-attack, or auto-submission.

Updated: 2026-07-16

## What this rollup is

A single pass/fail aggregation of the existing lab leadership gates:

1. **Black-box leadership** — HAR golden + dual-intake isomorphism (`lab_quality_leadership` slice)
2. **A+B falsify leadership** — Candidate Hunter hard corpus (82 scenarios)
3. **Human-hour scorecard** — review-ready density proxy on synthetic A+B
4. **Human-hour calibration** — redacted review-minute calibration fixture

All four must pass for the rollup to pass. The rollup never grants execution or report submission.

## Gate command

```powershell
cd apps/api
python -m app lab-leadership-rollup --out tmp/lab-leadership.json
python -m pytest tests/test_lab_leadership_rollup.py tests/test_ab_leadership_gate.py -q
```

## Interpretation

| Field | Meaning |
| --- | --- |
| `passed` | Every component gate passed |
| `failures` | Component names that failed |
| `gates` | Per-gate pass + headline metrics |
| `non_claims` | Explicit non-claims (live / XBOW) |
| `component_results` | Nested metrics for audit |

Use this as the **lab TOP1 dashboard**, not as a live-program ranking.


## Related commercial readiness

```powershell
python -m app delivery-readiness --out tmp/delivery-readiness.json
python -m app authorized-live-calibration --out tmp/live-calibration.json
```

Delivery readiness aggregates lab rollup + authorized live **infra** gate. It does not claim live TOP1.
