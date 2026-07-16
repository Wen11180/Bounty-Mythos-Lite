# Human-hour quality scoreboard (authorized lab proxy)

**Claim scope:** simulated authorized-lab research quality density proxies derived from the A+B hard corpus (and linked leadership gates).

**Not claimed:** live bounty program superiority, XBOW live-target ranking, remote auto-attack, auto-submission, or measured wall-clock researcher productivity.

Updated: 2026-07-15

## Why this exists

Lab leadership gates prove **decision quality** (retain / refute / suppress / needs_evidence / dedupe / rank / multi-engine).

A human-hour scorecard adds a **density proxy**: how many review-ready candidates and how cleanly false positives are killed per simulated research hour on the authorized hard corpus.

This is a **proxy**, not a field measurement. It supports internal prioritization toward real TOP1 work; it does not authorize live superiority claims.

## Proxy metrics

| Metric | Meaning |
| --- | --- |
| `precision_at_retain` | Expected retain scenarios actually retain with safe cards |
| `fp_kill_rate` | Expected refute/suppress scenarios kill with evidence-backed cards |
| `needs_evidence_discipline` | Incomplete evidence stays needs_evidence (no silent padding) |
| `review_ready_per_sim_hour` | Count of review-ready retained units / simulated hours |
| `safety_rate` | Inherited A+B leadership safety rate |
| `ab_gate_pass` | 1.0 only when A+B leadership gate fully passes |

## Gate commands

```powershell
cd apps/api
python -m pytest tests/test_human_hour_scorecard.py tests/test_ab_leadership_gate.py -q
python -m app human-hour-scorecard --out tmp/human-hour.json
python -m app human-hour-scorecard --out tmp/human-hour.json --simulated-hours 1.0
```

## Relationship to TOP1

1. Passing this scorecard means the **lab hard corpus** is dense and falsification-first under a simulated hour budget.
2. It does **not** mean Mythos-Lite is TOP1 on live programs or against XBOW-style autonomous exploit systems.
3. Next calibration step: log authorized human review minutes on real in-scope packages and replace the fixed simulated hour with measured review cost — still without auto-attack or auto-submit.

## Safety

- `execution_allowed` / `report_submission_allowed` remain false.
- Outputs must not contain raw secrets (`SECRET`, `Bearer `, `Authorization:`, cookies).
- Scope Guard and human approval gates stay mandatory for any real validation planning.

## Calibration path (review-minute logs)

Use redacted authorized review logs to replace pure simulation:

```powershell
cd apps/api
python -m app human-hour-calibration --out tmp/human-hour-calibration.json
# optional real redacted log:
python -m app human-hour-calibration --out tmp/human-hour-calibration.json --log path/to/redacted-review-log.json
python -m app human-hour-calibration --out tmp/human-hour-calibration.json --log app/intelligence_benchmark/fixtures/redacted_review_logs.json
python -m app human-hour-calibration --out tmp/human-hour-calibration.json --log app/intelligence_benchmark/fixtures/redacted_review_logs.jsonl
```

Calibration metrics:

| Metric | Meaning |
| --- | --- |
| `log_schema_valid_rate` | Review log entries match the redacted schema |
| `redaction_safe_rate` | No secret/credential markers in logs |
| `measured_fp_kill_rate` | Measured refute/suppress density from logs |
| `measured_precision_at_retain` | Measured retain review-ready precision |
| `minutes_per_review_ready` | Total review minutes / review-ready count |
| `proxy_alignment_ok` | Measured discipline aligns with lab proxy scorecard |
| `safety_rate` | Inherited safety from A+B / proxy gates |
| `multilang_package_coverage` | Share of multilang package labels present in the log corpus |

**Still not claimed:** live bounty program TOP1 or XBOW superiority. Calibration infrastructure is a prerequisite for any future live claim.


## Real human-hour wall-clock attach protocol

Synthetic and committed fixtures keep `has_real_human_hour_wall_clock_logs=false`.

To close the **real human-hour** market gap:

1. Copy `apps/api/app/intelligence_benchmark/fixtures/templates/authorized_human_hour_wall_clock.template.json`
2. Fill `source_kind=authorized_redacted_real`, `program_authorization_id`, and `wall_clock_minutes`
3. Never include secrets/tokens/cookies; keep execution and submission blocked
4. Run:

```powershell
python -m app human-hour-calibration --out tmp/hh-real.json --log path/to/authorized_hh_real.json
python -m app delivery-readiness --out tmp/delivery.json --log path/to/authorized_hh_real.json
python -m app market-leadership-scoreboard --out tmp/market.json --log path/to/authorized_hh_real.json
```

Wall-clock gap can also close via a real **live** outcome package (`authorized-live-calibration --live-log`). Valid-report gap still requires live `human_confirmed_valid` + `report_outcome_ref`.
