# Authorized live calibration scoreboard

**Claim scope:** `authorized_live_calibration_infra` only.

**Not claimed:** live bounty TOP1, XBOW ranking, remote auto-attack, auto-submission.

Updated: 2026-07-16

## Why this exists

Live track record is a competitive lag versus exploit-automation narratives.

Mythos-Lite closes it **lawfully**: authorized programs only, human-confirmed outcomes, redacted logs, submission blocked.

## Metrics (must be 1.0)

| Metric | Meaning |
| --- | --- |
| `log_schema_valid_rate` | Outcome entries match redacted schema |
| `redaction_safe_rate` | No secret/credential markers |
| `authorized_program_rate` | Every entry is explicitly authorized |
| `human_confirmed_rate` | Every entry is human-confirmed |
| `measured_precision_at_confirmed` | Valid / held candidates stay schema-safe |
| `measured_fp_kill_rate` | Human-confirmed FPs recorded cleanly |
| `safety_rate` | No high-risk secret markers in gate output |

## Commands

```powershell
cd apps/api
$env:PYTHONPATH = (Get-Location).Path
python -m app authorized-live-calibration --out tmp/live-calibration.json
python -m app authorized-live-calibration --out tmp/live-calibration.json --log path/to/redacted-live-outcomes.json
python -m pytest tests/test_authorized_live_calibration.py -q
```

## Real package attach protocol

Use the template:

`apps/api/app/intelligence_benchmark/fixtures/templates/authorized_wall_clock_and_outcomes.template.json`

| Field | Required for real flags |
| --- | --- |
| `source_kind` | `authorized_redacted_real` or `authorized_program_redacted` |
| `program_authorization_id` | package-level or per-entry |
| `wall_clock_minutes` | for `has_real_wall_clock_logs` |
| `outcome=human_confirmed_valid` + `report_outcome_ref` | for `has_real_live_valid_report_outcomes` |
| secrets/tokens/cookies | **never** |

Then:

```powershell
python -m app authorized-live-calibration --out tmp/live-real.json --log path/to/authorized_redacted_real.json
python -m app delivery-readiness --out tmp/delivery.json --live-log path/to/authorized_redacted_real.json
```

Synthetic fixtures (including the committed `authorized_live_outcomes.json` with `source_kind=synthetic`) **must not** flip `has_real_*`.

## Non-claims

- Passing this gate proves **infrastructure**, not live ranking.
- Synthetic committed fixture is allowed.
- Real program logs may replace the fixture later without enabling auto-attack.

## Track-record summary fields

Infra payload now includes `measured.track_record_summary`:

- `outcome_counts` — human-confirmed outcome histogram
- `language_families` — languages present in the authorized log package
- `wall_clock_entries` / `wall_clock_minutes_total` — optional advisory fields when present
- `source_kind` / `package_source_kind` — synthetic vs authorized redacted real
- `has_real_wall_clock_logs` / `has_real_live_valid_report_outcomes` — remain **false** until real program packages are attached

Passing the infra gate is a prerequisite for future live claims, not a live TOP1 claim.
