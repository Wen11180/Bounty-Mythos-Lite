# Authorized live calibration scoreboard

**Claim scope:** `authorized_live_calibration_infra` only.

**Not claimed:** live bounty TOP1, XBOW ranking, remote auto-attack, auto-submission.

Updated: 2026-07-16

## Why this exists

Live track record is a competitive lag versus exploit-automation narratives.

Mythos-Lite closes it **lawfully**: authorized programs only, human-confirmed outcomes, redacted logs, submission blocked.

## Infrastructure checks (must be 1.0)

| Metric | Meaning |
| --- | --- |
| `log_schema_valid_rate` | Outcome entries match redacted schema |
| `redaction_safe_rate` | No secret/credential markers |
| `authorized_program_rate` | Every entry is explicitly authorized |
| `human_confirmed_rate` | Every entry is human-confirmed |
| `measured_precision_at_confirmed` | Legacy schema/redaction proxy for valid/held rows; not precision@K |
| `measured_fp_kill_rate` | Legacy schema/redaction proxy for confirmed-FP rows; not false-positive rate |
| `safety_rate` | No high-risk secret markers in gate output |

These checks prove the logging pipeline, not research effectiveness. They remain
separate from the outcome metrics below and must never be described as live
precision or false-positive performance.

## Outcome Metrics

`measured.track_record_summary.outcome_metrics` reports the following only from
a schema-clean, redacted, `authorized_redacted_real` package without a
synthetic/template marker. Those inputs are **operator-attested**, not
independently verified.

| Metric | Required data | Meaning |
| --- | --- | --- |
| `precision_at_k` | package `evaluation_top_k`; unique `candidate_rank` covering `1..K` for every terminal outcome | confirmed-valid candidates in the top K / K |
| `false_positive_rate` | terminal candidate outcomes | `human_confirmed_fp` / terminal outcomes |
| `duplicate_rate` | terminal candidate outcomes | `human_deduplicated` / terminal outcomes |
| `report_readiness_rate` | `report_ready` boolean on every `human_confirmed_valid` row | report-ready valid candidates / valid candidates |
| `valid_report_rate` | `report_valid` boolean on every `human_confirmed_valid` row | report-valid candidates / valid candidates |

Any missing ranking or result field leaves the affected value as `null` with an
availability reason. It does not become a proxy score.

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
| `source_kind` | `authorized_redacted_real` or `authorized_program_redacted` after replacing template markers |
| `program_authorization_id` | package-level or per-entry |
| `evaluation_top_k` | package-level positive integer, required to calculate `precision_at_k` |
| `wall_clock_minutes` | for `has_real_wall_clock_logs` |
| `outcome=human_confirmed_valid` + `report_outcome_ref` | for `has_real_live_valid_report_outcomes` |
| `candidate_rank` | unique positive rank on every terminal outcome for `precision_at_k` |
| `report_ready` / `report_valid` | booleans on every `human_confirmed_valid` entry for report rates |
| secrets/tokens/cookies | **never** |

The bundled template intentionally uses `source_kind=template`, a
`fixture_kind` marker, and `REPLACE_*` placeholders. Replace every placeholder,
set the source kind to an authorized value, and remove the marker only after
entering redacted, operator-attested outcomes. A template, demo, or scaffold
example cannot close the real-data gaps by adding an authorization reference.

Then:

```powershell
python -m app authorized-live-calibration --out tmp/live-real.json --log path/to/authorized_redacted_real.json
python -m app delivery-readiness --out tmp/delivery.json --live-log path/to/authorized_redacted_real.json
```

Synthetic fixtures (including the committed `authorized_live_outcomes.json` with `source_kind=synthetic`) **must not** flip `has_real_*`.

## Evidence Boundary

`source_kind=authorized_redacted_real` means the operator attests that the
redacted package came from an authorized program. The calibration pipeline does
not independently verify that assertion, validate an external report outcome,
or grant execution or submission permission. Output therefore exposes
`attestation_status=operator_attested` and
`independent_verification=false`; independent verification remains a separate
human-controlled evidence process.

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
- `attestation_status` / `independent_verification` — operator attestation is not independent verification
- `has_real_wall_clock_logs` / `has_real_live_valid_report_outcomes` — remain **false** until real program packages are attached
- `outcome_metrics` — actual, nullable precision/FP/duplicate/report metrics rather than infrastructure proxies

Passing the infra gate is a prerequisite for future live claims, not a live TOP1 claim.
