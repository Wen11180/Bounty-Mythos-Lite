# A+B Portfolio Health Check (no H1 API)

Updated: 2026-07-12T08:56:50Z

Purpose: while live H1 acquisition remains 401-blocked, re-verify the full authorized package portfolio and hunter gate without inventing new demo packages.

## Results

### Hunter gate

- Command: `apps/api/scripts/run_hunter_gate.ps1`
- Result: **194 passed** in ~18s
- Exit: **0**

### Portfolio operator trial

Source: `docs/hunter-ab-portfolio-trial.md` / `.json`

| Package | Expected | Decisions | Finals | Dispositions | Decision quality | Safety |
| --- | --- | --- | --- | --- | --- | --- |
| `my-h1-gitlab-own-instance` | refute | 5 | 0 | refuted=5 | pass | ok |
| `my-h1-wordpress-core-rest` | refute | 4 | 0 | refuted=4 | pass | ok |
| `my-h1-nodejs-core-permission` | refute | 5 | 0 | refuted=5 | pass | ok |
| `my-local-dvwa-authz-lab` | retain | 1 | 1 | retained=1 | pass | ok |
| `my-local-juice-shop-basket-lab` | retain | 1 | 1 | retained=1 | pass | ok |
| `my-local-new-api-access-key-lab` | refute | 3 | 0 | refuted=3 | pass | ok |

Overall portfolio decision quality: **PASS**

Notes:

- retain packages show `evaluation_status=failed` in raw scorecards when gold single-family denominators are zero; that is expected and **not** a decision-quality failure.
- All retained cards remain non-executing: `execution_allowed=false`, `validation_allowed=false`, `report_submission_allowed=false`.
- Teaching labs (DVWA / Juice Shop) are intentional retain demos, not bounty submissions.
- Guarded source packages (GitLab / WordPress / Node / new-api) correctly refute naive ownership-gap claims.

## Product signal

| Class | Expected behavior | Observed |
| --- | --- | --- |
| Faithful guarded source model | refute / 0 finals | GitLab, WP, Node, new-api |
| Intentional unguarded lab | retain + safety blocked | DVWA, Juice Shop |
| Hunter unit/release gate | green | 194 passed |

## What this unblocks without H1

1. Confidence that A+B harness is still green after new-api work
2. A single portfolio scorecard for operator review
3. Clear free capacity for **report-draft bridge**, **validation workspace wiring**, or **user-supplied non-teaching materials** next

## Still blocked / not done

- Live H1 program/scope refresh (API 401)
- Daily high-impact discovery on large real authorized targets
- Multi-engine CRS / fuzz execution path as daily workflow
- Automatic anything that touches live validation or submission

## Follow-on (same day)

- Report draft bridge: **green** (`docs/hunter-ab-report-bridge.md`)
- Validation workspace link for retained cards: prep-only / `awaiting_approval` / `allowed_to_execute=false`
- Checked: 2026-07-12T09:02:16Z

