# Advisory Static Engines (Semgrep / CodeQL) v0

Offline, non-executing advisory inputs for the multi-engine verifier.

## Hard safety

- Does **not** run scanners against live remote targets by default
- Does **not** execute validation or submit reports
- Never sets `confirmed_vulnerability=true`
- Findings are advisory only; hunter + human review still required

## Module

`apps/api/app/advisory_static_engines`

## Inputs

- Inline finding list
- `{"findings":[...]}` JSON
- Minimal SARIF (`runs[].results[]`)
- File path to UTF-8 JSON (no secrets)

Finding fields (any subset):

- `rule_id` / `ruleId` / `check_id`
- `message`
- `path` / `file`
- `root_cause_id` (best for matching A+B cards)
- `polarity`: `support` (default) | `control` / `oppose`
- `tags`: e.g. `["control"]`

## Outputs

EngineSignal-compatible dicts:

- `engine`: `semgrep_advisory` | `codeql_advisory`
- `supports_candidate`: true | false | null
- absolute safety floor flags all false

## Wiring

Optional kwargs on:

- `build_multi_engine_verdict(..., semgrep_signal=..., codeql_signal=...)`
- `verdict_from_hunter_and_map(..., semgrep_signal=..., codeql_signal=...)`

## Tests

`apps/api/tests/test_advisory_static_engines.py`

## Not done yet

- Local Semgrep CLI: done in docs/hunter-ab-semgrep-runner.md (human flag; offline rules). CodeQL CLI still pending.
- Package-level `inputs/advisory/*.json` auto-ingest in operator trial

## Package auto-ingest

Optional offline advisory files under authorized packages:

- `inputs/advisory/*.json`
- `inputs/advisory.json`

Loader: `load_package_advisory_bundle(package_root)`

Trial wiring: `run_candidate_hunter_authorized_lab_package` attaches `advisory_bundle`.
Report bridge: `bridge_operator_trial_result` / `build_submission_blocked_report_bundle` pass signals into multi-engine verdicts.

Filenames containing secret/token/cookie/credential/password/apikey are skipped.
