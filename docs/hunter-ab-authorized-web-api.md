# Authorized Web/API Plan (Package Ingest)

Plan-only authorized Web/API surface modeling for A+B packages.

## Status

- Module: `apps/api/app/authorized_web_api/`
- Bridge: `attach_authorized_web_api_to_bridge_result` in `run_ab_report_bridge.py`
- Scheduler: sets `authorized_bug_bounty` so `T-004` becomes `planned`
- Execution: always `plan_only`; never live network validation or submit

## What it does

1. **Explicit dict path** (compat): `build_authorized_bug_bounty_plan(scope_policy, code_files)` keeps stage `v2_authorized_bug_bounty`.
2. **Package root path**: loads `inputs/scope.json`, `inputs/api.json`, optional `inputs/roles.json`, `package.json`, and local code under preferred roots.
3. Builds:
   - allowed assets (`local_only` → `local_authorized_package`, `${STAGED_CODE_ROOT}` → `local_staged_code_root`)
   - API operations from `allowed_routes` + OpenAPI + codebase route map
   - role models (synthetic lab labels only when `local_only` and no roles file)
   - role-diff plans and business-logic candidates (all `execution_allowed=False`)
4. Bridge alias: `authorized_bug_bounty` + `authorized_web_api` for scheduler/report.

## Safety invariants

- offline package artifacts only
- no network access by planner
- no credential collection (password/token/api_key never stored; secret-looking labels redacted)
- no automatic report submission
- human approval required before any validation

## Console fields

- `web=` status (`authorized_web_api_plan_ready` / empty / missing)
- `wops=` operation count
- `wdiff=` role-diff plan count

## Smoke (retain / cal)

```text
$env:PYTHONPATH="apps/api"
.\.venv\Scripts\python.exe apps/api/scripts/run_ab_report_bridge.py --package-root authorized_packages/my-local-ssrf-retain --package-root authorized_packages/my-gh-cal-ssrf
```

Expect both packages: `web=authorized_web_api_plan_ready`, `wops>=2`, submission blocked.

## Tests

```text
$env:PYTHONPATH="apps/api"
.\.venv\Scripts\python.exe -m pytest apps/api/tests/test_authorized_web_api.py -q
```