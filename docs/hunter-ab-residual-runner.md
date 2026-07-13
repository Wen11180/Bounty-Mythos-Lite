# Hunter A+B — Human-approved Residual Runner

Updated: 2026-07-12T17:55:00Z

## Purpose

Automate the **local residual verification** slice from `docs/hunter-ab-residual-runbook.md`
behind durable `residual_review` human approvals.

- Plan residual probes from package residual checklist
- Execute **local static** control-token probes only when residual approval is active
- Optionally consume offline `inputs/residual_runs.json` fixtures
- Never network, never live exploit, never unlock submit

## Safety

| Flag | Value |
| --- | --- |
| human_approval_required | true |
| network_access | false |
| live_validation_executed | false |
| execution_allowed | false |
| validation_allowed | false |
| report_submission_allowed | false |
| confirmed_vulnerability | false |
| finding_promotion_allowed | false |

Without active residual approval → `skipped_no_human_approval` (plan only).  
Human rejected/FP → `skipped_human_rejected_or_fp`.  
Approved → local static probes may complete; still never live/submit.

## Module

- `apps/api/app/residual_runner/__init__.py`
- `build_residual_probe_plan(...)`
- `run_residual_probes(...)`
- `load_package_residual_runner(...)`
- `attach_residual_runner_to_bridge_result(...)`

## Wired into

- `apps/api/scripts/run_ab_report_bridge.py` (after dependency attach)
- `industrial_scheduler` task `T-007b` (`residual_runner`) after report draft `T-007`
- Patch agent `T-008` depends on `T-007b`

## Probe methods (v0)

| Method | When |
| --- | --- |
| local_static_code_search | approved residual run; scans package code for control/sink tokens |
| offline_residual_fixture | optional package JSON residual run fixtures |

Comment-only / markdown prose token hits are filtered to reduce teaching-doc false positives.

## Tests

`apps/api/tests/test_residual_runner.py`

## Explicit non-goals

- Live HTTP residual validation against public targets
- Automatic residual approval
- Finding promotion or report submission
- Semgrep CLI invoke (separate optional flag later)