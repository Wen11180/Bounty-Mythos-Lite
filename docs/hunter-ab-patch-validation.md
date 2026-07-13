# Patch Validation (V3 non-destructive recheck planner)

## Purpose

Final-scheme V3 Patch Validation:

- Aggregate patch industrial loop / patch suggestions / crash regression (+ optional offline JSON)
- Emit **non-destructive** human recheck steps after fix artifacts
- Optional export under `package/_export/patch_validation/` with human flag
- **Never** applies patches, never auto-PR, never live-validates, never marks `patch_ready`

This slice advances the factory while live H1 e2e human gates remain blocked (`h1_api=blocked_401`).

## Safety floor

Always forced false / blocked:

- `execution_allowed`
- `validation_allowed`
- `live_validation_allowed`
- `report_submission_allowed`
- `confirmed_vulnerability`
- `finding_promotion_allowed`
- `patch_ready`
- `auto_pr_allowed`
- `network_access`
- `live_validation`

## Offline ingest paths

| Path | Role |
| --- | --- |
| `inputs/patch_validation.json` | Preferred recheck items/steps |
| `inputs/patch_validation/*.json` | Split items |

Bridge sources: `patch_industrial_loop`, `patch_suggestions`, `crash_regression`.

## Pipeline position

```text
patch industrial loop / PR plan / crash regression
  -> agent memory (T-010)
  -> continuous scan (T-011)
  -> patch validation (T-012)  [this module]
  -> final MEV re-deepen (includes patch_validation engine)
```

## Bridge

```text
python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg>
# default: pval=patch_validation_plan_ready or waiting_for_fix_artifacts

python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg> \
  --allow-patch-validation-export
# writes package/_export/patch_validation/<stamp>/ ; still never live-validates
```

Console fields: `pval`, `pvaln`, `pvalr`, `pvals`, `pvalx`.

## Multi-engine

Engine id: `patch_validation` (`ENGINE_PATCH_VALIDATION`).

`signal_from_patch_validation` is advisory recheck evidence only. Unsafe patch_ready / live_validation / auto_pr flags force blocked.

## Scheduler

- **T-012** `patch_validation_agent` depends on patch loop / PR / crash regression + agent memory
- **B-009** parallel batch: `["T-012"]`
- Never unlocks submit or execution

## Module API

- `run_patch_validation(...)` / `build_patch_validation(...)`
- `attach_patch_validation_to_bridge_result(...)`

## Tests

`apps/api/tests/test_patch_validation.py`

Verified: 2026-07-12T19:30:47Z
