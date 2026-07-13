# Long Horizon Agent (V4 plan-only)

Updated: 2026-07-12T19:47:37Z

## Purpose

Industrialize the final-scheme **V4 Long-Horizon Agent** as a **failure-triggered path-switch / reflection planner**.

This is **not** a live multi-hour autonomous loop. It never auto-executes alternate paths, never exploits, never validates live, never promotes findings, and never submits reports.

## Safety floor (always false)

- `execution_allowed`
- `validation_allowed`
- `report_submission_allowed`
- `confirmed_vulnerability`
- `finding_promotion_allowed`
- `ranking_permission_granted`
- `auto_path_switch_allowed`
- `network_access`
- `live_validation`

## Inputs

1. Bridge residual stack (preferred):
   - `deep_research` chains / variants / unresolved refutations / long_horizon_plan fallbacks
   - residual gates, agent memory FP pressure, CRS parser candidates, drafts
2. Optional offline package artifacts:
   - `inputs/long_horizon.json`
   - `inputs/long_horizon/plan.json`
   - `inputs/v4_long_horizon.json`
   - `inputs/long_horizon/*.json`

## Outputs

- Bridge fields: `long_horizon`, `long_horizon_status`, `long_horizon_path_count`, `long_horizon_switch_count`, `long_horizon_iteration_count`, `long_horizon_reflection_count`, `long_horizon_export_written`, `long_horizon_auto_path_switch_allowed=false`
- Optional export (human flag only): `_export/long_horizon/<stamp>/plan.json` + `summary.json`
- MEV engine: `long_horizon` (`ENGINE_LONG_HORIZON`)
- Scheduler: **T-014** / **B-011** (`long_horizon_agent`)

## Bridge attach order (residual tail)

```text
human_gate -> agent_memory -> continuous_scan -> patch_validation
-> deep_research -> long_horizon -> final MEV re-deepen
```

## CLI

```text
python apps/api/scripts/run_ab_report_bridge.py \
  --package-root authorized_packages/<authorized-lab> \
  [--allow-long-horizon-export]
```

`--allow-long-horizon-export` writes package export only. It never enables auto path switch or execution.

## Dual-lab smoke (expected)

| Field | Expected |
| --- | --- |
| `lhor` | `long_horizon_plan_ready` |
| `lhorp` | >= 1 |
| `lhors` | >= 1 |
| `lhori` | >= 1 |
| `lhorx` | False without export flag |
| `mevenc` | 20 (includes long_horizon engine) |
| `dres/cscan/pval/amem/hg` | still green |
| `submission_blocked` | True |

## Tests

```text
$env:PYTHONPATH="apps/api"
.\venv\Scripts\python.exe -m pytest apps/api/tests/test_long_horizon.py -q
```

Covers: path/switch plan from deep research signals, offline inputs, human-flag export only, safety floor, MEV unsafe block on `auto_path_switch_allowed`, scheduler T-014/B-011.

## Honest gap after this module

- Still plan depth, not a true multi-hour agent loop with live protocol fuzz execution
- Path switches are a catalog for human review, not autonomous execution
- Live H1 e2e human gates remain blocked by H1 API 401
