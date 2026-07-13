# Continuous Scan (V3 advisory cadence planner)

## Purpose

Final-scheme V3 Continuous Scan:

- Build **plan-only** re-audit cadence for authorized packages
- Emit job list + watch paths for human / approved CI operators
- Optional offline config under package `inputs/`
- Optional export under `package/_export/continuous_scan/` with human flag
- **Never** auto-scans, never network/public targets, never execute/submit

This slice advances the factory while live H1 e2e human gates remain blocked (`h1_api=blocked_401`).

## Safety floor

Always forced false / blocked:

- `execution_allowed`
- `validation_allowed`
- `report_submission_allowed`
- `confirmed_vulnerability`
- `finding_promotion_allowed`
- `auto_scan_allowed`
- `network_access`
- `live_validation`

Cadence labels that imply auto/interval execution are collapsed to `manual_or_approved_ci_only`.

## Offline ingest paths

| Path | Role |
| --- | --- |
| `inputs/continuous_scan.json` | Preferred jobs/watch plan |
| `inputs/scan_cadence.json` | Cadence override (sanitized) |
| `inputs/continuous_scan/plan.json` | Split plan file |

## Pipeline position

```text
agent memory (T-010)
  -> continuous scan (T-011)  [this module]
  -> patch validation (T-012)
  -> final MEV re-deepen (includes continuous_scan engine)
```

## Bridge

```text
python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg>
# default: cscan=continuous_scan_plan_ready with cscann/cscanw/cscanx

python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg> \
  --allow-continuous-scan-export
# writes package/_export/continuous_scan/<stamp>/ ; still never auto-scans
```

Console fields: `cscan`, `cscann`, `cscanw`, `cscanx`.

## Multi-engine

Engine id: `continuous_scan` (`ENGINE_CONTINUOUS_SCAN`).

`signal_from_continuous_scan` is advisory plan evidence only. Unsafe auto-scan / network / execute flags force blocked.

## Scheduler

- **T-011** `continuous_scan_agent` depends on intake/scope + agent memory
- **B-008** parallel batch: `["T-011"]`
- Never unlocks submit or execution

## Module API

- `run_continuous_scan(...)` / `build_continuous_scan(...)`
- `attach_continuous_scan_to_bridge_result(...)`

## Tests

`apps/api/tests/test_continuous_scan.py`

Verified: 2026-07-12T19:30:47Z
