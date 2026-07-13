# Wall-Clock Multi-Hour Runner (beyond multi-hour plan)

Updated: 2026-07-12T20:10:42Z

## Purpose

Convert the **multi-hour agent loop** session/phase/gate plan into a true
**wall-clock schedule** plus a **human-gated tick ledger**.

This is **not** a live autonomous runner. It never auto-ticks sessions, never
auto-executes phases, never exploits, never validates live, never promotes
findings, and never submits reports.

Every tick in the ledger is dry-run only and requires offline human approval.

## Safety floor (always false)

- `execution_allowed`
- `validation_allowed`
- `report_submission_allowed`
- `confirmed_vulnerability`
- `finding_promotion_allowed`
- `ranking_permission_granted`
- `auto_tick_allowed`
- `auto_session_advance_allowed`
- `network_access`
- `live_validation`

## Outputs

- Bridge: `wall_clock_multi_hour_runner*` fields (`wclk` / `wclks` / `wclkt` / `wclkg` / `wclkx`)
- Optional export: `_export/wall_clock_multi_hour_runner/<stamp>/{plan,tick_ledger,summary}.json`
- MEV engine: `wall_clock_multi_hour_runner` (engine count **23** after attach)
- Scheduler: **T-017** / **B-014**

## Bridge attach order

```text
... -> multi_hour_agent_loop -> wall_clock_multi_hour_runner -> final MEV re-deepen
```

## Dual-lab smoke (verified 2026-07-12T20:10:42Z)

| package | wclk | wclks | wclkt | wclkg | wclkx | mhal | mevenc | submission_blocked |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| my-local-ssrf-retain | wall_clock_multi_hour_runner_plan_ready | 6 | 16 | 6 | False | multi_hour_agent_loop_plan_ready | 23 | True |
| my-gh-cal-ssrf | wall_clock_multi_hour_runner_plan_ready | 6 | 16 | 6 | False | multi_hour_agent_loop_plan_ready | 23 | True |

## Tests

```text
$env:PYTHONPATH="apps/api"
.\venv\Scripts\python.exe -m pytest apps/api/tests/test_wall_clock_multi_hour_runner.py -q
```

## Honest gap

- Wall-clock **plan/tick-ledger** only; still no live autonomous multi-hour execution
- Ticks never advance without offline human approval
- H1 e2e human gates remain blocked while H1 is 401
