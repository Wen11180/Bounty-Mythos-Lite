# Multi-Hour Agent Loop (beyond V4 long-horizon)

Updated: 2026-07-12T20:04:12Z

## Purpose

Plan a **multi-session, multi-hour** research loop from residual stack signals
(knowledge_base, long_horizon, deep_research, human gates, etc.).

This is **not** a live autonomous runner. It never auto-ticks sessions, never
auto-executes phases, never exploits, never validates live, never promotes
findings, and never submits reports.

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

- Bridge: `multi_hour_agent_loop*` fields (`mhal` / `mhalp` / `mhals` / `mhalg` / `mhalx`)
- Optional export: `_export/multi_hour_agent_loop/<stamp>/{plan,sessions,summary}.json`
- MEV engine: `multi_hour_agent_loop` (engine count 22 after attach)
- Scheduler: **T-016** / **B-013**

## Bridge attach order

```text
... -> knowledge_base -> multi_hour_agent_loop -> final MEV re-deepen
```

## Dual-lab smoke (verified 2026-07-12T20:04:12Z)

| package | mhal | mhalp | mhals | mhalg | mhalx | mevenc | kbase | submission_blocked |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| my-local-ssrf-retain | multi_hour_agent_loop_plan_ready | 6 | 6 | 5 | False | 22 | knowledge_base_ready | True |
| my-gh-cal-ssrf | multi_hour_agent_loop_plan_ready | 6 | 6 | 5 | False | 22 | knowledge_base_ready | True |

## Tests

```text
$env:PYTHONPATH="apps/api"
.\venv\Scripts\python.exe -m pytest apps/api/tests/test_multi_hour_agent_loop.py -q
```

## Honest gap

- Plan depth only; campaign_orchestrator still owns DB ticks separately
- Wall-clock runner now exists as plan/tick-ledger only (see hunter-ab-wall-clock-multi-hour-runner.md); still no live auto-tick execution
- H1 e2e human gates remain blocked while H1 is 401
