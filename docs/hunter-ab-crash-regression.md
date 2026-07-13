# Crash residual regression (plan-only)

## Purpose

Final-scheme residual after crash triage (5.11 Patch/Regression + 8.2 Fuzz workflow):

- Map **triaged crash clusters** to non-executing **regression test suggestions**
- Prefer minimized / reproducible seeds as fixture guidance (text only)
- Optionally enrich from advisory **crash_codepath** links (static only; never confirmed)
- Optional export under `package/_export/crash_regression/` with human flag
- **Never** auto-run tests, promote crashes, spawn fuzzers, or submit reports

## Safety floor

Always forced false / blocked:

- `execution_allowed`
- `validation_allowed`
- `test_auto_execute_allowed`
- `report_submission_allowed`
- `finding_promotion_allowed`
- `crash_promotion_allowed`
- `process_spawn_allowed`
- `network_access`
- `confirmed_vulnerability`

## Pipeline position

```text
CRS plan (T-003)
  -> harness export (T-003b)
  -> sandbox recipes (T-003c)
  -> in-process fuzz run (T-003d)
  -> crash triage + minimize (T-003e)
  -> advisory code-path linking (T-003g)
  -> residual regression plan (T-003f)  [this module; may consume codepath]
  -> multi-engine deepen (includes crash_regression + crash_codepath signals)
```

## Bridge

```text
python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg>
# default: creg=crash_regression_no_clusters (when no triage clusters) cregn=0 cregx=False

python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg> \
  --allow-crash-triage --allow-crash-regression-export
# still never auto-runs tests; export only when clusters exist
```

Console fields: `creg`, `cregn`, `cregx`, `cregc` (codepath-linked suggestion count).

## Multi-engine

Engine id: `crash_regression` (`ENGINE_CRASH_REGRESSION`).

`signal_from_crash_regression` is advisory evidence only. Unsafe auto-execute/promote flags force blocked.

## Scheduler

- **T-003f** `crash_regression_agent` depends on `T-003`..`T-003e`
- Parallel batch **B-002h**
- **T-006b** depends on `T-003f`

## API sketch

```python
from app.crash_regression import build_crash_regression_plan, run_crash_regression_plan

plan = build_crash_regression_plan(crash_triage={...})
assert plan.test_auto_execute_allowed is False
assert plan.crash_promotion_allowed is False
```

## Related

- `docs/hunter-ab-crash-triage.md`
- `docs/hunter-ab-local-fuzz-runner.md`
- `apps/api/app/crash_regression/__init__.py`
- `apps/api/tests/test_crash_regression.py`

## Codepath-aware enrichment

When bridge attaches `crash_codepath` before regression, suggestions may include:

- `codepath_linked` / `codepath_primary` / raise&call sites
- Extra plan step `*-03b` to anchor assertions near the advisory static path
- Notes: `enriched_from_advisory_crash_codepath` (still never confirmed / never auto-run)

Updated: 2026-07-12T19:02:07Z
