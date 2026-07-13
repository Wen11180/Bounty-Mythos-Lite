# Crash code-path linking (advisory static)

## Purpose

Final-scheme residual after crash triage (5.11 root-cause + 8.2 fuzz workflow):

- Statically link **triaged crash clusters** to likely **code paths** (file / function / symbol / lines)
- Authorized package source read only
- Optional export under `package/_export/crash_codepath/` with human flag
- **Never** execute package code, promote crashes, spawn fuzzers, or submit reports
- **Never** sets `confirmed_vulnerability`

## Safety floor

Always forced false / blocked:

- `execution_allowed`
- `validation_allowed`
- `package_code_execution_allowed`
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
  -> residual regression plan (T-003f)
  -> advisory code-path linking (T-003g)  [this module]
  -> multi-engine deepen (includes crash_codepath signal)
```

## Bridge

```text
python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg>
# default: cpath=crash_codepath_no_clusters cpathn=0 cpathr=0 cpathx=False (when no triage clusters)

python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg> \
  --allow-crash-triage --allow-crash-codepath-export
# still never executes package code for linking; export only when clusters exist
```

Console fields: `cpath`, `cpathn`, `cpathr`, `cpathx`.

## Multi-engine

Engine id: `crash_codepath` (`ENGINE_CRASH_CODEPATH`).

`signal_from_crash_codepath` is advisory evidence only. Unsafe promote/execute flags force blocked.

## Scheduler

- **T-003g** `crash_codepath_agent` depends on `T-003`..`T-003e`
- Parallel batch **B-002i**
- **T-006b** depends on `T-003g`

## API sketch

```python
from app.crash_codepath import build_crash_codepath_plan, run_crash_codepath_link

plan = build_crash_codepath_plan(crash_triage={...}, package_root="authorized_packages/...")
assert plan.package_code_execution_allowed is False
assert plan.crash_promotion_allowed is False
assert plan.confirmed_vulnerability is False
```

## Related

- `docs/hunter-ab-crash-triage.md`
- `docs/hunter-ab-crash-regression.md`
- `apps/api/app/crash_codepath/__init__.py`
- `apps/api/tests/test_crash_codepath.py`