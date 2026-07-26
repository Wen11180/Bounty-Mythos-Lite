# Local fuzz target planner

## Purpose

V1 residual after CRS harness export + local fuzz sandbox plan/export:

- **Always:** plan-only target discovery
- **Compatibility flag:** `human_allow_local_fuzz_run` / bridge `--allow-local-fuzz-run` records operator intent but cannot enable execution
- **Execution model:** target code is never loaded into the API process; an independently isolated runner is required
- **Never:** spawn AFL++ / libFuzzer / external fuzzer processes
- **Never:** promote crashes, unlock validation, or submit reports

## Safety floor

Always forced false / blocked:

- `execution_allowed`
- `validation_allowed`
- `report_submission_allowed`
- `finding_promotion_allowed`
- `crash_promotion_allowed`
- `process_spawn_allowed`
- `external_fuzzer_spawn_allowed`
- `network_access`

No crash artifacts are produced by this module because it does not execute target code.

## Pipeline position

```text
CRS plan (T-003)
  -> optional harness export (T-003b)
  -> optional sandbox recipes (T-003c)
  -> plan-only fuzz target discovery (T-003d)  [this module]
  -> multi-engine deepen (includes local_fuzz_runner signal)
```

## Bridge

```text
python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg>
# plan-only by default: lfr=skipped_no_human_local_fuzz_flag lfre=False lfrc=0

python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg> --allow-local-fuzz-run
# compatibility flag only; still plan-only and never loads target code
```

Console fields: `lfr`, `lfre`, `lfrc`.

## Multi-engine

Engine id: `local_fuzz_runner`.

Unsafe promotion/spawn flags force a blocked signal. Crash counts are advisory evidence refs only — never confirmed vulnerability.

## Scheduler

- **T-003d** `local_fuzz_runner_agent` depends on `T-003`, `T-003b`, `T-003c`
- Parallel batch **B-002f**
- **T-006b** depends on `T-003d`

## Limits (intentional)

- Target discovery is advisory and does not prove harness viability
- No in-process Python, AFL++, or libFuzzer execution even with the compatibility flag
- A future runner must provide OS/process isolation, bounded resources, and blocked network/filesystem access
- Crashes never enter hunter retain/promotion path automatically

## Related

- `docs/hunter-ab-crs-fuzzing.md`
- `docs/hunter-ab-local-fuzz-sandbox.md`
- `apps/api/app/local_fuzz_runner/__init__.py`
- `docs/hunter-ab-crash-triage.md`
