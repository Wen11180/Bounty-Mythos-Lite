# Local fuzz runner (human-gated in-process)

## Purpose

V1 residual after CRS harness export + local fuzz sandbox plan/export:

- **Default:** plan-only (no in-process run)
- **Human flag:** `human_allow_local_fuzz_run` / bridge `--allow-local-fuzz-run`
- **Execution model:** in-process Python only (AST-extracted top-level functions; restricted builtins)
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

Crash artifacts (when any) land under:

```text
{package}/_export/fuzz_runs/<stamp>/<crash_id>/
  meta.json
  traceback.txt
  README.md
```

Each artifact states `promotion_allowed=false` and is local triage material only.

## Pipeline position

```text
CRS plan (T-003)
  -> optional harness export (T-003b)
  -> optional sandbox recipes (T-003c)
  -> optional in-process Python fuzz run (T-003d)  [this module]
  -> multi-engine deepen (includes local_fuzz_runner signal)
```

## Bridge

```text
python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg>
# plan-only by default: lfr=skipped_no_human_local_fuzz_flag lfre=False lfrc=0

python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg> --allow-local-fuzz-run
# in-process only; still never promotes/submits
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

- Python only for auto-run; other languages stay external-preview
- Seed corpus is small/synthetic; not coverage-guided mutation
- No AFL++/libFuzzer auto-spawn even with the human flag
- Crashes never enter hunter retain/promotion path automatically

## Related

- `docs/hunter-ab-crs-fuzzing.md`
- `docs/hunter-ab-local-fuzz-sandbox.md`
- `apps/api/app/local_fuzz_runner/__init__.py`
- `docs/hunter-ab-crash-triage.md`
