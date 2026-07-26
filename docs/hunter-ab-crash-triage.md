# Crash metadata triage (plan-only)

## Purpose

V1 residual after local fuzz runner collects crash candidates:

- **Always:** classify + signature cluster without loading target code
- **Compatibility flag:** `human_allow_crash_triage` / bridge `--allow-crash-triage` records operator intent but cannot enable execution
- **Output:** advisory `RootCauseNote`; reproduction and minimization require a separately isolated runner
- **Never:** promote crashes, spawn AFL++/libFuzzer, open network, submit reports, or mark confirmed vulnerability

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
- `confirmed_vulnerability`

Invariants (`SAFETY_INVARIANTS`):

- local_or_authorized_package_only
- no_public_target_scanning
- no_external_fuzzer_process_spawn
- no_network_access
- no_crash_promotion
- no_report_submission
- advisory_root_cause_only
- no_in_process_target_execution
- isolated_runner_required_for_reproduction
- human_review_required_before_any_promotion

## Pipeline position

```text
CRS plan (T-003)
  -> optional harness export (T-003b)
  -> optional sandbox recipes (T-003c)
  -> plan-only fuzz target discovery (T-003d)
  -> plan-only crash metadata triage (T-003e)  [this module]
  -> optional residual regression plan (T-003f)
  -> multi-engine deepen (includes crash_triage / crash_regression signals)
```

This module writes no reproduction or minimized-seed artifacts because it does not execute target code.

## Bridge

```text
python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg>
# plan-only by default: ctr=... ctre=False (often no_crashes / ready plan)

python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg> --allow-crash-triage
# compatibility flag only; remains plan-only
```

Console fields: `ctr`, `ctre`, `ctrc`, `ctrep`.

Markdown bridge section includes: status, input_crashes, clusters, reproducible, minimized, executed, export_written.

## Multi-engine

Engine id: `crash_triage` (`ENGINE_CRASH_TRIAGE`).

`signal_from_crash_triage` contributes advisory evidence refs only. Unsafe promotion/spawn flags force a blocked signal. Never confirmed vulnerability.

## Scheduler

- **T-003e** `crash_triage_agent` depends on `T-003`, `T-003b`, `T-003c`, `T-003d`
- Parallel batch **B-002g**
- **T-006b** depends on `T-003e`

## API sketch

```python
from app.crash_triage import build_crash_triage_plan, run_crash_triage, attach_crash_triage_to_bridge_result

plan = build_crash_triage_plan(package_root="authorized_packages/my-local-ssrf-retain")
assert plan.crash_promotion_allowed is False

result = run_crash_triage(
    package_root="authorized_packages/my-local-ssrf-retain",
    human_allow_crash_triage=True,  # records intent; still never executes
)
assert result.confirmed_vulnerability is False
assert result.triage_executed is False
```

## Limits (intentional)

- Reproduction and minimization are unavailable until an isolated runner exists
- Root-cause notes are advisory hypotheses for human review
- No auto-promotion into hunter retain path
- No external fuzzer spawn even with the human flag
- Empty/no-crash packages stay plan-only / no_crashes

## Related

- `docs/hunter-ab-local-fuzz-runner.md`
- `docs/hunter-ab-local-fuzz-sandbox.md`
- `docs/hunter-ab-crs-fuzzing.md`
- `apps/api/app/crash_triage/__init__.py`
- `apps/api/tests/test_crash_triage.py`
- `docs/hunter-ab-crash-regression.md`
