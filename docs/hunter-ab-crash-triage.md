# Crash triage + minimization (human-gated)

## Purpose

V1 residual after local fuzz runner collects crash candidates:

- **Default:** plan-only classify + signature cluster (no minimize/repro)
- **Human flag:** `human_allow_crash_triage` / bridge `--allow-crash-triage`
- **Execute:** cluster by signature; re-run in-process harness; delta-debug minimize; mark `reproducible`; emit advisory `RootCauseNote`
- **Never:** promote crashes, spawn AFL++/libFuzzer, open network, submit reports, or mark confirmed vulnerability

## Safety floor

Always forced false / blocked:

- `execution_allowed` (except local in-process triage under human flag; never external spawn)
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
- minimization_local_in_process_only
- human_review_required_before_any_promotion

## Pipeline position

```text
CRS plan (T-003)
  -> optional harness export (T-003b)
  -> optional sandbox recipes (T-003c)
  -> optional in-process Python fuzz run (T-003d)
  -> optional crash triage + minimize (T-003e)  [this module]
  -> optional residual regression plan (T-003f)
  -> multi-engine deepen (includes crash_triage / crash_regression signals)
```

## Export layout

When triage executes and writes artifacts:

```text
{package}/_export/crash_triage/<stamp>/
  index.json
  <cluster_id>/
    triage.json
    README.md
    minimized seed preview (when applicable)
```

Each cluster states `promotion_allowed=false` and root-cause is advisory only.

## Bridge

```text
python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg>
# plan-only by default: ctr=... ctre=False (often no_crashes / ready plan)

python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg> --allow-crash-triage
# may minimize/repro when runner crashes exist; still never promotes/submits
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
    human_allow_crash_triage=True,  # still never promotes
)
assert result.confirmed_vulnerability is False
```

## Limits (intentional)

- Minimization is local in-process delta-debug only (not coverage-guided)
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
