# Local Fuzz Sandbox (approved plan/export under human gate)

Final-scheme residual gap after CRS harness export: prepare a **local-only** fuzz sandbox handoff recipe. Mythos still never spawns AFL++/libFuzzer, never opens network, and never promotes crashes.

## Hard safety

- Always `execution_mode=plan_only`
- Always `process_spawn_allowed=false`
- Always `network_access=false`
- Always `crash_promotion_allowed=false`
- Never unlocks `execution_allowed` / `validation_allowed` / `report_submission_allowed`
- Optional export requires explicit human flag and still never executes

## API

```python
from app.local_fuzz_sandbox import (
    build_local_fuzz_sandbox_plan,
    attach_local_fuzz_sandbox_to_bridge_result,
)

# From CRS payload (or package root; will rebuild CRS plan internally)
plan = build_local_fuzz_sandbox_plan(
    crs_fuzzing={"status": "crs_fuzzing_plan_ready", "harness_plans": [...]},
)
assert plan.execution_allowed is False
assert plan.process_spawn_allowed is False

# Optional local recipe export (write-only; human flag)
plan = build_local_fuzz_sandbox_plan(
    package_root="authorized_packages/my-local-ssrf-retain",
    human_allow_sandbox_write=True,
)
# When harness targets exist: status may be local_fuzz_sandbox_export_written
# Files land under {package}/_export/fuzz_sandbox/<nn-symbol>/
```

## Bridge

Automatically attached by `run_ab_report_bridge.py` **after** CRS attach.

Console fields: `fsb=` / `fsbe=` / `fsbc=`.

CLI human flag (default off):

```text
--allow-local-fuzz-sandbox-write
```

Writes recipes under `package/_export/fuzz_sandbox/` only. Never runs fuzzers.

## Optional sandbox export layout

When `human_allow_sandbox_write=True` and `package_root` is a valid directory with CRS harness plans:

```text
_export/fuzz_sandbox/<nn-symbol>/
  Dockerfile.sandbox
  sandbox_recipe.md
  README.md
  meta.json
  run_notes.md
```

Safety floor after write remains:

- `execution_allowed=false`
- `process_spawn_allowed=false`
- crash promotion blocked
- no process spawn / network

## Scheduler

- Task `T-003c` agent `local_fuzz_sandbox_agent` — plan/export sandbox recipes
- Batch `B-002e` — depends on `T-003` + `T-003b`
- Status `planned` when context includes CRS / sandbox artifacts
- `requires_human_review=True`, `execution_allowed=False`

## Multi-engine verifier

- Engine `local_fuzz_sandbox` (advisory only)
- Unsafe flags force `blocked` signal
- Never supports candidate confirmation

## Module / tests

- `apps/api/app/local_fuzz_sandbox`
- `apps/api/tests/test_local_fuzz_sandbox.py`

## Done in this slice

- Human-flagged local sandbox recipe export under `_export/fuzz_sandbox/`
- Bridge `--allow-local-fuzz-sandbox-write`, console `fsb=` / `fsbe=` / `fsbc=`
- Scheduler `T-003c` / `B-002e`
- Deeper multi-engine signal attachment

## Still not done (honest)

- Actual approved sandbox **execution** (AFL++/libFuzzer under human gate)
- Crash triage / minimization pipeline
- End-to-end human gates with live H1 when unblocked
