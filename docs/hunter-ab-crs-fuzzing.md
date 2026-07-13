# CRS / Fuzzing Planner (V1 plan-only package ingest)

Final-scheme V1 CRS/Fuzz seed: detect parser/decoder/validator candidates and emit **non-executable** harness + fuzzer plans from authorized packages.

## Hard safety

- Always `execution_mode=plan_only`
- Never spawns fuzzers, never opens network, never scans public targets
- Crash promotion stays `blocked_until_reproducible_local_crash` with `promotion_allowed=false`
- Human approval required before any future local run
- Never unlocks report submission or confirmed vulnerability
- Optional harness file export requires explicit human flag and still never executes

## API

```python
from app.crs_fuzzing import (
    build_crs_fuzzing_plan,
    attach_crs_fuzzing_to_bridge_result,
    collect_authorized_code_files,
)

# From explicit authorized code files
plan = build_crs_fuzzing_plan([{"path": "src/p.py", "content": "def parse_x(b):\n    return b\n"}])
assert plan.execution_allowed is False

# From authorized package root (package ingest)
plan = build_crs_fuzzing_plan(package_root="authorized_packages/my-local-ssrf-retain")
assert plan.fuzzer_plan.status == "not_executed"

# Optional local harness sketch export (write-only; human flag)
plan = build_crs_fuzzing_plan(
    package_root="authorized_packages/my-local-ssrf-retain",
    human_allow_harness_write=True,
)
assert plan.execution_allowed is False
# When candidates exist: status may be crs_fuzzing_harness_export_written
# Files land under {package}/_export/crs_harness/<nn-symbol>/
```

## Bridge

Automatically attached by `run_ab_report_bridge.py`.

Console fields: `crs=` / `ccand=` / `hexport=` / `hexpc=`.

CLI human flag (default off):

```text
--allow-crs-harness-write
```

Writes sketches under `package/_export/crs_harness/` only. Never runs fuzzers.

## Optional harness export layout

When `human_allow_harness_write=True` and `package_root` is a valid directory with harness plans:

```text
_export/crs_harness/<nn-symbol>/
  harness_sketch.txt
  README.md
  meta.json
  seeds/README.md
```

Safety floor after write remains:

- `execution_allowed=false`
- fuzzer `not_executed`
- crash promotion blocked
- no process spawn / network

## Multi-language candidate detection

- Python `def`
- JS/TS `function` / `const x = (`
- Go `func`
- Java methods (heuristic)
- Rust `fn`

Markers: parse/decode/deserialize/load/read/validate/verify + protocol sinks (`json.loads`, `JSON.parse`, `struct.unpack`, …).

## Scheduler

- Task `T-003` agent `crs_fuzzing_agent` — plan harness/fuzzer work
- Task `T-003b` / batch `B-002d` — optional local harness sketch export (write-only)
- Status `planned` when context includes `crs_fuzzing` artifacts, else `skipped_no_crs_artifacts`
- `requires_human_review=True`, `execution_allowed=False`

## Module / tests

- `apps/api/app/crs_fuzzing`
- `apps/api/tests/test_crs_fuzzing.py`

## Done in this slice

- Optional approved harness sketch file write under `_export/crs_harness/` with human flag
- Bridge `--allow-crs-harness-write`, console `hexport=` / `hexpc=`
- Scheduler `T-003b` / `B-002d`
- Safety force after write; tests cover default-off, write-on, no-root skip, attach strip

## Not done yet

- Approved local fuzzer execution sandbox
- Crash minimization / sanitizer triage pipeline
- Live crash promotion under human evidence review

## Related

- Local sandbox recipes (next stage): docs/hunter-ab-local-fuzz-sandbox.md / T-003c
