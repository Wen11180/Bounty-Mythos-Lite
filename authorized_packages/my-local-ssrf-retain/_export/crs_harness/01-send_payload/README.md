# CRS harness export — send_payload

- package_id: `my-local-ssrf-webhook-retain-lab`
- source_path: `inputs/code.ts`
- harness_kind: `local_unit_harness`
- export_dir: `_export/crs_harness/01-send_payload`
- status: exported sketch only (not executed)

## Safety

- execution_allowed=false
- no process spawn by Mythos
- no network
- no crash promotion / report submission
- human must approve any future local sandbox run outside this planner

## Contents

- `harness_sketch.txt` — advisory sketch only
- `meta.json` — non-secret metadata
- `seeds/README.md` — seed corpus placeholder

Do not treat this export as a confirmed vulnerability or runnable exploit.
