# Hunter A+B — Intake Agent (stack / entrypoint detection)

Updated: 2026-07-12T17:10:00Z

## Purpose

Final-scheme **V0 Intake Agent (5.2)** for authorized local packages:

- Detect languages, frameworks, package managers
- Detect entrypoints / route-ish symbols
- Detect auth-related components
- Produce an advisory project profile for attack-surface context

## Safety

| Flag | Value |
| --- | --- |
| network_access | false |
| execution_allowed | false |
| validation_allowed | false |
| report_submission_allowed | false |
| confirmed_vulnerability | false |
| finding_promotion_allowed | false |

- Scans only under `package_root` (`inputs/`, `_upstream/`, `_extract/`, top-level manifests)
- Optional in-memory `authorized_code_files`
- Skips filenames containing secret/token/cookie/credential/password/apikey
- Never clones remotes, never runs live scanners, never unlocks submit

## Module

- `apps/api/app/intake_agent/__init__.py`
- `build_intake_profile(...)`
- `load_package_intake_profile(package_root)`
- `attach_intake_profile_to_bridge_result(...)`

## Wired into

- `apps/api/scripts/run_ab_report_bridge.py`
- `industrial_scheduler` task `T-001b` (`intake_agent`) after `T-001` scope

## Output shape (summary)

```json
{
  "status": "intake_profile_ready",
  "language": ["TypeScript", "Python"],
  "framework": ["Express", "FastAPI"],
  "package_managers": ["npm"],
  "entrypoints": ["POST /api/..."],
  "auth_components": [".../auth.ts"],
  "dependency_manifests": ["package.json"],
  "attack_surface_summary": {"entrypoint_count": 2}
}
```

## Tests

`apps/api/tests/test_intake_agent.py` (+ industrial scheduler assertion for `T-001b`).