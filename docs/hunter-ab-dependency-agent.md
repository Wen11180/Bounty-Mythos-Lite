# Hunter A+B — Dependency Agent / SBOM (local advisory)

Updated: 2026-07-12T17:45:00Z

## Purpose

Final-scheme **V0 Dependency Agent (5.5)** for authorized local packages:

- Read dependency manifests from authorized artifacts
- Build a lightweight SBOM component list
- Heuristic reachability from local imports (not live OSV)
- Optional offline advisory flags only (never network CVE lookup)

## Safety

| Flag | Value |
| --- | --- |
| network_access | false |
| live_advisory_lookup | false |
| execution_allowed | false |
| validation_allowed | false |
| report_submission_allowed | false |
| confirmed_vulnerability | false |
| finding_promotion_allowed | false |

- Scans only under `package_root` (`inputs/`, `_upstream/`, `_extract/`, top-level manifests)
- Optional in-memory `authorized_code_files`
- Offline fixtures: `inputs/dependencies.json`, `inputs/sbom.json`, etc.
- Skips filenames containing secret/token/cookie/credential/password/apikey
- Never installs packages, never queries OSV/NVD, never unlocks submit

## Module

- `apps/api/app/dependency_agent/__init__.py`
- `build_dependency_profile(...)`
- `load_package_dependency_profile(package_root)`
- `attach_dependency_profile_to_bridge_result(...)`

## Wired into

- `apps/api/scripts/run_ab_report_bridge.py` (after intake attach)
- `industrial_scheduler` task `T-001c` (`dependency_agent`) after `T-001b` intake
- Downstream `T-002` / `T-003` / `T-004` depend on `T-001c`

## Supported manifests (local parse)

| Ecosystem | Files |
| --- | --- |
| npm | package.json, package-lock.json (top-level) |
| pypi | requirements.txt, pyproject.toml |
| go | go.mod |
| cargo | Cargo.toml |
| composer | composer.json |
| rubygems | Gemfile |

Import reachability heuristics: JS/TS, Python (with aliases e.g. `yaml`→`pyyaml`), Go, Ruby, PHP.

## Output shape (summary)

```json
{
  "status": "dependency_profile_ready",
  "ecosystems": ["npm"],
  "component_count": 1,
  "reachable_count": 1,
  "advisory_flagged_count": 0,
  "live_advisory_lookup": false,
  "components": [
    {
      "package": "express",
      "version": "unknown",
      "ecosystem": "npm",
      "reachable": "yes",
      "known_advisory": false
    }
  ]
}
```

## Factory smoke (this slice)

| package | retained | deps | ecosystems | intake |
| --- | --- | --- | --- | --- |
| my-local-ssrf-retain | 1 | 1 (express reachable) | npm | True |
| my-gh-cal-ssrf | 0 | 8 | npm | True |

## Tests

`apps/api/tests/test_dependency_agent.py` (+ industrial/intake scheduler assertions for `T-001c`).

## Explicit non-goals

- Live CVE / OSV / GitHub Advisory network queries
- Package install / lockfile registry resolution
- Auto-promotion of dependency advisories to confirmed findings
- Auto-submit or auto-PR