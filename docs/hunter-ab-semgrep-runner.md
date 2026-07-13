# Local Semgrep Runner (human-flagged CLI)

Final-scheme Static Analyzer seed: optional **local-only** Semgrep CLI invoke.

## Hard safety

- Default is **plan-only** (`skipped_no_human_local_flag`) — no subprocess
- Executes only when `human_allow_local_semgrep=True` or bridge `--allow-local-semgrep`
- Scans only paths under authorized `package_root`
- Never pulls remote rule packs (`p/` / `r/` configs rejected by construction)
- `--metrics off`, `--disable-version-check`
- Missing binary => `skipped_semgrep_not_installed` (use offline `inputs/advisory/*`)
- Never unlocks `execution_allowed` / `validation_allowed` / `report_submission_allowed`
- Never sets `confirmed_vulnerability=true` or `finding_promotion_allowed=true`
- Completed findings may merge into package advisory bundle as **advisory only**

## API

```python
from app.semgrep_runner import (
    run_local_semgrep,
    attach_semgrep_runner_to_bridge_result,
    build_semgrep_signal_from_runner,
)

# Plan only (default)
plan = run_local_semgrep(package_root="authorized_packages/my-local-ssrf-retain")
assert plan.status == "skipped_no_human_local_flag"
assert plan.command_executed is False

# Explicit human flag — still fails closed if binary missing
run = run_local_semgrep(
    package_root="authorized_packages/my-local-ssrf-retain",
    human_allow_local_semgrep=True,
)
# status: completed | skipped_semgrep_not_installed | failed
assert run.report_submission_allowed is False
```

## Bridge CLI

```text
python apps/api/scripts/run_ab_report_bridge.py \
  --package-root authorized_packages/my-local-ssrf-retain \
  --allow-local-semgrep
```

Without the flag, smoke shows `sgrep=skipped_no_human_local_flag sfind=0`.

## Config resolution (package-confined)

1. Explicit `--config` only if path stays under package_root
2. Else package files: `inputs/semgrep.yml`, `inputs/semgrep/rules.yml`, `semgrep.yml`, …
3. Else embedded offline mini-rulepack (tempfile; deleted after run)

## Scheduler

- Task `T-002b` agent `semgrep_runner` after intake/dependency (`T-001c`)
- Batch `B-002b`
- Dedup/risk (`T-005`/`T-006`) depend on `T-002b`
- Always `requires_human_review=True`, `execution_allowed=False`

## Module / tests

- `apps/api/app/semgrep_runner`
- `apps/api/tests/test_semgrep_runner.py`

## Not done yet

- Industrial rulepack management beyond embedded mini rules
- Auto language-aware rule selection from intake profile

## Related

- CodeQL CLI runner (symmetric): `docs/hunter-ab-codeql-runner.md` ? wired with `T-002c` / `--allow-local-codeql`
