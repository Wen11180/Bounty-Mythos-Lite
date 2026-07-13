# Local CodeQL Runner (human-flagged CLI)

Final-scheme Static Analyzer seed: optional **local-only** CodeQL CLI invoke.

## Hard safety

- Default is **plan-only** (`skipped_no_human_local_flag`) ? no subprocess
- Executes only when `human_allow_local_codeql=True` or bridge `--allow-local-codeql`
- Operates only under authorized `package_root`
- Requires **pre-built local CodeQL database** + **local query suite** under package
- Never downloads remote query packs or language packs (`codeql/javascript-queries` style refs rejected)
- Missing binary / DB / suite => fail-closed skip (use offline `inputs/advisory/*`)
- Never unlocks `execution_allowed` / `validation_allowed` / `report_submission_allowed`
- Never sets `confirmed_vulnerability=true` or `finding_promotion_allowed=true`
- Completed findings may merge into package advisory bundle as **advisory only**

## API

```python
from app.codeql_runner import (
    run_local_codeql,
    attach_codeql_runner_to_bridge_result,
    build_codeql_signal_from_runner,
)

# Plan only (default)
plan = run_local_codeql(package_root="authorized_packages/my-local-ssrf-retain")
assert plan.status == "skipped_no_human_local_flag"
assert plan.command_executed is False

# Explicit human flag ? still fails closed if binary/DB/suite missing
run = run_local_codeql(
    package_root="authorized_packages/my-local-ssrf-retain",
    human_allow_local_codeql=True,
)
# status: completed | skipped_codeql_not_installed | skipped_no_local_database |
#         skipped_no_local_query_suite | failed
assert run.report_submission_allowed is False
```

## Bridge CLI

```text
python apps/api/scripts/run_ab_report_bridge.py \
  --package-root authorized_packages/my-local-ssrf-retain \
  --allow-local-codeql
```

Without the flag, smoke shows `cq=skipped_no_human_local_flag cfind=0`.

## Artifact resolution (package-confined)

Database candidates (examples):

- `inputs/codeql/database`
- `inputs/codeql-db`
- `inputs/codeql_database`
- explicit path only if under package_root

Query suite candidates (examples):

- `inputs/codeql/suite.qls`
- `inputs/codeql/queries.qls`
- `inputs/codeql/qlpack.yml`
- `inputs/codeql/query.ql`
- remote pack names rejected

Unlike Semgrep embedded mini-rules, CodeQL does **not** auto-create databases or download packs.

Offline advisory fixtures (`inputs/advisory/codeql.json`) remain a separate teaching path.

## Scheduler

- Task `T-002c` agent `codeql_runner` after intake/dependency (`T-001c`)
- Batch `B-002c`
- Dedup/risk (`T-005`/`T-006`) depend on `T-002b` **and** `T-002c`
- Always `requires_human_review=True`, `execution_allowed=False`

## Module / tests

- `apps/api/app/codeql_runner`
- `apps/api/tests/test_codeql_runner.py`

## Not done yet

- Industrial CodeQL DB build orchestration (still human/offline pre-built only)
- Auto language-aware suite selection from intake profile
- Real patch PR workflow outside this system
