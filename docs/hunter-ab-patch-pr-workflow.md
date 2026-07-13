# External Patch PR Workflow (plan/export only)

Final-scheme §5.11 handoff: export an **external human PR package** from advisory patch artifacts.

Mythos never opens PRs, never runs git/gh, never marks `patch_ready=true`.

## Hard safety

- Always `execution_mode=plan_only_external_human_pr`
- `auto_pr_allowed=false`, `pr_opened=false`, `patch_ready=false`
- No git apply/push, no `gh` CLI, no network, no exploit PoC, no report submit
- Optional local export write only under package `_export/patch_pr/<item_id>/` when human sets `--allow-patch-pr-export-write`
- Bridge payload keeps file **previews only** (full content stripped)

## Statuses

| status | meaning |
| --- | --- |
| `patch_pr_export_empty` | no advisory patch sources |
| `patch_pr_export_package_missing` | package_root missing |
| `patch_pr_export_blocked_until_patch_review` | items planned, but no accepted `patch_review` and no export-write flag |
| `patch_pr_export_ready` | accepted review (or write flag) — still plan-only |
| `patch_pr_export_written_local` | local export files written under package root |

## API

```python
from app.patch_pr_workflow import (
    build_patch_pr_workflow,
    attach_patch_pr_workflow_to_bridge_result,
)

result = build_patch_pr_workflow(
    package_root="authorized_packages/my-local-ssrf-retain",
    patch_industrial_loop=loop_dict,
    human_approvals=approvals,  # optional patch_review approved/waived
    human_allow_export_write=False,  # default off
)
assert result.auto_pr_allowed is False
assert result.pr_opened is False
assert result.patch_ready is False
```

Sources (priority):

1. `patch_industrial_loop.items` (skip not_applicable / skipped)
2. fallback `patch_suggestions`

Planned export files per item:

- `README.md` — operator steps
- `PR_BODY.md` — manual PR description
- `CHECKLIST.md` — human regression/safety checklist
- `minimal_diff_sketch.txt` — advisory sketch only
- `meta.json` — metadata; always forces auto_pr/pr_opened/patch_ready false

## Bridge

Attached by `run_ab_report_bridge.py` after patch industrial loop.

CLI:

```bash
python apps/api/scripts/run_ab_report_bridge.py \
  --package-root authorized_packages/my-local-ssrf-retain \
  --allow-patch-pr-export-write   # optional local write only
```

Console fields: `ppr=` / `ppready=` / `pprexport=`.

## Scheduler

- Task `T-008c` agent `patch_pr_workflow`
- Batch `B-005c` after `B-005b` / depends on `T-008b`
- Status `planned` when context has `patch_pr_workflow` / `patch_industrial_loop` / `patch_suggestions`
- else `skipped_no_patch_pr_artifacts`
- Always `execution_allowed=false`, `requires_human_review=true`

## Human steps (outside Mythos)

1. Review advisory root-cause + sketch
2. Confirm residual/patch human review disposition
3. Copy export files (if written) or use plan previews
4. Create branch manually (example in `branch_name`)
5. Re-implement fix in authorized checkout
6. Run local tests under your process
7. Open PR yourself with your own credentials
8. Keep report submission blocked until a separate human report gate

## Smoke (retain/cal)

| package | ppr status | ready | export |
| --- | --- | --- | --- |
| my-local-ssrf-retain | blocked_until_patch_review (no approval/write) | 0 | false |
| my-gh-cal-ssrf | empty (loop all not_applicable) | 0 | false |
