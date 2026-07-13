# Factory smoke — Patch industrial loop slice

Updated: 2026-07-12T17:08:46Z

Bridge: `apps/api/scripts/run_ab_report_bridge.py`

```text
my-local-ssrf-webhook-retain-lab: retained=1 ... ploop=patch_loop_completed_advisory pitems=2
my-gh-cal-webhook-ssrf-lab: retained=0 ... ploop=patch_loop_skipped_all_not_applicable pitems=2
```

| package | retained | residual_gate | ploop | pitems | auto_pr | sgrep | rrun |
| --- | --- | --- | --- | --- | --- | --- | --- |
| my-local-ssrf-retain | 1 | ready_for_human_review | patch_loop_completed_advisory | 2 | false | skipped_no_human_local_flag | skipped_no_human_approval |
| my-gh-cal-ssrf | 0 | human_rejected_or_fp | patch_loop_skipped_all_not_applicable | 2 | false | skipped_no_human_local_flag | skipped_no_human_approval |

Safety: `submission_blocked=True`, `auto_pr_allowed=False`, `patch_ready=False` on all items.

Focused unit tests: **13 passed** (`test_patch_agent` + industrial + `test_patch_suggestion`).

See also: `docs/hunter-ab-patch-agent.md`, `docs/hunter-ab-status.md`.
