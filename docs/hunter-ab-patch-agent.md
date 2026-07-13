# Patch Agent Industrial Loop (advisory)

Updated: 2026-07-12T17:08:46Z

Final-scheme **5.11 Patch Agent** industrial batch loop over advisory patch suggestions.

## Hard safety

- Always advisory (`patch_loop_completed_advisory` / partial / skipped_all_not_applicable)
- `patch_ready=false` always
- `auto_pr_allowed=false` / `pr_opened=false`
- `exploit_poc_included=false`
- Never applies diffs, opens PRs, runs live validation, or unlocks submit/promote
- Never sets `confirmed_vulnerability=true`
- Regression plans are human-only (`auto_execute=false`, `network_access=false`)

## Loop phases (advisory)

1. **suggest** — reuse `app.patch_suggestion` playbooks per candidate
2. **local_code_context** — static sniff under package root for control/sink tokens
3. **regression_plan** — non-executing local recheck steps
4. **patch_review_context** — optional `patch_review` human approval stamps (context only)
5. **stop_no_auto_pr** — safety floor re-asserted

## Status values

| Status | Meaning |
| --- | --- |
| `patch_loop_empty` | no candidates |
| `patch_loop_planned_advisory` | planned only |
| `patch_loop_completed_advisory` | advisory items with sketches |
| `patch_loop_partial_advisory` | mix of advisory + NA |
| `patch_loop_skipped_all_not_applicable` | FP/controls oppose all |

## API

```python
from app.patch_agent import (
    run_patch_industrial_loop,
    attach_patch_industrial_loop_to_bridge_result,
    build_minimal_diff_sketch,
    build_regression_validation_plan,
    sniff_local_code_context,
)

result = run_patch_industrial_loop(
    package_root="authorized_packages/my-local-ssrf-retain",
    drafts=[...],  # or candidates from hunter/report bridge
)
assert result.auto_pr_allowed is False
assert result.patch_ready is False
assert result.report_submission_allowed is False
```

## Wiring

- Bridge: `run_ab_report_bridge.py` calls `attach_patch_industrial_loop_to_bridge_result` after patch suggestions / semgrep
- Console: `ploop=` / `pitems=`
- Markdown: Patch industrial loop section per package
- Scheduler: `T-008b` agent `patch_industrial_loop` after `T-008`; batch `B-005b`

## Factory smoke (verified)

| package | ploop | pitems | auto_pr | patch_ready |
| --- | --- | --- | --- | --- |
| my-local-ssrf-retain | `patch_loop_completed_advisory` | 2 | false | false |
| my-gh-cal-ssrf | `patch_loop_skipped_all_not_applicable` | 2 | false | false |

## Module / tests

- `apps/api/app/patch_agent`
- `apps/api/tests/test_patch_agent.py`

## Not done yet

- Residual/patch decision HTTP thin wrap (next)
- Real human PR workflow outside Mythos (never auto)
- Live patch validity measurement against authorized targets
