# Human Review Approvals (residual + patch)

Updated: 2026-07-12T20:18:11Z

Durable / offline human decisions for residual and patch review stages in the final-scheme factory.

## Hard safety (non-negotiable)

- Approvals **never** set:
  - `execution_allowed`
  - `validation_allowed`
  - `report_submission_allowed`
  - `confirmed_vulnerability`
  - `auto_pr_allowed` / `pr_opened`
  - `patch_ready`
- Missing / expired / denied / rejected_fp => fail-closed (no residual ready-context; no patch acceptance)
- Secrets in reason/payload are redacted
- Filenames containing secret/token/cookie/credential are skipped on package ingest
- No auto-submit, no auto-PR, no live validation

## Approval kinds

| Kind | Maps to gate context |
| --- | --- |
| `residual_review` | `human_approved` / `human_rejected` on residual gate only |
| `patch_review` | `human_patch_reviewed` / `patch_review_accepted|rejected` on suggestions only |

## Decisions

| Status | Residual effect | Patch effect |
| --- | --- | --- |
| requested / pending | no context clear | no review stamp |
| approved | residual context cleared | advisory accepted (still not patch_ready) |
| waived | residual context cleared | waived_no_patch |
| denied / rejected_fp / revoked | residual rejected | patch rejected |
| expired | inactive | inactive |

## Package offline ingest

Optional (missing is OK):

- `inputs/human_review_approvals.json`
- `inputs/approvals.json`
- `inputs/approvals/*.json`
- `_extract/HUMAN_REVIEW_APPROVALS.json`
- `HUMAN_REVIEW_APPROVALS.json`

Example:

```json
{
  "approvals": [
    {
      "approval_kind": "residual_review",
      "status": "approved",
      "candidate_id": "H-1",
      "actor": "reviewer",
      "reason": "residuals cleared with local static evidence"
    },
    {
      "approval_kind": "patch_review",
      "status": "approved",
      "candidate_id": "H-1",
      "actor": "reviewer",
      "reason": "advisory direction OK; no auto-PR"
    }
  ]
}
```

## API surface (module)

```python
from app.human_review_approvals import (
    build_human_review_approval,
    decide_human_review_approval,
    load_package_human_review_approvals,
    attach_human_review_approvals_to_bridge_result,
    persist_human_review_approval,
    residual_flags_from_approval,
    patch_context_from_approval,
)

rec = build_human_review_approval(
    approval_kind="residual_review",
    package_id="pkg",
    candidate_id="H-1",
    status="approved",
)
assert rec.report_submission_allowed is False
assert residual_flags_from_approval(rec)["human_approved"] is True
```

## Wiring

- `attach_human_residual_gates_to_bridge_result` consumes residual_review decisions
- `attach_patch_suggestions_to_bridge_result` stamps patch_review context
- `run_ab_report_bridge.py` attaches package offline approvals
- Optional DB persist via existing `ApprovalRecord` (`approval_type=residual_review|patch_review`, payload safety floor)

## Module

`apps/api/app/human_review_approvals`

## Tests

`apps/api/tests/test_human_review_approvals.py`

## Deepen — package counters + MEV + scheduler (2026-07-12T20:18:11Z)

Scaffold deepen for A+B factory residual/patch human review approvals:

| Surface | Detail |
| --- | --- |
| Bridge counters | `human_review_approvals_status/count/decided_count/residual_count/patch_count` + summary |
| Console | `hreview` / `hreviewn` / `hreviewd` / `hreviewr` / `hreviewp` (plus early present bool) |
| MEV engine | `human_review_approvals` (engine count **24** after attach when present) |
| Scheduler | **T-018** / **B-015** `human_review_approvals_agent` |
| Dual-lab fixture | `my-local-ssrf-retain/inputs/human_review_approvals.json` (teaching residual+patch approved; still not patch_ready) |

Safety floor unchanged: never `execution_allowed` / `validation_allowed` / `report_submission_allowed` / `confirmed_vulnerability` / `patch_ready` / `auto_pr_allowed`.

Unsafe unlock flags on approval payload force MEV engine status `blocked`.


