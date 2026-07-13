# Residual / Patch Decision API (thin wrap)

Updated: 2026-07-12T17:12:59Z

HTTP thin wrap over durable residual_review + patch_review human decisions.

## Hard safety

- Never sets `execution_allowed` / `validation_allowed` / `report_submission_allowed`
- Never sets `confirmed_vulnerability` / `finding_promotion_allowed`
- Never sets `patch_ready` / `auto_pr_allowed` / `pr_opened`
- Secrets in reason fields are redacted by human_review_approvals
- Unknown kinds rejected (only residual_review / patch_review)

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/mythos/factory/residual-patch-decisions` | Create residual/patch decision request |
| GET | `/mythos/factory/residual-patch-decisions` | List (filter package/candidate/kind/run) |
| GET | `/mythos/factory/residual-patch-decisions/{approval_id}` | Get one |
| POST | `/mythos/factory/residual-patch-decisions/{approval_id}/decisions` | Apply human decision |

## Create body

```json
{
  "approval_kind": "residual_review",
  "package_id": "my-local-ssrf-retain",
  "candidate_id": "H-001",
  "actor": "reviewer",
  "reason": "Need residual review",
  "persist": true
}
```

Kinds: `residual_review` | `patch_review` (aliases: residual / patch).

## Decision body

```json
{
  "decision": "approved",
  "actor": "lead_reviewer",
  "reason": "Local static residuals cleared"
}
```

Allowed decisions: approved, denied, rejected_fp, waived, expired, revoked.

Effects (context only):

| Kind | approved | rejected_fp/denied | waived |
| --- | --- | --- | --- |
| residual_review | residual flags cleared for runner gating | human_rejected | residual cleared |
| patch_review | advisory accepted (still not patch_ready) | patch rejected | waived_no_patch |

## Module

- `apps/api/app/residual_patch_decision_api`
- Wired in `apps/api/app/main.py`
- Persistence: `persist_human_review_approval` → `ApprovalRecord` (`approval_type=residual_review|patch_review`)

## Tests

`apps/api/tests/test_residual_patch_decision_api.py` (6 passed)

## Explicit non-goals

- Live validation unlock
- Report submission unlock
- Auto PR / patch apply
- Treating model/scanner output as confirmed vulnerability


## Offline snapshot / export / import (human-gated)

Updated: 2026-07-12T20:24:37Z

Bridge-attached offline residual/patch decision snapshot for authorized packages.

### Module helpers

| Helper | Purpose |
| --- | --- |
| `build_residual_patch_decision_snapshot` | Build snapshot from package `inputs/human_review_approvals.json` or bridge HRA |
| `export_residual_patch_decision_snapshot` | Write `_export/residual_patch_decision_api/<stamp>/{snapshot,decisions,summary}.json` only when `human_allow_export_write=True` |
| `import_residual_patch_decisions_to_package` | Write `inputs/human_review_approvals.json` only when `human_allow_import_write=True` |
| `attach_residual_patch_decision_api_to_bridge_result` | Attach counters + optional export; never unlocks gates |

### Bridge CLI

```text
--allow-residual-patch-decision-api-export
```

Console counters: `rpda` / `rpdan` / `rpdad` / `rpdar` / `rpdap` / `rpdax`

### Multi-engine

Engine id: `residual_patch_decision_api` (advisory context only).

### Scheduler

Covered under T-018 / B-015 evidence_refs (`human_review_approvals`, `residual_patch_decision_api`).

### Safety floor

Always false: execution / validation / report_submission / confirmed_vulnerability / finding_promotion / auto_pr / patch_ready / pr_opened / ranking_permission / auto_tick / network / live_validation.

