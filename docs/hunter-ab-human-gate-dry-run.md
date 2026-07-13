# Human Gate dry-run (offline e2e proof)

## Purpose

Final-scheme Human Gate proof without a live HackerOne token (scheme 8.3 / V2 Human Gate):

- Walk residual gate -> approvals -> report draft -> patch/PR -> crash stack -> multi-engine
- Prove every stage remains submission-blocked and non-executing
- Optional export under `package/_export/human_gate_dry_run/` with human flag
- **Never** probes HackerOne, live-validates, auto-submits, or promotes findings

This is the offline substitute for end-to-end human gates while `h1_api` remains `blocked_401`.

## Safety floor

Always forced false / blocked:

- `execution_allowed`
- `validation_allowed`
- `report_submission_allowed`
- `confirmed_vulnerability`
- `finding_promotion_allowed`
- `crash_promotion_allowed`
- `live_validation`
- `network_access`
- `auto_pr_allowed` / `pr_opened` / `patch_ready`

Dry-run **fails** if any unsafe true flag appears in bridge payloads.

## Checkpoints

| ID | Title |
| --- | --- |
| HG-01 | Authorized package identity present |
| HG-02 | Package-level submission remains blocked |
| HG-03 | Human residual gate present and non-submitting |
| HG-04 | Report drafts stay submission-blocked |
| HG-05 | Multi-engine never confirms vulnerability |
| HG-06 | Human review approvals remain context-only (optional skip) |
| HG-07 | Patch / PR workflow blocked (optional skip) |
| HG-08 | Crash stack non-promote (optional skip) |
| HG-09 | Global safety scrub |
| HG-10 | Human next action present |

Core chain complete requires HG-01..05 + HG-09 pass and zero fails.

## Pipeline position

```text
report draft (T-007)
  -> residual runner (T-007b)
  -> patch + PR export (T-008..T-008c)
  -> multi-engine deepen (T-006b)
  -> offline human-gate dry-run (T-009)  [this module]
```

## Bridge

```text
python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg>
# default: hg=human_gate_dry_run_ready (or safety_failure) with hgpass/hgfail/hgok/hgsafe/hgx

python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg> \
  --allow-human-gate-dry-run-export
# writes package/_export/human_gate_dry_run/<stamp>/ ; still never H1 probe/submit
```

Console fields: `hg`, `hgpass`, `hgfail`, `hgok`, `hgsafe`, `hgx`.

## Multi-engine

Engine id: `human_gate_dry_run` (`ENGINE_HUMAN_GATE_DRY_RUN`).

`signal_from_human_gate_dry_run` is advisory evidence only. Unsafe submit/execute/promote flags force blocked.

Bridge order: first MEV deepen -> dry-run attach -> re-deepen so MEV can include dry-run posture.

## Scheduler

- **T-009** `human_gate_dry_run_agent` depends on report/residual/patch/MEV/crash stages
- Parallel batch **B-006**
- Never unlocks submit

## API sketch

```python
from app.human_gate_dry_run import run_human_gate_dry_run, attach_human_gate_dry_run_to_bridge_result

result = run_human_gate_dry_run(bridge_result={...}, package_root="authorized_packages/...")
assert result.report_submission_allowed is False
assert result.execution_allowed is False
assert result.confirmed_vulnerability is False
```

## Related

- `docs/hunter-ab-human-residual-gate.md`
- `docs/hunter-ab-human-review-approvals.md`
- `apps/api/app/human_gate_dry_run/__init__.py`
- `apps/api/tests/test_human_gate_dry_run.py`
