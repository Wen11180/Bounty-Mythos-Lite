# Patch Diff Learner (V4 plan-only)

Updated: 2026-07-12T21:04:27Z

## What landed

Standalone factory module (not only nested under deep_research):

- `apps/api/app/patch_diff_learner/__init__.py`
- Bridge attach + console: `pdl=` / `pdln=` / `pdlx=`
- CLI: `--allow-patch-diff-learner-export`
- MEV engine: `patch_diff_learner` (mevenc dual-lab retain **27**, mealie-inject **26**)
- Scheduler: **T-008d** / **B-005d** (`patch_diff_learner_agent`)
- Tests: `apps/api/tests/test_patch_diff_learner.py` (9 tests + scheduler covered)

## Inputs

1. Offline `inputs/patch_diff*.json` under authorized package root
2. Bridge `patch_diff` object/list
3. Bridge `patch_industrial_loop.items` (metadata only)
4. Bridge `patch_suggestions` / single `patch_suggestion`
5. Optional human export flag writes `_export/patch_diff_learner/`

## Outputs (plan-only)

- Learned patterns: root-cause summary, fix strategy, regression suggestion
- Changed-files metadata + applicability boundary
- Human questions (never auto-apply)

## Safety floor (always false)

execution / process_spawn / network / live_validation / validation / report_submission /
confirmed_vulnerability / finding_promotion / auto_pr / patch_ready / pr_opened

## Dual-lab smoke

| Package | pdl status | patterns | mevenc | submission_blocked |
|---|---|---:|---:|---|
| my-local-ssrf-retain | plan_ready | 3 | 27 | True |
| my-gh-mealie-inject | plan_ready | 4 | 26 | True |

## Distance note

Does **not** claim 100% factory complete. H1 still `blocked_401`; live e2e human gates and live wall-clock remain intentionally human-gated/missing.

Next optional V4 depth: first-class **Variant Analysis** module beyond nested deep_research stubs.
