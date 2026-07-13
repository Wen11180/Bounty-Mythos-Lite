# Variant Analysis (V4 plan-only)

Updated: 2026-07-12T21:09:44Z

## What landed

Standalone factory module (supersedes thin nested deep_research variant stubs for bridge path):

- `apps/api/app/variant_analysis/__init__.py`
- Bridge attach + console: `va=` / `van=` / `vas=` / `vax=`
- CLI: `--allow-variant-analysis-export`
- MEV engine: `variant_analysis` (mevenc dual-lab retain **28**, mealie-inject **27**)
- Scheduler: **T-013b** / **B-010b** (`variant_analysis_agent`)
- Tests: `apps/api/tests/test_variant_analysis.py` (9 tests + scheduler covered)

## Inputs

1. Bridge source_hypotheses / hypotheses / retained candidates / report drafts
2. Bridge confirmed_findings (seed only; never re-confirm)
3. Bridge `patch_diff_learner.patterns` as optional seeds
4. Residual gates / family hints
5. Offline `inputs/variant*.json` under authorized package root
6. Optional human export flag writes `_export/variant_analysis/`

## Outputs (plan-only)

- Variant search plans: scopes, search pattern, similar-sink notes, guard comparison
- Refutation questions + safe next step (local code search only)
- Family counts + seed accounting
- Human questions (never auto-search public targets)

## Safety floor (always false)

execution / process_spawn / network / live_validation / validation / report_submission /
confirmed_vulnerability / finding_promotion

## Dual-lab smoke

| Package | va status | variants | seeds | mevenc | submission_blocked |
|---|---|---:|---:|---:|---|
| my-local-ssrf-retain | plan_ready | 5 | 5 | 28 | True |
| my-gh-mealie-inject | plan_ready | 6 | 6 | 27 | True |

## Distance note

Does **not** claim 100% factory complete. H1 still `blocked_401`; live e2e human gates and live wall-clock remain intentionally human-gated/missing.

Next priorities remain: e2e human gates when H1 unblocked; no H1 thrash while 401; optional portfolio intake expand.
