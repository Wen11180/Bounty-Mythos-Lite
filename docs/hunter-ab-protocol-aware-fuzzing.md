# Protocol-Aware Fuzzing (V4 plan-only)

Updated: 2026-07-12T20:56:21Z

## What landed

Standalone factory module (not only nested under deep_research):

- pps/api/app/protocol_aware_fuzzing/__init__.py
- Bridge attach + console: paf= / pafn= / pafg= / pafs= / pafx=
- CLI: --allow-protocol-aware-fuzzing-export
- MEV engine: protocol_aware_fuzzing (mevenc dual-lab retain **26**, mealie-inject **25**)
- Scheduler: **T-003h** / **B-002j** (protocol_aware_fuzzing_agent)
- Tests: pps/api/tests/test_protocol_aware_fuzzing.py

## Inputs

1. CRS parser_candidates (or harness_plans fallback)
2. Optional offline inputs/protocol*.json under authorized package root
3. Optional human export flag writes _export/protocol_aware_fuzzing/

## Outputs (plan-only)

- Grammar sketch per target
- Message-boundary plan
- Seed corpus plan (no real user data / secrets)
- Harness linkage notes + human questions

## Safety floor (always false)

execution / process_spawn / network / live_validation / validation / report_submission /
confirmed_vulnerability / finding_promotion / crash_promotion

## Dual-lab smoke

| Package | paf status | targets | mevenc | submission_blocked |
|---|---|---:|---:|---|
| my-local-ssrf-retain | plan_ready | 1 | 26 | True |
| my-gh-mealie-inject | plan_ready | 3 | 25 | True |

## Distance note

Does **not** claim 100% factory complete. H1 still locked_401; live e2e human gates and live wall-clock remain intentionally human-gated/missing.

Patch Diff Learner is now first-class (`docs/hunter-ab-patch-diff-learner.md`). Next optional V4 depth: **Variant Analysis** module beyond nested deep_research stubs.
