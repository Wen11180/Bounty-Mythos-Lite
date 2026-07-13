# Candidate Hunter Day 1 Baseline

Date: 2026-07-12

Scope: measure the A+B Candidate Hunter main path, freeze non-hunter work,
and pin fail-closed gates before Day 2 hard-case work.

## Freeze

For Day 1-3, do not expand:

- new dashboard/UI pages
- new database tables
- live validation / automatic submission
- multi-language expansion beyond existing TS/Express facts
- large refactors of `main.py` / `studio_workspace.py`

Only touch hunter loop, evidence, release gate, and tests unless a safety bug
forces a wider fix.

## Commands and results

All commands were run from the repo root with workspace basetemp because the
default user temp directory is not writable in this environment:

```powershell
$base = "apps\api\.pytest-tmp"
$env:TEMP = $base
$env:TMP = $base
.\.venv\Scripts\python.exe -m pytest <paths> -q --tb=line --basetemp "$base\<batch>"
```

| Batch | Paths | Result |
| --- | --- | --- |
| safety + loop | `test_scope_guard.py`, `test_scope_guard_api.py`, `test_candidate_hunter_loop.py` | **84 passed** |
| evidence + fixtures + generator | `test_candidate_hunter_evidence.py`, `test_candidate_hunter_release_fixtures.py`, `test_cross_source_candidate_generator.py` | **41 passed** |
| release evaluator + runner | `test_candidate_hunter_release_benchmark.py`, `test_candidate_hunter_release_runner.py` | **47 passed** |
| **Total Day 1 baseline (pre-hardening)** | above | **172 passed** |
| Day 1 after regression pins | loop + release evaluator/runner focused recheck | **114 passed** on changed suites; full gate subsets green |

Notes:

- First full run against `%TEMP%\pytest-of-Administrator` failed setup with
  `PermissionError` (25 errors). This is an environment issue, not a hunter
  logic failure.
- `.pytest_cache` emits `WinError 183` warnings; tests still pass.

## Release metrics contract

From `apps/api/app/intelligence_benchmark/release_v1.py`:

| Metric | Threshold |
| --- | --- |
| `precision_at_5` | 0.8 |
| `valuable_recall_at_5` | 0.8 |
| `evidence_traceability_rate` | 1.0 |
| `effective_refutation_rate` | 0.8 |
| `duplicate_suppression_rate` | 1.0 |
| `human_worth_validation_rate` | 0.8 |

Suite layout (`suite-manifest.json`):

- development: 12 cases (authorization / injection / data_exposure)
- release held-out: 12 cases (authentication / workflow / configuration)
- each suite covers retain / refute / deduplicate / suppress

## Critical path map

| Stage | Owner | Function |
| --- | --- | --- |
| observations | `candidate_hunter_loop.py` | `build_candidate_hunter_observations` |
| round advance | `candidate_hunter_loop.py` | `advance_candidate_hunter_round` |
| multi-round loop | `candidate_hunter_loop.py` | `run_candidate_hunter_loop` |
| projection | `candidate_hunter_loop.py` | `load_candidate_hunter_projection` |
| evidence materialize | `candidate_hunter_evidence.py` | `materialize_evidence_inspection_task` |
| evidence execute | `candidate_hunter_evidence.py` | `run_evidence_inspection_task` |
| evidence resume | `candidate_hunter_evidence.py` | `resume_candidate_hunter_after_evidence` |
| release capture | `release_runner.py` | `run_candidate_hunter_release_fixture` |
| release gate | `release_runner.py` | `_apply_loop_audit_gate` |
| score | `release_v1.py` | `evaluate_candidate_hunter_release_v1` |

## Known path risks (not suite red)

1. `normalize_studio_candidates_for_release_v1()` always emits
   `candidate_decisions: []`. It is a capture helper, not a completed loop
   projection. Release scoring must use
   `load_candidate_hunter_projection(... status == ready)`.
2. Before Day 1 hardening, evaluator schema allowed non-empty
   `final_candidates` with empty `candidate_decisions` when gold only needed
   retain-side denominators carefully. Day 1 adds an explicit schema fail for
   final candidates without covering retained decisions.
3. Invalid loop projection already fails closed in
   `test_runner_fails_closed_when_persisted_stage_projection_is_invalid`.

## Weak Five

These are the highest-risk behaviors to watch even while the suite is green.
They are prioritization targets for Day 2, not current red tests.

| # | case_id | suite | expected | Why weak / high value | Suspect area |
| --- | --- | --- | --- | --- | --- |
| 1 | dev-002 | development | refute | Ownership guard present; false retain if control ref not linked into `source_fact_refs` | `advance_candidate_hunter_round` control_ref branch; TS ownership facts |
| 2 | dev-004 | development | suppress | Public visibility path; false retain if public filter fact missed | `public_evidence_ref` / `_typescript_public_filter_fact` |
| 3 | dev-003 | development | deduplicate | Multi-root case; ranking/dedupe identity must keep only canonical retain | `_duplicate_targets`, root_cause_id merge |
| 4 | rel-002 | release | refute | Held-out authentication family; overfit risk if only dev ownership patterns work | cross-source + evidence resume generalization |
| 5 | hard: missing code link | not in 24-case suite yet | request / no retain | API/HAR without handler link must not invent code path or retain | evidence request completeness; generator citation validation |

Day 2 should add adversarial fixtures for #5 and keep pressure on #1/#2.

## Day 1 regression pins added

- Evaluator rejects final candidates that lack covering retained decisions.
- Loop incomplete candidates still request evidence and never terminal-retain.
- Normalizer empty decisions remain explicitly non-authoritative.

## Next

Day 2:

1. Harden missing-evidence retain block if any gap remains.
2. Add hard cases: hallucination bait + missing code link.
3. Repair top Weak Five bugs only when a failing test proves them.
## Local gate script

`powershell
powershell -File apps/api/scripts/run_hunter_gate.ps1
`

Uses workspace basetemp under pps/api/.pytest-tmp to avoid unwritable user TEMP.