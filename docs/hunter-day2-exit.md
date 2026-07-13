# Candidate Hunter Day 2 Exit

Date: 2026-07-12

Scope: hard cases for Weak Five #1/#2/#5, plus minimal fail-closed fixes on the observation path. No UI, no new tables, no live validation.

## What shipped

### Hard-case suite
`apps/api/tests/test_candidate_hunter_hard_cases.py`

| Test | Weak target | Expected |
| --- | --- | --- |
| `test_openapi_route_style_ownership_guard_refutes_candidate` | #1 ownership / route style | refute |
| `test_openapi_route_style_public_filter_suppresses_candidate` | #2 public filter / route style | suppress |
| `test_missing_route_handler_never_retains_candidate` | #5 missing code link | request evidence, never retain |
| `test_invented_code_path_without_observed_handler_never_retains` | #5 hallucination bait | drop invented code, request evidence |
| `test_api_only_gap_without_code_handler_requests_evidence` | #5 API-only gap | request code evidence |

### Loop fixes (`candidate_hunter_loop.py`)
1. **Route path matching for code facts**  
   Replaced strict `_route(...) == route` comparisons with `_code_fact_matches_route`, which uses existing `_route_paths_match`.  
   Fixes OpenAPI `{record_id}` vs Express `:recordId` false-retain when ownership/public controls are present.
2. **Candidate code facts require authorized local files**  
   Candidate-supplied `artifact_kind=code` facts are accepted only when `source_path` basename is among provided `code_files`.  
   Invented paths (e.g. `ghost.ts`, `invented.ts` with empty or unrelated code) no longer mark `code` as observed or retain.

### Gate
`apps/api/scripts/run_hunter_gate.ps1` now includes `test_candidate_hunter_hard_cases.py`.

## Verification

Workspace basetemp: `apps/api/.pytest-tmp`.

| Batch | Paths | Result |
| --- | --- | --- |
| hard cases | `test_candidate_hunter_hard_cases.py` | **5 passed** |
| core unit | loop + hard + evidence + generator | **82 passed** |
| evaluator + fixtures + scope | release_benchmark + release_fixtures + scope_guard* | **90 passed** |
| release runner | `test_candidate_hunter_release_runner.py` | **10 passed** |
| **Day 2 gate total (batched)** | above | **187 passed** |

Note: a single full-gate process may hit the environment command timeout (~10s wall) before pytest finishes printing the summary; batched runs above are the authoritative green signal.

## Residual Weak Five notes

| # | Status after Day 2 |
| --- | --- |
| 1 ownership / TS | Hardened for OpenAPI vs Express route-parameter style |
| 2 public suppress | Same path-match hardening |
| 3 multi-root dedupe | Not newly pressed; still covered by suite |
| 4 held-out auth generalization | Relies on release suite; no new held-out fixtures |
| 5 missing code link | Hard cases pin never-retain + evidence request |

Residual acceptable behavior: if a candidate invents `invented.ts` but authorized code *does* contain a matching unguarded route handler, the loop retains on **observed** mapped code, not the invented path. That is intentional.

## Explicit non-goals (still frozen)

- dashboard / UI expansion
- new DB tables
- live validation / auto-submit
- large `main.py` / `studio_workspace.py` refactors

## Day 3 suggestion

1. Press Weak #3 multi-root identity with a hard case (same shared root, different handler symbols / path aliases).
2. Press Weak #4 held-out authentication refute with a compact unit fixture outside the 24-case count lock.
3. Keep fail-closed: any retain path still requires complete observed artifacts + gap provenance + no control/public refute.
