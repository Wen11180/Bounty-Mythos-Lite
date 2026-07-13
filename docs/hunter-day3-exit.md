# Candidate Hunter Day 3 Exit

Date: 2026-07-12

Scope: hard cases for Weak Five #3 (multi-root dedupe) and #4 (held-out / auth-family refute), plus minimal identity fixes on fact dedupe and shared-root selection. No UI, no new tables, no live validation, no 24-case suite expansion.

## What shipped

### Hard-case suite additions
`apps/api/tests/test_candidate_hunter_hard_cases.py` (Day 1–2 cases retained; Day 3 appends)

| Test | Weak target | Expected |
| --- | --- | --- |
| `test_typescript_multi_root_shared_service_deduplicates` | #3 multi-root via shared helper | 1 retain + 2 dedupe on `loadRecord` |
| `test_typescript_multi_root_equal_priority_is_deterministic` | #3 canonical stability | lower `candidate_id` wins ties |
| `test_typescript_multi_root_direct_same_sink_deduplicates` | #3 direct same sink (no helper) | same `shared_root`, not dual retain |
| `test_held_out_transfer_ownership_guard_refutes_under_openapi_route` | #4 held-out transfer + OpenAPI path | refute |
| `test_authentication_family_session_ownership_guard_refutes` | #4 auth-family ownership | refute |
| `test_authentication_family_unguarded_session_can_retain` | #4 negative control | retain when unguarded |

Hard-case file total: **11 tests**.

### Loop / map fixes
1. **`apps/api/app/codebase_map/__init__.py` — `_dedupe_facts`**  
   Dedupe key now includes `handler` (and keeps `caller`) for multi-handler `sensitive_sink` / `authz_check` / gap / service_call facts.  
   Prevents multi-handler sinks from collapsing to a single fact before observation.

2. **`apps/api/app/candidate_hunter_loop.py` — `_shared_root`**  
   Preference order:
   - service callee that reaches a sink (shared helper path), else
   - sink **symbol** for direct-sink handlers (e.g. both call `sendFile`), else
   - handler if the handler itself is a sink  
   Fixes the Weak #3 failure where two handlers calling the same direct sink retained both with empty/mismatched roots.

## Verification

Workspace basetemp: `apps/api/.pytest-tmp` (user TEMP unwritable).  
Single full-gate process may hit ~10s wall timeout before summary; batched runs are authoritative.

| Batch | Paths | Result |
| --- | --- | --- |
| hard + loop | `test_candidate_hunter_hard_cases.py` + `test_candidate_hunter_loop.py` | **74 passed** |
| scope + evidence | `test_scope_guard.py` + `test_scope_guard_api.py` + `test_candidate_hunter_evidence.py` | **25 passed** |
| generator | `test_cross_source_candidate_generator.py` | **11 passed** |
| release eval + fixtures | `test_candidate_hunter_release_benchmark.py` + `test_candidate_hunter_release_fixtures.py` | **68 passed** |
| release runner | `test_candidate_hunter_release_runner.py` | **10 passed** |
| **Day 3 gate total (batched)** | gate targets | **188 passed** |

## Weak Five status after Day 3

| # | Status |
| --- | --- |
| 1 ownership / TS + route style | Day 2 hardened; still green |
| 2 public suppress + route style | Day 2 hardened; still green |
| 3 multi-root dedupe | **Hardened**: shared helper + direct same sink + deterministic canonical |
| 4 held-out / auth-family refute | **Hardened** with compact unit fixtures outside 24-case count lock |
| 5 missing / invented code link | Day 2 never-retain; still green |

## Residual notes (acceptable)

- Invented candidate code path is dropped, but if authorized local code still maps an unguarded handler, retain is on **observed** code — intentional.
- Direct-sink `shared_root` is the sink symbol (e.g. `sendFile`); evidence ref remains `code:<file>:<symbol>` and must appear in `source_fact_refs` for dedupe grouping.
- 24-case release suite counts remain locked; Day 3 pressure stayed in hard-case unit tests.

## Explicit non-goals (still frozen)

- dashboard / UI expansion
- new DB tables
- live validation / auto-submit
- large `main.py` / `studio_workspace.py` refactors
- expanding release suite case counts

## Day 4 suggestion

1. Stability pass only: re-run gate after any adjacent map changes; no new Weak unless red on real fixtures.
2. If quality work continues: shallow multi-language pressure (Python multi-handler same-sink / FastAPI path params) only if current TS/Python asymmetry is proven.
3. Keep fail-closed: complete artifacts + gap provenance + no control/public refute before retain; human gates remain required for validation/report.
