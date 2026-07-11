# Stateful Candidate Hunter Loop Implementation Plan

> **Execution rule:** Every behavior change starts with a focused failing test.
> No phase may weaken Scope Guard, controlled-workspace containment,
> structured redaction, human approval, or submission blocking.

## Scope

This plan implements the approved stateful A+B Candidate Hunter loop and makes
the existing release benchmark a meaningful gate. It uses one
`candidate_hunter_loop` Task per eligible pipeline run and immutable
`candidate_hunter_snapshot`, `candidate_hunter_evidence_request`,
`candidate_hunter_decision`, and `candidate_hunter_rerank` Stages.

Approved references:

- `docs/superpowers/specs/2026-07-11-stateful-candidate-hunter-loop-design.md`
- `docs/superpowers/specs/2026-07-10-candidate-hunter-release-benchmark-design.md`
- `docs/superpowers/specs/2026-07-10-local-candidate-hunter-safety-design.md`

The worktree already contains the uncommitted release runner, fixture corpus,
and baseline fixes listed in `docs/current-worktree-review-units.md`. Preserve
those changes and edit only files named in this plan.

## Phase 0: Verified Documentation Boundaries

### Allowed APIs and copy-ready patterns

| Need | Existing source | Required use |
| --- | --- | --- |
| Read a pipeline run | `apps/api/app/repository.py:410` `DatabaseRepository.get_pipeline_run(run_id)` | Resolve the authoritative run; do not accept a caller-supplied payload copy. |
| Create/read Campaigns | `apps/api/app/repository.py:508` `create_campaign(...)`, `list_campaigns()` | Copy the current read-only Campaign persistence pattern. |
| Create/update Tasks | `apps/api/app/repository.py:614` `create_campaign_task(...)`, `update_campaign_task_status(...)` | Use one Task with `pipeline_run:<id>` in `input_refs`. |
| Idempotent Stage writes | `apps/api/app/repository.py:1011` `save_pipeline_stage(...)` | Include a stable payload `idempotency_key`; never update an old loop Stage. |
| Rebuild run history | `apps/api/app/repository.py:1092` `list_pipeline_stages_for_run(...)` | Projection and resume must read persisted Stages, not process memory. |
| Idempotency test pattern | `apps/api/tests/test_database_repository.py:782` | Copy the repeated-write assertion and prove the original Stage is unchanged. |
| Controlled Studio run | `apps/api/app/main.py:2498` `run_mythos_studio_workspace_research(...)` | Invoke the loop only after the source run and redacted candidate view exist. |
| Redacted candidate view | `apps/api/app/main.py:6872` `_studio_candidates_for_run(...)` | Use its Top-5 candidates as the initial snapshot without changing its response contract. |
| Authorized code projection | `apps/api/app/main.py:2996` `_studio_authorized_code_files(...)` | Read only files under the configured workspace and pass them transiently to observation extraction. |
| API/HAR facts | `apps/api/app/main.py:7491` `_studio_authorization_context_facts(...)` and `:7512` `_studio_imported_surface_facts(...)` | Reuse normalized facts; do not persist raw OpenAPI or HAR bodies. |
| Static code facts | `apps/api/app/codebase_map/__init__.py:181` `map_authorized_code_files(...)` | Re-run the existing local parser for route, call, authz, and sink facts. |
| Gap candidate facts | `apps/api/app/codebase_map/__init__.py:1064` `_authorization_gap_candidates(...)` | Retain only evidence-backed gaps; use the surrounding route/authz/sink facts for refutation and suppression. |
| Safe source facts | `apps/api/app/source_audit/__init__.py:987` `_source_fact_from_codebase_candidate(...)` | Copy the observed-only reference and semantic-field pattern. |
| Release fixture staging | `apps/api/app/intelligence_benchmark/release_fixtures.py:43` `stage_release_fixture_inputs(case)` | Keep `gold.json` outside staged inputs and validate metadata first. |
| Release capture order | `apps/api/app/intelligence_benchmark/release_runner.py:86` `_capture_candidate_hunter_release_fixture(...)` | Preserve inputs -> Studio -> loop projection -> gold ordering. |
| Pure evaluator | `apps/api/app/intelligence_benchmark/release_v1.py:25` `evaluate_candidate_hunter_release_v1(...)` | Keep thresholds and matching unchanged. |
| Scope rejection test | `apps/api/tests/test_studio_api.py:2482` | Copy the assertion that no persistence occurs for an out-of-scope workspace. |

### Allowed new module API

Add `apps/api/app/candidate_hunter_loop.py` with a small public surface:

```python
build_candidate_hunter_observations(
    *, pipeline_run_id: str, candidates: list[dict], code_files: list[dict],
    surface_facts: list[dict], context_facts: list[dict]
) -> dict

advance_candidate_hunter_round(
    *, pipeline_run_id: str, round_number: int,
    candidate_states: list[dict], observations: dict,
    prior_decisions: list[dict]
) -> dict

run_candidate_hunter_loop(
    *, repository: DatabaseRepository, record: PipelineRunRecord,
    policy_text: str, candidates: list[dict], observations: dict
) -> dict

load_candidate_hunter_projection(
    *, repository: DatabaseRepository, pipeline_run_id: str
) -> dict
```

Names may be shortened only if the resulting surface stays smaller. The pure
transition function must not import repository, filesystem, network, clock,
fixture, or evaluator code.

### Anti-pattern guards

- Do not read `case_id`, `risk_family`, `expected_disposition`, fixture paths,
  or gold data in Candidate Hunter code.
- Do not classify from words such as `retain`, `refute`, `deduplicate`, or
  `suppress` in names or text.
- Do not infer a decision from a missing candidate.
- Do not invent root causes or evidence refs to match gold.
- Do not add a new table, migration, public API route, UI, model call, or
  configurable workflow engine.
- Do not update an existing loop Stage payload.
- Do not treat `human_validation_readiness=ready` as validation permission.

## Phase 1: Lock Benchmark Integrity Before Loop Logic

### Files

- Update `apps/api/tests/test_candidate_hunter_release_fixtures.py`.
- Update `apps/api/app/intelligence_benchmark/release_fixtures.py` only when a
  loader-level invariant is required.
- Replace the 24 static case directories and
  `apps/api/tests/fixtures/candidate_hunter_release/suite-manifest.json`.
- Update `apps/api/tests/test_candidate_hunter_release_runner.py` references
  to opaque case IDs.

### RED tests

1. Add a test that scans every staged input path and content value and rejects
   outcome-label words. Verify it fails against the current corpus.
2. Add a test that case IDs and workspace child paths are opaque and do not
   contain suite, risk-family, or disposition labels. Verify current IDs fail.
3. Add a semantic-fixture test that parses local code with
   `map_authorized_code_files(...)` and proves:
   - retain inputs expose a gap candidate with no decisive control;
   - refute inputs expose a sensitive route plus a positive guard/control fact
     available to bounded re-analysis;
   - deduplicate inputs expose two gap routes that reach the same shared
     service/root;
   - suppress inputs expose positive public/self-only or non-sensitive
     evidence rather than merely lacking a candidate.
4. Add a perturbation test that changes opaque case IDs and manifest order and
   proves staged semantic inputs are unchanged.

### GREEN implementation

1. Rename cases to opaque IDs such as `dev-001` and `rel-001`; keep suite,
   family, and expected disposition only in non-staged manifest/case metadata.
2. Use neutral routes, operation IDs, symbols, policy text, and workspace
   names. No outcome label appears in `inputs/`.
3. Make the four outcomes structurally observable using ordinary code:
   unguarded sensitive flow, positive custom control, shared service root, and
   explicit safe/public flow. Do not add magic comments or test-only markers.
4. Regenerate each safe gold oracle by hand from the independent semantic
   design. Evidence refs must use the normal observed fact-ref scheme.
5. Keep all inputs synthetic, local-only, secret-free, and free of real user
   data.

### Verification

```powershell
.\.venv\Scripts\python.exe -m pytest apps/api/tests/test_candidate_hunter_release_fixtures.py -q
.\.venv\Scripts\python.exe -m pytest apps/api/tests/test_codebase_map.py -q
```

### Guards

- The fixture loader may validate staged inputs, but it must not expose the
  expected disposition to the runtime entrypoint.
- Do not loosen the 24-case balance or safety metadata checks.
- Do not use case metadata as an observation source.

## Phase 2: Pure Observation and State Transition Logic

### Files

- Add `apps/api/app/candidate_hunter_loop.py`.
- Add `apps/api/tests/test_candidate_hunter_loop.py`.

### RED tests

1. Build minimal ordinary candidate/fact inputs and assert stable identity is
   `pipeline_run_id + hypothesis_id`.
2. Assert an evidence-complete unguarded sensitive flow becomes `retained`.
3. Assert a positive observed control becomes `refuted` with a decisive ref.
4. Assert two candidates sharing an observed service/root produce one
   retained canonical candidate and one `deduplicated` decision whose
   `duplicate_of` names the canonical root.
5. Assert explicit safe/public evidence produces `suppressed` with a positive
   evidence ref.
6. Assert missing root cause, route, provenance, or required artifact kinds
   remains unresolved and produces an evidence request, not a terminal
   decision.
7. Assert ordering is evidence completeness, priority descending, candidate ID
   ascending, with at most five final candidates.
8. Assert any true/missing execution, dispatch, validation, promotion, or
   submission flag fails closed to an empty projection.
9. Assert raw secrets and real-user-data markers never enter observations,
   decisions, or final candidates.

### GREEN implementation

1. Project route, authz, sensitive-sink, shared-call-root, API/HAR surface, and
   scope/policy context into safe cited observations. Raw file contents stay
   transient.
2. Use only positive observations for terminal decisions. A missing fact is an
   evidence request.
3. Normalize root IDs from observed route/root symbols using one deterministic
   function. Apply the same function to decisions and final candidates.
4. Return a round result containing snapshot candidates, evidence requests,
   terminal decisions, unresolved states, final candidates, state digest, and
   stop candidate.
5. Keep all permission fields hard-coded false and all required safety
   blockers present.

### Verification

```powershell
.\.venv\Scripts\python.exe -m pytest apps/api/tests/test_candidate_hunter_loop.py -q
.\.venv\Scripts\python.exe -m pytest apps/api/tests/test_codebase_map.py apps/api/tests/test_source_audit.py -q
```

### Guards

- Do not import release fixture or evaluator modules.
- Do not inspect names for disposition words.
- Do not add abstractions beyond the observation projector, pure transition,
  persistence coordinator, and projection loader in the approved design.

## Phase 3: Persist and Resume Immutable Multi-Round State

### Files

- Extend `apps/api/app/candidate_hunter_loop.py`.
- Extend `apps/api/tests/test_candidate_hunter_loop.py`.
- Update `apps/api/app/repository.py` only if a narrow query helper eliminates
  repeated full scans; no schema changes.

### RED tests

1. Assert out-of-scope, missing, or ambiguous runs create no Campaign, Task,
   or Stage.
2. Assert an eligible run creates exactly one read-only Campaign, a zero
   validation budget, and one `candidate_hunter_loop` Task.
3. Assert one round writes exactly the four approved Stage keys in order, with
   stable idempotency keys and every hard permission flag false.
4. Invoke the coordinator twice and assert it reuses the same Campaign, Task,
   and Stages without changing original payloads.
5. Seed a partial round and assert resume appends only missing Stages.
6. Cover `all_candidates_terminal`, `no_candidates`, `no_state_change`,
   `no_processable_candidates`, and `max_rounds_reached` Task statuses and
   stop reasons.
7. Assert the projection loader rejects a malformed or unsafe Stage sequence.

### GREEN implementation

1. Find exact ownership through Campaign payload plus Task input ref
   `pipeline_run:<id>`; never reuse by program alone.
2. Create the Campaign with `level_0_read_only`, the source run's program and
   asset, source policy text, allowed read-only tools, and validation budget
   zero.
3. Derive each Stage idempotency key from run ID, round, Stage key, and state
   digest. Reuse `save_pipeline_stage(...)` unchanged.
4. Reconstruct progress from persisted Stages. Treat Task status as a mutable
   summary only.
5. Load final candidates and release-shaped decisions only from the latest
   valid rerank Stage.

### Verification

```powershell
.\.venv\Scripts\python.exe -m pytest apps/api/tests/test_candidate_hunter_loop.py apps/api/tests/test_database_repository.py -q
```

### Guards

- Do not call `update_pipeline_stage_status(...)` for Candidate Hunter Stages.
- Do not trust Task payload as the final projection.
- Do not claim concurrent cross-process task creation is atomic.

## Phase 4: Integrate the Real Studio Research Path

### Files

- Update `apps/api/app/main.py` narrowly around
  `run_mythos_studio_workspace_research(...)`.
- Extend `apps/api/tests/test_studio_api.py`.

### RED tests

1. Extend the existing controlled Studio run test to assert one loop Task and
   the four Stage types are persisted for its pipeline run.
2. Assert the existing `/runs` and `/candidates` response shapes remain
   compatible.
3. Add a two-round case where bounded local re-analysis changes an unresolved
   candidate into a terminal decision.
4. Assert out-of-scope and unsafe input failures still occur before Campaign
   or Task persistence.
5. Assert raw code, headers, tokens, and fixture metadata are absent from
   every loop Stage.

### GREEN implementation

1. After saving the source pipeline run, build the existing redacted Studio
   candidates and normalized context/surface facts.
2. Pass transient authorized code files and safe facts to the observation
   projector, then invoke the persistence coordinator.
3. Keep the loop result out of existing response payloads for this slice;
   audit data remains available through existing Campaign/Stage queries.

### Verification

```powershell
.\.venv\Scripts\python.exe -m pytest apps/api/tests/test_studio_api.py -q
.\.venv\Scripts\python.exe -m pytest apps/api/tests/test_campaign_api.py -q
```

### Guards

- Do not add a public API route or UI.
- Do not persist transient authorized code bodies.
- Do not change existing report, candidate, or benchmark-template behavior.

## Phase 5: Project Persisted Results Into the Release Runner

### Files

- Update `apps/api/app/intelligence_benchmark/release_runner.py`.
- Update `apps/api/tests/test_candidate_hunter_release_runner.py`.

### RED tests

1. Replace the raw-candidate normalizer assertion with a projection-loader
   assertion containing persisted final candidates and decisions.
2. Monkeypatch the gold loader and assert the event order is:
   `inputs_staged`, `candidates_captured`, `loop_projected`, `gold_loaded`.
3. Assert the Candidate Hunter entrypoint receives no fixture object, case ID,
   expected disposition, suite, risk family, or oracle.
4. Assert each case result contains safe Campaign/Task/round/Stage audit refs.
5. Assert malformed Stage audit makes the case fail closed even if metric
   values would otherwise pass.

### GREEN implementation

1. Read the projection created by the Studio path using only `run_id` and the
   repository.
2. Keep `normalize_studio_candidates_for_release_v1(...)` for its existing
   observed-field unit contract, but do not use it as the stateful suite's
   authoritative output.
3. Add loop audit metadata without raw payloads.
4. Load each oracle only after every case capture and projection is complete.

### Verification

```powershell
.\.venv\Scripts\python.exe -m pytest apps/api/tests/test_candidate_hunter_release_runner.py -q
.\.venv\Scripts\python.exe -m pytest apps/api/tests/test_candidate_hunter_release_benchmark.py -q
```

### Guards

- Do not pass `ReleaseFixtureCase` into Candidate Hunter code.
- Do not synthesize decisions in the runner.
- Do not weaken evaluator thresholds or safety failures.

## Phase 6: Development Gate, Held-Out Release Gate, and Full Verification

1. Run fixture, loop, runner, evaluator, Studio, Scope Guard, source audit,
   repository, migration, policy, and worker tests.
2. Run the development suite and record every metric and Stage-audit result.
   Fix Hunter behavior or fixture semantics; never change gold to match output.
3. Only after development passes, run all 12 held-out release cases. Require:
   - `precision_at_5 >= 0.80`;
   - `valuable_recall_at_5 >= 0.80`;
   - `evidence_traceability_rate == 1.00`;
   - `effective_refutation_rate >= 0.80`;
   - `duplicate_suppression_rate == 1.00`;
   - `human_worth_validation_rate >= 0.80`;
   - no schema, safety, Stage-audit, secret, or permission failure.
4. Run the full backend, Web, Studio, Compose, and diff checks.
5. Search staged fixture inputs and loop output code for forbidden outcome
   label dependencies and gold imports.
6. Update `docs/current-worktree-review-units.md` only if this new behavior
   changes the existing review-unit map.

### Final commands

```powershell
.\.venv\Scripts\python.exe -m pytest apps/api/tests -q

Set-Location apps/web
npm test
npm run lint
npm run build

Set-Location ../studio
npm test

Set-Location ../..
docker compose -f infra/docker-compose.yml config --quiet
git diff --check
rg -n -i "retain|refute|deduplicate|suppress" apps/api/tests/fixtures/candidate_hunter_release/*/*/inputs
rg -n "gold|expected_disposition|ReleaseFixtureCase" apps/api/app/candidate_hunter_loop.py
```

## Completion Evidence

Do not mark this plan complete from unit tests alone. Completion requires:

- the corrected corpus contains no outcome-label leakage;
- a real Studio run creates one persistent, resumable loop Task and immutable
  rounds;
- all terminal decisions cite observed facts;
- the release runner reads persisted results before loading gold;
- the held-out release suite meets every approved metric;
- all permission flags remain false; and
- the complete repository verification chain is green.
