# Candidate Hunter Release Benchmark Implementation Plan

> **Execution rule:** Every production change starts with a focused failing
> test. No phase may weaken Scope Guard, workspace containment, redaction,
> review-only validation, or submission-blocked behavior.

## Scope

This plan implements stage 3 of the active objective: an offline,
release-quality A+B Candidate Hunter benchmark. It establishes the evaluator,
fixture corpus, and controlled runner that the future persistent multi-round
Hunter loop must pass. It does not implement that future loop itself.

Approved references:

- `docs/superpowers/specs/2026-07-10-candidate-hunter-release-benchmark-design.md`
- `docs/superpowers/specs/2026-07-10-local-candidate-hunter-safety-design.md`

## Phase 0: Verified Documentation Boundaries

### Allowed existing APIs and patterns

| Need | Existing source | Required use |
| --- | --- | --- |
| Legacy evaluator | `app.intelligence_benchmark.evaluate_studio_candidates` | Preserve input, output, and old-fixture semantics. |
| Legacy template | `build_studio_expectations_template` | Keep draft-only; never derive release gold from candidates. |
| Route matching | `_route_paths_match` | Reuse documented template behavior only. |
| CLI pattern | `app.cli.run_studio_eval_command` | Copy JSON/exit-code shape into a separate release command. |
| Controlled workspace | `create_workspace`, `import_workspace_artifact`, `resolve_workspace_file` | Use for all end-to-end staging. |
| Studio A+B flow | `/workspaces`, `/imports`, `/runs`, `/candidates` | Drive real local intake and candidate construction. |
| Test setup | `test_studio_api.py:_configure_studio_workspace_root` | Reuse the temporary workspace root fixture. |
| Local source audit | `run_source_audit` and its allowlist tests | Use synthetic, allowlisted local code only. |
| Policy / Scope Guard | `parse_policy_text`, `evaluate_validation_request` | Prove the benchmark cannot authorize validation. |

### Contract decision

Use separate enums so the evaluator never normalizes an unobserved decision:

```text
gold.expected_disposition: retain | refute | deduplicate | suppress
candidate_decision.disposition: retained | refuted | deduplicated | suppressed
```

The normalizer passes through observed fields only. Missing root causes,
evidence references, decisions, or human-validation readiness must fail the
relevant gate instead of being inferred.

### Anti-pattern guards

- Do not place release fixtures in `tests/fixtures/studio_benchmarks`.
- Do not change `evaluate_studio_candidates` or `studio-eval` semantics.
- Do not stage or load `gold.json` before Hunter output is captured.
- Do not use a caller-selected root, external path, live URL, model-provider
  call, raw credential, or real user data.
- Do not infer refutation or deduplication from a missing final candidate.

## Phase 1: Pure Versioned Release Evaluator

### Files

- Add `apps/api/app/intelligence_benchmark/release_v1.py`.
- Update `apps/api/app/intelligence_benchmark/__init__.py` only to re-export
  the explicit V1 function.
- Add `apps/api/tests/test_candidate_hunter_release_benchmark.py`.

### Tasks

1. Write failing tests for a valid normalized Hunter output and independent
   gold oracle. Require a versioned, machine-readable result with each metric's
   threshold, numerator, denominator, and pass state.
2. Add the pure deterministic entrypoint:

   ```python
   evaluate_candidate_hunter_release_v1(normalized_output, gold_oracle) -> dict
   ```

3. Validate output and oracle schemas before calculation: positive
   denominators, at most five final candidates, unique ranks, required route /
   vulnerability / root-cause fields, and valid enums.
4. Implement rank-ordered one-to-one matching for retained roots. Every
   unmatched returned Top-5 candidate is a false positive; every unmatched
   retained root is missed.
5. Add tests and implementation for Precision@5, valuable recall@5, evidence
   traceability, effective refutation, duplicate suppression, and
   human-worth-validation rate.
6. Add hard-fail tests and implementation for safety blockers, false
   execution/validation/submission flags, secret-shaped text, real-user-data
   markers, unsafe validation language, and unsafe report actions.

### Verification

```powershell
cd apps/api
..\..\.venv\Scripts\python.exe -m pytest tests/test_candidate_hunter_release_benchmark.py -q
..\..\.venv\Scripts\python.exe -m pytest tests/test_intelligence_benchmark.py -q
```

### Guards

- Keep legacy result shapes byte-for-byte compatible in focused tests.
- Do not add fuzzy matching beyond the documented route-template behavior.
- Treat zero denominators as configuration failures, never `1.0` metrics.

## Phase 2: Independent Fixture Corpus and Loader

### Files

- Add `apps/api/app/intelligence_benchmark/release_fixtures.py`.
- Add `apps/api/tests/fixtures/candidate_hunter_release/suite-manifest.json`.
- Add 24 static case directories under `development/` and `release/`.
- Add `apps/api/tests/test_candidate_hunter_release_fixtures.py`.

### Tasks

1. Write failing tests for manifest-driven suite assignment, unique IDs, 24
   cases, all six risk families across the corpus, and all four outcome classes
   in each suite.
2. Implement a pure fixture loader that validates metadata before reading case
   inputs: `synthetic`, `authorized_for_local_benchmark`,
   `contains_real_user_data=false`, and `contains_secrets=false`.
3. Add fixture-text scanning with release safety rules. Reject path escapes,
   unsupported kinds, secret-shaped text, raw authorization/cookie/token
   material, and real-user-data markers.
4. Add independent `case.json`, `inputs/`, and `gold.json` for each case. The
   inputs contain only scope, policy, OpenAPI, sanitized HAR, and local code;
   gold contains only safe IDs, routes, expected dispositions, root causes, and
   evidence references.
5. Keep gold outside `inputs/`. Loader APIs return staged inputs first and load
   the oracle only when explicitly asked after candidate capture.

### Verification

```powershell
cd apps/api
..\..\.venv\Scripts\python.exe -m pytest tests/test_candidate_hunter_release_fixtures.py -q
```

### Guards

- Never generate roots from current candidate output.
- Never copy real program materials, hosts, credentials, or authorization
  headers into fixtures.
- Never infer suite membership from directory names; use the manifest.

## Phase 3: Controlled End-to-End Runner and Normalizer

### Files

- Add `apps/api/app/intelligence_benchmark/release_runner.py`.
- Add `apps/api/tests/test_candidate_hunter_release_runner.py`.
- Add only narrowly necessary Studio imports or test helpers.

### Tasks

1. Write a failing end-to-end test that stages only `inputs/` into a temporary
   controlled workspace, creates a Studio workspace, imports scope/policy/code
   /api/HAR, runs `/mythos/studio/workspaces/runs`, and captures `/candidates`
   before reading gold.
2. Implement the runner through existing controlled workspace APIs. It must use
   temporary `STUDIO_WORKSPACE_ROOT` and reject paths outside
   `workspace/<kind>/`.
3. Implement a pure normalizer from Studio candidates to the release V1
   contract. Preserve observed evidence and safety values; do not fabricate
   missing required fields.
4. Add tests proving the oracle loader is not called before candidate capture,
   no external URL is used, and captured candidates remain review-only with
   execution, validation, and report submission disabled.
5. Evaluate normalized output only after loading gold. Initial failures due to
   absent persistent decisions are expected evidence for the next stateful-loop
   stage, not a reason to fabricate decisions.

### Verification

```powershell
cd apps/api
..\..\.venv\Scripts\python.exe -m pytest tests/test_candidate_hunter_release_runner.py tests/test_studio_api.py -q
```

### Guards

- Do not use `/mythos/studio/workspaces/benchmarks/run`; it reads legacy
  expectations from the workspace before evaluation.
- Do not call local source audit alone a complete A+B flow; stage all five
  A+B artifacts through Studio.
- Do not add a network client or fixture-controlled subprocess path.

## Phase 4: Versioned CLI and Gate Wiring

### Files

- Update `apps/api/app/cli.py`.
- Extend `test_candidate_hunter_release_benchmark.py` with CLI coverage.

### Tasks

1. Write a failing CLI test using `cli_main([...])`, `tmp_path`, and the
   existing JSON-output pattern.
2. Add:

   ```text
   aegis candidate-hunter-release-eval --hunter-output PATH --gold PATH [--output PATH]
   ```

3. Call only the pure V1 evaluator, emit the versioned result, and return zero
   only for `status=passed`.
4. Keep the end-to-end suite runner in-process until persistent decision data
   exists; do not expose a misleading release-run CLI early.

### Verification

```powershell
cd apps/api
..\..\.venv\Scripts\python.exe -m pytest tests/test_candidate_hunter_release_benchmark.py tests/test_intelligence_benchmark.py -q
```

## Phase 5: Verification and Handoff

1. Run release evaluator, fixture, runner, Studio API, policy-ingestion, Scope
   Guard, source-audit, and migration tests.
2. Run the full backend suite using the repository `.venv`.
3. Run Web unit tests, lint, production build, Studio tests, and Docker Compose
   configuration validation.
4. Run `git diff --check` and search new fixture/output paths for forbidden
   secrets and external-host patterns.
5. Record actual release-suite metrics. Benchmark infrastructure is complete
   when it produces fail-closed diagnostics; the active goal advances to the
   persistent candidate loop only when the real Hunter meets the approved
   thresholds without fabricated data.

### Final Commands

```powershell
cd apps/api
..\..\.venv\Scripts\python.exe -m pytest -q

cd ../web
npm test
npm run lint
npm run build

cd ../studio
npm test

cd ../..
docker compose -f infra/docker-compose.yml config --quiet
git diff --check
```
