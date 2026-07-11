# Closed-loop implementation review units

Snapshot: 2026-07-11, relative to `10779574`.

This map separates the 2026-07-11 closed-loop change set by behavior. It is a
review and history guide only; it does not widen the safety boundary.

## Baseline evidence

- `.\.venv\Scripts\python.exe -m pytest apps/api/tests -q`: 920 passed.
- `apps/web`: `npm test` 188 passed, `npm run lint` clean, `npm run build` passed.
- `apps/studio`: `npm test` 25 passed.
- `docker compose -f infra/docker-compose.yml config --quiet`: passed.
- Candidate Hunter development and held-out release suites: all six metrics
  passed at `1.00`, with no schema, safety, or Stage-audit failures.

`apps/web/tsconfig.tsbuildinfo` is a generated TypeScript artifact and is
ignored. It is not a review or staging unit.

## Unit 1: database and migration safety

Purpose: use Alembic for durable database initialization, preserve supported
unversioned SQLite databases, and keep migration configuration portable.

Files:

- `apps/api/alembic.ini`
- `apps/api/app/db.py`
- `apps/api/migrations/env.py`
- migration-specific portions of `apps/api/tests/test_migrations.py`

Review focus:

- fresh and in-memory databases still initialize deterministically;
- only known legacy schemas may be stamped, otherwise initialization fails;
- no schema path bypasses Alembic for persistent databases.

## Unit 2: Program creation API

Purpose: persist operator-provided Program records through the public API while
rejecting duplicate identifiers.

Files:

- Program creation portions of `apps/api/app/main.py` and
  `apps/api/app/repository.py`
- `apps/api/tests/test_api.py`

Review focus:

- Program creation uses the database-backed repository;
- duplicate Program identifiers return an explicit conflict;
- request-scoped database dependency overrides remain testable.

## Unit 3: campaign guardrails and authorized source intake

Purpose: enforce saved Scope Guard state, account for time/token budgets, record
dispatch failures, harden policy wording, and reject code paths that escape an
authorized repository through symlinks.

Files:

- `apps/api/app/campaign_orchestrator/__init__.py`
- `apps/api/app/policy_ingestion/__init__.py`
- `apps/api/app/source_audit/__init__.py`
- `apps/api/app/worker/tasks.py`
- campaign/scope portions of `apps/api/app/main.py`
- campaign/budget/redaction portions of `apps/api/app/repository.py`
- related sections of `apps/api/tests/test_campaign_api.py`,
  `test_campaign_orchestrator.py`, `test_database_repository.py`,
  `test_policy_ingestion.py`,
  `test_source_audit.py`, `test_studio_api.py`, and `test_worker.py`

Review focus:

- a campaign cannot start or resume without an in-scope saved rule;
- budget accounting never grants execution and dispatch failures are auditable;
- policy parsing remains conservative and source intake stays inside authorized
  local roots;
- sanitization does not treat token-usage counters as secrets.

## Unit 4: stateful Candidate Hunter loop and release benchmark

Purpose: run one bounded, resumable Candidate Hunter loop per eligible Studio
pipeline run and make its persisted output reproducible against fully synthetic,
authorized, redacted A+B fixtures without exposing a runtime benchmark endpoint.

Files:

- `apps/api/app/candidate_hunter_loop.py`
- `apps/api/app/codebase_map/__init__.py`
- `apps/api/app/intelligence_benchmark/__init__.py`
- `apps/api/app/intelligence_benchmark/release_v1.py`
- `apps/api/app/intelligence_benchmark/release_fixtures.py`
- `apps/api/app/intelligence_benchmark/release_runner.py`
- `apps/api/app/cli.py`
- Candidate Hunter integration portions of `apps/api/app/main.py`
- `apps/api/tests/fixtures/candidate_hunter_release/`
- `apps/api/tests/test_candidate_hunter_loop.py`
- `apps/api/tests/test_candidate_hunter_release_benchmark.py`
- `apps/api/tests/test_candidate_hunter_release_fixtures.py`
- `apps/api/tests/test_candidate_hunter_release_runner.py`
- `apps/api/tests/test_codebase_map.py`
- Candidate Hunter integration portions of `apps/api/tests/test_studio_api.py`

Review focus:

- one read-only Campaign/Task owns each eligible run and persists immutable,
  idempotent snapshot, evidence-request, decision, and rerank Stages;
- initial Studio facts remain unresolved until bounded local re-analysis, while
  concrete HAR routes correlate safely with template API/code routes;
- evidence requests carry refutation questions and local inspection targets,
  and terminal decisions cite only observed facts;
- all safety booleans remain false and unsafe/secret-bearing output hard-fails;
- fixture inputs contain no real user data, raw credentials, or external target
  access;
- suite aggregation does not hide zero-denominator or invalid-decision failures;
- CLI evaluates caller-provided JSON only and cannot dispatch validation or
  submit a report.

## Unit 5: truthful Web mutation outcomes

Purpose: remove UI fallbacks that could display a successful mutation after the
API rejected it, while preserving read-only demo data and submission blocks.

Files:

- `apps/web/lib/api.ts`
- `apps/web/lib/api.test.ts`
- `apps/web/app/page.tsx`
- `apps/web/lib/pipeline-runs-data.test.ts`
- mutation pages under `apps/web/app/campaigns/[campaignId]/`
- `apps/web/app/reports/[runId]/page.tsx`
- `apps/web/app/source-audit/page.tsx`
- `apps/web/app/validation-workspace/[runId]/page.tsx`
- `apps/web/app/studio/studio-workbench.tsx`
- `apps/web/lib/campaigns-data.test.ts`
- `apps/web/lib/studio-data.test.ts`

Review focus:

- rejected and network-failed POSTs produce explicit blocked/error state rather
  than a fallback record;
- the static dashboard uses its explicit demo Scope Guard decision and makes no
  build-time POST;
- manual validation, promotion, cycle review, Studio, and report flows remain
  human-gated with execution and submission blocked.

## Commit sequence

1. `ef58cca0` `fix(db): run migrations during initialization`
2. `db7adba4` `feat(api): add program creation endpoint`
3. `6435bb1c` `fix(campaigns): enforce runtime guardrails`
4. `f5c15c92` `feat(hunter): add stateful candidate loop`
5. `6531797e` `fix(web): stop masking failed mutations`

Shared files were staged by behavior so each commit retains a focused review
surface. Re-run the baseline evidence after any commit is changed or separated.
