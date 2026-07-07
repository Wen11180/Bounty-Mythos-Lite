# ChatGPT Project Review Brief

Date prepared: 2026-07-07

## How to use this file

Give this file to ChatGPT together with the repository, or paste it before uploading selected project files.

If ChatGPT only receives this file, ask for an architecture and risk review. If it also receives the repository, ask for a line-level code review with file and line references.

## Review prompt to give ChatGPT

You are reviewing Bounty Mythos-Lite, a lawful bug bounty research assistant. Review it as a senior product-security and full-stack engineering reviewer.

Do not propose public-target attack automation, destructive validation, DoS, credential attacks, social engineering, real-user-data access, raw secret storage, or automatic bounty submission. The product must remain a safe, auditable research workflow with Scope Guard, explicit human approval, redaction review, and submission-blocked report drafts.

Please produce findings first, ordered by severity. For each finding include:

- Severity: P0, P1, P2, or P3
- Location: file path and line reference if the repository is available
- Problem: what can go wrong
- Why it matters: safety, correctness, data integrity, UX, or maintainability impact
- Minimal fix: the smallest practical change
- Verification: tests or checks that should prove the fix

Focus especially on:

- Scope Guard and approval gates failing closed
- Stale approval, mismatched scope, mismatched campaign, and budget bypass risks
- Evidence promotion and report-chain safety
- Redaction of secrets, cookies, tokens, auth headers, and real user data
- Whether LLM, scanner, imported artifact, or model output can be mistaken for verified facts
- Whether learning signals can accidentally grant execution permission
- API response payload leaks and frontend fallback/demo/live-state confusion
- Database and migration consistency
- Test coverage gaps around the above

Avoid broad refactors. Prefer simple, surgical fixes that preserve current architecture.

## Project summary

Bounty Mythos-Lite is an authorized autonomous vulnerability research system for lawful bug bounty work. It is campaign-driven: policy parsing, Scope Guard checks, target modeling, hypothesis generation, refutation, non-destructive validation planning, evidence review, report drafts, and advisory learning loops.

It deliberately must not perform public-target scanning, exploit execution, destructive validation, credential attacks, real-user-data collection, or automatic bounty submission.

The intended research loop is:

```text
observe -> model -> hypothesize -> plan -> validate -> refute -> report -> learn
```

All live, sensitive, state-changing, or test-account validation must remain gated by Scope Guard, approval records, preflight, budget checks, redaction, and human review.

## Safety boundaries

Hard boundaries from `AGENTS.md` and product docs:

- Do not automatically attack public targets.
- Do not run destructive validation, DoS, credential stuffing, social engineering, or high-frequency scanning.
- Do not touch, collect, store, display, or report real user data.
- Do not save raw secrets, tokens, cookies, credentials, or authorization headers.
- Do not treat model output, scanner output, or imported third-party findings as confirmed vulnerabilities.
- Do not bypass Scope Guard, human approval, redaction review, or report submission gates.
- Do not submit reports automatically.
- Learning signals are advisory only and must not grant execution permission.

## Current implementation shape

Backend:

- `apps/api`: FastAPI API, SQLAlchemy persistence, Alembic migrations, Celery worker scaffold.
- Main API file: `apps/api/app/main.py`
- Persistence: `apps/api/app/db_models.py`, `apps/api/app/repository.py`
- Safety gate: `apps/api/app/scope_guard/__init__.py`
- Pipeline: `apps/api/app/mythos_pipeline/__init__.py`
- Reporting: `apps/api/app/mythos_report/__init__.py`
- Brain and learning: `apps/api/app/mythos_brain/__init__.py`
- Hunter scoring: `apps/api/app/hunter_intelligence/__init__.py`
- Worker research task materialization: `apps/api/app/worker/tasks.py`
- Code mapping: `apps/api/app/codebase_map/__init__.py`
- Artifact ingestion: `apps/api/app/artifact_ingestion/__init__.py`
- Target modeling: `apps/api/app/target_model/__init__.py`

Frontend:

- `apps/web`: Next.js dashboard/operator console.
- API client and shared types: `apps/web/lib/api.ts`
- Campaign data shaping: `apps/web/lib/campaigns-data.ts`
- Pipeline run shaping: `apps/web/lib/pipeline-runs-data.ts`
- Main dashboard: `apps/web/app/page.tsx`
- Campaign pages: `apps/web/app/campaigns/**`
- Run, report, artifact, and validation workspace pages: `apps/web/app/runs/**`, `apps/web/app/reports/**`, `apps/web/app/artifacts/**`, `apps/web/app/validation-workspace/**`

Infrastructure:

- `infra/docker-compose.yml` defines Postgres, Redis, API, worker, migrations, and web.
- Backend dependencies are pinned in `apps/api/requirements.txt`.
- Frontend dependencies and scripts are in `apps/web/package.json`.

## Primary API surfaces to review

The main API exposes these groups:

- Campaign lifecycle: create, list, start, pause, resume, control center.
- Campaign tasks and agent runs.
- Research task review, refutation decisions, feedback review, cycle review.
- Approval records and approval decisions.
- Validation runs, preflight, and manual results.
- Artifact repository and provenance filtering.
- Pipeline dry-run, pipeline run list/detail, report preview, claim review, manual observation, finding candidate promotion.
- Mythos Brain learning signals, lessons, and outcomes.
- LLM generation with audit records.
- Scope Guard evaluation.
- Sample programs, findings, and reports.

When reviewing, check that every route returning or mutating campaign, validation, evidence, report, learning, or approval state preserves the hard safety gates.

## Data model concepts

Core tables include:

- `programs`
- `artifacts`
- `findings`
- `reports`
- `llm_runs`
- `pipeline_runs`
- `campaigns`
- `campaign_budgets`
- `campaign_tasks`
- `agent_runs`
- `approval_records`
- `pipeline_stages`
- `codebase_maps`
- `codebase_facts`
- `scanner_runs`
- `validation_runs`
- `learning_signals`

Important review questions:

- Are approval records campaign-bound, scope-bound, plan-bound, and expiry-aware?
- Can terminal approval states be reopened or reused?
- Can validation runs execute from stale `allowed_to_execute`, `preflight_passed`, or polluted payload fields?
- Are report-chain blockers enforced when artifacts, evidence, or observations are unsafe?
- Can learning signal identity deduplication merge unrelated outcomes?
- Are JSON payload fields sanitized before display, export, report preview, and learning usage?

## Current known gaps from docs

The docs explicitly say the system is still a safe foundation, not a complete autonomous research crew.

Known gaps include:

- Specialist agents are not fully wired to independent tool workflows.
- Codebase map extraction needs deeper route/handler/authz/sink enrichment.
- Scanner run persistence and SARIF-to-target-model merge are incomplete.
- Exploit-chain reasoning is not yet a full workflow with primitive extraction and refutation questions.
- Validation remains intentionally constrained; no autonomous live validation harness should be added without stronger gates.
- Structured LLM workflows need tighter schemas, replayability, and campaign-stage wiring.
- Production authentication, tenant/workspace isolation, and secret management are required before hosted or multi-user use.

These are not necessarily bugs. Treat them as review context and prioritize issues that violate stated safety or correctness rules.

## Repository state note

At preparation time, the working tree already had many uncommitted changes. Treat the current files as the review target, but do not assume they are committed.

Observed scale:

- About 117 source/doc/test files in the main app and docs areas.
- `git diff --stat` showed 57 modified tracked files with roughly 16,578 insertions and 1,978 deletions, plus new files.
- Notable new or untracked areas included a migration `0010_learning_signal_identity_hash.py`, codebase map tests, validation/cycle/feedback review pages, workbench display helpers, and `docs/mythos-5-audit.md`.

## Suggested review order

1. Read `AGENTS.md`, `README.md`, and `docs/product/requirements-and-features.md`.
2. Review backend safety primitives: `scope_guard`, `repository`, `db_models`, `main`.
3. Review pipeline/report/evidence chain: `mythos_pipeline`, `mythos_report`, `evidence`, `mythos_finding`.
4. Review campaign orchestration and worker behavior: `campaign_orchestrator`, `worker/tasks.py`.
5. Review artifact/code/target modeling: `artifact_ingestion`, `codebase_map`, `target_model`.
6. Review learning and advisory memory: `mythos_brain`, `hunter_intelligence`.
7. Review frontend API types and data shaping: `apps/web/lib/api.ts`, `campaigns-data.ts`, `pipeline-runs-data.ts`, `workbench-detail-data.ts`.
8. Review UI pages for whether they clearly distinguish live, dry-run, fallback, blocked, approval-required, and report-chain-unsafe states.
9. Review tests for missing negative cases around stale approval, cross-campaign reuse, payload pollution, unsafe evidence, and secret redaction.

## Verification commands

Backend:

```powershell
cd apps/api
python -m pip install -r requirements.txt
python -m pytest
```

Frontend:

```powershell
cd apps/web
npm install
npm test
npm run lint
npm run build
```

Docker Compose configuration:

```powershell
docker compose -f infra/docker-compose.yml config --quiet
```

## Desired final output from ChatGPT

Please return:

1. Findings first, ordered by severity.
2. Open questions or assumptions.
3. Test gaps.
4. A short summary of the project health.
5. A minimal prioritized fix plan.

Keep recommendations scoped. Do not recommend features that expand autonomous exploitation or bypass human review.
