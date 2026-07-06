# Mythos-Lite Autonomous Implementation Blueprint

## Goal

Build Mythos-Lite as an authorized autonomous vulnerability research system, not a passive scanner or dashboard.

The system should run bounded research campaigns that can read authorized materials, map attack surfaces, generate hypotheses, refute weak candidates, plan safe validation, pause for approval, build evidence, draft reports, and learn from outcomes.

It must not become unrestricted exploitation automation.

## Parallel Agent Findings

This blueprint integrates six parallel analysis tracks.

| Agent | Dedicated goal | Main output |
| --- | --- | --- |
| Architecture Agent | Define the final Mythos-Lite autonomous system architecture. | Use `ResearchCampaign` as the primary object and build a durable orchestrator around tasks, agent runs, approvals, budgets, and audit records. |
| Backend Data Agent | Define the database and API foundation. | Add normalized campaign, task, agent-run, approval, pipeline-stage, codebase-map, scanner-run, and validation-run records before adding deeper autonomy. |
| Orchestrator Agent | Design the autonomous agent loop and worker model. | Use a hybrid DB-backed orchestrator plus bounded Celery worker tasks. Celery runs work; the database owns state. |
| Safety Agent | Define hard safety boundaries and validation rules. | Make Scope Guard the central runtime authority. Durable approval records replace caller-supplied approval booleans. |
| Frontend Agent | Define the operator control center. | Pivot UI from run-centric workbench to Campaign Control Center with agent runs, validation queue, evidence review, and report drafts. |
| Delivery Agent | Define engineering release readiness. | Fix migration drift, add CI, harden Docker migration flow, and keep safety regression tests as release blockers. |

## Final Product Shape

Mythos-Lite should revolve around a `ResearchCampaign`.

Campaign loop:

```text
observe -> model -> hypothesize -> plan -> validate -> refute -> report -> learn
```

Runtime boundary:

```text
UI/API
  -> Campaign Orchestrator
    -> Campaign Tasks
      -> Agent Runs
        -> Scope Guard
        -> Approval Records
        -> Evidence/Provenance
        -> Audit Events
```

The orchestrator is the only component allowed to advance campaign state. Specialist agents must operate through durable task records and Scope Guard decisions.

## Non-Negotiable Safety Rules

- Authorized targets and user-provided or explicitly authorized artifacts only.
- No public-target attack automation without explicit scope and approval.
- No destructive validation, DoS, credential attacks, social engineering, or high-frequency scanning.
- No real user data access or storage.
- No raw secret, token, cookie, credential, or authorization-header storage.
- No automatic bounty submission.
- Unknown validation modes fail closed.
- LLM, scanner, imported, or agent output is never confirmed fact without evidence and review.
- Learning memory can rank and explain; it cannot grant permission.
- Every autonomous action must record input refs, output refs, status, gate decision, actor/agent, timestamp, and stop reason.

## Priority 0: Stabilize The Foundation

### P0.1 Delivery Baseline

Tasks:

- Run current API and web tests.
- Record the supported local workflow in README.
- Confirm Docker Compose config.
- Identify unrelated dirty worktree changes before editing implementation files.

Verification:

```powershell
cd apps/api; python -m pytest
cd apps/web; npm run test; npm run lint; npm run build
docker compose -f infra/docker-compose.yml config
```

### P0.2 Migration Correctness

Tasks:

- Add missing Alembic migration for `learning_signals.target_relationships`.
- Make Alembic the production schema source of truth.
- Keep `Base.metadata.create_all()` limited to tests or explicit demo/dev paths.
- Ensure the API Docker image can run Alembic by copying `alembic.ini` and migrations.

Verification:

```powershell
cd apps/api
$env:DATABASE_URL="sqlite:///./migration-check.db"
alembic upgrade head
python -m pytest tests/test_database_repository.py tests/test_mythos_brain_api.py
```

## Priority 1: Autonomous Data Foundation

Add first-class records before adding more autonomous behavior.

Required tables:

- `campaigns`
- `campaign_budgets`
- `campaign_tasks`
- `agent_runs`
- `approval_records`
- `pipeline_stages`

Minimum repository methods:

- `create_campaign`
- `list_campaigns`
- `get_campaign`
- `update_campaign_status`
- `upsert_campaign_budget`
- `create_campaign_task`
- `list_campaign_tasks`
- `update_campaign_task_status`
- `save_agent_run`
- `finish_agent_run`
- `create_approval_record`
- `decide_approval_record`
- `save_pipeline_stage`

Minimum API:

- `POST /mythos/campaigns`
- `GET /mythos/campaigns`
- `GET /mythos/campaigns/{campaign_id}`
- `POST /mythos/campaigns/{campaign_id}/start`
- `POST /mythos/campaigns/{campaign_id}/pause`
- `POST /mythos/campaigns/{campaign_id}/resume`
- `GET /mythos/campaigns/{campaign_id}/tasks`
- `GET /mythos/campaigns/{campaign_id}/agent-runs`
- `GET /mythos/campaigns/{campaign_id}/approvals`
- `POST /mythos/approvals/{approval_id}/decisions`

Verification:

- Schema tests assert tables and foreign keys exist.
- Repository tests cover create/list/get/update and ordering.
- API tests cover create/list/detail/start/pause/resume.
- Redaction tests prove secrets, tokens, cookies, emails, JWTs, and raw policy text are not persisted or returned.

## Priority 2: Scope Guard Runtime And Approval Service

Tasks:

- Turn Scope Guard into the central runtime authority.
- Store policy-derived rules and approval records; do not trust request-level `human_approved`.
- Bind approval to actor, timestamp, campaign id, task id, asset, validation mode, plan digest, allowed accounts, budget, expiry, and reason.
- Add explicit states: `approved`, `denied`, `revoked`, `expired`, `used`.
- Add fail-closed behavior for missing policy, unknown mode, ambiguous scope, approval mismatch, and plan digest mismatch.

Verification:

- Out-of-scope asset blocks.
- Unknown validation mode blocks.
- Missing approval produces `awaiting_approval`, not execution.
- Expired or mismatched approval blocks.
- Approval never authorizes forbidden validation classes.

## Priority 3: Campaign Orchestrator Skeleton

Implement the first safe autonomous loop.

Campaign states:

- `draft`
- `ready`
- `running`
- `paused`
- `awaiting_approval`
- `blocked`
- `completed`
- `failed`
- `canceled`

Task states:

- `queued`
- `scope_checking`
- `ready`
- `dispatched`
- `running`
- `completed`
- `awaiting_approval`
- `blocked`
- `failed_retryable`
- `failed_terminal`
- `skipped`
- `canceled`

Core functions:

- `create_campaign`
- `plan_campaign_tick`
- `dispatch_ready_tasks`
- `reconcile_agent_run`
- `stop_campaign`

Celery tasks:

- `campaign.tick(campaign_id)`
- `agent.run(task_id)`

Rules:

- Celery receives only IDs, never raw policy text, prompts, secrets, cookies, tokens, or evidence payloads.
- Workers reload campaign/task from DB and rerun Scope Guard.
- Workers write `agent_runs`.
- Budget is reserved before dispatch and settled after completion.
- Stuck tasks use leases/heartbeats and become retryable.

Verification:

- Orchestrator does not dispatch when paused, blocked, canceled, or out of budget.
- Scope Guard is called before dispatch and inside worker execution.
- Agent run records include input refs, output refs, status, safety gate state, stop reason, and timestamps.
- Retry caps produce terminal failures.

## Priority 4: Artifact, Codebase, And Scanner Fact Layer

Add:

- `codebase_maps`
- `codebase_facts`
- `scanner_runs`

Codebase map must extract:

- Routes and handlers.
- Controllers and services.
- Data models and identifiers.
- Authn/authz checks.
- Role and permission hints.
- Sensitive sinks and state-changing functions.
- Source-to-route relationships.

Scanner runs:

- Local/static tools and SARIF only at first.
- Store command hash and summaries, not raw sensitive stdout.
- Treat findings as candidates, never confirmed vulnerabilities.

Verification:

- Code facts link to source and provenance.
- Secret-like content is redacted or rejected.
- Scanner output cannot become report evidence without review.

## Priority 5: Hypothesis, Exploit Chain, And Refutation Loop

Tasks:

- Merge artifacts, code facts, scanner facts, and policy facts into a target graph.
- Generate security invariants.
- Generate many hypotheses with source facts, broken invariant, evidence needed, validation mode, risk, duplicate risk, and policy risk.
- Add exploit-chain reasoning as structured output: primitives, preconditions, required roles, required objects, impact, confidence, and refutation questions.
- Run refutation before validation planning.

Verification:

- Candidates are labeled as candidates, not confirmed findings.
- Out-of-scope, duplicate, self-impact-only, best-practice-only, weak-impact, and real-user-data-dependent candidates are blocked or parked.
- Report drafts cannot use model reasoning as observed fact.

## Priority 6: Validation Queue And Harness

Add `validation_runs`.

Allowed default modes:

- Static/local checks.
- Local fixture repro.
- Unit or local regression tests.
- Static tool run.

Approval-required modes:

- Role matrix check.
- Two-account authorization comparison.
- Redacted request/response diff against explicitly approved test accounts.

Forbidden modes:

- Destructive validation.
- DoS.
- Credential attacks.
- Social engineering.
- Unauthorized public-target scanning.
- Real user data access.
- Automatic report submission.

Verification:

- Local fixture validation can run.
- Live/test-account validation without matching approval blocks.
- Postflight secret/PII detection blocks evidence promotion.
- Rate and budget limits stop execution.

## Priority 7: Evidence, Claims, Reports, And Learning

Tasks:

- Normalize evidence records when filtering/review needs exceed current JSON payloads.
- Separate evidence display from evidence promotion.
- Add claim review workflow with observed facts, model reasoning, unverified claims, refuted claims, and reviewed facts.
- Keep report generation draft-only and submission-blocked.
- Feed outcomes into Mythos Brain as advisory lessons.

Verification:

- Unsupported evidence is rejected.
- Redacted-only evidence cannot support claims.
- Unsafe artifacts cannot enter report chain.
- `submission_blocked` remains true for all generated reports.
- Learning cannot approve validation or remove Scope Guard blockers.

## Priority 8: Campaign Control Center

Top-level UI should become:

- Campaigns.
- Campaign Detail.
- Agent Runs.
- Attack Surface Map.
- Codebase Map.
- Hypothesis Board.
- Validation Queue.
- Evidence Review.
- Report Drafts.
- Brain.

Every page must distinguish:

- `live`
- `dry_run`
- `fallback_demo`
- `blocked`
- `approval_required`
- `report_chain_unsafe`

P0 frontend tasks:

- Add campaign API types.
- Add `/campaigns`.
- Add `/campaigns/[campaignId]`.
- Add read-only validation queue.
- Add reusable `DataModeBadge`, `SafetyStateBadge`, `Metric`, `SectionHeader`, and `Field` components.

Verification:

- Route smoke tests for campaigns, campaign detail, validation queue, and agent runs.
- Badge tests for all data/safety states.
- Redaction helpers are used anywhere agent outputs, approval reasons, artifacts, or evidence are displayed.

## Implementation Order

1. Fix migration drift and CI/Docker baseline.
2. Add campaign core tables and repository/API tests.
3. Add durable approval records and Scope Guard runtime checks.
4. Add orchestrator skeleton using current dry-run pipeline as first campaign workflow.
5. Add agent run persistence and Celery bounded task execution.
6. Add codebase map and scanner run records.
7. Add target graph, hypothesis, exploit-chain, and refutation task loop.
8. Add validation queue and constrained local/static harness.
9. Add evidence/claim/report/learning promotion workflow.
10. Build Campaign Control Center pages over the stable APIs.

## Definition Of Done

Mythos-Lite reaches the intended system shape when a user can:

1. Create an authorized research campaign.
2. Provide scope, policy, artifacts, local code, allowed tools, budgets, and autonomy level.
3. Start a campaign that autonomously runs safe read-only and local/static research tasks.
4. See agent runs, blockers, approvals, stop reasons, and budget usage.
5. Review hypotheses, exploit-chain reasoning, refutation decisions, and validation plans.
6. Approve narrow validation batches where allowed.
7. Review redacted evidence and claim quality.
8. Generate submission-blocked report drafts.
9. Feed outcomes into advisory learning memory.
10. Prove through tests that safety gates cannot be bypassed.
