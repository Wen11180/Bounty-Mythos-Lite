# Autonomous Research Runtime Implementation Plan

> Every production behavior starts with a focused failing test. Scope Guard,
> durable approval, redaction, and submission blocking remain hard invariants.

## Phase 0: Verified Contracts

| Need | Existing contract | Source |
| --- | --- | --- |
| Read-only dispatch | `dispatch_agent_task(campaign_task_id=...)` and `run_agent_task(task_id, repository=...)` | `apps/api/app/worker/tasks.py:35-84` |
| Campaign/task persistence | `create_campaign`, `upsert_campaign_budget`, `create_campaign_task`, `list_campaign_tasks` | `apps/api/app/repository.py:1079-1237` |
| Audit append | `save_pipeline_stage(...)` has idempotency-key lookup | `apps/api/app/repository.py:1582-1625` |
| Budget preflight | `_campaign_stop_reason` and related helpers | `apps/api/app/campaign_orchestrator/__init__.py:206-314` |
| Candidate refutation | `run_candidate_hunter_loop(...)`, `load_candidate_hunter_projection(...)` | `apps/api/app/candidate_hunter_loop.py:2116-2605` |
| Evidence resume | `materialize_evidence_inspection_task`, `run_evidence_inspection_task`, `resume_candidate_hunter_after_evidence` | `apps/api/app/candidate_hunter_evidence.py:42-305` |
| Report gate | `build_report_preview_response(record)` | `apps/api/app/mythos_report/__init__.py:171-276` |

### Guards

- Do not replace `tick_campaign(...)`; its four-task batch remains the
  backwards-compatible manual campaign flow.
- Do not call `update_pipeline_stage_status(...)` for autonomous-runtime
  stages. Append idempotent stages instead.
- Do not put raw code bodies, credentials, target URLs, prompts, or real-user
  data in task or stage payloads.
- Do not use plan-only scheduler modules as execution engines.
- Do not issue a remote lease, invoke validation preflight, or start a browser
  from an autonomous tick.

## Phase 1: Pure Tick Selection and Safety Contract

### Files

- Add `apps/api/app/autonomous_research_runtime.py`.
- Add `apps/api/tests/test_autonomous_research_runtime.py`.

### RED tests

1. A running in-scope Campaign with no runtime stages selects only
   `campaign_observation`.
2. Selection advances in dependency order: observation, attack-surface map,
   hypothesis generation, Candidate Hunter refutation, dedup/rank, report
   review.
3. Paused, terminal, out-of-scope, stale, or exhausted Campaigns select no
   work and return a safe stop reason.
4. An active autonomous task prevents a duplicate tick.
5. A malformed or unsafe prior runtime stage fails closed.
6. Every result has fixed-false execution, validation, promotion, and
   submission fields.

### GREEN implementation

1. Copy only the existing budget/status checks from
   `campaign_orchestrator/__init__.py:206-314` into a focused preflight helper.
2. Add pure `select_autonomous_research_work(...)` that returns one stable
   work-item specification or a stop result.
3. Derive source-snapshot identity from existing safe provenance digests. A
   missing digest blocks rather than inventing an ID.
4. Export `tick_autonomous_research_campaign(...)`; it does not dispatch work
   in this phase.

### Verify

```powershell
& .\.venv\Scripts\python.exe -m pytest apps/api/tests/test_autonomous_research_runtime.py -q
& .\.venv\Scripts\python.exe -m pytest apps/api/tests/test_campaign_orchestrator.py -q
```

## Phase 2: One-Work-Item Durable Dispatch

### Files

- Extend `apps/api/app/autonomous_research_runtime.py`.
- Extend `apps/api/app/worker/tasks.py` only for new safe task routing.
- Extend `apps/api/tests/test_autonomous_research_runtime.py` and
  `apps/api/tests/test_worker.py`.

### RED tests

1. One due tick creates one deterministic Campaign Task, Agent Run, and
   append-only runtime stage, then dispatches only its task ID.
2. Replaying the same tick reuses the task/stage and does not dispatch again.
3. Inline and Celery dispatch expose the same safe task identity.
4. Worker failure records a failure stage and permits explicit safe retry
   without duplicating successful prior work.
5. Runtime payloads contain references/projections only and reject raw source,
   secret, cookie, token, and real-user-data markers.

### GREEN implementation

1. Reuse `create_campaign_task`, `save_agent_run`, and
   `save_pipeline_stage`, with a runtime idempotency key patterned after
   `candidate_hunter_loop.py:2867-2877`.
2. Use the existing ID-only `dispatch_agent_task` seam. Preserve inline/Celery
   behavior rather than adding a second queue.
3. Derive cadence from the latest runtime stage and `now`; do not add a
   migration or another scheduler table.

### Verify

```powershell
& .\.venv\Scripts\python.exe -m pytest apps/api/tests/test_autonomous_research_runtime.py apps/api/tests/test_worker.py -q
& .\.venv\Scripts\python.exe -m pytest apps/api/tests/test_database_repository.py -q
```

## Phase 3: Candidate Hunter, Evidence, Deduplication, and Report Handoff

### Files

- Extend `apps/api/app/autonomous_research_runtime.py`.
- Extend `apps/api/app/worker/tasks.py` narrowly for
  `candidate_refutation`, `finding_dedup_and_rank`, and `report_review`.
- Extend `apps/api/tests/test_autonomous_research_runtime.py`,
  `apps/api/tests/test_candidate_hunter_loop.py`, and
  `apps/api/tests/test_worker.py`.

### RED tests

1. A safe hypothesis Pipeline Run triggers the existing Candidate Hunter and
   records its projection without creating a parallel Campaign.
2. An evidence gap reuses the existing local evidence task; its redacted result
   makes the next tick eligible.
3. Persisted Candidate Hunter output is the sole input to dedup/rank. Refuted,
   suppressed, unresolved, and duplicate items never enter Top 1-5.
4. Report review builds only a submission-blocked preview and never creates an
   executable validation/remote-lease record.
5. Same-basename source files cannot collide in evidence references; ambiguity
   fails closed.

### GREEN implementation

1. Reuse `run_candidate_hunter_loop` and `load_candidate_hunter_projection`,
   never raw generation output.
2. Reuse Candidate Hunter evidence materialization/resume and validate immutable
   relative source manifests.
3. Rank from survived refutation, evidence completeness, priority, and stable
   candidate ID. `finding_dedup_risk` remains advisory, not decision authority.
4. Build report preview only from the persisted Pipeline Run and preserve
   human-review/submission-blocked states.

### Verify

```powershell
& .\.venv\Scripts\python.exe -m pytest apps/api/tests/test_autonomous_research_runtime.py apps/api/tests/test_candidate_hunter_loop.py apps/api/tests/test_candidate_hunter_evidence.py -q
& .\.venv\Scripts\python.exe -m pytest apps/api/tests/test_finding_dedup_risk.py apps/api/tests/test_candidate_report_bridge.py apps/api/tests/test_evidence_model.py -q
```

## Phase 4: Human-Gated Validation Handoff and Local Wake-Up

### Files

- Extend `apps/api/app/autonomous_research_runtime.py`.
- Extend `apps/api/app/main.py` only if an existing Campaign route cannot call
  the runtime service.
- Extend `apps/studio/main.cjs` and a focused scheduler helper only after the
  backend runtime is proven.

### RED tests

1. A retained candidate creates a human-review validation handoff whose
   execution, validation, and submission flags are false.
2. Approval, plan, scope, policy, origin, rate, or expiry changes stop further
   runtime work.
3. Studio wake-up schedules due local research ticks but never starts a browser
   context, remote lease, or validation request.
4. Restart recovery advances a due in-scope Campaign exactly once and leaves
   paused/review/validation/terminal Campaigns untouched.

### GREEN implementation

1. Reference existing approval/validation records only; do not call validation
   preflight or remote lease issuance from runtime code.
2. Add a local due-campaign helper following the launch/cleanup pattern in
   `apps/studio/main.cjs:1-134`.
3. Bound automatic work to one task per tick, 60-second minimum interval, and
   20 local work items per source snapshot.
4. On discrepancy, append a blocked stage and await human action.

### Verify

```powershell
& .\.venv\Scripts\python.exe -m pytest apps/api/tests/test_autonomous_research_runtime.py apps/api/tests/test_campaign_api.py -q
Set-Location apps/studio
npm test
```

## Phase 5: Full Verification

1. Run a simulated multi-hour Campaign with restart, evidence result,
   deduplication, report review, and approval-handoff checkpoints.
2. Run release fixtures through the persisted Candidate Hunter projection only;
   load gold after capture, not before.
3. Search outputs for source bodies, headers, cookies, tokens, credentials,
   real-user markers, validation execution, and report submission.
4. Run the full repository checks.

```powershell
& .\.venv\Scripts\python.exe -m pytest apps/api/tests -q

Set-Location apps/web
npm test
npm run lint
npm run build
npm run e2e

Set-Location ../studio
npm test

Set-Location ../..
docker compose -f infra/docker-compose.yml config --quiet
git diff --check
rg -n 'update_pipeline_stage_status' apps/api/app/autonomous_research_runtime.py
rg -n 'remote_lease|issue_remote_human_lease|context.request.fetch' apps/api/app/autonomous_research_runtime.py
```

## Completion Evidence

The slice is complete only with fresh evidence that an authorized Campaign
survives restart, advances one local research item per due tick, produces a
persisted Top 1-5/review projection, stops at the human validation boundary,
and keeps every safety flag false. Broader semantic coverage, real field-pilot
outcomes, and multi-day calibration remain follow-on work toward the full
system.
