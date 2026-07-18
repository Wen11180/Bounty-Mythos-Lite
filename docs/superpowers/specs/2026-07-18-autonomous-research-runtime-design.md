# Autonomous Research Runtime Design

**Date:** 2026-07-18
**Status:** Proposed

## Purpose

This design delivers the first executable vertical slice toward the Mythos-Lite
autonomous vulnerability research system:

```text
approved local policy / scope / API / HAR / code
-> durable campaign tick
-> target and attack-surface facts
-> candidate hypotheses
-> refutation and deduplication
-> redacted report-draft review work
-> human-approved validation queue
```

It makes the research control plane run for a bounded period, survive process
restarts, and advance only from persisted, authorized evidence. It does not
turn Mythos-Lite into an unattended scanner or exploit system.

## Scope

### In scope

- A durable, resumable Campaign research runtime for authorized local inputs.
- One bounded work item per tick, selected from persisted campaign state.
- Deterministic advancement through attack-surface mapping, hypothesis
  generation, refutation, deduplication, ranking, and report-review work.
- Audit stages that record inputs, decisions, stop reasons, and fixed-false
  permission fields.
- A validation handoff that can create only a human-review work item.
- A replay-safe scheduler entrypoint usable by inline workers, Celery workers,
  or a future local Studio timer.

### Out of scope

- Target enumeration, public scanning, mutation fuzzing, exploitation, or
  unapproved network traffic.
- Automatic human approval, validation execution, finding promotion, or report
  submission.
- Replacing the existing short-lived remote black-box lease. That lease remains
  the only path that may perform its narrow, human-approved replay.
- Storing raw source bodies, secrets, cookies, authorization headers, or real
  user data in campaign or stage payloads.
- A new dashboard, a generic workflow engine, or a schema migration in the
  first slice.

## Current Constraints

The implementation must reuse the existing `CampaignRecord`,
`CampaignTaskRecord`, `AgentRunRecord`, `PipelineStageRecord`, and Campaign
budget records. The current `campaign_orchestrator.tick_campaign` dispatches a
single fixed read-only batch and then waits for review. The existing
`candidate_hunter_loop` persists bounded evidence/refutation rounds for one
pipeline run, while `candidate_hunter_evidence` can materialize and resume one
local evidence inspection task. Those contracts are the foundation, not
parallel state stores.

The full runtime must preserve these invariants on every transition:

- the effective Scope Guard rule is present and `in_scope`;
- all research inputs are local, authorized, and redacted projections;
- each permission flag remains false: `execution_allowed`,
  `validation_allowed`, `candidate_promotion_allowed`, and
  `report_submission_allowed`;
- a model proposal is an unverified candidate, never authority or evidence;
- a validation request is a human gate, never a dispatch command;
- any ambiguity, stale policy, exhausted budget, or malformed persisted state
  fails closed.

## Selected Architecture

The runtime is a state machine owned by one Campaign. It has two separate
planes.

### Research control plane

The control plane only reads approved artifacts and writes redacted facts,
candidate decisions, queue state, and report-draft readiness. It may run
without an operator while its scope snapshot remains effective.

```text
campaign tick
-> scope and budget preflight
-> choose one persisted research task
-> dispatch local read-only worker
-> save immutable result stage
-> recompute queue and next due time
```

Each tick performs at most one task. This prevents a restart or retry from
amplifying work and makes every state transition observable.

### Validation plane

When a retained candidate needs validation, the control plane creates a
`needs_human_approval` validation work item. It cannot issue a remote lease,
run a browser, or change a validation record to executable. A human may later
use the existing Scope Guard preflight and short-lived black-box lease. Its
redacted outcome is then imported as evidence and wakes the control plane for a
new review tick.

```text
retained candidate
-> validation work item (blocked)
-> human approval and existing bounded verifier
-> redacted evidence import
-> refutation / report-review tick
```

## State Model

The mutable Campaign status remains a high-level summary. Immutable Pipeline
Stages and completed Agent Runs are authoritative. The runtime derives its next
action from them after every restart.

| Runtime state | Required evidence | Next action | Terminal condition |
| --- | --- | --- | --- |
| `intake_ready` | approved scope and artifact manifest | map surface | missing or invalid scope blocks |
| `surface_ready` | route/code/API/HAR facts | generate or enrich hypotheses | no supported facts completes empty |
| `hypotheses_ready` | traceable candidate states | refute/deduplicate/rank | no candidate becomes explicit empty result |
| `needs_local_evidence` | bounded local inspection request | inspect authorized artifact | unavailable artifact awaits review |
| `review_ready` | retained Top 1-5 candidates | create report-review and optional validation work | human review required |
| `awaiting_validation` | approval-gated validation item | wait for human evidence | no automatic dispatch |
| `completed` | final report-review projection | stop | new artifact snapshot creates a new run |
| `blocked` | preflight failure | stop | explicit human correction only |

The queue is recomputed rather than stored as an independent source of truth.
Task identity is `campaign_id + task_type + source_snapshot_digest`. An
idempotency key includes the campaign ID, source snapshot digest, stage key,
and input digest. A retry may reuse an identical completed stage but may not
rewrite it.

## Work Item Selection

The runtime recognizes exactly these work items in the first slice:

1. `campaign_observation`: read campaign scope, budgets, prior stages, and
   approved artifact manifest.
2. `attack_surface_mapping`: invoke existing static code/API/HAR mapping only.
3. `hypothesis_generation`: invoke the existing local candidate/hunter path;
   optional LLM proposals must pass fact-bound validation.
4. `candidate_refutation`: resume the existing Candidate Hunter loop or its
   evidence specialist when an authorized local artifact can resolve a gap.
5. `finding_dedup_and_rank`: recompute deterministic clusters and Top 1-5
   priority order from observed root cause, route, and evidence references.
6. `report_review`: generate the existing submission-blocked report preview
   and create review/validation gates only.

Selection order is dependency-first, then risk priority, then stable task ID.
The runtime cannot schedule a later task until all required prior stages are
complete or explicitly blocked. A task with no new evidence is terminal for
the current source snapshot and records `no_state_change`, not a retry loop.

## Tick Contract

The proposed service interface is deliberately narrow:

```python
def tick_autonomous_research_campaign(
    campaign_id: str,
    *,
    repository: DatabaseRepository,
    dispatcher: DispatchCampaignTask,
    now: datetime | None = None,
) -> dict[str, object]:
```

It returns only safe summary fields:

- `status`: `dispatched`, `awaiting_evidence`, `awaiting_review`, `completed`,
  or `blocked`;
- one optional `campaign_task_id`;
- a `stop_reason` or `next_due_at`;
- fixed-false permission fields.

It accepts neither raw code, credentials, target URLs, validation payloads, nor
model prompts. Workers load only existing authorized projections referenced by
the selected task.

The API and Studio timer use the same service. A timer is a wake-up mechanism,
not a source of permission: it may call the tick only while the campaign is
running and its next due time has passed. Celery remains an optional executor.
Inline mode must produce the same persisted result.

## Scheduling and Recovery

The first production-like runtime uses conservative bounded cadence:

- one work item per tick;
- at least 60 seconds between automatic ticks for the same campaign;
- no more than 20 local research work items per source snapshot;
- all existing time, token, and tool-call budgets remain hard ceilings;
- `awaiting_review`, `awaiting_validation`, `blocked`, and `completed`
  campaigns are never auto-ticked;
- an evidence result may schedule an immediate next tick, still subject to the
  one-work-item rule.

On startup, the Studio host may query due running campaigns and schedule the
nearest tick. It must not launch a network-capable browser, issue a validation
lease, or process a campaign with a stale or unapproved scope snapshot. If the
host is down, no work occurs; the next start reconstructs due work from the
database and continues safely.

## Deduplication and Ranking

The first slice improves only the existing observed-fact deduplication. A
candidate cluster requires matching normalized vulnerability family, root-cause
identity, and affected route/component evidence. Ambiguous candidates remain
separate and receive a `deduplication_review_required` blocker.

Ranking uses deterministic inputs only:

1. survived refutation score;
2. evidence completeness;
3. existing priority/risk score;
4. stable candidate ID.

The Top 1-5 projection contains only retained, traceable candidates. It never
changes a candidate into a confirmed vulnerability or submission-ready report.

## Reporting and Learning

Each `report_review` tick builds the existing claim ledger and records missing
evidence, validation status, provenance, and human-review blockers. A report
is always `submission_blocked`.

Learning signals remain advisory. Field-pilot feedback may adjust future
ranking hints only after operator-confirmed, redacted feedback. It cannot make
scope effective, schedule validation, elevate a candidate, or submit a report.

The runtime-quality release gate will eventually require real authorized,
redacted outcomes. It must not treat fixture precision as a substitute for
external report quality.

## Failure Handling

| Condition | Required behavior |
| --- | --- |
| scope missing, stale, changed, or out of scope | write blocked stage; dispatch nothing |
| budget exhausted | write paused/blocked stage; preserve all prior evidence |
| duplicate tick or worker retry | reuse idempotent stage; do not duplicate task or Agent Run |
| local evidence unavailable | write `awaiting_evidence`; request human review only |
| worker error | mark only that work item failed; retain campaign audit state and allow explicit retry |
| malformed prior stage or unsafe flag | fail closed with no final candidates |
| remote verification required | create only human approval work; no browser or network call |

## Test Strategy

Development follows red-green-refactor. Tests are written before runtime code.

1. Pure selection tests cover dependency order, stable ordering, cadence,
   budget exhaustion, and terminal no-progress behavior.
2. Repository tests cover idempotent task/stage creation, restart recovery,
   exactly-one work item per tick, and immutable audit stages.
3. Worker tests cover every permitted work item and prove that none receive raw
   source bodies or network execution permission.
4. Safety tests cover scope loss, stale policy, malformed stages, secret-like
   values, and all permission flags.
5. Studio integration tests prove a local campaign advances across at least
   three persisted ticks, pauses at a human validation gate, then resumes only
   after a redacted evidence result.
6. Existing Candidate Hunter, black-box lease, report, and field-pilot tests
   must remain green.

## Acceptance Criteria

The first runtime slice is complete only when current-worktree evidence proves:

- a running in-scope campaign survives restart and advances one authorized
  research item per due tick;
- each advancement has immutable, idempotent, redacted audit records;
- target facts, hypotheses, refutation, deduplication, ranking, and a
  submission-blocked report-review projection occur in the same campaign;
- budget, scope, stale-policy, and malformed-state failures stop work safely;
- validation remains a human-approved handoff and no automatic remote request
  occurs;
- a simulated multi-hour run produces bounded progress without duplicated
  tasks or unbounded retries; and
- backend, Studio, Web, Compose, and release-gate verification remain green.

## Follow-on Deliveries

After this slice is proven, the remaining end-state work is intentionally
separate:

1. broaden local language/framework semantic analysis and attack-surface
   evidence;
2. harden human-approved validation evidence import across authorized targets;
3. collect field-pilot outcomes and calibrate ranking/report quality;
4. operate the runtime for multi-day authorized research with operational
   observability and recovery drills.
