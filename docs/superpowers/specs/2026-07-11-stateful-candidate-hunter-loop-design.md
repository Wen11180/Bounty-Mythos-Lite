# Stateful Candidate Hunter Loop Design

## Status

Approved architecture for the next A+B Candidate Hunter slice. The selected
shape is one `candidate_hunter_loop` Campaign Task for each source pipeline
run, with immutable Pipeline Stage records carrying every round.

This specification extends:

- `2026-07-10-local-candidate-hunter-safety-design.md`;
- `2026-07-10-candidate-hunter-release-benchmark-design.md`.

It does not add a UI, a new database table, live validation, target contact,
or report submission. It also does not authorize a benchmark-specific path
that can see fixture labels or gold data.

## Problem

The current Studio research path persists a `PipelineRunRecord` and exposes up
to five candidate-shaped hypotheses. The release runner can capture those
candidates, but its normalizer always emits an empty `candidate_decisions`
list. Consequently, the controlled release suite currently finds candidates
but cannot prove evidence closure, refutation, duplicate suppression, or a
persisted final ranking.

The existing per-candidate `research_queue_review` Tasks are appropriate for
human review. They are not a good owner for a deterministic cross-candidate
loop because deduplication and Top 1-5 ranking require one consistent view of
all candidates from a pipeline run.

## Goals

1. Persist a real, resumable multi-round review loop for one pipeline run.
2. Re-analyze only authorized local artifacts in response to explicit evidence
   gaps and refutation questions.
3. Record why each candidate was retained, refuted, deduplicated, suppressed,
   or left unresolved.
4. Produce a deterministic Top 1-5 projection from persisted audit records.
5. Feed that same projection into the release benchmark without exposing the
   oracle to the Hunter.
6. Preserve Scope Guard, redaction, human approval, and submission blocking.

## Non-Goals

- Automatic validation, exploitation, scanning, fuzzing, or target requests.
- Treating a retained candidate as a confirmed vulnerability.
- Automatically promoting a candidate into a report or finding.
- Replacing the existing human `research_queue_review` workflow.
- A configurable workflow engine, a new state table, or a schema migration.
- LLM-based decisions in this first slice. A future LLM may propose observed
  facts, but it may not grant permission or bypass the deterministic gates.

## Existing Contracts Reused

The implementation reuses these current records and APIs:

- `CampaignRecord` carries scope, policy hash, autonomy, and budget context.
- `CampaignTaskRecord` carries one loop's current summary status.
- `PipelineStageRecord` is the immutable audit log for each loop round.
- `DatabaseRepository.save_pipeline_stage(...)` already deduplicates a stage
  by `pipeline_run_id`, `campaign_id`, `task_id`, `stage_key`, and payload
  `idempotency_key`.
- `DatabaseRepository.list_pipeline_stages_for_run(...)` reconstructs the
  persisted loop without reading transient process state.
- The release evaluator already accepts `final_candidates` and
  `candidate_decisions` and hard-fails unsafe permission flags.

No new table or Alembic migration is required.

## Ownership and Lifecycle

### One Dedicated Campaign and Task Per Eligible Pipeline Run

The loop entrypoint receives a `PipelineRunRecord`, its already redacted Studio
candidate view, and the policy text available at run creation. It first
requires the run's stored `scope_status` to be exactly `in_scope`. A missing,
blocked, or ambiguous status returns `scope_not_in_scope`, creates no Campaign
or Task, and produces no candidate projection.

For an eligible run, the entrypoint finds an existing `candidate_hunter_loop`
Task whose `input_refs` include `pipeline_run:<run_id>`. If found, it resumes
that Task. Otherwise it creates:

1. a dedicated read-only Campaign linked to the run in its payload; and
2. one `candidate_hunter_loop` Task in that Campaign.

The dedicated Campaign copies the source run's program, asset, policy hash via
the supplied policy text, and `scope_status`. It uses read-only autonomy and
allows only the existing static analyzer and API artifact mapper. Its
validation budget is zero. Its payload and the Task payload keep every
execution, validation, dispatch, promotion, and submission flag `false`.

The implementation must not opportunistically reuse an unrelated Campaign
merely because it has the same program. Reuse requires the exact pipeline-run
reference. This gives each run one unambiguous audit owner.

The local desktop application is a single-operator, synchronous deployment.
Task lookup plus creation is sufficient for this slice; the design does not
claim cross-process task-creation atomicity that the current schema cannot
provide. Stage writes remain idempotent.

### Task Status

The Task is a mutable summary only. Pipeline Stages are authoritative.

- `in_progress`: at least one round can still make progress;
- `completed`: every input candidate has a terminal decision and a final
  rerank exists, or the input candidate set is empty;
- `needs_evidence`: unresolved candidates remain but no authorized local
  observation can currently change state;
- `blocked`: Scope Guard or a safety invariant failed.

Changing Task status never rewrites a previous Stage.

## Candidate Identity and Evidence

The stable candidate key is `pipeline_run_id + hypothesis_id`. The
`hypothesis_id` must come from the persisted hypothesis or its existing
assessment candidate ID. A candidate without a stable observed ID remains
unresolved and cannot enter final output.

The following fields may be projected only when already observed in the
authorized run or its staged artifacts:

- vulnerability type;
- route method and template;
- root-cause ID;
- source-fact references;
- evidence-trace status;
- priority and ranking reasons;
- safe validation plan and safety blockers.

The loop may derive a stable reference from an observed artifact kind, path,
symbol, method, or route. It must not invent a root cause, route, evidence
reference, human-value label, or disposition. Missing required fields remain
missing and fail closed.

Every stored candidate and decision passes through the existing structured
redactor. Raw headers, bodies, tokens, cookies, credentials, secrets, and real
user data are never stage payloads or output refs.

## Components and Interfaces

The first implementation slice has four focused components in one Candidate
Hunter loop module:

1. **Observation projector**: receives the controlled workspace manifest, the
   persisted pipeline run, and the redacted Studio candidates. It uses the
   existing workspace resolvers and parsers to return only safe, cited facts
   from policy, scope, OpenAPI, HAR, and local code. It never returns raw file
   bodies or fixture metadata.
2. **Pure transition function**: receives the current candidate states plus
   safe observations and returns evidence requests, terminal decisions,
   unresolved states, and a deterministic rerank. It has no repository,
   filesystem, network, clock, or benchmark dependency.
3. **Persistence coordinator**: validates scope, creates or resumes the exact
   Campaign and Task for a run, invokes the pure transition for up to three
   rounds, and writes idempotent Stages.
4. **Projection loader**: validates the persisted Stage sequence and returns
   the final release-shaped candidates, decisions, and safe audit metadata.

The runtime entrypoint accepts ordinary domain values: repository, pipeline
run, policy text, and safe observations. It accepts no case ID, expected
disposition, fixture object, oracle, or `gold.json` path. The release runner
calls the same entrypoint used by Studio and only invokes the evaluator after
the projection loader has returned.

## Round Model

The loop runs at most three rounds. Each round appends four Stage types in this
order:

```text
candidate_hunter_snapshot
-> candidate_hunter_evidence_request
-> candidate_hunter_decision
-> candidate_hunter_rerank
```

Every Stage payload includes:

- `schema_version: candidate_hunter_loop_v1`;
- `round`;
- `idempotency_key`;
- the input state digest;
- `execution_allowed: false`;
- `dispatch_allowed: false`;
- `validation_allowed: false`;
- `candidate_promotion_allowed: false`;
- `report_submission_allowed: false`;
- `raw_payload_processed: false`.

The idempotency key is derived from the pipeline run, round, Stage type, and
input state digest. Replaying an identical partial or completed round returns
the existing Stage. A changed source artifact requires a new pipeline run; it
does not mutate the prior loop's history.

### Snapshot Stage

The snapshot contains the redacted candidate state at the start of the round,
including stable IDs, observed facts, evidence gaps, existing decisions, and
the prior rank. The first snapshot comes from the real Studio candidate view.
Later snapshots come from the prior rerank plus newly derived local facts.

### Evidence Request Stage

For every unresolved candidate, this Stage records:

- missing evidence references;
- unanswered refutation questions;
- the exact authorized local artifact kinds or symbols to inspect;
- why the requested observation can change a decision.

It then invokes bounded deterministic re-analysis of the already staged local
policy, scope, OpenAPI, HAR, and code artifacts. Re-analysis may add only facts
that cite those inputs. It cannot perform a network request, execute a
validation plan, read a gold file, or infer authority from caller data.

`needs_evidence` is represented only here. It is not a release
`candidate_decisions` disposition.

### Decision Stage

The Stage records one of these terminal decisions when its evidence rule is
satisfied:

- `retained`: evidence is traceable, required references are present, the
  candidate is not refuted or merged, and it is worth human review;
- `refuted`: decisive observed evidence disproves the candidate;
- `deduplicated`: the candidate shares an observed root cause with a retained
  canonical candidate and records that canonical root in `duplicate_of`;
- `suppressed`: observed scope, policy, reachability, or quality evidence makes
  the candidate out of scope or not worth human validation.

Every terminal decision has a nonempty list of observed evidence references.
A deduplicated decision also has a nonempty `duplicate_of`. A candidate that
does not satisfy a terminal evidence rule remains unresolved; absence from the
final list is not itself a decision.

Existing human research decisions keep their current vocabulary. When they
are present in the same audit chain, the projection maps only these explicit
states:

- `refuted` -> `refuted`;
- `parked_duplicate` -> `deduplicated`;
- `policy_blocked` -> `suppressed`.

`needs_evidence` remains unresolved. `needs_validation_review` may create the
existing approval/preflight records, but it does not become a benchmark
decision and never changes an execution flag.

### Rerank Stage

The rerank is computed from persisted snapshot facts and terminal decisions,
not from insertion order. It:

1. removes refuted, deduplicated, suppressed, and unresolved candidates;
2. sorts retained candidates by evidence completeness, existing priority
   score descending, then candidate ID ascending;
3. assigns stable ranks; and
4. emits at most five candidates.

The Stage also stores the release-shaped `candidate_decisions` projection for
all terminal decisions. The final candidates remain "worth human safety
validation," not confirmed findings. Their `execution_allowed`,
`validation_allowed`, and `report_submission_allowed` fields are always
`false`, and all required safety blockers remain present.

## Stop and Resume Rules

Scope eligibility is checked before Task creation and before any round. After
a round starts, it appends all four Stage types unless the process is
interrupted; a retry resumes from the first missing Stage.

The loop stops after a rerank when the first matching condition applies:

1. `all_candidates_terminal`: mark the Task completed;
2. `no_candidates`: complete with an empty projection;
3. `no_state_change`: mark the Task `needs_evidence` when a full round adds no
   facts or decisions;
4. `no_processable_candidates`: mark the Task `needs_evidence` when all
   unresolved requests require unavailable or unauthorized evidence;
5. `max_rounds_reached`: mark the Task `needs_evidence` after round three and
   omit unresolved candidates from the final projection.

On retry after a process failure, the loop reads the latest complete Stage,
reuses matching idempotent stages, and appends only missing work. It does not
delete or update old Stage payloads.

## Runtime Integration

The domain logic lives in a focused Candidate Hunter loop module. This is new
functionality, not a broad refactor of the current `main.py` hotspot.

`run_mythos_studio_workspace_research(...)` invokes the observation projector
and loop after the source pipeline run and the redacted Studio candidate view
exist. The existing raw candidate-list response can remain compatible; the
loop's authoritative final projection is read from its persisted rerank Stage.

The first implementation slice adds no new UI or public API route. Existing
Campaign Task and Pipeline Stage endpoints provide the audit view.

## Release Runner Integration

The release runner continues this order:

```text
stage authorized inputs
-> run the real Studio research path
-> complete/read the persisted Candidate Hunter loop
-> capture final projection and Stage audit
-> load gold
-> evaluate
```

The runner no longer normalizes raw Studio candidates with an empty decision
list. It reads `final_candidates` and `candidate_decisions` from the persisted
final rerank Stage. The Hunter entrypoint receives neither a
`ReleaseFixtureCase` nor any oracle data.

Each case result records safe loop audit metadata: Campaign ID, Task ID, round
count, Stage refs, final state digest, and stop reason. Release acceptance
requires both the existing metric gate and a valid persisted Stage sequence.
The pure evaluator's metric definitions remain unchanged.

## Benchmark Integrity Correction

The current 24-case corpus leaks the expected outcome through `case_id`, route
paths, operation IDs, policy text, and workspace names. In addition, the
retain, refute, and suppress code inputs within a family are nearly identical.
A Hunter could therefore appear to pass by reading words such as `retain` or
`refute`, while no semantic evidence distinguishes the outcomes.

That corpus cannot serve as the release-quality proof described by the
approved benchmark design. Before the stateful loop can be accepted, the
fixtures must be corrected as follows:

1. Use opaque case IDs and neutral route, operation, symbol, policy, and
   workspace names. No staged input may contain a disposition label.
2. Make outcomes semantically observable:
   - retain: a sensitive path reaches a sink without the required guard;
   - refute: a decisive ownership, role, tenant, or input guard is observed;
   - deduplicate: two surfaces share one observed vulnerable root cause;
   - suppress: policy, reachability, or safe implementation evidence makes the
     candidate low value without relying on a label.
3. Make every gold evidence reference derivable from the normal source-fact
   reference scheme.
4. Keep `gold.json` outside staged inputs and load it only after capture.
5. Add a leakage test that rejects outcome words in every staged path and
   content field.
6. Add a perturbation test proving that changing opaque case IDs or directory
   order does not change Hunter decisions.
7. Keep release cases out of loop unit-test expectations; only the release
   runner evaluates them against their isolated oracle.

Passing the current label-leaking corpus is not a completion criterion.

## Safety Invariants

Every entrypoint, Stage, projection, and test must prove:

- the source run is explicitly `in_scope`;
- all inputs are local, authorized, and redacted;
- no live target request or validation execution occurs;
- no real user data or raw secret is read into a Stage payload;
- model or heuristic output is evidence, not confirmation or authority;
- human review is required before any validation workflow;
- `execution_allowed`, `dispatch_allowed`, `validation_allowed`,
  `candidate_promotion_allowed`, and `report_submission_allowed` are `false`;
- report submission remains blocked.

Any missing or malformed safety field fails closed and yields no final
candidate projection.

## Test Strategy

Implementation follows red-green-refactor in this order:

1. Fixture-integrity tests fail on leaked labels and semantically
   indistinguishable outcomes, then the fixtures are corrected.
2. Pure loop tests cover stable identity, observed-only facts, all four
   decisions, unresolved candidates, deterministic deduplication, Top 1-5
   ranking, and every stop condition.
3. Repository integration tests prove one Task per run, immutable four-Stage
   rounds, idempotent replay, and resume after a partial round.
4. Safety tests prove out-of-scope runs, secrets, real-user-data markers, and
   any permission escalation produce no final candidates.
5. Studio integration tests prove the normal research path creates the loop
   and that at least one controlled case changes state across two rounds.
6. Release-runner tests prove all candidates and persisted decisions are
   captured before gold is loaded and that no fixture metadata reaches the
   Hunter entrypoint.
7. The corrected development suite must pass before the held-out release
   suite is run. The release suite must meet every existing metric threshold
   and the Stage-audit gate.
8. Full backend, Web test/lint/build, Studio, Compose, and diff checks remain
   required before completion.

## Delivery Order

1. Correct and lock the benchmark corpus against answer leakage.
2. Add the pure Candidate Hunter state transition and projection logic.
3. Add Campaign, Task, and immutable Stage persistence with resume support.
4. Integrate the loop into the real Studio research path.
5. Project persisted results into the release runner.
6. Meet the development and held-out release gates without weakening safety.
7. Only after the gate passes, resume the separately planned hotspot and
   shared-contract extraction work.

## Acceptance Criteria

This slice is complete only when all of the following are proven from the
current worktree:

- one and only one `candidate_hunter_loop` Task owns each eligible in-scope
  pipeline run, while an ineligible run creates no loop Task;
- the persisted four-Stage rounds are idempotent, resumable, and auditable;
- decisions cite observed evidence and unresolved items are not silently
  treated as rejected;
- final output contains 1-5 traceable retained candidates when qualifying
  candidates exist, otherwise an explicit empty result and stop reason;
- the corrected release suite meets all approved quality thresholds;
- the benchmark cannot infer outcomes from names, metadata, or gold data;
- all hard permission flags remain `false` throughout; and
- the complete repository verification chain is green.
