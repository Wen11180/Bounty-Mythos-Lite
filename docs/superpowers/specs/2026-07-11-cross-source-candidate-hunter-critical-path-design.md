# Cross-Source Candidate Hunter Critical Path Design

## Status

Approved in conversation for written review.

This design completes the current A+B Candidate Hunter critical path. It adds
model-assisted cross-source candidate generation for TypeScript/Express and
turns Candidate Hunter evidence requests into durable, read-only specialist
work. It preserves every existing Scope Guard, redaction, validation,
promotion, and report-submission boundary.

## Scope

The implementation must accept an explicitly authorized Studio workspace with
all five A+B artifact kinds:

- scope;
- policy;
- API description;
- HAR traffic; and
- local code.

Without manually supplied candidates, the normal Studio run must correlate the
artifacts, generate evidence-traceable candidates, refute or suppress candidates
when local evidence warrants it, deduplicate shared roots, and persist a Top 1-5
projection.

The first new language and framework slice is TypeScript with Express. Existing
Python behavior remains supported.

## Non-Goals

This slice does not add:

- CodeQL execution;
- additional new language or framework families;
- live target validation;
- fuzzing, crash triage, patch generation, or regression execution;
- a generic workflow engine;
- new database tables;
- new UI controls; or
- automatic candidate promotion or report submission.

## Design Principles

1. Models propose interpretations; deterministic code owns facts, identity,
   safety, and permissions.
2. Every accepted candidate must cite observed facts from the current run.
3. Model failure must be visible and safe, not disguised as a successful model
   result.
4. Evidence work is bounded, resumable, local, read-only, and auditable.
5. Existing repository records are reused unless a new durable entity is
   required. No new entity is required for this slice.

## Architecture

### TypeScript/Express Fact Extraction

`app.codebase_map` gains a TypeScript/Express extraction path. It emits the
same fact family consumed by the current Candidate Hunter and adds only facts
that can be observed from authorized local files:

- Express route and router registrations;
- route method and path;
- handler and service call relationships;
- inline or middleware authorization signals;
- ownership, tenant, and role comparisons;
- sensitive sinks; and
- stable relative source paths and symbol names.

The base extractor does not decide whether a vulnerability exists. It records
structural facts and syntactic authorization signals. Decisive one-hop guard
and reachability conclusions are produced only by a targeted evidence
inspection. Ambiguous patterns remain candidate facts, and unsupported syntax
produces no invented fact.

The initial implementation covers conventional Express calls such as
`app.get`, `router.post`, handler references, middleware lists, and direct or
one-hop service calls. It does not attempt a general TypeScript compiler or
whole-program dataflow engine.

### Cross-Source Candidate Generator

A new `app.cross_source_candidate_generator` module owns:

- fact-pack construction;
- bounded model prompt construction;
- the structured model-output schema;
- proposal validation;
- baseline and model proposal merging;
- stable candidate identity;
- deterministic deduplication; and
- generation result normalization.

It consumes only normalized facts and existing baseline source-audit
hypotheses. It does not read workspace files directly and does not persist raw
model text.

The generator accepts this async boundary:

```text
CandidateReasoner.generate(fact_pack, model_config, request_key)
    -> CandidateModelResult
```

The production `RegistryCandidateReasoner` uses the existing `LLMRegistry`.
Tests and release runners inject a `ReplayCandidateReasoner`; replay is not a
new public `LLMMode` and cannot be selected by an ordinary Studio API request.

### Candidate Hunter Evidence Specialist

A new `app.candidate_hunter_evidence` module owns:

- materializing one evidence-inspection Task per eligible Hunter round;
- Task idempotency;
- read-only worker execution;
- immutable evidence-result Stage creation;
- result validation; and
- reconstruction of observations for the parent loop.

It reuses `CampaignTaskRecord`, `AgentRunRecord`, and `PipelineStageRecord`.
Specialist Tasks are children of the dedicated Candidate Hunter Campaign but
are separate from the single `candidate_hunter_loop` owner Task.

### Runtime Wiring

The Studio workspace run becomes async so it can await the existing async LLM
registry without a nested event loop. Its order is:

```text
validate complete A+B workspace
-> run authorized local source audit
-> persist the source pipeline run
-> atomically create or load the Candidate Hunter Campaign and owner Task
-> build normalized surface, context, code, and scanner facts
-> atomically claim one model-generation AgentRun
-> generate and validate cross-source candidates
-> persist cross_source_candidate_generation Stage
-> start or resume Candidate Hunter
-> dispatch bounded evidence inspection when needed
-> resume after a valid evidence-result Stage
-> return current persisted projection
```

The synchronous release runner invokes the async Studio workflow through one
explicit adapter at its process boundary. Core generation code remains async;
it does not call `asyncio.run` from inside an active event loop.

Owner creation, model-attempt claim, successful Stage insertion, and specialist
Task creation use deterministic record IDs derived from their idempotency keys.
The database primary keys therefore provide the atomic insert boundary without
a new table or a payload-only check-then-insert race.

## Data Contracts

### Candidate Model Configuration

`StudioWorkspaceRunRequest` gains an optional `candidate_model` object:

```json
{
  "provider": "openai",
  "model": "configured-model-name",
  "mode": "live"
}
```

The caller must explicitly select `live` before any normalized facts are sent
to a provider. When configuration is absent, the deterministic baseline still
runs and the generation Stage records `model_not_requested`. A dry-run response
does not count as a model-generated candidate.

The model-augmented release gate requires a replay or live model configuration;
the runtime fallback is for availability and safety, not proof of model quality.
The release CLI selects replay through an explicit local response-file option
that injects `ReplayCandidateReasoner`; it does not place `replay` in the Studio
request or existing `LLMMode` enum.

### Fact Pack

The versioned fact pack contains only bounded, redacted fields:

```text
schema_version
pipeline_run_id
source_snapshot_digest
source file reference and content-digest manifest
scope_status
policy_summary facts
surface facts from API and HAR
code facts from the codebase map
scanner facts
baseline candidate summaries
allowed fact_ref set
all permission booleans set to false
```

Facts use stable `fact_ref` values. Source paths are workspace-relative. Raw
source content, raw HTTP bodies, headers, cookies, tokens, credentials, real
user data, and full policy text are excluded.

### Model Proposal

The model returns one JSON object with `schema_version` and at most five
proposals. Each proposal contains:

- vulnerability family;
- affected endpoint;
- affected code path or an explicit missing-link reason;
- suspected broken invariant;
- impact rationale;
- evidence requirements;
- refutation questions;
- root-cause summary;
- risk estimate; and
- cited `fact_ref` values.

The Pydantic schema forbids extra fields. It contains no confirmation or
permission field. Candidate IDs, root-cause IDs, ranking scores, and all safety
fields are assigned by deterministic code after validation.

An accepted model proposal must cite at least one code fact and one API or HAR
surface fact. A proposal that cannot link both sides may be retained only as an
explicit unresolved evidence request; it cannot enter the final Top 1-5.

### Generation Stage

The immutable `cross_source_candidate_generation` Stage uses order zero for
the pipeline run and records:

- fact-pack and source-snapshot digests;
- baseline, proposed, accepted, rejected, and merged counts;
- normalized rejection reason counts;
- accepted candidate projections;
- model audit record reference, provider, model, mode, and prompt hash;
- `model_status`;
- idempotency key; and
- all hard permission flags set to false.

Before calling a model, the controller atomically inserts a deterministic
generation `AgentRunRecord` in `running` state. A completed matching generation
Stage is reused without another call. Concurrent callers that lose the insert
race observe the active attempt and do not call the model.

If a worker is lost after the provider call but before durable completion, exact
once delivery cannot be guaranteed across all supported providers. After the
bounded lease expires, a retry may issue the same read-only request key. The
retry is audited, consumes budget, and uses a provider idempotency key when the
provider supports one. This is at-least-once recovery, not a false exactly-once
claim.

Neither the prompt nor raw model response is stored. The original source-audit
payload remains unchanged. Candidate APIs derive the current count and content
from the generation Stage and latest valid Hunter projection.

## Candidate Validation and Merge Rules

The validator rejects a proposal when any of the following is true:

- its schema is invalid or has extra fields;
- it cites a fact outside the current fact pack;
- it contains a secret-shaped or real-user-data value;
- it claims confirmation, exploitation, validation, or report readiness;
- its route or code path contradicts the cited facts;
- it requests a live action;
- it attempts to set a permission; or
- it cannot be given a stable, evidence-derived identity.

Accepted proposals are merged with baseline candidates by normalized root cause,
route, method, and vulnerability family. The merge preserves every unique fact
reference and refutation question. Model text cannot remove baseline evidence
or mark a baseline candidate refuted. Candidate Hunter remains responsible for
terminal dispositions.

The generator returns two distinct collections:

- `working_candidates`: at most ten merged baseline and model candidates,
  including unresolved items that need specialist evidence; and
- `final_candidates`: always produced by Candidate Hunter and capped at five.

The working pool is ordered by evidence completeness, priority, then stable
candidate ID. Missing-link candidates may enter the working pool but never the
final projection until the required cross-source evidence is observed. An
explicit empty result is valid when no candidate meets the working threshold.

## Evidence Specialist State Machine

### Materialization

When a Hunter round emits evidence requests, the controller atomically creates
at most one logical `candidate_hunter_evidence_inspection` Task for that round.
Its deterministic primary-key input is:

```text
pipeline_run_id + evidence_request_stage_id + state_digest
```

Its payload contains only:

- schema version;
- pipeline run and request Stage references;
- round and state digest;
- sanitized candidate IDs;
- requested artifact kinds;
- refutation questions;
- local inspection targets;
- source snapshot digest; and
- all permission booleans set to false.

The parent Hunter owner Task becomes `needs_evidence`, and the loop returns
`awaiting_evidence`. This is resumable, not terminal.

The specialist lifecycle is:

```text
Task queued
-> one AgentRun atomically claims running
-> completed result transaction OR failed attempt record
-> Task completed, retryable, budget_exhausted, or blocked
-> idempotent parent resume
```

A compare-and-swap update may claim only a queued or explicitly retryable Task.
One active AgentRun is allowed per Task. A stale running attempt may be marked
`worker_lost` only after its bounded lease expires.

### Dispatch

The dedicated Hunter Campaign remains `level_0_read_only` and is advanced to
`running` only after its saved scope snapshot is valid. Its budget is:

- 15 cumulative execution minutes;
- 8,000 model tokens;
- at most four calls: one initial model attempt and up to three inspection
  attempts;
- zero validation calls;
- no dispatchable tool other than the local evidence inspector.

The generic budget guard must treat zero validation budget as a prohibition on
validation tasks, not as exhaustion for read-only tasks.

The Campaign payload stores the source Pipeline Run reference, policy hash,
normalized saved Scope Guard rule, source snapshot digest, inspector tool
allowlist, and false permission fields. It does not store raw policy or source
content.

Model and inspector retries consume the same call budget. Model token usage is
the provider-reported prompt plus completion count. When a provider omits usage,
the adapter conservatively charges the bounded prompt estimate plus configured
maximum completion tokens. Time is the sum of AgentRun execution durations;
queue wait does not consume execution time. Budget checks happen before every
claim and after every attempt.

At dispatch, the worker reloads the source Pipeline Run and Campaign. It checks:

- both are still `in_scope`;
- policy hashes match;
- the saved Scope Guard rule still authorizes the local root;
- the source snapshot digest has not changed;
- the requested tool is allowlisted;
- the Task digest and request Stage match; and
- budget remains.

### Inspection Result

The worker does not use the network or spawn target code. It runs a targeted
semantic inspection over only the requested files and call edges. This pass may
add decisive ownership, tenant, role-guard, or sink-reachability facts that the
base structural pass deliberately did not assert. It then persists one
`candidate_hunter_evidence_result` Stage tied to the specialist Task. The Stage
contains:

- newly observed facts and valid fact references;
- answered and unanswered refutation questions;
- inspected target references;
- source snapshot and state digests;
- normalized usage counters;
- a stop reason when incomplete; and
- all permission booleans set to false.

Every new fact reference is deterministically derived from the extractor
version, source snapshot digest, relative path, file-content digest, symbol,
fact type, and normalized fact attributes. The result also cites the source
artifact and requested inspection target. The parent validates this derivation
against the persisted source manifest and result digest before adding the fact
to the allowed evidence set.

The successful completion transaction inserts the one canonical result Stage,
marks the AgentRun completed, and marks the Task completed. A crash or extractor
failure writes an immutable `candidate_hunter_evidence_attempt` Stage with no
decision-eligible facts, then marks the AgentRun failed and the Task retryable or
exhausted. It does not occupy the canonical result identity.

A canonical result may be complete even when some questions remain unanswered;
`complete` means the bounded inspection and integrity checks finished. The
parent loop accepts only a complete, digest-matching canonical result. It merges
validated facts, starts the next round, and never treats an unanswered question
as a negative answer.

### Stop and Resume

The maximum is three Hunter rounds and one specialist Task per round. The loop
stops with:

- `all_candidates_terminal`;
- `no_candidates`;
- `max_rounds_reached`;
- `budget_exhausted`;
- `scope_guard_changed`;
- `source_snapshot_changed`;
- a fail-closed Stage integrity reason.

Budget or round exhaustion preserves unresolved candidates. It never converts
them to refuted or suppressed.

Inline worker mode completes and resumes the bounded loop in the request. Celery
mode returns `awaiting_evidence`; worker completion calls a reconstruction-based
resume entrypoint that reads generation and result Stages rather than depending
on process memory.

Parent resume runs after the specialist completion transaction. A crash between
commit and resume is harmless: the next worker tick or explicit read-side resume
observes the completed Task and canonical Stage and performs the same idempotent
resume.

## Safety and Failure Handling

Every generation, dispatch, and resume entrypoint rechecks authoritative scope.
A source or policy drift returns an empty projection and a specific blocked stop
reason.

All generated and specialist records require these values:

```text
execution_allowed = false
dispatch_allowed = false
validation_allowed = false
candidate_promotion_allowed = false
report_submission_allowed = false
raw_payload_processed = false
```

`dispatch_allowed` describes downstream target or validation dispatch. The
internal read-only inspector is authorized only by its Task type, Scope Guard,
tool allowlist, and budget; it never turns that public permission flag true.

Model failures are normalized to categories such as `model_not_requested`,
`timeout`, `provider_error`, `invalid_json`, `invalid_schema`, and
`invalid_fact_refs`.
Provider error bodies and raw response text are not persisted.

Model status and Hunter loop status are separate:

- `completed`: validated model output, including a valid empty proposal list;
- `model_not_requested`: baseline-only runtime requested by the caller;
- `needs_model_review`: timeout, provider, parsing, schema, or reference failure.

For `model_not_requested` or `needs_model_review`, valid baseline candidates may
still run through Candidate Hunter and appear in the projection. The API returns
the baseline projection together with the model status and warning. When no
baseline exists, the projection is explicitly empty. A model failure is not a
Hunter stop reason and does not become `no_candidates` evidence about the
target. Model-augmented release gates require `model_status=completed`.

Prompt-injection-shaped strings are treated as data. They cannot add facts,
change the output schema, set permissions, or bypass the deterministic
validator. A sensitive model response rejects the affected proposal before any
Stage stores it.

Path containment and symlink checks are repeated during specialist inspection.
The worker receives references, not model-selected absolute paths. Network
access, subprocess execution, raw request bodies, and external target contact
remain prohibited.

Duplicate owners, Tasks, canonical result Stages, mismatched digests, missing
Stage sequences, or malformed safety fields fail closed. Deterministic primary
keys and compare-and-swap claims prevent concurrent duplicate calls. Replay
after a completed Stage performs no second call. A post-call worker-loss retry
follows the explicitly bounded at-least-once rule above.

## Test Strategy

Implementation follows red-green-refactor. No production behavior is added
before a test demonstrates the missing behavior.

### TypeScript/Express Unit Tests

Tests cover:

- direct `app` and `router` route registration;
- handler references and inline handlers;
- router and route middleware;
- inline ownership, tenant, and role guards;
- targeted one-hop service authorization guards;
- sensitive sink calls;
- route template correlation with concrete HAR paths;
- stable facts under file-order changes;
- unsupported or ambiguous syntax producing no invented fact; and
- secret-shaped content never appearing in a fact payload.

### Generator Unit Tests

Tests cover:

- valid structured proposals;
- unknown, mismatched, and missing fact references;
- extra fields and invalid JSON;
- stable candidate and root-cause identity;
- merge and deduplication behavior;
- Top-5 ordering;
- model timeout and provider failure;
- distinct model status and baseline projection behavior;
- baseline preservation;
- working-pool retention versus final Top-5 projection;
- prompt-injection-shaped artifact text;
- sensitive model output rejection; and
- every permission field remaining false.

### Persistence and Specialist Tests

Tests cover:

- one generation Stage per fact-pack and model digest;
- concurrent generation claims producing one active model attempt;
- one inspection Task per evidence request Stage;
- concurrent Task claims producing one active inspector attempt;
- completed replay without a second model or inspector call;
- worker-loss retry with bounded at-least-once accounting;
- failed attempt Stage followed by a canonical result Stage;
- atomic result, AgentRun, and Task completion;
- `awaiting_evidence` followed by a resumed round;
- decisions changing only from cited result facts;
- result fact-reference derivation and source-manifest validation;
- scope, policy, root, source snapshot, and digest drift;
- zero validation budget not blocking read-only inspection;
- tool, time, token, and round caps;
- unsafe or malformed result Stages failing closed; and
- unresolved candidates staying unresolved at exhaustion.

### Studio End-to-End Test

The primary integration fixture imports authorized scope, policy, OpenAPI, HAR,
and TypeScript/Express code. It provides no manual candidate input. A replayable
model proposal plus local inspection must produce a persisted candidate with:

- affected endpoint;
- affected code path;
- vulnerability family;
- broken invariant;
- impact rationale;
- evidence requirements;
- refutation questions;
- safe validation plan;
- safety blockers; and
- submission-blocked report readiness.

The same test proves at least two Hunter rounds, immutable Stages, idempotent
replay, and a final Top 1-5 projection.

## Release Quality Gates

### Deterministic Contract Gate

Default CI uses replayable model responses. This gate proves the protocol,
validation, persistence, specialist recovery, and safety behavior without a
network dependency.

### Independent Model Quality Gate

The release corpus contains 12 development and 12 held-out TypeScript/Express
cases. It is balanced across retained, refuted, deduplicated, and suppressed
outcomes and covers at least three authorization patterns.

The corpus must:

- use opaque case IDs, paths, routes, symbols, and workspace names;
- keep gold data outside staged inputs;
- load every oracle only after candidates and Stages are captured;
- reject disposition words or oracle metadata in inputs;
- preserve outcomes under case-ID and directory-order perturbation; and
- contain no real target, user, credential, cookie, token, or secret data.

The gate uses the existing six metrics:

- precision at 5;
- valuable recall at 5;
- evidence traceability rate;
- effective refutation rate;
- duplicate suppression rate; and
- human-worth-validation rate.

The development gate must pass before the held-out gate is run. Zero
denominators, invalid schemas, unsafe output, or Stage audit failures fail the
suite.

A live provider gate is opt-in through an explicit CLI model configuration. It
is never part of the default test command and never silently sends artifacts.
Passing the deterministic gates completes the repository implementation. A
specific live provider and model must pass the same development and held-out
corpus before that provider/model pair may be described as release-qualified.

## Acceptance Criteria

This slice is complete only when all of the following are proven from the
current worktree:

- an authorized TypeScript/Express A+B workspace can produce candidates without
  manual candidate input;
- accepted model candidates cite observed code and API or HAR facts;
- invalid or unavailable model output is visible and fails safely;
- the working pool preserves unresolved evidence requests separately from the
  final Top-5 projection;
- one durable, idempotent evidence-inspection Task owns each eligible evidence
  request round;
- concurrent workers cannot claim the same generation or inspection attempt;
- a completed immutable result Stage can resume the parent Hunter after process
  loss;
- no result fact without a valid snapshot, file digest, extractor provenance,
  and deterministic reference can change a candidate disposition;
- unresolved candidates are preserved at budget or round exhaustion;
- final output is a traceable Top 1-5 or an explicit empty result;
- every execution, validation, promotion, and submission permission remains
  false;
- development and held-out quality gates pass without answer leakage; and
- the full Backend, Web test/lint/build, Studio, Compose, and diff verification
  chain is green.

## Delivery Boundaries

The implementation should be split into reviewable behavior units:

1. TypeScript/Express code facts.
2. Cross-source model protocol and deterministic validation.
3. Studio generation Stage integration.
4. Evidence specialist Task, worker result, and resume path.
5. Independent TypeScript/Express release corpus and gates.
6. Documentation and final repository verification.

Each unit must preserve a green test baseline before the next unit begins.
