# Mythos Lessons V1 Design

## Goal

Move Bounty Mythos-Lite from program-scoped score memory toward long-term Mythos learning.

The current Mythos Brain can remember program-local learning signals and adjust high-value surfaces. Mythos Lessons V1 adds a reusable advisory layer above those signals. It turns repeated outcomes into explainable lessons that can be applied to future Brain and Hunter decisions without becoming execution permission.

The learning chain is:

```text
learning signals -> lesson builder -> program/platform/global lessons
-> Brain applied lessons -> Hunter advisory reasons
```

This is not an autonomous validation engine. It does not scan, exploit, submit reports, parse free-text feedback into permission, or bypass Scope Guard.

## Scope

Implement the smallest durable lesson layer that proves long-term learning can accumulate, explain itself, and safely influence future prioritization.

In scope:

- A `MythosLesson` domain model derived from existing learning signals.
- Lesson scopes for `program`, `platform`, and `global`.
- Deterministic lesson aggregation from structured learning signal fields.
- Brain profile output that shows applied and skipped lessons.
- Hunter advisory integration that can add bounded score deltas and reasons.
- Tests proving accepted, duplicate, rejected, weak-evidence, and safety-gated cases.

Out of scope:

- Vector search.
- Full knowledge graph storage.
- Natural-language triager feedback parsing.
- Automatic test-step generation.
- Automatic validation execution.
- Automatic platform submission.
- Authentication, tenancy, or production permission modeling.

## Success Criteria

1. Two or more accepted strong-evidence signals for the same playbook and surface pattern can produce a boost lesson.
2. Duplicate, N/A, or rejected signals for the same playbook and surface pattern can produce a penalize or duplicate-watch lesson.
3. Weak accepted evidence cannot produce a boost lesson.
4. A platform or global lesson can influence a similar future program through advisory reasons and a bounded score delta.
5. Brain profile output explains which lessons were applied, which were skipped, and why.
6. Hunter Intelligence treats lessons as advisory memory only; it cannot raise blocked, out-of-scope, real-user-data, or human-approval-only candidates above hard safety gates.
7. Lesson records never store raw triager feedback, observation text, request or response bodies, secrets, tokens, cookies, credentials, or real user data.

## Current Architecture

The codebase already has the right foundation:

- `LearningSignal` in `apps/api/app/mythos_brain/__init__.py` records structured outcome, playbook, surface, bounty, severity delta, evidence quality, target relationships, and redacted feedback.
- `build_program_intelligence` builds program-scoped attack surface memory, learning summary, high-value surface rankings, and safety notes.
- `build_learning_signal_from_outcome` derives playbook, surface, target relationships, and evidence quality from pipeline runs and reviewed claim state.
- Artifact usage records can cite learning signals without copying sensitive observation text.
- Hunter Intelligence already provides playbook, priority, duplicate risk, rejection risk, recommendation, evidence focus, and safety notes.

The missing layer is reusable lesson memory. Current learning affects a program profile directly; it does not yet create stable, inspectable rules of thumb that can be reused across a platform or globally.

## Domain Model

Add a domain model first. In V1, lessons are deterministic derived views over persisted learning signals, so the implementation does not need a new database table unless the implementation plan discovers a concrete performance or audit requirement that cannot be met from `learning_signals`.

```text
MythosLesson
  id
  scope_type: program | platform | global
  scope_key
  playbook_id
  surface_pattern
  outcome_counts
  evidence_quality_counts
  bounty_total
  severity_delta_counts
  confidence
  recommendation: boost | penalize | evidence_needed | duplicate_watch
  score_delta
  reasons
  source_signal_ids
  safety_notes
  created_at
  updated_at
```

### Scope

- `program`: applies only to one program.
- `platform`: applies to programs on the same platform, such as HackerOne or Bugcrowd.
- `global`: applies only when enough cross-program evidence exists.

Scope escalation must be conservative. A lesson starts at program scope. It can become platform or global only when signals come from more than one program and the evidence is not weak.

V1 currently implements program lessons and conservative global lessons. A global
lesson is derived when matching playbook/surface signals come from at least two
programs. Platform lessons remain a later extension because learning signals do
not yet carry a stable platform key.

### Surface Pattern

`surface_pattern` should stay simple and deterministic in V1:

```text
object_name:action
```

Examples:

- `file_id:export`
- `team_id:write`
- `invoice_id:refund`

If a learning signal has target relationships, the lesson can include relationship reasons such as:

```text
target_relationship:org_id>team_id>file_id
```

The relationship context influences explanation and matching. It should not replace the simple surface pattern in V1.

### Recommendation

Lesson recommendations are advisory:

- `boost`: similar candidates deserve more human attention.
- `penalize`: similar candidates have lower priority.
- `evidence_needed`: similar candidates need stronger evidence before promotion.
- `duplicate_watch`: similar candidates may be worth parking or checking for duplicate risk.

No recommendation can mark a finding verified, ready to submit, accepted, or safe to validate.

## Lesson Builder

The builder consumes `LearningSignal` records and returns lessons.

Grouping key:

```text
scope candidate + playbook_id + surface_pattern
```

Program lessons use one program's signals. Platform lessons group signals by platform. Global lessons group signals across programs.

### Boost Rules

Create a `boost` lesson when:

- at least two accepted signals exist in the group;
- at least one accepted signal has `evidence_quality = strong` or two have `evidence_quality = adequate`;
- rejected, N/A, and duplicate signals do not dominate the group.

Weak accepted signals do not count toward boost eligibility.

### Penalize Rules

Create a `penalize` lesson when:

- rejected or N/A signals dominate the group; or
- the group has repeated informative outcomes with weak evidence.

### Duplicate Watch Rules

Create a `duplicate_watch` lesson when:

- duplicate outcomes appear repeatedly for the group; or
- duplicate outcomes dominate accepted outcomes.

### Evidence Needed Rules

Create an `evidence_needed` lesson when:

- accepted signals exist but are weak or inconsistent;
- informative outcomes are tied to weak evidence; or
- severity is often reduced because impact proof is weak.

### Confidence

Confidence is a bounded integer from 0 to 100.

It should increase with:

- more source signals;
- accepted outcomes with strong or adequate evidence;
- paid bounty;
- severity upgrades;
- repeated target relationship context.

It should decrease with:

- weak evidence;
- severity reductions;
- mixed outcomes;
- a small sample size.

Confidence must be explainable through reasons. It is advisory and cannot unlock execution.

## Brain Integration

Program intelligence should include lesson context:

```text
applied_lessons
skipped_lessons
lesson_adjusted_surfaces
```

Applied lessons are lessons that match a high-value surface and pass safety checks.

Skipped lessons are lessons that match by playbook or surface but cannot apply because:

- the candidate or run is blocked;
- the asset is out of scope;
- real user data risk is present;
- human approval is required;
- evidence is weak and the lesson requires stronger evidence;
- the lesson scope does not match the program, platform, or global criteria.

Brain should explain lesson influence with reason strings, not hidden score changes. Example reasons:

```text
lesson:boost:accepted_strong_evidence
lesson:duplicate_watch:repeated_duplicate
lesson:skipped:scope_guard_blocked
lesson:evidence_needed:weak_accepted_evidence
```

## Hunter Integration

Hunter Intelligence can consume lessons after its existing safety checks and base scoring.

Lesson influence must be bounded:

- `boost`: small positive score delta.
- `penalize`: small negative score delta.
- `duplicate_watch`: increases duplicate risk or changes recommendation toward parking/checking.
- `evidence_needed`: raises evidence focus and rejection risk, but does not promote.

Hard safety gates win:

- blocked Scope Guard decision;
- out-of-scope asset;
- real user data risk;
- destructive or prohibited validation mode;
- human approval required without approval.

When a hard gate exists, matching lessons can appear only in skipped lessons or safety notes.

## API Design

V1 can expose lessons through Brain endpoints before adding a separate lesson management surface.

Recommended backend additions:

- `GET /mythos/brain/programs/{program_id}` returns applied and skipped lesson summaries.
- `GET /mythos/brain/lessons` returns filtered lesson summaries for debugging and review.

Suggested filters for `/mythos/brain/lessons`:

- `program_id`
- `platform`
- `scope_type`
- `playbook_id`
- `surface_pattern`
- `recommendation`

The API returns structured lesson summaries only. It must not return source note text, raw triager feedback, observation bodies, or report text.

## Frontend Design

Add lesson visibility where researchers already make prioritization decisions.

Minimal UI:

- Brain profile shows a compact "Lessons" section.
- Run or workbench detail can show applied lesson reasons beside Hunter assessment.
- Skipped lessons appear as safety-aware explanations, not as errors.

Do not add a new top-level navigation item in V1.

## Data Flow

1. Pipeline and validation workflow produce reviewed claims and learning outcomes.
2. Outcome intake writes structured learning signals.
3. Lesson builder groups learning signals into program, platform, and global lesson candidates.
4. Brain profile applies matching lessons to high-value surfaces and records skipped lesson reasons.
5. Hunter Intelligence applies bounded advisory deltas to future candidates.
6. Artifact usage records can cite lesson application by structured ref only.

## Safety And Privacy

Lessons are advisory memory only.

Required safety notes:

- `no_live_requests`
- `test_accounts_only`
- `human_review_required`
- `no_real_user_data`
- `advisory_memory_only`
- `scope_guard_wins`

Lessons must not store:

- raw triager feedback;
- manual observation text;
- request or response bodies;
- report draft prose;
- raw secrets;
- tokens;
- cookies;
- credentials;
- real user data.

Lessons may store:

- structured outcome counts;
- evidence quality counts;
- severity delta counts;
- bounty totals;
- playbook ids;
- surface patterns;
- target relationship labels;
- source learning signal ids;
- reason labels.

## Testing

Use TDD during implementation.

Backend tests:

- accepted strong-evidence signals build a boost lesson;
- weak accepted evidence does not build a boost lesson;
- duplicate outcomes build duplicate-watch;
- rejected and N/A outcomes build penalize;
- evidence weakness builds evidence-needed;
- platform or global lessons can apply across programs only when scope criteria are met;
- blocked and out-of-scope candidates skip matching lessons;
- lesson output does not include raw notes, feedback, request bodies, tokens, cookies, or observation text.

Integration tests:

- Brain profile returns applied and skipped lessons;
- Hunter assessment includes lesson advisory reasons and bounded score changes;
- hard safety gates remain unchanged after lesson matching.

Frontend checks:

- Brain profile renders applied and skipped lessons;
- missing lesson data falls back cleanly;
- build and lint pass.

Full verification:

```powershell
cd apps/api
python -m pytest

cd ../web
npm run lint
npm run build
```

## Tradeoffs

This design chooses deterministic structured lessons over vector retrieval or a graph database. That keeps V1 small, testable, and aligned with the existing repository.

It also deliberately limits lesson influence. A stronger Mythos should learn where to look and what evidence matters, not quietly grant itself permission to act. The result is a real step toward long-term hunter memory while preserving Scope Guard, human review, and evidence discipline as hard boundaries.
