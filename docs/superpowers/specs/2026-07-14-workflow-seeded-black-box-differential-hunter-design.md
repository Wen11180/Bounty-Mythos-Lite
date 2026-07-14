# Workflow-Seeded Black-Box Differential Hunter Design

Date: 2026-07-14

## Status

Approved section by section in conversation and ready for written review.

This design defines the next major product direction for Mythos-Lite: a
workflow-seeded, two-session black-box differential hunter for authorized Web
and API bug bounty research. It complements the existing A+B local
policy/API/HAR/code Candidate Hunter; it does not replace that path.

No implementation work is authorized by this document alone. A separate
implementation plan and a fresh user approval are required after written
review.

## Decision Summary

The approved product decisions are:

- black-box Web/API programs are expected to represent at least 70% of the
  operator's real bounty work;
- the first supported discovery family is IDOR/BOLA, role or privilege
  boundary failure, authentication failure, and stateful business-logic
  authorization defects;
- the operator manually logs into two isolated browser sessions once;
- secrets remain inside ephemeral browser contexts and are never persisted;
- the operator demonstrates one to three high-value normal workflows;
- the Hunter learns endpoints, roles, test-object ownership, and state
  transitions from those demonstrations;
- local, self-hosted, and dedicated test environments may use fully automated
  state-changing validation;
- a remote bounty target requires a bounded, human-issued execution lease
  before any generated request is sent;
- remote state changes are limited to reversible changes on the operator's
  test accounts and their own test objects;
- only stable, single-variable, independently reproduced, negatively
  controlled, and redacted observations may enter human review;
- report submission always remains manual; and
- early quality is judged by Top-10 review precision, while the ultimate
  product metric is bounty return per researcher-hour.

## Problem

Mythos-Lite's current strength is white-box and gray-box correlation across
authorized policy, scope, API/HAR, and local code. Its existing Candidate
Hunter, refutation, evidence, and report-readiness foundations are useful, but
they do not yet constitute a real black-box discovery loop.

A generic crawler or request mutator would increase coverage and candidate
count without reliably understanding business state, object ownership, or
role intent. That would create noise, operational risk, and weak evidence. The
missing capability is a small, state-aware differential loop that starts from
operator-demonstrated business workflows and tests only bounded authorization
invariants using the operator's own accounts and objects.

## Goals

1. Turn one to three normal workflow demonstrations into a traceable endpoint,
   role, ownership, and state-transition model.
2. Generate a small number of high-value authorization hypotheses rather than
   broad scanner output.
3. Execute only human-approved, low-rate, non-destructive remote checks inside
   Scope Guard and an explicit execution lease.
4. Prove candidates with stable baselines, single-variable differences,
   negative controls, independent reproduction, and refutation.
5. Persist useful structural evidence without persisting sessions, raw
   requests, raw responses, secrets, or real user data.
6. Reuse the current Candidate Hunter, audit, evidence-review, and
   submission-blocked report workflow.
7. Measure progress with blind held-out lab cases and real human or triager
   outcomes, not model self-assessment.

## Non-Goals

- Open-ended autonomous crawling from only a public root URL.
- Automatic target discovery or target enrollment.
- High-frequency scanning, endpoint spraying, fuzzing, or brute force.
- Destructive validation, denial of service, credential stuffing, social
  engineering, persistence, or evasion of WAF, CAPTCHA, or rate limits.
- Accessing, collecting, displaying, persisting, or reporting real user data.
- Paying, purchasing, inviting real users, sending messages or notifications,
  deleting accounts or data, exporting data, or changing real privileges.
- Automatic report submission.
- Treating a response-code difference, model output, or scanner output as a
  confirmed vulnerability.
- Persisting browser profiles or resuming raw sessions after process restart
  in the first release.
- Supporting every vulnerability class in the first release.
- Building a general workflow engine or completing the dashboard before the
  discovery loop is proven.

## Considered Approaches

### Blind crawl and mutation

Starting from a root URL provides broad coverage and little setup, but has weak
business context, high noise, and a larger chance of touching irrelevant or
unsafe surfaces. It is not the primary design. A later shallow discovery pass
may propose workflows, but it cannot autonomously mutate them.

### Workflow-seeded differential hunting

The operator demonstrates high-value workflows while the system records safe
structure. Two isolated sessions and operator-owned objects then provide
controlled comparisons. This gives the strongest path to IDOR/BOLA,
role-boundary, authentication, and business-state findings with the current
project foundation. This is the selected primary design.

### OpenAPI/HAR-first hunting

API artifacts improve endpoint coverage and are especially useful for
API-centric programs, but they often omit interactive state and role intent.
This is the selected secondary input path after the workflow-seeded core
works.

The final combination is workflow-seeded first, API/HAR augmentation second,
and only bounded shallow discovery later.

## System Boundary and Data Flow

\`\`\`text
operator-provided policy and scope
+ explicit execution lease
+ two ephemeral authenticated sessions
+ one to three demonstrated workflows
-> Scope Guard and lease preflight
-> redacted workflow normalization
-> endpoint, object-ownership, role, and state model
-> bounded differential hypotheses
-> per-request safety check
-> serial low-rate execution on test-owned objects
-> baseline, negative control, reproduction, and refutation
-> deduplicated ranked candidate queue
-> redacted evidence review
-> human confirmation
-> submission-blocked report draft
-> manual submission outside Mythos-Lite
\`\`\`

The system has five distinct trust planes:

1. **Authority plane**: policy, scope, human approval, and the execution lease.
2. **Secret plane**: ephemeral browser contexts and in-memory request values.
3. **Research plane**: normalized workflows, object aliases, hypotheses,
   structural response differences, and safe audit records.
4. **Evaluation plane**: hidden lab labels and later human or triager outcomes.
5. **Decision plane**: human evidence promotion, confirmation, and submission.

Data and permission may move only in the stated direction. A model,
observation, benchmark result, or learning signal cannot grant authority.

## Core Components

### Scope and Lease Controller

This component binds every run to a policy and scope digest, allowed active
origins, optional passive rendering origins, account aliases, action classes,
time and request budgets, expiry, and rollback requirements.

Public reachability, a bounty-program listing, or a model conclusion is not
authorization. A lease can be issued only after the operator supplies the
current policy and scope, explicitly selects the asset, and identifies the
test-account aliases for that run. The system never enrolls or starts testing
a target on its own.

It checks authority before session attachment, workflow recording, plan
creation, and every generated request. A policy or scope change invalidates the
lease. Passive origins may serve resources needed to render the target, but
they are never mutation targets and their bodies are not persisted.

### Ephemeral Session Broker

The broker owns two isolated browser contexts and exposes only opaque,
non-serializable handles such as \`session_a\` and \`session_b\`. Login occurs
under operator control before recording begins. The recorder must not capture
password-entry or login-submission traffic.

Cookies, tokens, authorization headers, CSRF values, and browser storage remain
inside the context or an in-memory request adapter. Session close, expiry,
process exit, or safety stop destroys the contexts.

### Workflow Recorder and Normalizer

The recorder observes the operator's normal post-login workflow and emits a
safe normalized trace:

- active origin and route template;
- HTTP method and operation signature;
- parameter names, locations, and coarse types;
- source and destination state aliases;
- account and role alias;
- object aliases created, selected, read, or updated;
- safe response shape, status class, and timing;
- whether an action appears read-only, creating, reversible, or prohibited.

Raw headers, request bodies, response bodies, and dynamic secret values are
not persisted. Imported HAR material passes through the same normalization and
redaction boundary.

### Object-Provenance Ledger and State Model

Every object eligible for a differential test must be tied to an observed
creation or selection step under a test account. The ledger records a safe
alias, object type, owner alias, creating workflow step, parent alias,
lifecycle state, and reversibility.

Actual IDs and relationship values exist only in memory. Persistent audit
records use aliases or one-way run-scoped hashes. An object with unknown
ownership is never mutated or used as a cross-account test target.

The state model represents only observed states and transitions. It does not
invent hidden application states or treat front-end labels as server-side
authorization facts.

### Differential Planner

The planner accepts normalized steps, the object ledger, state model, scope,
and remaining lease budget. It produces a finite list of single-variable
hypotheses and their required controls.

The first release supports:

- same-role cross-account object substitution;
- replay of a demonstrated operation under a lower-role test session;
- unauthenticated replay of a demonstrated read-only operation;
- parent and child substitution using only test-owned objects; and
- out-of-order state transitions on reversible test-owned objects.

The planner emits no arbitrary parameter fuzzing, wordlists, identifier
enumeration, credential attempts, or unobserved high-impact actions.

### Safety Classifier and Bounded Executor

The classifier validates destination, action class, object provenance,
reversibility, rollback readiness, session alias, budget, and stop state for
every planned trial. Missing information fails closed.

The executor runs one active request at a time in this sequence:

\`\`\`text
preflight
-> stable A and B baselines
-> one differential trial
-> owner/session negative controls
-> independent differential reproduction
-> rollback when applicable
-> post-rollback control
\`\`\`

Remote writes are allowed only when explicitly named by the lease, applied to
test-owned objects, and limited to creation or an already-demonstrated
reversible update. Local or dedicated labs may grant broader state-changing
classes, but the global destructive and privacy prohibitions still apply.

### Differential Oracle, Refutation, and Ranking

The oracle evaluates a declared security invariant, not a status code alone.
Useful signals include:

- a test-account session receiving the stable marker or structural identity of
  another test account's object;
- a lower-role session completing a state transition reserved for the
  demonstrated higher role;
- an unauthenticated session receiving the same protected test-object result;
- an unauthorized trial causing a state change later observed by the owning
  account; and
- the result remaining stable after negative controls and independent repeat.

When a normal workflow offers a benign operator-controlled text field, the
system may insert a random non-secret canary into its own test object. Only the
canary hash and match result are persisted. This allows strong BOLA evidence
without saving response content. If a safe canary is unavailable, the
candidate must rely on other structural evidence or remain inconclusive.

Refutation explicitly tests session expiry, cache behavior, object
nonexistence, intended sharing, public-resource policy, role equivalence,
client-only display differences, and unstable application behavior.

Candidates first pass hard gates for scope, safety, evidence, and
reproducibility. Passing candidates are then ranked lexicographically by:

1. evidence strength and traceability;
2. plausible security impact;
3. reproducibility;
4. lower preconditions;
5. novelty after semantic deduplication.

The first release should not introduce configurable model weights. The
persisted review queue is capped at ten candidates, while Studio highlights
the strongest one to five to remain compatible with the current North Star.

## Data Contracts

### Execution Lease

An execution lease contains only safe authority metadata:

- lease ID, operator approval timestamp, and expiry;
- policy and scope digest;
- allowed active and passive origins;
- allowed account and role aliases;
- allowed action classes;
- workflow, time, request, and frequency budgets;
- rollback requirements; and
- explicit blocked-action declarations.

It contains no credential, cookie, token, authorization header, or raw login
artifact. A remote lease is single-run and cannot survive a changed scope or
expired session.

### Session Handle

A session handle is opaque and non-serializable. It identifies an in-memory
browser context without exposing authentication material.

### Workflow Step

A persistent workflow step stores a normalized operation signature, account
and role aliases, pre-state and post-state aliases, safe parameter schema,
object-alias relationships, action classification, and source trace.

### Test Object

A persistent test object stores its safe alias, type, owner alias, parent
alias, creation step, observed lifecycle, and reversibility. Its concrete
identifier and canary value remain in memory.

### Differential Plan

A plan stores the source step, one changed variable, expected security
invariant, baseline and negative-control requirements, risk class, budget
cost, rollback requirement, and safety blockers.

### Trial Summary

A trial summary stores safe request fingerprints, status class, response
schema fingerprint, length bucket, canary-match boolean, state-transition
result, timing bucket, redaction status, and stop reason. It never stores raw
request or response content.

### Candidate and Evidence Bundle

A candidate stores the affected normalized operation, suspected invariant,
test-account roles, evidence references, alternative explanations, refutation
results, reproduction status, plausible impact, scope digest, and safety
blockers.

An evidence bundle contains only human-reviewable redacted steps, structural
differences, test-owned canary results, rollback evidence, and audit
references. Evidence promotion remains a human action.

## Persistence Boundary

| Data | Memory only | Safe persistence |
| --- | --- | --- |
| Passwords and login input | required during operator login | never |
| Cookies, tokens, authorization and CSRF values | browser context or adapter | never |
| Actual object IDs and relationship values | current run | alias or run-scoped hash |
| Raw request and response content | transient processing only | never |
| Normalized operation and parameter schema | optional cache | yes |
| State graph and ownership aliases | active model | yes |
| Structural response fingerprints | active comparison | yes |
| Unexpected third-party or real-user content | discard immediately | never |
| Candidate, refutation, and stop reasons | active run | yes, after redaction |

The first release intentionally does not restore sessions or concrete object
maps after restart. It can resume safe planning and audit state, but the
operator must log in again and re-establish or re-demonstrate test objects
before execution.

## Candidate Lifecycle

\`\`\`text
hypothesis
-> observed
-> reproduced
-> review_ready
-> human_confirmed
-> submission_blocked_report_draft
\`\`\`

Any non-terminal state may become \`refuted\` or \`inconclusive\`.

The model, planner, executor, or benchmark cannot set \`human_confirmed\`.
A report draft can be generated only after the evidence bundle has passed
human redaction and confirmation. Mythos-Lite never submits it.

An observation reaches \`review_ready\` only when all of these are true:

1. A and B normal baselines are stable.
2. The trial changes exactly one authorization-relevant variable.
3. The observed difference violates the declared invariant.
4. Negative controls exclude the principal benign explanations.
5. An independent repeat reproduces the result.
6. Scope, lease, provenance, rollback, and redaction checks pass.

## Remote Execution Limits

The initial remote preset is intentionally fixed and conservative:

- at most one active generated request every three seconds;
- active-request concurrency of one;
- at most fifty generated requests per demonstrated workflow;
- at most three demonstrated workflows per lease;
- a maximum lease duration of thirty minutes; and
- no automatic retry after a safety stop.

Program policy or the operator may tighten these values. The first release
does not allow a remote lease to exceed the preset. Local and dedicated lab
profiles may use separate faster budgets because they are controlled
environments.

Ordinary browser resources needed for an operator demonstration are distinct
from generated active test requests. During automated replay, third-party
origins are blocked unless explicitly listed as passive rendering origins;
passive origins are not captured as evidence or mutation targets.

## Stop and Failure Rules

The current path stops immediately when:

- scope is missing, ambiguous, changed, or exceeded;
- a redirect or active destination leaves the allowed origin set;
- the lease expires or a request, workflow, or time budget is exhausted;
- a session expires or authentication state becomes ambiguous;
- CAPTCHA, WAF intervention, or HTTP 429 is observed;
- the baseline remains unstable;
- an unknown or non-test-owned object is required;
- unexpected third-party or real-user content appears;
- an action is irreversible, prohibited, or affects more than the expected
  test object;
- rollback fails or cannot be proved;
- repeated server errors suggest service instability; or
- redaction or audit persistence cannot be completed safely.

The stopped path records only a safe reason and audit reference. It does not
save the triggering content, evade the control, change identities, increase
frequency, or continue with another mutation.

Expected authorization denials such as 401 or 403 are ordinary observations,
not executor failures. An unstable or ambiguous result becomes
\`inconclusive\`, not a retained candidate.

On a process crash, safe persisted plans and audit records remain available.
Sessions and concrete object values are lost by design. Resume therefore
requires new operator login and provenance reconstruction rather than secret
recovery.

## Evidence and Report Boundary

The system may generate a submission-blocked draft containing:

- the affected normalized endpoint or workflow step;
- the expected authorization invariant;
- test-account and test-object aliases;
- reproducible safe steps;
- structural or canary evidence;
- impact reasoning stated as a hypothesis until human confirmation;
- alternative explanations and completed refutations;
- cleanup or rollback confirmation; and
- explicit redaction and scope status.

It must not include real user data, raw authentication material, unredacted
traffic, automatic severity claims, or a submission action. The operator
reviews and manually transfers the final report to the bounty platform.

## Quality and Evaluation Strategy

### Gate 1: Engineering Ready

All deterministic scope, lease, session-isolation, redaction, provenance,
budget, stopping, candidate-state, and human-gate tests pass. Any secret
persistence, real-user-data retention, prohibited action, scope escape, or
automatic submission is a hard failure.

Replay tests qualify software contracts only. They do not qualify black-box
discovery quality.

### Gate 2: Lab Qualified

The Hunter runs through real HTTP and browser behavior against local,
self-hosted, or dedicated authorized applications. Labels are hidden until all
candidates are captured. Development and held-out sets are split by
application, not by endpoint.

The held-out aggregate thresholds are:

| Metric | Minimum |
| --- | ---: |
| Supported-family recall | 0.70 |
| Precision at 10 | 0.50 |
| Independent reproduction rate | 0.90 |
| Evidence traceability rate | 1.00 |
| Safety-invariant pass rate | 1.00 |

The corpus includes real positives and realistic negatives: correct
authorization, intended sharing, public resources, caching, session expiry,
unstable responses, redirect boundaries, rate limits, CSRF changes, and
rollback failures. Case IDs, routes, workflow names, and fixtures cannot reveal
the expected outcome.

### Gate 3: Authorized Field Pilot

Before calling the system field-ready, the operator reviews at least thirty
candidates across at least five independent authorized engagements. Aggregate
Top-10 submit-worthy precision must reach 0.30, with zero scope, secret,
privacy, destructive-action, or submission incidents.

Field labels are \`valid\`, \`duplicate\`, \`invalid\`, \`out_of_scope\`, and
\`needs_evidence\`. They are recorded manually after redaction. Feedback may
change future ranking explanations but cannot grant permissions.

### Gate 4: Outcome Proven

A genuine Mythos/XBOW-quality claim requires external outcomes across at least
three independent programs: at least ten reports judged technically valid by
external triagers, including at least five that receive a bounty.

The ultimate metric is bounty value per researcher-hour. Candidate count,
coverage, model confidence, and scanner findings remain diagnostic metrics
only. Until this gate is met, the product must use narrower labels such as
\`engineering_ready\`, \`lab_qualified\`, or \`field_pilot\`.

## Test Strategy

Implementation should proceed test-first in this order:

1. Pure Scope Guard and execution-lease tests, including policy changes,
   expiry, budgets, and blocked action classes.
2. Session-broker tests proving isolation, non-serialization, login-capture
   exclusion, destruction, and re-authentication behavior.
3. Workflow-normalization and redaction tests using synthetic traffic.
4. Object-ledger tests proving that unknown or non-test-owned objects fail
   closed.
5. Planner tests proving finite single-variable plans with no enumeration,
   arbitrary fuzzing, or prohibited action.
6. Executor tests against a small synthetic two-account application, covering
   baselines, negative controls, reproduction, rollback, rate limits, and every
   stop condition.
7. Oracle tests proving that response codes alone cannot retain a candidate
   and that benign alternative explanations cause refutation or
   inconclusive status.
8. Persistence tests proving that no raw secret, header, body, concrete object
   ID, or real-user marker enters stored records.
9. End-to-end Studio tests from manual session attachment through a
   review-ready candidate and submission-blocked draft.
10. Blind application-level benchmark tests and comparison with the existing
    Candidate Hunter and a simple replay baseline.
11. Full backend, Web, Studio, packaging, and scoped diff verification before
    a delivery is called complete.

All automated discovery benchmarks run only against local, self-hosted, or
dedicated authorized fixtures. Remote bounty pilots require a fresh explicit
human lease and are never part of default CI.

## Integration with Existing Mythos-Lite

The existing A+B path remains authoritative for policy/API/HAR/local-code
correlation. The black-box subsystem adds observed runtime facts and
differential evidence; it does not replace static or semantic code analysis.

The first implementation should reuse existing Campaign, Task, immutable
Stage, candidate, refutation, evidence-review, and report-readiness contracts
where their current safety semantics fit. Session handles and concrete object
maps must remain outside persisted domain records.

The implementation plan must identify the smallest adapter boundary around
the current plan-only authorized Web/API capability. It should not refactor
unrelated Candidate Hunter code or introduce a new general orchestration
framework.

The initial Studio surface needs only:

- lease review and approval;
- two session readiness indicators;
- start and stop workflow recording;
- normalized workflow and object-alias review;
- bounded-run approval and stop state;
- candidate evidence and refutation review; and
- manual evidence promotion and report-draft generation.

Dashboard expansion is explicitly lower priority than proving the discovery
loop.

## Delivery Sequence

1. Define pure lease, session-handle, workflow, object, plan, trial, and stop
   contracts with safety tests.
2. Build a controlled two-account local lab and blind benchmark skeleton.
3. Implement ephemeral session attachment and post-login workflow recording.
4. Build the object-provenance ledger and observed state model.
5. Implement the finite differential planner and local-lab executor.
6. Add the oracle, refutation, deduplication, ranking, and redacted evidence
   bundle.
7. Integrate the minimal Studio approval and review flow.
8. Pass the engineering and held-out live-lab gates.
9. Only then enable the fixed conservative remote execution profile behind a
   fresh human lease.
10. Run authorized field pilots and add advisory ranking feedback.

Each delivery unit must leave report submission blocked and must be useful
without later units. Remote execution is not an acceptable shortcut around
the lab gate.

## Acceptance Criteria

This design is implemented only when the following are proven:

- a user can attach two ephemeral post-login sessions without any raw secret
  entering persistence or logs;
- one to three demonstrated workflows become redacted endpoint, role, object,
  and state models;
- every differential trial uses only explicitly observed, test-owned objects
  and changes one authorization-relevant variable;
- every generated remote request passes Scope Guard and a current
  human-issued lease;
- the remote preset enforces serial low-rate execution, request and time
  budgets, reversible own-object changes, and all stop rules;
- CAPTCHA, WAF, rate limiting, unexpected data, unknown ownership, rollback
  failure, or scope ambiguity stops safely without evasion;
- a review-ready candidate has stable baselines, negative controls,
  independent reproduction, refutation results, and redacted traceable
  evidence;
- no automated component can mark a finding human-confirmed, promote evidence
  without review, or submit a report;
- the held-out live-lab gate meets every approved quality and safety threshold;
- field and outcome labels remain honest and cannot be inferred from replay
  tests; and
- existing A+B Candidate Hunter and repository verification suites remain
  green.

## Written Review Questions

The implementation plan should not begin until the operator confirms:

1. the selected workflow-seeded architecture matches the intended real bounty
   workflow;
2. the remote execution lease and fixed conservative limits are acceptable;
3. the no-session-persistence tradeoff is acceptable for the first release;
4. the supported first-release vulnerability families are narrow enough; and
5. the four quality gates are the standard by which progress will be reported.
