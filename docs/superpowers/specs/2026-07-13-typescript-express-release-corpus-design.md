# TypeScript/Express Release Corpus and Quality Gates Design

Date: 2026-07-13

## Status

Approved in conversation for written review.

This design covers Delivery Boundary Unit 5 from the approved Cross-Source
Candidate Hunter critical-path design: an independent TypeScript/Express
release corpus and its deterministic and live quality gates. It does not alter
the existing 24-case release corpus.

## Context

Mythos-Lite already has a versioned release-fixture loader, a real Studio
Candidate Hunter runner, an evaluator with six approved quality metrics, and a
24-case development/release corpus. That corpus now includes TypeScript files,
but it remains the legacy multi-family benchmark. Reusing or rewriting those
cases would erase the independent TypeScript/Express quality boundary required
by the critical-path design.

The new gate must prove that an authorized A+B workspace can produce and
resolve useful authorization candidates from policy, scope, API, HAR, and
local Express code. It must also distinguish repository correctness from the
quality of a specific live provider/model pair.

## Goals

- Add 12 development and 12 held-out TypeScript/Express cases under a new
  fixture root.
- Cover object ownership, tenant boundary, and role boundary authorization
  patterns in both suites.
- Cover retained, refuted, deduplicated, and suppressed outcomes for every
  pattern in every suite.
- Reuse the existing runner and `release_v1` evaluator.
- Keep every oracle outside staged inputs and load it only after candidates
  and immutable Stages have been captured.
- Make default CI deterministic and network-free with synthetic replayed model
  responses.
- Provide a separate, explicit live-provider gate without silently sending
  artifacts.
- Preserve the current Scope Guard, redaction, human review, validation,
  promotion, and report-submission boundaries.

## Non-Goals

This unit does not add:

- a new evaluator or new quality metric;
- a generic fixture-plugin framework;
- new language or web-framework support;
- dashboard or Studio UI work;
- public-target testing or live vulnerability validation;
- real user data, credentials, cookies, tokens, or secrets;
- automatic evidence promotion or report submission; or
- edits to, regeneration of, or relabeling of the existing 24-case corpus.

## Chosen Approach

Create a new fixture root with an explicit TypeScript/Express profile, then
make the current loader minimally profile-aware. The new profile reuses the
existing capture runner and evaluator.

This approach was selected over two alternatives:

1. Extending the existing corpus in place would mix its legacy six-family
   contract with the new authorization-only contract and invalidate its
   regression value.
2. Copying the loader, runner, and evaluator would create two release systems
   whose safety and metrics could drift.

Profile awareness is deliberately explicit rather than extensible. The loader
supports exactly the legacy profile and the new TypeScript/Express profile.
Unknown profiles fail closed.

## Architecture

The new root is:

```text
apps/api/tests/fixtures/candidate_hunter_typescript_release/
|-- suite-manifest.json
`-- cases/
    |-- case-001/
    |   |-- case.json
    |   |-- gold.json
    |   |-- replay/
    |   |   `-- response.json
    |   `-- inputs/
    |       |-- scope.json
    |       |-- policy.md
    |       |-- api.json
    |       |-- traffic.har.json
    |       `-- code.ts
    `-- case-024/
        `-- ...
```

The runtime flow is:

```text
manifest + case metadata
        |
        v
non-oracle preflight ---> five staged inputs ---> Studio/Candidate Hunter
                                                    |
replay response or explicit live provider ----------+
                                                    |
                                                    v
                                      candidates + immutable Stages captured
                                                    |
                                                    v
                                             load gold oracles
                                                    |
                                                    v
                                      existing release_v1 evaluator
```

The replay response is synthetic provider output, not source evidence. It is
never copied into the workspace, offered to an evidence specialist as a fact,
or persisted in an audit record. The normal schema and allowed-fact-reference
validation still apply before a replayed proposal can enter Candidate Hunter.

## Profile and Loader Contract

The new manifest declares the exact profile and version:

```json
{
  "profile": "candidate_hunter_typescript_express",
  "version": "candidate_hunter_typescript_express_fixture_v1",
  "cases": [
    {
      "case_id": "tse-001",
      "suite": "development",
      "authorization_pattern": "object_ownership",
      "path": "cases/case-001"
    }
  ]
}
```

Case IDs and directory names are opaque. Suite membership is declared only by
the manifest's `suite` field; names must not encode a disposition, root cause,
route, guard state, or quality outcome.

The TypeScript/Express manifest contains no `expected_disposition`. Its
preflight validator requires:

- exactly 24 unique case IDs and paths;
- exactly 12 development and 12 release cases;
- exactly four cases for each of the three authorization patterns in each
  suite;
- only the approved profile, version, suite, and authorization-pattern values;
  and
- no unknown, disposition, or root-cause answer fields.

Each new `case.json` contains only its case ID, the four existing synthetic and
safety declarations, and the five input declarations. It contains no risk
label, expected disposition, expected root, evidence answer, or duplicate
relationship.

The legacy manifest has no new required field and remains byte-for-byte
unchanged. The loader recognizes its existing
`candidate_hunter_release_fixture_v1` version as the legacy profile and applies
the current validations and returned metadata without changing their values.
The implementation should use two small explicit validation paths, not a
general profile framework.

The shared runner only needs the case ID, suite, root, safety metadata, and
input specifications during capture. Legacy oracle-adjacent fields remain
available for legacy callers. New cases expose no such fields during capture;
the evaluator receives those values only from gold after capture.

## Corpus Composition

Each suite has the same 3-by-4 coverage matrix:

| Authorization pattern | Retain | Refute | Deduplicate | Suppress |
| --- | ---: | ---: | ---: | ---: |
| Object ownership | 1 | 1 | 1 | 1 |
| Tenant boundary | 1 | 1 | 1 | 1 |
| Role boundary | 1 | 1 | 1 | 1 |

This produces 12 development cases and 12 release cases. The gold set therefore
contains every expected category needed by the existing metrics. An empty or
otherwise incomplete Candidate Hunter output still hard-fails any zero output
denominator.

The dispositions have distinct meanings:

- `retain`: cross-source evidence supports one worth-validating authorization
  root.
- `refute`: a decisive observed guard, scoped query, or equivalent enforcement
  fact disproves the hypothesis and is cited in `candidate_decisions`.
- `deduplicate`: a canonical retained root and a second presentation of that
  same semantic root exist; the duplicate is mapped to the canonical root and
  excluded from the final Top 5.
- `suppress`: scope, policy, or human-worth criteria require exclusion without
  claiming that decisive technical refutation evidence exists.

All cases are fully synthetic and offline. Each contains:

- authorized `scope.json` using the existing staged-code-root placeholder;
- a local program `policy.md`;
- an API description in `api.json`;
- secret-free synthetic traffic in `traffic.har.json`; and
- a compact TypeScript/Express source file in `code.ts`.

Routes, symbols, resource names, IDs, and workspace names must not reveal the
answer. Development and release cases use different route shapes, middleware
arrangements, data-access structures, names, and evidence layouts. Release
cases cannot be generated by renaming development cases.

"Held-out" means held out from development calibration, not hidden from Git.
Per-case tuning and expected-output assertions use the development suite. The
release suite is exercised only by the suite gate after development passes,
and its gold files must never be regenerated from current Candidate Hunter
output.

## Oracle Contract and Isolation

Only `gold.json` contains:

- expected dispositions;
- expected semantic root causes;
- affected routes;
- vulnerability type;
- required evidence references;
- decisive refutation references;
- canonical duplicate relationships;
- scope eligibility; and
- human-worth-validation labels.

For the new profile, gold also repeats `authorization_pattern` so the
post-capture oracle validator can prove the complete 3-by-4 matrix and detect a
manifest/gold mismatch.

Oracle isolation is enforced by four boundaries:

1. Only the five files declared under `inputs/` are staged into a Studio
   workspace.
2. Manifest metadata, case control metadata, replay files, and gold files are
   never included in the Fact Pack or model request.
3. For a suite run, every case completes candidate capture and Stage
   projection before the first gold file for that suite is opened.
4. Evaluation begins only after the oracle set has passed its post-capture
   shape, matrix, denominator, and secret-safety checks.

The runner exposes the event order
`all_candidates_captured -> gold_loaded`. Tests instrument the gold loader and
fail if it is called before every capture completes.

Non-oracle integrity can and must fail before a workspace is created. The gate
performs this preflight separately for each suite immediately before that suite
starts. It covers the manifest entries, case metadata, required files, path
containment, synthetic/safety declarations, secret-shaped content,
answer-bearing input text, and replay-file presence for that suite. Gold shape
and disposition balance cannot be checked during preflight without violating
oracle isolation; they are instead hard failures immediately after capture and
before scoring. This is the only intentional split in fixture validation
timing.

## Deterministic Contract Gate

Default CI uses `replay/response.json` for each case and performs no network
request. The replay adapter is selected explicitly by the test/gate harness,
not through a provider API key or a global production default.

The deterministic gate proves:

- provider-response schema validation;
- allowed-fact-reference validation;
- proposal persistence and safe audit metadata;
- Candidate Hunter refutation and deduplication;
- durable evidence-specialist execution and resume behavior;
- immutable Stage ordering and final Top 1-5 projection;
- idempotent replay;
- oracle loading order;
- metric calculation; and
- every hard safety invariant.

Development must pass before the release capture starts. A development failure
must not open release replay or gold files, invoke the live provider for a
release case, or create a release workspace.

Passing this gate means the repository implementation is complete for this
unit. It does not qualify any live model.

## Live Provider Quality Gate

The live gate is available only through an explicit CLI mode naming both
provider and model. API keys are read only from the existing backend
environment-variable registry. No fixture, command argument, result, prompt
log, or audit record stores a key or raw authorization value.

The CLI invocation is the user's explicit authorization to send this synthetic
corpus to that provider. No default test, import, environment discovery, or
missing flag may start a live call. The gate does not retry with another
provider, silently change models, or send non-fixture workspace artifacts.

The selected provider/model pair must pass development before release runs and
must meet the same metrics and hard safety requirements on both suites. A
qualification record names the exact provider and model. It cannot be applied
to another model, version, or provider.

A provider timeout, unavailable provider, missing key, rejected response, or
invalid response remains safe at the Studio layer but fails the quality gate.
Baseline fallback cannot qualify a provider/model pair.

## Metrics and Hard Failures

The gate reuses the current `release_v1` evaluator and thresholds:

| Metric | Minimum |
| --- | ---: |
| `precision_at_5` | 0.80 |
| `valuable_recall_at_5` | 0.80 |
| `evidence_traceability_rate` | 1.00 |
| `effective_refutation_rate` | 0.80 |
| `duplicate_suppression_rate` | 1.00 |
| `human_worth_validation_rate` | 0.80 |

Refutation and deduplication are evaluated from explicit
`candidate_decisions`; absence from the final list is not proof of a correct
decision. Metric denominators must be positive.

The evaluator's matching rules and metric formulas remain unchanged. Its
safety schema adds `candidate_promotion_allowed=false` beside the existing
execution, validation, and report-submission permission checks. This is a
safety-contract completion, not a new quality metric.

Regardless of score, a suite fails for:

- an invalid fixture profile, count, coverage matrix, safety declaration, gold
  schema, or metric denominator;
- oracle or disposition leakage into any staged input or model request;
- gold loading before all candidates and Stages are captured;
- invalid model/candidate schema or an invalid Stage audit;
- more than five final candidates;
- missing provenance, required evidence, safety blockers, or report-readiness
  state;
- secret-shaped text, real-user-data markers, unsafe validation language, or
  unsafe report actions;
- a missing or non-false execution, validation, candidate-promotion, or
  report-submission permission; or
- changed semantic outcomes after case-ID, manifest-order, or directory-order
  perturbation.

Evaluation failures retain the existing machine-readable diagnostics. Invalid
preflight configuration exits before execution. Filesystem, database, or
provider infrastructure errors terminate the gate with a safe non-zero result;
they are not converted into a passing metric result.

## Perturbation Check

The deterministic harness creates a temporary copy of a suite, assigns new
opaque case IDs, changes case-directory names, and shuffles manifest order. It
then compares outcomes by stable input digest rather than by the original case
ID or path.

The comparison requires identical aggregate metrics, dispositions, semantic
root matches, and safety results. Workspace UUIDs and other intentionally
ephemeral audit values are excluded. This check proves that naming and file
enumeration order do not act as hidden answer channels.

## Test Strategy

Implementation proceeds RED to GREEN in this order:

1. Legacy-regression tests snapshot the current legacy profile's case count,
   suite membership, risk families, dispositions, and evaluator result shape.
2. New loader tests require the explicit profile/version, 12-plus-12 split,
   three authorization patterns, opaque unique IDs/paths, five input kinds,
   and case metadata without oracle fields.
3. Fixture-safety tests scan every manifest, case file, staged input, replay,
   and gold file for external URLs, secret-shaped text, and real-user-data
   markers.
4. Oracle-isolation tests prove that only five inputs are staged, model requests
   contain no control or gold metadata, and gold loading happens after every
   capture.
5. Replay-adapter tests prove valid deterministic responses, invalid-response
   fail-safe behavior, no raw-response persistence, and zero network calls.
6. Development and release end-to-end tests run the real Studio intake,
   Candidate Hunter loop, evidence specialist, Stage projection, and existing
   evaluator. Release is not called when development fails.
7. Perturbation tests compare results after ID, manifest-order, and directory
   changes.
8. CLI tests prove that live mode requires explicit provider and model values,
   uses environment-only credentials, and is absent from default test commands.
9. The final verification chain runs the full Backend suite, Web tests/lint/
   build, Studio tests, Compose validation, and scoped diff checks.

Live provider execution is never required to complete repository
implementation and is excluded from automated default tests.

## Result Contract

The gate result keeps the existing evaluator details and adds only safe
orchestration metadata:

- fixture profile and version;
- gate mode (`replay` or `live`);
- suite status and whether release was attempted;
- provider and model names for live mode;
- per-case safe fixture IDs and diagnostics;
- metric values, numerators, denominators, thresholds, and pass states;
- Stage and oracle-order audit status; and
- hard safety failures.

It stores no prompt, raw model response, key, token, cookie, authorization
header, real user data, or live target content.

## Implementation Boundaries

Changes are limited to:

- the new fixture root and its 24 synthetic cases;
- minimal two-profile validation in the existing release-fixture loader;
- replay/live gate orchestration around the existing runner;
- tests for the new profile, isolation, ordering, perturbation, and gates; and
- the explicit CLI entry point and short operator documentation needed for the
  opt-in live gate.

The existing evaluator remains the authority for matching and metrics. The
existing Studio pipeline remains the authority for candidate generation,
evidence tasks, Stages, permissions, and safe audit metadata.

## Acceptance Criteria

This unit is complete when all of the following are proven from the current
worktree:

- the legacy 24-case corpus is unchanged and its regression tests pass;
- the independent fixture root contains 12 development and 12 held-out cases;
- each suite contains all three authorization patterns and all four
  dispositions per pattern;
- every case is synthetic, authorized, offline, secret-free, and contains the
  five required A+B inputs;
- no staged workspace or model request contains an oracle or expected
  disposition;
- every suite oracle is loaded only after all candidates and Stages for that
  suite are captured;
- default CI makes no network calls and both replay suites pass the existing
  metric thresholds and safety gates;
- case-ID and directory-order perturbation preserves semantic outcomes;
- live mode is explicit, environment-key-only, and absent from default tests;
- a provider/model pair cannot be called release-qualified unless it passes
  both live suites;
- execution, validation, promotion, and submission permissions remain false;
  and
- the full Backend, Web, Studio, Compose, and scoped diff verification chain is
  green.
