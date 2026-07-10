# Candidate Hunter Release Benchmark Design

## Status

Approved design for the release-quality benchmark in the active A+B Candidate
Hunter objective. This specification defines an offline, deterministic quality
gate. It does not add a dashboard, execute validation, contact a target, or
grant any new permission.

It extends, but does not replace,
`2026-07-10-local-candidate-hunter-safety-design.md`. The local-only,
controlled-workspace, Scope Guard, redaction, human-review, and
submission-blocked guarantees from that design are prerequisites for every
benchmark run.

## Problem

The current Studio benchmark evaluates saved candidate JSON against saved
expectations. Its fixtures contain one prewritten positive candidate and one
matching expectation per risk family. That proves field completeness and
safety labels, but it cannot prove that Candidate Hunter discovers candidates
from authorized material, rejects a false positive, merges duplicates, or
keeps weak candidates out of Top 5.

The release gate must evaluate the actual Candidate Hunter flow using
independent, secret-free, authorized synthetic inputs and an oracle that is
never supplied to the Hunter.

## Goals

1. Measure `Precision@5`, evidence traceability, effective refutation,
   duplicate suppression, and human-worth-validation rate.
2. Fail closed on missing labels, ambiguous matching, secret-shaped text,
   unsafe permission flags, or incomplete metric denominators.
3. Make every failure explainable by case, candidate, expected root cause, and
   missing evidence or decision reference.
4. Keep all fixtures fully synthetic, locally authorized, redacted, and
   deterministic.
5. Support a development suite for implementation iteration and a separate
   release suite for the hard quality gate.

## Non-Goals

- Live Web/API validation, crawling, scanning, fuzzing, report submission, or
  model-provider calls.
- A new Web or Studio UI.
- A benchmark whose answer key is generated from the candidates it evaluates.
- Using learning signals as permission to validate or submit.

## Architecture

The benchmark has two layers.

### Layer 1: Evaluator Contract Tests

`app.intelligence_benchmark` receives normalized Hunter output plus a
human-authored oracle. Unit tests validate one-to-one matching, metric math,
zero-denominator handling, safety failures, and useful diagnostics. This layer
makes an evaluator failure easy to diagnose without running Studio.

Existing `evaluate_studio_candidates` remains available for backwards
compatible saved-candidate checks. The release evaluator is a separate,
explicit versioned entrypoint rather than silently changing the meaning of
existing fixture results.

### Layer 2: End-to-End Scenario Suite

The suite stages a case's authorized local inputs through the real Studio
intake and research path, captures normalized final candidates and decision
records, then passes only that output to the evaluator. The oracle is loaded
only after Hunter output is complete.

```text
synthetic scope / policy / code / OpenAPI / HAR
-> controlled Studio workspace
-> Candidate Hunter
-> normalized candidates + decisions
-> release evaluator + isolated gold oracle
-> metrics, failures, and hard pass/fail result
```

No benchmark component may make a network request to an externally supplied
host. The runner uses only a temporary controlled workspace and local fixture
paths that pass the workspace-boundary checks.

## Fixture Layout

Fixture source and oracle files live below:

```text
apps/api/tests/fixtures/candidate_hunter_release/
  development/
    <case-id>/
      inputs/
        scope.json
        policy.md
        openapi.json
        traffic.har
        code/
      gold.json
  release/
    <case-id>/
      inputs/
        ...
      gold.json
```

Each case is standalone and includes metadata declaring:

- `case_id`, `suite`, and `risk_family`;
- `synthetic: true`;
- `authorized_for_local_benchmark: true`;
- `contains_real_user_data: false`;
- `contains_secrets: false`.

Fixture loading validates that metadata before reading the payload. Any missing
or false safety declaration fails the case. Fixture text is checked against the
same forbidden-text rules used by the candidate evaluator.

The first benchmark corpus contains 24 independent cases: six risk families,
each with a retain, refute, duplicate, and low-value-suppress case. Three
risk families belong to the development suite and three are held out in the
release suite; each suite includes all four outcome classes. The release suite
is the hard gate, while the complete corpus remains the coverage target. The
families are:

| Risk family | Retain | Refute control | Duplicate | Suppress |
| --- | --- | --- | --- | --- |
| Object access | export lacks ownership check | repository enforces tenant scope | export/download share root cause | public/self-only file path |
| Role boundary | member can alter admin policy | owner middleware is decisive | invite/domain policy share bad guard | policy explicitly permits action |
| Webhook egress | unvalidated URL reaches client | IP and redirect re-check blocks it | retry/test use same dispatcher | fixed allowlisted provider |
| Money flow | client credit is accepted | server recomputes balance and limit | apply/finalize share authority flaw | stateless quote preview |
| RAG authorization | retriever misses tenant ACL | principal filter plus post-filter | query/search share retriever | public synthetic corpus |
| Agent tool authorization | privileged tool lacks principal grant | per-tool capability check | sync/queue share executor | sandboxed read-only tool |

The exact development/release family assignment is stored in a suite manifest,
not inferred from file names. A case may refer to a canonical root in another
case only through a safe root identifier; it never imports another case's raw
content.

## Oracle and Output Contracts

`gold.json` is authored independently of candidate output and is not exposed
to the Hunter. The end-to-end runner stages only `inputs/` before research and
loads the oracle only after it captures Hunter output. Each expected root has:

```json
{
  "gold_id": "object-export-owner-check",
  "root_cause_id": "missing-object-ownership-check",
  "route": {"method": "GET", "path": "/files/{file_id}/export"},
  "vuln_type": "authorization_gap",
  "disposition": "retain",
  "worth_validation": true,
  "required_evidence_refs": ["code:export-handler", "api:file-export"],
  "decisive_refutation_refs": [],
  "duplicate_of": null,
  "scope_allowed": true
}
```

Allowed dispositions are `retain`, `refute`, `deduplicate`, and `suppress`.
`refute` records require nonempty `decisive_refutation_refs` and
`deduplicate` records require `duplicate_of`.

The normalizer creates a release-evaluation payload with two collections:

```json
{
  "final_candidates": [
    {
      "candidate_id": "...",
      "rank": 1,
      "vuln_type": "...",
      "route": {"method": "GET", "path": "/..."},
      "root_cause_id": "...",
      "source_fact_refs": ["..."],
      "evidence_trace_status": "traceable",
      "human_validation_readiness": "ready",
      "execution_allowed": false,
      "validation_allowed": false,
      "report_submission_allowed": false,
      "safety_blockers": ["execute_live_validation", "touch_real_user_data", "submit_report"]
    }
  ],
  "candidate_decisions": [
    {
      "candidate_id": "...",
      "root_cause_id": "...",
      "disposition": "refuted",
      "evidence_refs": ["code:tenant-guard"],
      "duplicate_of": null
    }
  ]
}
```

The normalizer may map existing Candidate Hunter fields into this shape, but it
must never invent a root cause, evidence reference, disposition, or human-value
label. Missing source fields remain missing and fail the appropriate gate.

## Matching Rules

Matching is deterministic and one-to-one. Candidates are considered in rank
order, and each may match at most one retained gold root. A match requires the
same normalized vulnerability type, compatible route template, and the same
`root_cause_id`. A candidate that matches no retained root is a false positive.
One candidate cannot satisfy two expected roots, and two final candidates for
one root do not produce two true positives.

Refute and deduplicate results are evaluated from `candidate_decisions`, not
from an absent final candidate. An absent item is not proof that it was
considered and correctly rejected.

## Metrics and Gate

All metrics are calculated on the release suite, with per-case diagnostics.

| Metric | Definition | Minimum |
| --- | --- | --- |
| `precision_at_5` | unique retained gold roots matched in final Top 5 divided by returned final candidates, up to five | 0.80 |
| `valuable_recall_at_5` | unique retained, worth-validating gold roots matched in Top 5 divided by expected retained, worth-validating roots | 0.80 |
| `evidence_traceability_rate` | required evidence references present and traceable for matched retained roots divided by required evidence references | 1.00 |
| `effective_refutation_rate` | expected refute roots with a `refuted` decision that cites a decisive refutation reference divided by expected refute roots | 0.80 |
| `duplicate_suppression_rate` | expected duplicate roots correctly deduplicated to their canonical root and absent from final Top 5 divided by expected duplicate roots | 1.00 |
| `human_worth_validation_rate` | final Top-5 candidates matched to a `worth_validation: true` retained root and marked `human_validation_readiness: ready`, divided by returned final candidates | 0.80 |

`valuable_recall_at_5` is a supporting anti-gaming metric: without it, one
obvious correct candidate could pass precision while hiding missed high-value
roots. `human_worth_validation_rate` is distinct from precision: a correctly
identified root is not considered ready for a human to validate until its
evidence and review state are complete. This state does not grant validation
permission.

Every metric denominator must be positive for a release suite. A zero or
missing denominator is a configuration failure, not a passing score. The suite
also hard-fails when it returns more than five final candidates or when a final
candidate has missing provenance, a non-traceable evidence state, a missing
hard safety blocker, `execution_allowed=true`, `validation_allowed=true`, or
`report_submission_allowed=true`.

Secret-shaped text, raw authorization values, cookies, tokens, credentials,
real-user-data markers, unsafe validation language, or unsafe report actions
are hard failures regardless of score.

## Failure Result

The evaluator returns a machine-readable result containing:

- `status: passed | failed`;
- each metric, threshold, numerator, denominator, and pass state;
- one-to-one match assignments;
- false positives and missed retained roots;
- invalid refutation and deduplication decisions;
- unsafe field or text findings;
- case-level diagnostic messages that name only safe fixture IDs and refs.

The existing Studio benchmark result format remains unchanged. The new release
result is versioned so old callers cannot mistake a completeness check for a
discovery-quality gate.

## Test Strategy

1. Evaluator unit tests cover one-to-one matches, unmatched Top-5 false
   positives, duplicate reuse, missing and zero denominators, every metric
   threshold, and every hard safety failure.
2. Fixture validation tests ensure all 24 cases are synthetic, authorized,
   secret-free, and contain the appropriate independent gold labels.
3. End-to-end tests stage each case through the real Studio intake and
   Candidate Hunter path, then evaluate normalized output against its isolated
   gold file.
4. Development-suite tests are fast feedback. Release-suite tests are required
   before a release and must not be regenerated from current candidate output.
5. Full backend, Web, Studio, Compose, and diff checks remain required after
   benchmark implementation.

## Delivery Order

1. Add versioned release-evaluator contracts and pure evaluator tests.
2. Add fixture metadata validation and the 24-case development/release suite.
3. Add the controlled end-to-end fixture runner and release result artifact.
4. Connect the future stateful Candidate Hunter loop to the normalizer.
5. Require the release suite before later architecture extraction work.
