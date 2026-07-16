# Falsification-First Candidate Engine Design

Date: 2026-07-15

## Status

**Slice 1 implemented (2026-07-15 lab).** Black-box L2 ranking value is green; A+B Falsification Card v1 is wired into Candidate Hunter Decision Stage with schema validation, hard-scenario audit, and `ab-leadership-gate`. Claim scope remains lab/synthetic authorized quality only — not live-program TOP1.

Earlier note: black-box remains a primary battlefield when no authorized live target is available. This design is the shared quality layer for A+B Top 1-5 retention.

This design extends:

- `docs/product/north-star.md`
- `docs/superpowers/specs/2026-07-11-stateful-candidate-hunter-loop-design.md`
- `docs/superpowers/specs/2026-07-13-studio-cross-source-reasoner-design.md`
- `docs/superpowers/specs/2026-07-10-local-candidate-hunter-safety-design.md`

It does not replace the stateful Candidate Hunter loop. It makes **falsification**
the first-class decision core of that loop, so Mythos-Lite competes on research
quality rather than scan volume or autonomous exploitation.

## Decision Summary

1. Every candidate is a **hypothesis under attack**, not a finding.
2. The engine's primary job is structured kill attempts before human validation.
3. Only survivors with closed or explicitly listed evidence gaps enter Top 1-5.
4. Kill decisions must cite observed local facts; missing evidence fails closed.
5. LLM/scanner/model output may propose hypotheses or kill questions, never
   grant authority, confirm a vulnerability, or bypass Scope Guard.
6. Validation, promotion, execution, dispatch, and report submission remain
   blocked unless a later, separately approved human-gated slice changes them.

## Problem

Mythos-Lite can already emit candidate-shaped hypotheses, refutation questions,
evidence gaps, and a multi-round loop shell. The product gap is sharper:

- generation is louder than falsification;
- refutation questions often stay unanswered narrative text;
- terminal decisions are not forced through a fixed kill taxonomy;
- operators cannot quickly see **why a candidate is still alive**;
- industry tools already generate noisy findings; few systems are built to
  disprove weak AI hypotheses with auditable local evidence.

Without falsification discipline, more reasoning, more models, and more
scanners only increase review cost.

## Goals

1. Make falsification the default path from hypothesis to rank.
2. Define a stable **Falsification Card** contract per candidate.
3. Encode a deterministic kill taxonomy with evidence requirements.
4. Persist every kill/survive attempt in the existing immutable Stage audit
   chain.
5. Rank only retained survivors into Top 1-5 for human safety review.
6. Provide Studio-facing projection that prioritizes "why not dead yet".
7. Keep all hard safety flags false and all inputs authorized/local/redacted.

## Non-Goals

- Live target contact, exploit execution, destructive validation, or DoS.
- Treating retained candidates as confirmed vulnerabilities.
- Automatic report submission or finding promotion.
- New database tables or Alembic migrations in the first implementation slice.
- A general workflow engine, free-form agent toolkit, or dashboard redesign.
- Using learning signals as execution permission.
- Replacing human `research_queue_review` approval workflow.

## Existing Contracts Reused

| Contract | Role |
| --- | --- |
| `candidate_hunter_loop` Campaign Task | Owns multi-round generate/refute/rank lifecycle |
| Immutable `PipelineStageRecord` rounds | Audit log for snapshot, evidence, decision, rerank |
| Candidate key `pipeline_run_id + hypothesis_id` | Stable identity across rounds |
| Existing decision vocabulary | `retained`, `refuted`, `deduplicated`, `suppressed` |
| Existing unresolved state | `needs_evidence` remains non-terminal |
| Studio candidate view | Input snapshot and operator-facing projection |
| Release `candidate_decisions` | Benchmark projection only for terminal states |
| Cross-source reasoner proposals | Optional hypothesis source; still must pass falsification |

No new table is required for the first slice. Falsification state lives inside
Decision Stage payloads and the final projection.

## Product Shape

```text
authorized policy / scope / API / HAR / local code
  -> Scope Guard
  -> attack-surface + invariant extraction
  -> hypothesis generation (baseline and/or opt-in model)
  -> Falsification Engine   <- this design
  -> Top 1-5 retained survivors
  -> human-gated safe validation plan
  -> redacted evidence review
  -> submission-blocked report draft
```

Falsification sits **before** human validation and **after** hypothesis
generation. It is the quality gate of A+B Candidate Hunter.

## Falsification Card

Each candidate carries one card. Fields may be empty only where the schema
explicitly allows; empty critical fields block retention.

```json
{
  "schema_version": "falsification_card_v1",
  "candidate_key": "pipeline_run:<id>+hypothesis:<id>",
  "hypothesis": {
    "title": "string",
    "vuln_family": "string",
    "affected_endpoint": "string|null",
    "affected_code_path": "string|null",
    "cross_source_link_note": "string"
  },
  "broken_invariant": "string",
  "supporting_fact_refs": ["fact:..."],
  "kill_attempts": [
    {
      "dimension": "scope|policy|invariant|cross_source|defense|duplicate|impact|evidence",
      "question": "string",
      "status": "open|killed|survived|insufficient_evidence",
      "evidence_refs": ["fact:..."],
      "rationale": "string",
      "actor": "deterministic_rules|model_assist|human_note"
    }
  ],
  "evidence_gaps": ["string"],
  "safe_validation_plan": {
    "mode": "non_destructive_local_or_human_approved",
    "steps": ["string"],
    "blockers": ["string"]
  },
  "decision": {
    "status": "unresolved|needs_evidence|retained|refuted|deduplicated|suppressed",
    "duplicate_of": "hypothesis_id|null",
    "rank": "int|null",
    "why_still_alive": ["string"],
    "why_dead": ["string"]
  },
  "safety": {
    "execution_allowed": false,
    "dispatch_allowed": false,
    "validation_allowed": false,
    "candidate_promotion_allowed": false,
    "report_submission_allowed": false
  }
}
```

### Card Invariants

- `broken_invariant` is required for `retained`.
- Every `killed` attempt needs at least one `evidence_refs` item.
- `survived` attempts should cite supporting or non-disproving refs when
  available; pure model opinion is not enough for retention.
- `insufficient_evidence` keeps the candidate unresolved or
  `needs_evidence`; it is not a silent reject.
- `duplicate_of` is required when status is `deduplicated`.
- All safety flags are always `false` in this slice.
- No raw secrets, cookies, tokens, credentials, or authorization headers.

## Kill Taxonomy

Deterministic rules run first. Model assist may only suggest additional
questions or map observed facts into these dimensions. It may not invent
facts, invent routes/code paths, or override Scope Guard.

| Dimension | Kill when | Survive only if |
| --- | --- | --- |
| `scope` | out of program, excluded asset, ambiguous scope | source run `scope_status == in_scope` and asset link holds |
| `policy` | forbidden test class / policy conflict | policy text does not block the hypothesis class |
| `invariant` | no concrete security invariant, or invariant is not security-relevant | broken invariant is explicit and business/security meaningful |
| `cross_source` | endpoint/code/HAR facts contradict or cannot be linked and no honest missing-link note exists | endpoint and code path both present, or missing side is explicitly explained with refs |
| `defense` | local code/framework path shows decisive protection that closes the hypothesized break | no decisive local defense fact found, or defense is bypassable by cited facts |
| `duplicate` | same observed root cause as a retained canonical candidate | unique root-cause signature or explicit non-duplicate rationale |
| `impact` | no realistic authorized impact without destructive/real-user/out-of-scope steps | impact story is in-scope, non-destructive, and relevant to bounty value |
| `evidence` | critical claim lacks fact refs | every critical claim is fact-backed or listed as an evidence gap |

### Decision Mapping

- Any decisive `killed` on `scope`, `policy`, `defense`, `impact`, or
  `evidence` that fully disproves the hypothesis -> `refuted` or
  `suppressed` (scope/policy/quality use `suppressed` when "not worth human
  validation" is clearer than disproof).
- Decisive `duplicate` kill -> `deduplicated`.
- All required dimensions closed with no kill, evidence complete enough for
  human review -> `retained`.
- Open dimensions remain only because authorized local observation cannot yet
  answer them -> `needs_evidence` / unresolved.
- Never map unresolved absence from Top 1-5 as a terminal reject.

## Loop Integration

Reuse the four-stage round shape from the stateful loop:

1. **Snapshot**: include full Falsification Cards, prior kill attempts, and rank.
2. **Evidence Request**: convert open kill dimensions and unanswered questions
   into bounded local re-analysis requests over authorized artifacts only.
3. **Decision**: apply kill taxonomy; append kill_attempt records; emit one
   terminal decision only when evidence rules are satisfied.
4. **Rerank**: keep only `retained`; sort by evidence completeness, then
   existing priority, then candidate id; emit at most five.

### Round Rules

- Idempotent by existing stage `idempotency_key` rules.
- Resume from first missing stage; never rewrite prior stages.
- Stop conditions remain those of the stateful loop:
  all terminal, no candidates, no state change, max rounds, blocked.
- Model-assisted proposals, if enabled for a run, enter as hypotheses and then
  must pass the same falsification path as baseline candidates.

## Studio Projection

Operator-facing candidate cards should prioritize falsification state:

1. Decision badge: `Retained` / `Refuted` / `Deduplicated` / `Suppressed` /
   `Needs evidence`
2. `broken_invariant`
3. `why_still_alive` or `why_dead` (short bullets from kill attempts)
4. Open kill dimensions and evidence gaps
5. Supporting fact refs
6. Safe validation plan and safety blockers
7. Only then narrative title / family / severity hints

Studio must not present retained candidates as confirmed vulns. Language stays
hypothesis / candidate / research-ready.

UI work in the first slice is projection-only: no new dashboard module, no
permission controls beyond existing gates.

## Ranking and Quality Metrics

### Ranking Inputs for Retained Candidates

1. Number of survived kill dimensions with evidence refs
2. Cross-source completeness (endpoint + code path + link note)
3. Specificity of broken invariant
4. Existing priority score
5. Stable candidate id as final tie-breaker

### Product Metrics

| Metric | Intent |
| --- | --- |
| Falsification kill rate | Share of input hypotheses ending `refuted` / `suppressed` / `deduplicated` |
| Kill precision | Sampled killed candidates that a human agrees should not consume validation time |
| Precision@5 | Share of retained Top 1-5 worth human safety validation |
| Evidence closure rate | Share of retained candidates with no critical unanswered kill dimension |
| Hallucination rate | Assertions without fact refs; must trend to zero and fail closed |
| Human-minutes per retained candidate | Operator cost proxy |

Benchmark gold labels still never enter the Hunter. Metrics use persisted
decisions and offline evaluation only.

## Safety Invariants

Every entrypoint, stage, projection, and test must prove:

- source materials are authorized, local, and redacted;
- source run is `in_scope` before loop creation or continuation;
- no live request, exploit, destructive validation, credential attack, or
  high-frequency scan;
- no real user data or raw secret material in stage payloads;
- model/scanner/heuristic output is never confirmation;
- learning signals may rank or prioritize kill order only;
- `execution_allowed`, `dispatch_allowed`, `validation_allowed`,
  `candidate_promotion_allowed`, and `report_submission_allowed` remain false;
- report submission stays manually blocked.

Any malformed safety field fails closed and yields no retained projection.

## First Implementation Slice

### In Scope

1. `falsification_card_v1` payload shape inside Candidate Hunter Decision and
   Rerank stages.
2. Deterministic kill taxonomy for the eight dimensions.
3. Mapping into existing terminal decisions and `needs_evidence`.
4. Projection helpers for Studio candidate cards and release
   `candidate_decisions`.
5. Unit tests for kill mapping, fail-closed evidence rules, Top 1-5 retention,
   and safety flags.
6. At least one multi-round fixture proving a candidate dies or survives based
   on newly observed local facts.

### Out of Scope for Slice 1

- LLM-authored free-form kill judgments without deterministic gates
- New DB schema
- Black-box differential hunter integration
- Automatic validation execution
- Full Studio redesign
- Learning-memory writeback beyond existing advisory hooks

## Delivery Order

1. Lock card schema and decision mapping tests (red).
2. Implement pure falsification functions over candidate snapshots.
3. Wire into existing Decision/Rerank stage builders without new tables.
4. Project `why_still_alive` / `why_dead` into Studio candidate payload.
5. Add safety and multi-round regression tests.
6. Run existing Candidate Hunter / Studio / release gates; do not weaken
   thresholds to pass.
7. Only after review, plan slice 2: model-assisted kill-question proposals and
   learning-informed kill priority.

## Acceptance Criteria

This design is implementation-ready only after review. The first code slice is
complete only when all are true from the worktree:

1. Every candidate entering Decision stage has a `falsification_card_v1`
   object or an explicit schema error that fails closed.
2. Terminal `refuted` / `suppressed` / `deduplicated` decisions cite kill
   dimensions and evidence refs.
3. `retained` candidates always include `broken_invariant`, supporting or gap
   refs, and all safety flags false.
4. Unresolved/`needs_evidence` candidates never silently become rejected and
   never enter Top 1-5.
5. Studio projection can show why each candidate is alive or dead without
   exposing secrets or confirmation language.
6. Existing stateful loop resume/idempotency behavior still holds.
7. Safety regression suite remains green; no permission flag becomes true.
8. Release evaluation continues to treat retained output as research-ready
   hypotheses, not confirmed findings.

## Open Questions for Review

1. Should decisive `policy` kills always be `suppressed` rather than
   `refuted`, to keep "disproved technically" separate from "not allowed /
   not worth review"?
2. For slice 1, is endpoint-without-code always `needs_evidence`, or may it be
   `retained` when `cross_source_link_note` honestly states code is unavailable
   in the authorized package?
3. Should human review notes be allowed to add kill attempts with
   `actor=human_note` in slice 1, or remain a later slice?

## Recommendation

Approve this design as the next product-quality core of A+B Candidate Hunter.
It is the smallest industry-differentiating capability that stays inside
Mythos-Lite safety boundaries and directly improves Top 1-5 research value.
