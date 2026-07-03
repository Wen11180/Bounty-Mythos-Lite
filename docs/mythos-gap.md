# Mythos Gap

## Current State

Bounty Mythos-Lite now has a safe foundation and a first dry-run pipeline. It can parse a simple policy, build a lightweight target model from OpenAPI-like input, derive security invariants, generate hypotheses, run refutation checks, build a safe validation plan, and produce a report draft candidate.

This is still not the full Mythos. It is the first testable spine.

## V1 Pipeline

1. Policy Ingestion
   - Input: program policy text and asset.
   - Output: executable Scope Guard rule.
   - Acceptance: forbidden test types, automation posture, scope status, and human approval are explicit.
   - Does not: claim complete platform-policy understanding.

2. Target Understanding
   - Input: OpenAPI-like artifact.
   - Output: endpoints, detected objects, sensitive actions, rough roles.
   - Acceptance: file/team/org/invoice-like boundaries are visible.
   - Does not: parse every OpenAPI edge case.

3. Security Invariants
   - Input: target model.
   - Output: a small set of high-signal invariants.
   - Acceptance: invariants explain what the system must protect.
   - Does not: generate noisy generic scanner findings.

4. Hypothesis
   - Input: invariants.
   - Output: hypothesis, vuln type, broken invariant, evidence needed, validation mode, risk, policy risk.
   - Acceptance: every hypothesis has a concrete evidence path.
   - Does not: treat model output as confirmed vulnerability.

5. Refutation
   - Input: hypothesis and Scope Guard decision.
   - Output: passed or blocked with reasons.
   - Acceptance: out-of-scope, policy risk, self-impact, best-practice-only, and real-user-data risks are explicit.
   - Does not: let any agent bypass Scope Guard.

6. Safe Validation Plan
   - Input: hypothesis and refutation result.
   - Output: non-destructive validation plan.
   - Acceptance: only test accounts, local review, role matrix checks, request/response diff, and low-risk business checks appear.
   - Does not: perform public-target attacks, DoS, credential stuffing, social engineering, real-user-data access, or automatic submission.

7. Report Draft
   - Input: hypothesis, validation plan, refutation.
   - Output: human-review-required report draft candidate.
   - Acceptance: severity, scope status, safety notes, steps, expected result, and actual-result placeholder are present.
   - Does not: submit reports automatically.

8. Learning Loop
   - Input: submission result and triager feedback.
   - Output: future prioritization rules.
   - Acceptance: accepted, duplicate, informative, N/A, bounty, and feedback become structured learning signals.
   - Does not: exist in this v1 slice yet.

## Remaining Gaps

- Real artifact ingestion for HAR, Postman, docs, code, and SARIF.
- Better object and role modeling.
- Provider-backed structured LLM workflows with evals.
- Persistent pipeline run records.
- Rich duplicate and bounty-impact scoring.
- Evidence capture and audit trail.
- Authentication, workspace isolation, and production permissions.

## Next Workable Research Flow Gaps

The next stage should turn the current dry-run reasoning spine into a working research flow. Dry-run can explain a target and propose safe next steps, but a researcher still needs durable inputs, reproducible runs, and reviewable evidence before the product can support real case work.

### Artifact Ingestion

- Input: user-provided HAR files, Postman collections, OpenAPI documents, local notes, code excerpts, SARIF output, and policy documents from authorized programs.
- Output: normalized artifacts linked to a program, asset, source type, capture time, and ingestion status, with extracted endpoints, objects, roles, and policy hints available to the pipeline.
- Acceptance: uploads or local imports are parsed deterministically; unsupported formats fail with a clear reason; every derived target-model fact points back to its source artifact; duplicate artifacts are detected without losing provenance.
- Does not: crawl public targets, attack internet services, ingest real user data, collect secrets, bypass Scope Guard, or treat imported scanner output as confirmed vulnerability evidence.

### Pipeline Run Persistence

- Input: policy rules, normalized artifacts, target model, generated invariants, hypotheses, refutation decisions, validation plans, report draft candidates, and human review decisions for a single pipeline run.
- Output: immutable run records with stage status, timestamps, inputs, outputs, safety decisions, errors, and links to the artifacts and evidence used to produce the result.
- Acceptance: a run can be resumed or inspected without re-running every stage; two runs over the same inputs can be compared; blocked Scope Guard decisions remain visible; report drafts can cite the exact run that produced them.
- Does not: execute background attacks, submit reports automatically, hide failed stages, overwrite prior run history, or allow agents to continue after a blocked safety decision.

### Evidence Model

- Input: safe validation notes, local request/response diffs, screenshots, role-matrix observations, sanitized logs, reproduction steps, and human reviewer annotations.
- Output: evidence records linked to hypotheses, validation plans, and report drafts, with source metadata, sensitivity labels, redaction status, and reviewer approval state.
- Acceptance: each reportable claim can reference specific evidence; evidence containing sensitive values is redacted before display or export; real user data is rejected or removed; human reviewers can distinguish observed facts from model-generated reasoning.
- Does not: store raw secrets, retain real user data, perform destructive validation, prove impact without human review, or send evidence to a platform automatically.

Together these gaps form the bridge from reasoning to research operations: Artifact Ingestion gives the system authorized material to understand, Pipeline Run Persistence makes each reasoning pass reproducible and auditable, and the Evidence Model turns safe observations into report-ready facts without crossing product safety boundaries.
