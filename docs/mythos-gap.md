# Mythos Gap

## Current State

Bounty Mythos-Lite now has a safe foundation and a first dry-run pipeline. It can parse a simple policy, build a lightweight target model from OpenAPI-like input, derive security invariants, generate hypotheses, run refutation checks, build a safe validation plan, and produce a report draft candidate.

Artifact ingestion, pipeline run persistence, and the evidence model now extend that spine into a first research-operations foundation: authorized materials can enter the system, runs can be reviewed later, and safe observations can be linked to report claims.

This is still not the full Mythos. It is a testable spine plus the first audit trail.

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

- Artifact repository, search, versioning, and provenance graph.
- Stage-based run timeline that explains each decision and safety stop.
- Validation workspace that connects safe plans, evidence, review, and report readiness.
- Better object and role modeling.
- Provider-backed structured LLM workflows with evals.
- Rich duplicate and bounty-impact scoring.
- Authentication, workspace isolation, and production permissions.

## Implemented Research Flow Foundation

The latest foundation turns the original dry-run reasoning spine into a working research flow. Dry-run can explain a target and propose safe next steps, while ingestion, run persistence, and evidence records give researchers durable inputs, reproducible runs, and reviewable facts.

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

Together these implemented slices form the bridge from reasoning to research operations: Artifact Ingestion gives the system authorized material to understand, Pipeline Run Persistence makes each reasoning pass reproducible and auditable, and the Evidence Model turns safe observations into report-ready facts without crossing product safety boundaries.

## Next Mythos Gaps

The next stage is about productizing the audit trail. The system already has records; it now needs a repository for those records, a timeline that explains them, and a controlled workspace where humans validate claims without crossing safety boundaries.

### Artifact Repository + Provenance

- Goal: make imported artifacts searchable, versioned, reusable, and explainable across programs, assets, runs, hypotheses, evidence, and report drafts.
- Input: normalized artifacts, source metadata, ingestion results, derived target facts, evidence links, run links, reviewer annotations, sensitivity labels, and redaction records.
- Output: artifact repository views, artifact versions, provenance edges, derived-fact references, usage records, sensitivity state, and stable provenance paths for downstream stages.
- Acceptance: researchers can filter artifacts by program, asset, source type, capture time, sensitivity, ingestion status, and usage; every derived fact shows its source artifact and parsing stage; re-imports preserve history instead of overwriting provenance; sensitive values must be redacted or rejected before display, export, or report use; Scope Guard and human approval status remain visible on every artifact usage path.
- Does not: crawl public targets, attack internet services, touch real user data, save raw secrets, retain tokens or cookies, treat third-party scanner output as confirmed impact, or allow artifact use after a blocked Scope Guard decision.

### Stage-based Pipeline Run Timeline

- Goal: turn persisted runs into an inspectable stage timeline that explains what happened, why it happened, what stopped, and what a human can safely do next.
- Input: pipeline run records, stage records, artifact provenance paths, Scope Guard decisions, human approval records, refutation results, validation plans, evidence links, report draft links, and stage errors.
- Output: timeline API and UI model with per-stage status, timestamps, input summary, output summary, safety decision, approval requirement, error summary, provenance links, and next allowed action.
- Acceptance: each run displays Policy Ingestion, Target Understanding, Security Invariants, Hypothesis, Refutation, Safe Validation Plan, Evidence, and Report Draft stages; blocked, failed, human_approval_required, and completed states are visually and semantically distinct; stages link back to their artifacts, hypotheses, plans, evidence, and drafts; failed stages do not overwrite earlier successful stages; execution after human_approval_required is disabled until approval exists.
- Does not: provide an entry point for public-target attacks, let agents continue after blocked decisions, hide Scope Guard reasons, rewrite history, auto-submit reports, or send evidence outside the workspace.

### Validation Workspace

- Goal: connect safe validation plans, evidence capture, redaction review, human decision-making, and report readiness in one controlled workspace.
- Input: safe validation plans, hypotheses, Scope Guard decisions, artifact provenance, timeline state, evidence records, redaction status, reviewer annotations, and report draft candidates.
- Output: validation tasks, manual check results, evidence attachments, claim-to-evidence mapping, redaction review state, reviewer decisions, and report readiness state.
- Acceptance: researchers can only work on non-destructive tasks allowed by Scope Guard or explicit human approval; the workspace distinguishes unverified claim, model reasoning, manual observation, refuted finding, and report-ready claim; every report-ready claim has redacted evidence and provenance; raw secrets, tokens, cookies, and real user data are blocked from the report chain; report submission remains human-review-required and never automatic.
- Does not: automatically attack public targets, scan, brute force, run DoS, perform social engineering, touch real user data, save raw secrets, execute validation steps autonomously, submit to platforms, or mark claims verified without evidence and human review.

Across all three gaps, Scope Guard and human approval are hard gates. The product must not auto-attack the public internet, must not touch real user data, must not save raw secrets, and must not submit anything automatically.
