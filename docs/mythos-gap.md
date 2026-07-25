> **状态（2026-07-24）**：本文为早期 spine 差距记录，**不作为现役能力声明**。
> 现役阶段目标见 `docs/product/north-star.md`；实现快照与剩余 gap 见 `docs/product/requirements-and-features.md` 的 Current Implementation Status；近期设计见 `docs/superpowers/`。

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
   - Output: human-review-required report draft candidate and claim ledger.
   - Acceptance: severity, scope status, safety notes, steps, expected result, actual-result placeholder, claim quality score, readiness level, and evidence/provenance blockers are present.
   - Does not: submit reports automatically.

8. Learning Loop
   - Input: submission result and triager feedback.
   - Output: future prioritization rules.
   - Acceptance: accepted, duplicate, informative, N/A, rejected, bounty, severity delta, evidence quality, and redacted triager feedback become structured learning signals.
   - Does not: execute validation, submit reports, or turn feedback into automatic permission.

## Remaining Gaps

- Artifact repository, search, versioning, and provenance graph.
- Stage-based run timeline that explains each decision and safety stop.
- Validation workspace that connects safe plans, evidence, review, and report readiness.
- Better object and role modeling.
- Provider-backed structured LLM workflows with evals.
- Rich duplicate, bounty-impact, and evidence-quality scoring beyond the current advisory v1.
- Authentication, workspace isolation, and production permissions.

## Implemented Research Flow Foundation

The latest foundation turns the original dry-run reasoning spine into a working research flow. Dry-run can explain a target and propose safe next steps, while ingestion, run persistence, and evidence records give researchers durable inputs, reproducible runs, and reviewable facts.

### Artifact Ingestion

- Input: user-provided HAR files, Postman collections, OpenAPI documents, local notes, code excerpts, SARIF output, and policy documents from authorized programs.
- Output: normalized artifacts linked to a program, asset, source type, capture time, and ingestion status, with extracted endpoints, objects, roles, policy hints, textual endpoint mentions, code route decorators, and SARIF message/location paths available to the pipeline.
- Acceptance: uploads or local imports are parsed deterministically; notes, code excerpts, policy documents, and SARIF output can produce OpenAPI-like endpoint paths without claiming complete source understanding; unsupported formats fail with a clear reason; every derived target-model fact points back to its source artifact; duplicate artifacts are detected without losing provenance.
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
- Output: artifact repository API, filtered list view, detail view, artifact versions, provenance edges, derived-fact references, usage records, sensitivity state, and stable provenance paths for downstream stages.
- Acceptance: researchers can filter artifacts by program, asset, source type, ingestion status, structured provenance ref, fact type, usage type, usage run, sensitivity label, redaction status, and report-chain eligibility; every derived fact shows its source artifact and parsing stage; duplicate re-imports preserve deduplicated `duplicate_imports` provenance history instead of overwriting the canonical artifact facts; artifact detail shows usage records for pipeline runs, hypothesis candidates, evidence bundles, report claims, claim review decisions, manual observations, finding candidates, and learning signals that cite the artifact; sensitive values must be redacted or rejected before display, export, or report use; Scope Guard, report-chain blockers, and human approval status remain visible on every artifact usage path.
- Does not: crawl public targets, attack internet services, touch real user data, save raw secrets, retain tokens or cookies, treat third-party scanner output as confirmed impact, or allow artifact use after a blocked Scope Guard decision.

### Stage-based Pipeline Run Timeline

- Goal: turn persisted runs into an inspectable stage timeline that explains what happened, why it happened, what stopped, and what a human can safely do next.
- Input: pipeline run records, stage records, artifact provenance paths, Scope Guard decisions, human approval records, refutation results, validation plans, evidence links, report draft links, and stage errors.
- Output: timeline API and UI model with per-stage status, timestamps, input summary, output summary, safety decision, approval requirement, error summary, provenance links, and next allowed action.
- Acceptance: each run displays Policy Ingestion, Target Understanding, Security Invariants, Hypothesis, Refutation, Safe Validation Plan, Evidence, and Report Draft stages; program-learning adjustments add an auditable advisory memory stage that names the applied learning reasons, and skipped memory boosts record hard safety-gate suppression; blocked, failed, human_approval_required, and completed states are visually and semantically distinct; stages link back to their artifacts, hypotheses, plans, evidence, and drafts; failed stages do not overwrite earlier successful stages; execution after human_approval_required is disabled until approval exists.
- Does not: provide an entry point for public-target attacks, let agents continue after blocked decisions, hide Scope Guard reasons, rewrite history, auto-submit reports, or send evidence outside the workspace.

### Validation Workspace

- Goal: connect safe validation plans, evidence capture, redaction review, human decision-making, and report readiness in one controlled workspace.
- Input: safe validation plans, hypotheses, Scope Guard decisions, artifact provenance, timeline state, evidence records, redaction status, reviewer annotations, and report draft candidates.
- Output: validation tasks, manual check results, evidence attachments, claim-to-evidence mapping, redaction review state, reviewer decisions, and report readiness state.
- Acceptance: researchers can only work on non-destructive tasks allowed by Scope Guard or explicit human approval; the workspace distinguishes unverified claim, model reasoning, manual observation, refuted finding, and report-ready claim; claim review decisions and manual observations write structured refs back to artifact usage records without copying rationale or observation text; every report-ready claim has redacted evidence and provenance; raw secrets, tokens, cookies, and real user data are blocked from the report chain; report submission remains human-review-required and never automatic.
- Claim Quality: report preview scores each claim from evidence refs, provenance refs, redaction state, artifact report-chain safety, claim type, review decision, and validation gates; high quality remains advisory and cannot unblock submission without the hard human gate or a blocked artifact safety path.
- Does not: automatically attack public targets, scan, brute force, run DoS, perform social engineering, touch real user data, save raw secrets, execute validation steps autonomously, submit to platforms, or mark claims verified without evidence and human review.

Across all three gaps, Scope Guard and human approval are hard gates. The product must not auto-attack the public internet, must not touch real user data, must not save raw secrets, and must not submit anything automatically.

## Hunter Intelligence V1

Hunter Intelligence adds the first top-hunter judgment layer on top of the safe pipeline. It does not validate a bug. It ranks and explains candidates before a human spends time on them.

- Input: target model facts, hypotheses, refutation results, policy risk, validation mode, evidence hints, and artifact provenance.
- Output: playbook match, hunter priority score, impact score, duplicate risk, policy risk, rejection risk, recommendation, next action, evidence focus, and safety notes.
- Acceptance: BOLA/IDOR, role-boundary, and money-flow candidates produce distinct playbook matches; out-of-scope and real-user-data blockers collapse priority; human-approval-only blockers become review recommendations rather than execution permission; the workbench can show the hunter summary beside each run.
- Does not: execute validation, attack public targets, prove impact, bypass Scope Guard, bypass Validation Workspace, touch real user data, save raw secrets, or submit reports automatically.

This is the bridge from "candidate generation" to "hunter triage." The remaining gap is outcome learning: accepted, duplicate, informative, N/A, bounty amount, and triager feedback should eventually tune these scores.

## Mythos Brain V1

Mythos Brain adds the first program-scoped memory layer. It is not another dashboard panel and it is not an execution engine. It turns target model facts, hunter scores, and human learning signals into reusable advisory memory for the next research decision.

- Input: program metadata, pipeline runs, target model objects, roles, sensitive actions, hunter intelligence, and manually recorded learning signals.
- Output: program score, attack surface memory, high-value surface ranking, learning summary, recent learning signals, outcome intake, and explicit safety notes.
- Acceptance: accepted outcomes boost similar playbooks, surfaces, and later hunter priority; duplicate, N/A, informative, and rejected outcomes raise future rejection risk; program learning can adjust later hunter duplicate/rejection risk without becoming execution permission; learning memory cannot change any hunter score for blocked or out-of-scope candidates above the hard safety gate; outcome intake can derive playbook and surface from a pipeline run and write structured learning signal refs back to artifact usage records; reviewed claim ledgers can infer strong, adequate, or weak evidence quality for the learning signal; bounty amount, severity delta, and evidence quality safely adjust advisory score/reasons; triager feedback is redacted and counted but not copied into artifact usage or parsed into execution permission; attack surface memory explains which object/action/role combinations are worth human attention; the dashboard can show the brain summary without hiding Scope Guard state.
- Does not: validate vulnerabilities, attack public targets, scan, brute force, run DoS, perform social engineering, touch real user data, save raw secrets, bypass human approval, or submit reports automatically.

This is the bridge from "hunter triage" to "hunter memory." The next gap is broader provenance-aware learning: richer claim quality signals, evidence provenance paths, and platform-specific triager patterns should shape future scoring without becoming automatic execution permission.

## Hunter Operating Loop V1

Hunter Operating Loop connects the research flow to long-term Finding DB memory. It is a promotion loop, not a validation engine.

- Input: pipeline run, report preview, claim quality, claim review decisions, hunter assessment, and LLM audit metadata.
- Output: finding candidate, hunter operating action, LLM run audit record, and safety notes.
- Acceptance: high-quality reviewed observed claims can become `finding_candidate_*` records; finding candidates preserve hunter operating reasons separately from evidence refs and write structured promotion refs back to artifact usage records without copying report text; LLM calls store provider/model/purpose/hash/latency/error without prompt text; hunter actions distinguish promote, stronger-evidence-needed, duplicate-risk parking, and policy blocking; generated findings remain candidates with human gates intact.
- Does not: validate vulnerabilities, attack public targets, scan, run DoS, touch real user data, save raw secrets, trust LLM output as fact, mark reports ready, or submit anything automatically.
