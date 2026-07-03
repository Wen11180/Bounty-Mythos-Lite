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
