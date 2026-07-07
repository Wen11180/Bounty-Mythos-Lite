# AGENTS.md

## 1. Think Before Coding

Do not assume. Do not hide confusion. Surface tradeoffs.

- State assumptions explicitly.
- Present multiple interpretations when the request is ambiguous.
- Push back when a simpler approach exists.
- Stop when confused and ask for clarification.

## 2. Simplicity First

Use the minimum code or documentation that solves the problem.

- Do not add features beyond what was asked.
- Do not add abstractions for single-use code.
- Do not add speculative configurability.
- Do not add error handling for impossible scenarios.
- If the solution can be shorter and clearer, make it shorter and clearer.

## 3. Surgical Changes

Touch only what the task requires.

- Do not improve adjacent code, comments, formatting, or documents unless needed.
- Match existing project style.
- Remove only imports, variables, functions, or text made unused by your own change.
- Mention unrelated dead code or stale docs instead of deleting them.
- Every changed line should trace directly to the request.

## 4. Goal-Driven Execution

Turn work into verifiable goals.

- Define success criteria before implementation.
- For bugs, reproduce or identify the failing behavior before fixing it.
- For validation or safety behavior, include tests or explicit checks.
- For multi-step tasks, state the plan and verification for each step.
- Loop until the agreed success criteria are met or a real blocker is identified.

## Mythos-Lite Safety Boundaries

Bounty Mythos-Lite is a lawful bug bounty research assistant. It must stay inside authorized, low-risk research workflows.

- Do not automatically attack public targets.
- Do not run destructive validation, DoS, credential stuffing, social engineering, or high-frequency scanning.
- Do not touch, collect, store, display, or report real user data.
- Do not save raw secrets, tokens, cookies, credentials, or authorization headers.
- Do not treat model output, scanner output, or imported third-party findings as confirmed vulnerabilities.
- Do not bypass Scope Guard, human approval, redaction review, or report submission gates.
- Do not submit reports automatically.

## Project North Star

This project targets the final direction in `私人 AI 漏洞研究系统最终方案.md`.

Bounty Mythos-Lite should evolve into a lawful, auditable AI vulnerability research factory:

```text
authorized policy/API/HAR/local code
-> Scope Guard
-> target intake
-> API/code attack-surface modeling
-> static analysis
-> semantic code audit
-> vulnerability hypotheses
-> refutation and deduplication
-> safe validation planning
-> evidence review
-> submission-blocked report draft
-> human review
```

The immediate implementation priority is A+B: policy/scope/API/HAR plus authorized local code, producing top high-quality vulnerability candidates with affected endpoints, affected code paths, evidence needs, refutation questions, safe validation plans, and report draft readiness.

Do not optimize for dashboard completeness before the autonomous candidate-hunter loop works.

## Expected Working Style

For this repository, prefer safe, auditable research operations over autonomous exploitation.

1. Parse program policy and Scope Guard rules first.
2. Ingest only user-provided or explicitly authorized artifacts.
3. Build target models, security invariants, and hypotheses from traceable evidence.
4. Refute candidates before planning validation.
5. Generate only non-destructive validation plans.
6. Require human approval for validation, evidence promotion, and report submission.
7. Keep learning signals advisory; they may rank and explain future work but must not grant execution permission.
