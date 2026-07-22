# Bounty Mythos-Lite North Star

## Long-Term Goal

Bounty Mythos-Lite should become a lawful, safe, verifiable, reproducible, and auditable AI vulnerability research factory with real Mythos / XBOW style high-quality vulnerability discovery capability.

The long-term reference is `私人 AI 漏洞研究系统最终方案.md`.

The final system should accept an authorized target package and autonomously run a bounded research loop:

```text
authorized policy / scope / API / HAR / local code
-> Scope Guard
-> target and attack-surface modeling
-> semantic code and API audit
-> vulnerability hypothesis generation
-> refutation, deduplication, and ranking
-> safe validation work queue
-> redacted evidence review
-> submission-blocked report draft
-> human review
```

The intended capability is not "summarize scanner output." It is to discover a small number of high-impact, evidence-traceable vulnerability candidates that a human bounty researcher would consider worth validating.

## Current Stage Goal

The current implementation target is A+B Autonomous Candidate Hunter:

```text
authorized program policy/scope
+ API or HAR artifacts
+ authorized local code
-> top high-quality vulnerability candidates
```

This stage is not a generic dashboard effort. It should prove that the system can read authorized target materials, understand API and code surfaces together, and produce a small set of candidates worth human validation.

Current implementation note: Mythos-Lite has the safety, artifact, candidate, report-readiness, and review-loop foundation, plus a bounded durable Candidate Hunter execution loop. It advances one persisted read-only task at a time through surface mapping, hypothesis generation, plan-only exploit-chain/variant/deep-code reasoning, refutation/evidence review, deduplication/ranking, and submission-blocked report review, then stops at the human validation boundary. Compact Finding Dedup Risk, Variant Analysis, and Deep Code Reasoning projections are snapshot-bound advisory inputs to report review; they cannot create a candidate, retain raw plan content, or grant execution, validation, promotion, or submission permission. Snapshot-bound, redacted SARIF route signals and directly imported SBOM dependency advisories can support cross-source review but cannot independently create a candidate validation target. It should not be described as already having final Mythos/XBOW-grade autonomous discovery execution; the next gaps are deeper independent specialist workflows, broader semantic coverage, and calibrated candidate quality on authorized benchmarks.

## Preferred Product Form

The preferred user experience is Mythos Studio: a local, desktop-style, chat-first research workspace. See `docs/superpowers/specs/2026-07-07-mythos-studio-design.md`.

The first implementation milestone is the local `/studio` workspace plus the Electron launcher in `apps/studio`.

The studio should let an operator create a local workspace, import authorized materials, direct the research agent through conversation, review candidate cards, approve or reject validation plans, attach redacted evidence, and export submission-blocked report drafts.

## Expected Inputs

- Program policy and scope.
- OpenAPI, Postman, HAR, notes, or equivalent authorized API artifacts.
- Authorized local code snapshots or repository excerpts.
- Optional historical outcomes, duplicate notes, and triager feedback after redaction.

## Expected Candidate Output

Each candidate should include:

- Affected endpoint.
- Affected code path.
- Vulnerability type.
- Why it may be high impact.
- Evidence needed.
- False-positive and refutation questions.
- Safe validation plan.
- Safety blockers.
- Report draft readiness.

The system should prefer 1-5 strong candidates over a long noisy list.

## Safety Boundaries

The system must not:

- Automatically attack public targets.
- Run destructive validation, DoS, credential stuffing, social engineering, or high-frequency scanning.
- Touch, collect, store, display, or report real user data.
- Save raw secrets, tokens, cookies, credentials, or authorization headers.
- Treat model output, scanner output, or imported third-party findings as confirmed vulnerabilities.
- Bypass Scope Guard, human approval, redaction review, or report submission gates.
- Submit reports automatically.

## Capability Path

1. A+B Candidate Hunter: correlate policy/API/HAR/local code and produce high-value candidates.
2. Autonomous Candidate-Hunter Loop: repeatedly generate, refute, deduplicate, rank, and improve candidates from traceable local evidence.
3. Static Analyzer Integration: ingest Semgrep, CodeQL, dependency, and language scanner results as advisory signals.
4. Verifier Workspace: support local or human-approved non-destructive validation, evidence review, and finding promotion.
5. Report and Patch Loop: produce submission-blocked reports, root-cause summaries, fix guidance, and regression test suggestions.
6. Learning and Deep Research: use accepted, duplicate, rejected, and triager feedback to improve future ranking without granting execution permission.

## Success Criteria

Given an authorized policy, API/HAR artifact, and local code sample, the system should produce 1-5 high-quality candidates that:

- Link an API surface to a code path or clearly state why the link is missing.
- Explain the suspected security invariant break.
- Provide concrete evidence requirements.
- Include refutation questions before validation.
- Stay inside Scope Guard and human-review boundaries.
- Produce a submission-blocked report preview only after evidence and safety blockers are explicit.
