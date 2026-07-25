# Bounty Mythos-Lite North Star

## Product Direction

**SRC/HackerOne-first autonomous vulnerability discovery system.**

Bounty Mythos-Lite exists to autonomously turn explicitly authorized program material into a few strong, evidence-traceable vulnerability candidates and submission-ready report drafts. Its primary measure is automated discovery quality, candidate quality, and better bounty outcomes per human hour, not generic platform completeness or unrestricted live execution.

The long-form `私人 AI 漏洞研究系统最终方案.md` is retained as a reference for possible future capabilities. It does not set the active implementation priority.

## Active Research Loop

For an explicitly authorized program, the product should autonomously run this bounded research loop:

```text
program policy / scope / operator-provided authorized artifacts
-> Scope Guard
-> autonomous target and attack-surface modeling
-> autonomous semantic code and API audit
-> automated vulnerability hypothesis generation
-> automated refutation, deduplication, and ranking
-> automated safe validation planning
-> redacted evidence review
-> submission-blocked report draft
-> manual outcome intake and learning
```

The intended capability is not "summarize scanner output" or "build an unrestricted attack platform." It is to automatically discover a short list of high-impact, evidence-traceable candidates, then explain what would disprove each one before validation. Human approval remains the gate for live validation, sensitive actions, and report submission.

## Current Stage Goal

The current implementation target is the **H1/SRC Autonomous Candidate Discovery Track**:

```text
explicit program policy and scope
+ API, HAR, documentation, notes, or authorized local code
-> automatic target modeling, hypothesis generation, refutation, and ranking
-> a short, ranked candidate queue
-> refutation questions and evidence gaps
-> safe validation plan for human review
-> submission-blocked report draft when evidence supports it
```

This stage is not a generic dashboard or live-execution-platform effort. It should prove that:

- program rules, exclusions, and automation posture become visible before research starts;
- the system can autonomously connect target surfaces, code paths, roles, objects, and business flows to a small set of candidates worth human validation;
- each retained candidate has concrete refutation questions, evidence requirements, a program-aware safe validation plan, and report readiness state;
- manual platform outcomes improve future ranking without becoming execution permission.

The current foundation for policy, artifacts, candidate generation, report readiness, and review loops remains useful. The next work is to make the candidate-hunter loop more autonomous and validate it on a small number of chosen in-scope programs, with emphasis on semantic coverage, impact calibration, duplicate avoidance, and report quality.

Existing Autopilot, scheduler, and execution-plane work should serve the autonomous discovery loop. New generic control-plane infrastructure, broad dashboard work, and autonomous live-operation features are deferred until outcome data shows that they remove a demonstrated discovery bottleneck.

## Preferred Product Form

The preferred user experience is Mythos Studio: a local, desktop-style, chat-first research workspace. See `docs/superpowers/specs/2026-07-07-mythos-studio-design.md`.

The first implementation milestone is the local `/studio` workspace plus the Electron launcher in `apps/studio`.

The studio should let an operator create a local workspace, import authorized materials, start and observe the autonomous research loop, review candidate cards, approve or reject validation plans, attach redacted evidence, and export submission-blocked report drafts. It should make autonomous research decisions and the next human gate clear without requiring a generic operations console.

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

Automation on the execution plane may schedule, resume, and prepare work; it must not grant itself validation, promotion, or submission authority.

## Capability Path

1. **Program intake**: normalize policy, scope, exclusions, automation posture, and operator-provided research artifacts for an SRC or HackerOne program.
2. **Autonomous candidate hunter**: model surfaces, roles, objects, and business flows; generate high-value hypotheses; actively refute weak and duplicate candidates; rank the retained queue without step-by-step operator steering.
3. **Research handoff**: automatically prepare evidence requirements, safe validation plans, and platform-style report drafts for human review.
4. **Outcome learning**: use accepted, duplicate, informative, N/A, rejected, severity, and triager feedback to improve ranking and explanation.
5. **Validated automation expansion**: add durable scheduling or execution support where it directly improves proven discovery workflows, while retaining Scope Guard and human gates for live validation, sensitive actions, and submission.

## Success Criteria

Given an authorized policy, API/HAR artifact, and local code sample, the system should produce 1-5 high-quality candidates that:

- Link an API surface to a code path or clearly state why the link is missing.
- Explain the suspected security invariant break.
- Provide concrete evidence requirements.
- Include refutation questions before validation.
- Stay inside Scope Guard and human-review boundaries.
- Produce a submission-blocked report preview only after evidence and safety blockers are explicit.

Across a portfolio of chosen programs, progress is measured by autonomous useful-candidate yield per human hour, manual validation and report readiness quality, duplicate and N/A rates, and eventually accepted outcomes. The autonomous candidate-hunter loop is the current priority; generic automation features must still remove a demonstrated bottleneck in that loop.
