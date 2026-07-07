# Mythos-Lite Autonomous Vulnerability Research System

## Product Positioning

Mythos-Lite is an authorized autonomous vulnerability research system. It is designed to behave like a coordinated security research team: it receives a legal scope, program policy, authorized artifacts, test accounts, and budgets; then it plans, delegates, explores, models, hypothesizes, refutes, validates safely, builds evidence, drafts reports, and learns from outcomes.

The target effect is similar to Mythos-style long-horizon research: not a one-shot scanner, not a passive dashboard, and not an unrestricted attack tool. The system should run research campaigns that autonomously advance through safe stages while pausing at hard gates for approval.

## Core Promise

Given an authorized bounty target and supporting materials, Mythos-Lite should:

1. Understand the program rules.
2. Build an attack surface map from code, API artifacts, traffic captures, scanner output, and documentation.
3. Generate high-value vulnerability hypotheses.
4. Reason about exploitability and possible exploit chains.
5. Refute weak, duplicate, out-of-scope, or policy-risky candidates.
6. Perform only allowed local, static, offline, or explicitly approved low-risk validation.
7. Build redacted, provenance-backed evidence.
8. Draft human-review-required reports.
9. Learn from accepted, duplicate, informative, N/A, rejected, bounty, severity, and triager feedback outcomes.

## Autonomy Model

The product must support autonomous research, but autonomy is tiered.

### Level 0: Read-Only Autonomy

Allowed:

- Parse policy.
- Read authorized artifacts.
- Map code and API surfaces.
- Import SARIF, SBOM, and static scanner outputs.
- Generate target models, invariants, hypotheses, and refutations.
- Build report drafts from existing evidence.

No approval required beyond campaign setup.

### Level 1: Local Validation Autonomy

Allowed:

- Run local tests.
- Analyze local request/response examples.
- Compare static fixtures.
- Execute safe local repro scripts against local fixtures.
- Run static tools against authorized local code.

Requires campaign-level authorization and tool allowlist.

### Level 2: Test-Account Validation Autonomy

Allowed:

- Use explicitly configured test accounts.
- Compare roles and object access.
- Perform low-frequency, non-destructive authorization checks.
- Capture redacted request/response diffs.

Requires human approval before each validation batch.

### Level 3: Sensitive Live Validation

Default state: blocked.

Requires explicit human approval with actor, timestamp, reason, scope reference, and validation plan. Even after approval, destructive behavior, real user data access, DoS, credential attacks, social engineering, and automatic report submission remain forbidden.

## Non-Negotiable Safety Requirements

- Scope Guard is a hard runtime gate for every agent, task, validation plan, and report promotion.
- Human approval is required before any live, state-changing, or sensitive validation.
- Unknown validation modes fail closed as blocked or needs-review.
- Real user data, raw secrets, tokens, cookies, credentials, and authorization headers must be rejected or redacted before display, export, evidence use, or report use.
- LLM output, scanner output, imported artifacts, and agent reasoning are not facts until supported by evidence and human review.
- Learning memory is advisory only. It may rank and explain future work but cannot grant execution permission.
- Reports are drafts only. Submission is always manual.
- Every autonomous action must have an audit record with inputs, outputs, status, safety gate state, and stop reason.

## Success Metrics

- Accepted bounty per human hour improves over time.
- Accepted rate trends toward 30% or higher.
- Duplicate rate stays below 25%.
- Informative / N/A rate stays below 15%.
- Policy violations remain at 0.
- Percentage of candidates killed by refutation increases before report stage.
- Percentage of reportable claims with evidence, provenance, redaction, and human review reaches 100%.
- Autonomous campaigns produce useful next actions without hiding safety blockers.

## Primary Object: Research Campaign

A campaign is the top-level autonomous research unit.

Campaign input:

- Program and platform.
- In-scope and out-of-scope assets.
- Program policy.
- Authorized artifacts.
- Local repository paths or uploaded code snapshots.
- Test account inventory.
- Allowed tool list.
- Autonomy level.
- Budget: time, token, tool-call, and validation budgets.
- Target vulnerability classes.

Campaign output:

- Attack surface map.
- Codebase map.
- Agent run history.
- Hypothesis board.
- Refutation decisions.
- Validation queue.
- Evidence bundles.
- Finding candidates.
- Report drafts.
- Learning signals.
- Campaign summary and residual risk.

## Autonomous Research Loop

Each campaign repeatedly executes this loop:

```text
observe -> model -> hypothesize -> plan -> validate -> refute -> report -> learn
```

The loop is not linear. Agents may branch, parallelize, revisit earlier stages, or stop early when safety gates, low confidence, duplicate risk, or budget limits apply.

Required loop behavior:

- Every iteration records why it continued, paused, or stopped.
- Every candidate has a lifecycle status.
- Every hypothesis links to source facts and broken invariants.
- Every validation plan is Scope Guard checked.
- Every report claim links to evidence and provenance.
- Every learned lesson is advisory and safety-gated.

## Core System Modules

### 1. Campaign Orchestrator

Purpose: own the autonomous research loop.

Must support:

- Campaign creation and resumption.
- Task decomposition.
- Agent assignment.
- Parallel task scheduling.
- Budget enforcement.
- Safety gate enforcement.
- Stop reasons.
- Campaign-level progress and final summary.

Must not:

- Let agents bypass Scope Guard.
- Continue after blocked or approval-required states.
- Hide failed or skipped stages.

### 2. Scope Guard Runtime

Purpose: enforce program policy and product safety at runtime.

Must support:

- Policy parsing into executable rules.
- Asset scope checks.
- Validation mode allowlists.
- Forbidden test classes.
- Human approval requirements.
- Approval records with actor, timestamp, reason, and scope reference.
- Machine-readable block reasons.

### 3. Artifact Intelligence Layer

Purpose: ingest and normalize authorized materials.

Supported inputs:

- Program policy.
- OpenAPI / Swagger.
- Postman collections.
- HAR files.
- Local notes.
- Local code repositories or snapshots.
- Code excerpts.
- SARIF output.
- SBOM/dependency manifests.
- Public docs supplied by the researcher.
- Historical public reports supplied by the researcher.

Must output:

- Normalized endpoint facts.
- Object and role facts.
- Sensitive action facts.
- Source hashes.
- Provenance refs.
- Usage records.
- Sensitivity and redaction state.
- Report-chain eligibility.

### 4. Codebase Map Engine

Purpose: autonomously map authorized source code into security-relevant structure.

Must extract:

- Files, modules, packages, and entrypoints.
- Routes and handlers.
- Controllers and services.
- Data models and identifiers.
- Authentication and authorization checks.
- Role and permission hints.
- Sensitive sinks and state-changing functions.
- Source-to-route relationships.
- Static tool findings linked to code locations.

Must not:

- Crawl unauthorized remote repositories.
- Treat static findings as confirmed vulnerabilities.
- Store raw secrets discovered in code.

### 5. Target Model Engine

Purpose: combine artifacts and code maps into a target understanding graph.

Must model:

- Endpoints.
- Objects.
- Roles.
- Sensitive actions.
- Parent-child object relationships.
- Business flows.
- Tenant boundaries.
- Trust boundaries.
- Tool or AI-agent permissions where relevant.

### 6. Security Invariant Engine

Purpose: define what the target must protect.

Initial invariant families:

- Private object access control.
- Tenant isolation.
- Member/admin role boundaries.
- Membership lifecycle and removed-user access.
- Server-authoritative money flow.
- Replay and state consistency.
- RAG/document authorization.
- AI agent tool authorization.

### 7. Hypothesis Engine

Purpose: generate high-value vulnerability hypotheses from target facts and invariants.

Each hypothesis must include:

- Hypothesis text.
- Vulnerability class.
- Broken invariant.
- Source facts.
- Evidence needed.
- Validation mode.
- Exploitability assumptions.
- Risk estimate.
- Policy risk.
- Duplicate risk.

Candidates are not confirmed findings.

### 8. Exploit Chain Reasoner

Purpose: reason about whether multiple primitives can form a reproducible vulnerability path.

Must support:

- Primitive extraction.
- Preconditions.
- Required roles.
- Required objects.
- Expected impact.
- Chain confidence.
- Refutation questions.
- Safe validation plan generation.

Must not:

- Produce destructive exploit execution.
- Execute public-target attacks without approval.
- Claim impact without evidence.

### 9. Refutation Engine

Purpose: kill bad candidates before they waste human time.

Must check:

- Out-of-scope assets.
- Forbidden validation.
- Missing approval.
- Real user data requirement.
- Self-impact-only findings.
- Best-practice-only issues.
- Duplicate likelihood.
- Missing security impact.
- Weak evidence path.
- High policy risk.

### 10. Validation Harness

Purpose: execute only allowed validation modes.

Allowed by default:

- Static/local checks.
- Unit or local regression tests.
- Fixture-based repros.
- Test-account authorization comparisons after approval.
- Role matrix checks after approval.
- Redacted request/response diff capture after approval.

Forbidden:

- Destructive validation.
- DoS.
- Credential stuffing.
- Social engineering.
- Unauthorized public-target scanning.
- Real user data access.
- Automatic report submission.

### 11. Evidence Builder

Purpose: convert safe observations into report-ready evidence.

Must support:

- Evidence bundles.
- Evidence type validation.
- Secret and PII detection.
- Redaction state.
- Review state.
- Claim-to-evidence mapping.
- Provenance refs.
- Report-chain blockers.

### 12. Report Builder

Purpose: generate human-review-required report drafts.

Must support:

- Observed facts.
- Model reasoning.
- Unverified claims.
- Claim ledger.
- Claim quality scoring.
- Readiness blockers.
- Human review decisions.
- Platform-style report drafts.

Must default to submission blocked.

### 13. Agent Team

Purpose: run bounded specialist agents under orchestration.

Planned agents:

- Policy Agent.
- Scope Guard Agent.
- Recon / Artifact Agent.
- Code Map Agent.
- API Modeling Agent.
- Business Flow Agent.
- Invariant Agent.
- Hypothesis Agent.
- Exploit Chain Agent.
- Refutation Agent.
- Validation Planner Agent.
- Validation Harness Agent.
- Evidence Agent.
- Report Agent.
- Learning Agent.

Each agent run must record:

- Agent type.
- Campaign id.
- Input refs.
- Output refs.
- Tool calls.
- Safety gate state.
- Status.
- Error.
- Stop reason.
- Started and finished timestamps.

### 14. LLM Workflow Layer

Purpose: provide audited structured model reasoning.

Must support:

- Dry-run mode.
- Live provider adapters.
- Purpose-specific workflows.
- JSON schema validation.
- Prompt hashing without storing raw prompt text.
- Output provenance.
- Safety notes.
- Fail-closed behavior for malformed output.

Workflow purposes:

- Policy parsing.
- Target modeling.
- Invariant generation.
- Hypothesis generation.
- Exploit-chain reasoning.
- Refutation.
- Report drafting.
- Learning summary.

### 15. Mythos Brain

Purpose: long-term autonomous research memory.

Must support:

- Program memory.
- Attack surface memory.
- Playbook performance.
- Accepted, duplicate, informative, N/A, and rejected outcomes.
- Bounty amount.
- Severity delta.
- Evidence quality.
- Redacted triager feedback.
- Lessons that boost, penalize, request evidence, or watch duplicates.

Must not:

- Grant execution permission.
- Override Scope Guard.
- Treat triager free text as policy authorization.

## Required Data Model Direction

Existing records should be extended with these first-class concepts:

- `campaigns`
- `campaign_budgets`
- `campaign_tasks`
- `agent_runs`
- `pipeline_stages`
- `approval_records`
- `codebase_maps`
- `codebase_facts`
- `scanner_runs`
- `validation_runs`
- `evidence_items`
- `claim_reviews`
- `finding_candidates`
- `learning_signals`
- `llm_runs`

The system may continue using JSON payloads for flexible stage outputs, but queryable lifecycle and audit objects must be normalized enough for filtering, replay, comparison, and safety review.

## Primary UI: Campaign Control Center

The frontend is not the core product. It is the operator console for autonomous campaigns.

Required pages:

- Campaigns: create, run, pause, resume, and inspect autonomous research campaigns.
- Campaign Detail: current loop state, budget, blockers, next actions, and active agents.
- Agent Runs: each agent's task, inputs, outputs, status, safety gate, and stop reason.
- Attack Surface Map: target objects, roles, endpoints, business flows, and sensitive actions.
- Codebase Map: routes, handlers, models, authz checks, sensitive sinks, and provenance.
- Hypothesis Board: candidates ranked by impact, exploitability, duplicate risk, policy risk, and evidence path.
- Validation Queue: approval-required and human-action-required validation steps.
- Evidence Review: redaction, provenance, evidence quality, and report-chain eligibility.
- Report Drafts: claim ledger and human-review-required report output.
- Brain: learned lessons, high-value surfaces, and program memory.

Every page must visibly distinguish:

- Live data.
- Dry-run data.
- Fallback demo data.
- Blocked data.
- Approval-required data.
- Report-chain unsafe data.

## Current Implementation Status

Implemented foundation in the current repository:

- FastAPI backend.
- Next.js campaign/workbench UI.
- SQLAlchemy models and Alembic migrations.
- Program, campaign, campaign task, artifact, finding, report, approval record, validation run, LLM run, pipeline run, pipeline stage, codebase map, feedback review, cycle review, and learning signal persistence.
- Dry-run Mythos pipeline.
- Campaign orchestrator foundation with task decomposition, stage records, approval gates, and stop reasons.
- Artifact repository with filters and provenance usage records.
- Validation workspace model.
- Validation queue and validation run records with approval/preflight/manual-result gates.
- Evidence bundle model.
- Report preview and claim ledger.
- Hunter Intelligence scoring.
- Mythos Brain profile, learning signals, and lessons.
- Finding candidate promotion.
- LLM provider registry and dry-run audit.
- Celery worker scaffold.
- Campaign Control Center pages for campaigns, agent runs, tasks, maps, hypotheses, validation queues, validation runs, evidence review, report drafts, timeline, and Brain.

Remaining gaps:

- The orchestrator is still a safe campaign skeleton, not a fully autonomous long-running research crew.
- Agent execution is recorded and surfaced, but specialist agents are not yet fully wired to independent tool workflows.
- Codebase maps exist as a product surface and persistence layer, but extraction depth still needs route/handler/authz/sink enrichment.
- Scanner run persistence and SARIF/SBOM-to-target-model merge are incomplete.
- Exploit-chain reasoning is not yet a first-class workflow with primitive extraction, preconditions, and refutation questions.
- Validation remains deliberately constrained to plans, approval records, preflight state, and manual observations; no autonomous live validation harness should be added without stronger gates.
- Structured LLM workflows need tighter schemas, replayability, and campaign-stage wiring.
- Production authentication, tenant/workspace isolation, and secret management remain required before multi-user or hosted use.

## Build Priorities

### P0: Gate-Correct Campaign Foundation

1. Keep Scope Guard as the single runtime gate for campaigns, tasks, validation plans, validation runs, evidence promotion, and report drafts.
2. Harden campaign orchestration around durable stage state, stop reasons, budgets, and resumability.
3. Ensure approval records, preflight checks, and manual validation observations cannot unlock unrelated runs or stale out-of-scope campaigns.
4. Keep report drafts submission-blocked until human review records are present.
5. Add production authentication, workspace isolation, and secret handling before hosted deployment.

### P1: Autonomous Research Loop

1. Improve artifact import for authorized materials with stronger provenance, sensitivity, and report-chain eligibility.
2. Deepen the codebase map engine for routes, handlers, models, authz checks, sensitive sinks, and source-to-route links.
3. Add scanner run persistence for authorized local/static tools, SARIF, and SBOM.
4. Merge target models across artifacts, code maps, scanner facts, and manual notes.
5. Run hypothesis/refutation loops over multiple candidates with duplicate and policy-risk scoring.
6. Add exploit-chain reasoning output schemas.
7. Expand validation harness records for allowed local and explicitly approved test-account validation modes.

### P2: Reportable Finding Loop

1. Tighten evidence review around redaction, provenance, claim coverage, and report-chain blockers.
2. Tighten claim review so unverified model/scanner claims cannot become report text without evidence.
3. Mature finding candidate lifecycle states from candidate to reviewed report draft.
4. Add platform-style report draft generation behind manual review gates.
5. Add learning outcome intake from manually submitted reports.
6. Apply Mythos Brain lessons only as advisory ranking and explanation signals.

### P3: Operator Console

1. Keep Campaign Control Center as the primary operator surface.
2. Improve Agent Runs with inputs, output refs, safety gate state, and stop reasons.
3. Improve Codebase Map and Attack Surface Map with provenance and authorization boundaries.
4. Improve Hypothesis Board with refutation state, duplicate risk, policy risk, and evidence gaps.
5. Improve Validation Queue and Validation Runs with read-only next actions and no execution bypass.
6. Improve Evidence Review and Report Drafts with submission-blocked defaults.
7. Improve Brain page while keeping learning advisory only.

## Out Of Scope

- Unrestricted autonomous exploitation.
- Public-target attack automation without explicit authorization and approval.
- Destructive validation.
- DoS testing.
- Credential attacks.
- Social engineering.
- Real-user-data workflows.
- Raw secret/token/cookie storage.
- Automatic bounty submission.
- Biology, healthcare, or drug design research.

## Final Product Definition

Mythos-Lite is complete when a user can create an authorized campaign, provide scope and artifacts, set budgets and autonomy level, and let the system autonomously run a safe vulnerability research loop. The system should parallelize specialist agents, build code and target models, generate and refute hypotheses, reason about exploit chains, perform allowed validation, pause for approval at hard gates, build evidence, draft reports, and learn from outcomes while preserving full auditability and safety boundaries.
