# Mythos Studio Design

## Goal

Mythos Studio is the preferred product form for Bounty Mythos-Lite: a local, desktop-style, chat-first vulnerability research workspace.

It should make the long-term target in `私人 AI 漏洞研究系统最终方案.md` comfortable to use without forcing the operator into a browser dashboard or a command-heavy CLI.

The product remains a lawful, auditable research assistant. It does not become an automatic public-target attack tool.

## Product Shape

Mythos Studio should feel closer to Cursor, Obsidian, or Burp Suite than to a hosted web app.

The operator opens a local app, creates a workspace, drops in authorized materials, and talks to the research agent in natural language. The system then runs safe local analysis and presents a small set of high-quality vulnerability candidates for human review.

Primary interaction:

```text
Open Mythos Studio
-> create or open workspace
-> import policy, scope, API/HAR, and authorized local code
-> ask the agent to start research
-> review candidate cards
-> approve or reject validation plans
-> attach redacted evidence
-> export submission-blocked report drafts
```

## Target User Experience

The default user should not need to write YAML, remember CLI flags, manage Docker services, or open a browser dashboard.

The main workflow should support natural commands such as:

- "Create a workspace for this program."
- "Import this local repo and this policy."
- "Start research, prioritize access control and role boundary issues."
- "Show me why H-001 is worth validating."
- "What evidence would refute this candidate?"
- "Generate a submission-blocked report draft for H-001."

The app may still expose CLI and API entrypoints for advanced automation, but the main product experience is the local studio.

## Interface Layout

Mythos Studio has four primary regions:

1. Workspaces
   - Lists local research workspaces.
   - Shows imported policy, scope, API/HAR, code, evidence, and reports.
   - Keeps all workspace data local by default.

2. Conversation
   - The main control surface.
   - Lets the operator direct research using natural language.
   - Shows concise agent progress, blockers, and next safe actions.

3. Candidate Board
   - Shows the top 1-5 vulnerability candidates.
   - Each card includes severity, confidence, status, affected endpoint, affected code path, evidence needs, refutation questions, and report readiness.
   - States include `needs_review`, `needs_evidence`, `awaiting_approval`, `blocked`, `parked`, and `report_draft_ready`.

4. Safety and Run Log
   - Shows Scope Guard status, approval gates, redaction gates, blocked actions, and current agent activity.
   - Keeps safety decisions visible while research is running.

## Core Workflow

1. Workspace Creation
   - Operator creates a workspace or opens an existing one.
   - The workspace stores references to local artifacts and generated outputs.

2. Artifact Intake
   - Operator imports program policy, scope, OpenAPI/Postman/HAR, notes, and authorized local code.
   - The system labels each artifact with provenance and sensitivity state.

3. Scope Guard
   - The app checks allowed repos, allowed assets, allowed domains, forbidden actions, and approval requirements before any research run.
   - If scope is missing or blocked, candidate generation does not proceed.

4. Candidate Research
   - The system correlates API/HAR routes with local code paths.
   - It uses static analysis, code surface mapping, and semantic review to produce a short candidate list.
   - Scanner or model output remains advisory and cannot directly become a confirmed finding.

5. Candidate Review
   - The operator opens a candidate and sees why it may matter, why it may be wrong, and what evidence is required.
   - The candidate is framed as a hypothesis until reviewed evidence supports it.

6. Validation Planning
   - The system generates only non-destructive validation plans.
   - Online, authenticated, state-changing, or sensitive validation requires explicit human approval.
   - The app records approval as a gate decision, not as a bypass.

7. Evidence Review
   - Evidence must be redacted and provenance-linked before it can support a report draft.
   - Raw secrets, cookies, tokens, credentials, authorization headers, and real user data are blocked from the report chain.

8. Report Draft
   - The system generates a submission-blocked report draft with scope confirmation, impact, root cause, safe reproduction steps, evidence refs, suggested fix, and regression test ideas.
   - The app never submits reports automatically.

## Architecture Direction

Recommended architecture:

```text
Desktop shell: Tauri or Electron
Local UI: React components reused from the existing web app where practical
Local backend: existing FastAPI app as a sidecar service
Worker: existing Celery-like worker path or a local task runner
Database: SQLite first for desktop simplicity; Postgres remains available for server mode
Storage: local workspace directory under user-controlled path
```

The first implementation should avoid a broad rewrite. It should add a studio shell around the existing API, pipeline, source audit, artifact, candidate, evidence, and report primitives.

## Local Workspace Model

Each workspace should have an operator-readable structure:

```text
workspace/
  manifest.json
  policy/
  scope/
  api/
  har/
  code/
  evidence/
  reports/
  runs/
```

`manifest.json` records artifact refs, source hashes, sensitivity labels, safety gate state, and latest run ids.

The workspace should store references where possible and avoid copying large code repositories unless the operator explicitly imports a snapshot.

## Safety Boundaries

Mythos Studio must preserve the repository safety boundaries:

- No automatic public-target attacks.
- No destructive validation, DoS, credential stuffing, social engineering, or high-frequency scanning.
- No real user data collection, storage, display, or reporting.
- No raw secrets, tokens, cookies, credentials, or authorization headers in stored artifacts or reports.
- No treating model, scanner, or third-party output as confirmed vulnerabilities.
- No bypassing Scope Guard, human approval, redaction review, or report submission gates.
- No automatic report submission.

## First Milestone

The first useful milestone is a local studio prototype that can:

1. Open a local workspace.
2. Import a policy file, scope file, API/HAR artifact, and authorized local repo path.
3. Run the existing source-audit or pipeline flow through the local backend.
4. Show 1-5 candidate cards with endpoint, code path, evidence needs, refutation questions, and safety blockers.
5. Show a conversation panel that can explain a selected candidate and generate a submission-blocked report preview.

This milestone should not attempt full autonomous validation, fuzzing, or public-target testing.

## Non-Goals

- Hosted SaaS deployment.
- Browser-first dashboard as the primary user experience.
- Fully autonomous online exploitation.
- Automatic bounty submission.
- Replacing human approval or evidence review.
- Building every final-plan agent before the studio loop works.

## Verification

A first implementation is acceptable when a local operator can:

1. Launch the studio without manually starting Docker services.
2. Create a workspace from authorized inputs.
3. Run a candidate research pass.
4. Review candidate cards and safety gates in the app.
5. Export a submission-blocked Markdown report draft.
6. Confirm no disallowed validation, secret storage, or automatic submission path exists.
