# Mythos Unified Control Center Design

Date: 2026-07-18

Status: Approved design, pending written-spec review

## Summary

Bounty Mythos-Lite will gain two visually unified operational surfaces:

1. The root route `/` becomes a real-time control center for research posture, authorized assets, agent progress, candidate review, research quality, report readiness, and sanitized audit events.
2. `/studio` becomes a three-column research desk with navigation on the left, conversation and mission context in the center, and candidate, evidence, validation, and report inspection on the right.

The work reuses the existing Campaign, Pipeline, Candidate Hunter, Validation, Report Draft, Scope Guard, and Electron foundations. It does not create a second source of truth and does not replace the existing research engine.

## Goals

- Match the approved Precision Ops visual direction, with restrained Obsidian Glass treatment on floating or transient surfaces.
- Give both the web control center and Electron Studio a coherent, production-grade design system.
- Display real backend state instead of hard-coded or loosely inferred metrics.
- Update long-running task state in near real time.
- Allow non-destructive validation steps to execute automatically after a human approves the complete validation plan.
- Generate and update submission-blocked report drafts automatically.
- Keep every action traceable to authorized inputs, Scope Guard decisions, approval records, and redacted evidence.
- Provide complete loading, empty, stale, offline, blocked, approval-required, error, success, focus, and disabled states.

## Non-Goals

- Do not automatically attack public targets.
- Do not run destructive validation, denial-of-service activity, credential attacks, social engineering, or high-frequency scanning.
- Do not bypass Scope Guard, approval records, preflight checks, redaction review, claim review, or report submission gates.
- Do not collect, store, display, or report real user data or raw credentials, tokens, cookies, or authorization headers.
- Do not expose automatic report submission.
- Do not replace the current Candidate Hunter, Campaign, Pipeline, or Studio business logic.
- Do not migrate Electron to Tauri.
- Do not rebuild the application as a single monolithic SPA.

## Approved Decisions

### Product Scope

- Redesign both `/` and `/studio`.
- Preserve their distinct jobs: `/` is the posture and triage surface; `/studio` is the sustained research surface.
- Use Chinese as the primary interface language while retaining necessary terms such as Scope Guard, Agent, API, HAR, SSE, and submission-blocked.
- Replace the reference image's revenue section with research quality statistics.
- Human approval applies to the complete validation plan. Once approved, the system may execute only the unchanged, approved, non-destructive steps.

### Technical Stack

- React 19 and Next.js 16
- TypeScript
- Tailwind CSS 4
- shadcn/ui source components for accessible controls and overlays
- ECharts for dashboard data visualization
- Electron for desktop packaging and the existing Studio bridge
- Lucide icons for interface actions

Ant Design is not selected because its visual system would require substantial overriding to match the approved direction. Recharts is not selected because ECharts better fits the dense operational charts and state visualizations. Tauri is not selected because the current Electron launcher and bridge already cover the required desktop behavior.

## Existing Foundations To Reuse

- Next.js routes and API client types under `apps/web`.
- Campaign, task, agent-run, approval, validation-run, pipeline-run, finding, report-preview, and Studio workspace endpoints.
- Source-audit and Candidate Hunter execution paths.
- Scope Guard and current program-rule enforcement.
- Black-box local-lab approval and bounded runner behavior.
- Electron startup, API/Web process management, navigation guard, and preload bridge.

Existing safety and business state remains authoritative. The new control center is a projection of that state.

## Information Architecture

### Root Control Center

The root surface contains:

1. Persistent navigation
   - Overview
   - Authorized Programs
   - Research Tasks
   - Vulnerability Candidates
   - Validation Approvals
   - Report Drafts
   - Audit Log
   - Scope Guard
2. Top command bar
   - Search programs, candidates, endpoints, code paths, and reports
   - Connection status
   - Refresh
   - Help
3. Operational metrics
   - Running research tasks
   - High-value retained candidates
   - Plans waiting for human approval
   - Safety or policy blocks
4. Agent research pipeline
   - Policy
   - Target modeling
   - Code/API audit
   - Refutation
   - Report drafting
5. Authorized asset table
6. Candidate and validation queue
7. Research quality statistics
8. Submission-blocked report preview
9. Sanitized audit-event stream

The dashboard does not show "confirmed vulnerabilities" unless a separate, human-reviewed domain state supports that wording. Candidate, observed claim, report draft, and manual submission record remain distinct.

### Studio Three-Column Research Desk

The Studio surface contains:

- Left: workspace navigation and current workspace safety status.
- Center: mission stages, research conversation, agent messages, instructions, and current task context.
- Right: tabs for candidate details, evidence, validation plan and approval, and report draft readiness.

Selecting a candidate updates the inspector without discarding the conversation or mission context. The right inspector becomes a drawer below 1100px. On mobile, Studio uses Overview, Candidates, and Details tabs instead of scaling the desktop layout down.

## Visual System

### Direction

The approved direction is Precision Ops with restrained Obsidian Glass influence.

- Near-black neutral base, not a uniform navy field.
- Solid data surfaces with 1px borders and 4-6px radii.
- Translucency and background blur only on the top bar, composer, inspector, drawers, and modals.
- No decorative glow blobs, bokeh, oversized gradients, or idle ambient animation.
- Dense operational composition with clear alignment and stable dimensions.

### Color Semantics

- Blue: primary actions, selection, active progress, links.
- Green: safe completion, in-scope state, healthy connection.
- Amber: human approval, missing evidence, waiting state.
- Red: blocked action, policy risk, error, unsafe requirement.
- Violet: report, learning, or advisory secondary state.
- Neutral gray: unavailable, inactive, historical, or supporting information.

Color is never the only status signal. Every colored state also has text and, where useful, an icon.

### Typography And Density

- Use a readable UI sans stack with Chinese coverage.
- Use a monospace face only for event timestamps, endpoint paths, IDs, hashes, and code paths.
- Do not scale font size with viewport width.
- Keep compact panel headings, stable table rows, and predictable chart dimensions.
- Use tooltips for unfamiliar icon-only controls.

## Frontend Architecture

### Shared Components

Create focused components under `apps/web/components/control-center/`:

- App shell and navigation
- Command bar
- Data-mode badge
- Safety-state badge
- Metric
- Section header
- Empty, stale, offline, and error states
- Responsive inspector and drawer
- Sanitized event stream

Shared components represent visual and interaction semantics only. They do not own Campaign, Candidate, Validation, or Report business rules.

### Root Components

Root-only components include:

- Control center overview
- Agent pipeline
- Authorized asset table
- Candidate queue
- Research quality charts
- Report readiness preview

`apps/web/app/page.tsx` becomes a composition and initial-data-loading boundary. It must no longer contain all presentation logic.

### Studio Components

Studio-only presentational components include:

- Studio shell
- Mission-stage strip
- Research conversation pane
- Candidate inspector
- Evidence inspector
- Validation-plan inspector
- Report inspector

In the first pass, `studio-workbench.tsx` remains the controller for existing state and mutation handlers. Only the visual sections touched by this redesign are extracted. This avoids simultaneously rewriting the Studio workflow and its presentation.

### Client And Server Responsibilities

- Next.js renders the initial control center snapshot.
- Client components subscribe to sanitized invalidation events and refresh only affected data.
- ECharts loads only on surfaces that render charts.
- Charts display server-derived metrics; they do not infer candidate truth, validation approval, or report readiness.
- The browser never becomes the source of truth for execution or approval state.

## Backend Architecture

### Overview Aggregator

Add a small control-center aggregation service that reads existing repository records and produces a display-safe view model.

The root overview contains:

- `data_mode`
- `generated_at`
- `snapshot_version`
- operational metrics
- agent-stage summaries
- authorized asset summaries
- candidate queue summaries
- research-quality statistics
- report-readiness summary
- sanitized recent events
- Scope Guard and approval pressure summaries

The service must calculate metrics from durable records. It must not reuse the current hard-coded KPI constants or count every finding as high-value.

### HTTP Surface

- `GET /mythos/control-center/overview`
  - Optional campaign filter.
  - Returns a display-safe snapshot.
- `GET /mythos/control-center/events`
  - Server-Sent Events stream.
  - Accepts a campaign or Studio run scope and a cursor.
  - Emits sanitized invalidation and status events only.

Studio continues to use its existing workspace mission, candidates, validation, and report endpoints. The event stream tells Studio which domain projection to refresh; it does not replace those endpoints.

### Event Delivery

The first version does not add an in-memory event broker or a second event database.

- The SSE endpoint checks durable repository update cursors every two seconds.
- When the cursor changes, it emits a small invalidation event containing stable IDs, event type, safe status, and timestamp.
- The client then refetches the relevant overview or Studio projection.
- SSE uses event IDs for reconnect behavior.
- A keepalive does not trigger data refresh.
- If SSE cannot connect, the client falls back to five-second polling and shows a degraded-connection state.

This design works across API processes because durable repository state, not process memory, drives invalidation.

## Data Honesty

Every surface must visibly distinguish:

- `live`
- `dry_run`
- `demo`
- `stale`
- `offline`
- `blocked`
- `approval_required`
- `report_chain_unsafe`

Demo data may appear only in an explicit demo or test mode with a persistent banner. A failed live request must not silently fall back to demo values.

Research-quality metrics replace revenue metrics:

- Candidate retention rate
- Refutation kill rate
- Evidence completeness
- Median human-review time

When the required records do not exist, the metric renders an empty state rather than zero, a trend, or a fabricated percentage.

## Controlled Automatic Validation

### Approval Unit

The complete validation plan is the approval unit. An approval record binds:

- Campaign ID
- Validation-run ID
- Authorized target origin
- Account and role aliases
- Scope snapshot/version
- Policy version
- Plan hash
- Allowed step set
- Request-rate ceiling
- Reviewer and decision time
- Expiry

### Execution Rules

After approval, the system may automatically execute the exact approved steps when all gates remain valid.

- Re-run Scope Guard before dispatch and before every step.
- Execute only allowlisted, non-destructive, rate-limited actions.
- Do not add, broaden, or reinterpret a step at runtime.
- Stop immediately on scope, origin, policy, readiness, rate, or response-safety mismatch.
- Store aliases, schema fingerprints, differences, safe counters, and provenance references only.
- Do not store raw headers, credentials, cookies, authorization values, or raw response bodies.

Automatic execution in the first release is limited to local, isolated, or explicitly authorized test environments supported by the existing safe runner. Public-target attack automation remains prohibited.

### Approval Invalidation

Approval becomes invalid if any of the following changes:

- Plan content or plan hash
- Scope or policy version
- Target origin
- Account readiness
- Validation-run binding
- Rate ceiling
- Approval expiry

Invalidation returns the plan to `approval_required` and emits a sanitized audit event.

## Automatic Report Drafting

The Report Agent may create or update a report draft after candidate, evidence, or validation-observation state changes.

Every generated report remains:

- `submission_blocked = true`
- Explicitly labeled as a draft
- Dependent on evidence review and human claim review
- Free of raw secrets and real user data

The UI exposes preview and local export only. It does not expose a report-submission command.

## Error And State Design

### Loading And Empty

- Use stable skeleton dimensions so content does not shift.
- Empty states explain which authorized input or run is missing.
- Empty charts do not render fake axes or zero trends.

### Stale And Offline

- Preserve the last safe snapshot with its timestamp.
- Display stale or offline status prominently.
- Disable mutation controls that require fresh approval state.

### Blocked And Approval Required

- State the blocking Scope Guard rule, missing evidence category, expired approval, or unsafe report-chain condition.
- Provide only safe next actions.
- Do not provide bypass or override actions.

### Partial Failure

- A failed panel does not collapse the full control center.
- Retry controls are keyboard accessible.
- Retry and recovery events are audited when they affect workflow state.

## Accessibility And Responsive Behavior

- Keyboard access for navigation, tables, tabs, drawers, dialogs, and primary actions.
- Visible focus rings on all interactive controls.
- WCAG AA contrast for body text and status labels.
- Correct landmarks, headings, labels, table headers, and live-region usage.
- Focus containment and restoration for drawers and dialogs.
- Reduced-motion support.
- At widths below 1100px, inspectors become drawers and dense tables gain deliberate horizontal behavior.
- On mobile, use tabbed task views rather than shrinking the desktop dashboard.

## Performance

- Target less than 500KB initial JavaScript for the root control center.
- Lazy-load ECharts and Studio-only panels.
- Stop chart and polling work when the page is hidden.
- Avoid idle animation.
- Keep the event payload small and display-safe.
- Use stable chart and table dimensions to prevent layout shift.

## Testing Strategy

### Backend

- Aggregated metrics derive from durable records.
- High-value candidate counts respect the real retention/readiness rules.
- Missing data returns explicit absence, not fabricated zero values.
- Display filtering removes secrets, credentials, authorization headers, cookies, raw bodies, and unsafe free text.
- SSE emits only safe invalidation events and supports reconnect cursors.
- Approval validity depends on campaign, scope, policy, plan hash, origin, readiness, rate, and expiry.
- Every automatic step re-runs Scope Guard.
- Report drafts remain submission-blocked.

### Frontend

- Pure tests cover status mapping, metric formatting, stale-snapshot detection, and event merging.
- Component behavior covers loading, empty, stale, offline, blocked, approval-required, error, focus, and disabled states.
- ECharts components handle empty and partial datasets without rendering fake trends.

### End-To-End

Use Playwright to verify:

1. Authorized research task starts.
2. Candidate appears with evidence and refutation state.
3. Human reviews and approves the complete safe validation plan.
4. Approved non-destructive steps execute automatically.
5. Sanitized observations update the candidate.
6. A submission-blocked report draft updates.
7. Scope or plan mutation invalidates approval and stops execution.

Capture visual regression screenshots at:

- 1680 x 944
- 1440 x 900
- 390 x 844

### Electron

- Launcher starts API and Web and opens Studio.
- Studio displays offline and degraded-connection states.
- Studio recovers after the local service returns.
- Existing navigation, origin, and preload-bridge safety constraints remain enforced.

## Rollout

1. Introduce visual tokens and shared control-center primitives.
2. Add tested overview aggregation and data-honesty rules.
3. Redesign the root control center with real snapshots.
4. Add SSE invalidation with polling fallback.
5. Redesign Studio around the approved three-column layout without rewriting its business controller.
6. Wire complete-plan approval to the existing bounded safe runner.
7. Add automatic submission-blocked report refresh.
8. Complete responsive, accessibility, visual-regression, Electron, and end-to-end verification.

Each stage must remain deployable and must preserve Scope Guard, human approval, redaction, and report-submission boundaries.

## Acceptance Criteria

- `/` and `/studio` use the approved visual system and shared status semantics.
- The root control center contains no hard-coded operational KPI values.
- Every visible metric can be traced to durable records or renders an explicit empty state.
- Running task state updates without a full page reload.
- Connection degradation is visible and recovers automatically.
- Human approval of an unchanged complete plan permits only its approved non-destructive steps.
- Any plan, scope, policy, target, readiness, rate, or expiry change invalidates approval before execution continues.
- Automatic report output remains submission-blocked and has no submission control.
- No displayed event or report contains raw secrets, credentials, cookies, authorization headers, raw responses, or real user data.
- Desktop and mobile screenshots are nonblank, correctly framed, free of incoherent overlap, and visually consistent with the approved design.
- Backend tests, frontend tests, lint, production build, Playwright flows, and Electron smoke tests pass.
