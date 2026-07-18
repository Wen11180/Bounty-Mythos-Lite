# Mythos Unified Control Center Implementation Plan

**Date:** 2026-07-18

**Design:** `docs/superpowers/specs/2026-07-18-mythos-unified-control-center-design.md`

**Status:** Ready for implementation; no production code has been changed by this plan

> Execution rule: every behavior change starts with a focused failing test and
> follows RED -> GREEN -> REFACTOR. Generated shadcn files are still covered by
> a failing repository contract test before the generator runs.

> Safety rule: automatic execution is limited to one unchanged, human-approved,
> bounded workflow in the existing Electron local lab. No browser-only or public-
> target execution path is added. Reports remain submission-blocked.

## Goal

Implement the approved Precision Ops control center and Studio research desk:

```text
durable Campaign / Pipeline / Candidate Hunter / Approval / Validation state
-> display-safe control-center projection
-> deterministic snapshot digest
-> initial Next.js snapshot + SSE invalidation
-> real root control center and three-column Studio UI
-> human approval of one complete bounded local plan
-> immediate non-destructive Electron execution
-> sanitized bounded result
-> automatically refreshed submission-blocked report preview
-> Windows x64 desktop installer
```

## Implementation Decisions Locked By This Plan

1. **The existing domain remains authoritative.** The new aggregate calls
   `DatabaseRepository`, `_campaign_control_center_response`,
   `load_candidate_hunter_projection`, current approval/preflight logic, and
   safe report builders. It does not introduce a Candidate table or duplicate
   Campaign state.
2. **Snapshot digests are SSE event IDs.** Mutable Campaign/Task/Stage records
   do not have reliable update timestamps. Every two seconds, the SSE generator
   opens a short database session, builds the canonical display-safe projection,
   hashes its canonical JSON, and emits an invalidation only when the digest
   differs. No schema migration or in-memory broker is needed.
3. **Root stays server-first.** `app/page.tsx` remains an async Server Component
   for the initial snapshot. EventSource, ECharts, drawers, and refresh behavior
   live in small Client Component leaves.
4. **Control-center reads are strict.** A new API helper returns live data or an
   explicit error. It must not use the current `apiGet(path, fallback)` behavior
   that silently substitutes demo values.
5. **Use shadcn source components, not a package import.** Initialize shadcn CLI
   `4.13.1` with Radix and CSS variables, then generate only the controls used by
   the approved design. Install ECharts `6.1.0` exactly and use tree-shakable
   imports.
6. **Keep the current test stack.** Pure TypeScript uses `node:test`; rendered
   interaction and visual behavior use Playwright. Do not add Jest, Vitest, or
   React Testing Library in this implementation.
7. **SSE uses native EventSource.** It connects to the configured loopback/API
   origin with CORS and no credentials or custom headers. Native reconnect and
   `Last-Event-ID` are used; a five-second fetch loop is activated only after
   repeated connection failures and is visibly labeled degraded.
8. **Automatic validation is immediate and non-resumable.** The human clicks one
   `Review and approve complete plan` action in Studio. A successful local-lab
   approval immediately dispatches the one approved workflow through the
   existing preload bridge. A restart, input change, scope change, expired
   approval, or failed preflight requires a new approval. No background queue or
   public browser automation is added.
9. **Report generation means a live draft preview.** A safe bounded result makes
   the existing report-preview builder reflect new evidence; SSE invalidation
   refreshes the draft. File export remains an explicit local action, and no
   submission endpoint or button exists.
10. **The first packaged deliverable is Windows x64 only.** Electron Forge
    `7.11.2` with Squirrel packages bundled Next standalone assets, a PyInstaller
    `6.21.0` one-directory FastAPI runtime, and the pinned Playwright Chromium.
    Multi-platform builds, auto-update, and public code signing are separate
    follow-up work.

## Phase 0: Verified Documentation And Allowed APIs

### Repository and official references

| Need | Verified source | Required use |
| --- | --- | --- |
| Approved behavior | `docs/superpowers/specs/2026-07-18-mythos-unified-control-center-design.md:1-448` | Preserve visual direction, truthful states, complete-plan approval, report block, and acceptance criteria. |
| Existing campaign aggregate | `apps/api/app/main.py:1402-1428,2590-2657` | Copy response-model and aggregate style; extend through a separate root projection instead of rewriting it. |
| Durable repository reads | `apps/api/app/repository.py:973-982,1069,1112-1153,1211-1237,1310,1527-1679,1886-2038` | Use actual repository methods; do not invent a generic event query. |
| Candidate truth | `apps/api/app/candidate_hunter_loop.py:2318-2398,2469-2603` | Load validated append-only candidate projection; do not count every Finding row as high value. |
| Scope and execution authority | `apps/api/app/main.py:2272-2387,12086-12185`; `apps/api/app/scope_guard/__init__.py:8-50` | Re-run current approval and Scope Guard checks before bounded dispatch. |
| Local bounded approval | `apps/api/app/main.py:3663-3749,2471-2498`; `apps/studio/black-box-runner.cjs:116-330,389-615,924-1038` | Preserve loopback-only, two-session, redacted-trace, lease, origin, and workflow gates. |
| Safe reports | `apps/api/app/main.py:4792-4865,10467-10478`; `apps/api/app/mythos_report/__init__.py:125-168,200-245` | Reuse builder with `human_review_required` and `submission_blocked` fixed true. |
| Short DB sessions | `apps/api/app/db.py:30-44,57-70` | Use `get_session_factory()` inside SSE polling; never hold request-scoped sessions for the stream lifetime. |
| FastAPI stream API | FastAPI 0.127 installed `fastapi.responses.StreamingResponse` | Return an async byte/string iterator with `media_type="text/event-stream"`. |
| Existing frontend boundary | `apps/web/app/page.tsx:176`; `apps/web/app/studio/page.tsx:1-5`; `apps/web/app/studio/studio-workbench.tsx:1,226-231` | Keep root server-first and reuse Studio's Server -> Client boundary and effect cleanup pattern. |
| Strict/fallback API reality | `apps/web/lib/api.ts:22-23,1106-1141` | Add a strict control-center helper; do not silently reuse `apiGet` fallback semantics. |
| Next client boundaries | [Next Server and Client Components](https://nextjs.org/docs/app/getting-started/server-and-client-components); [use client](https://nextjs.org/docs/app/api-reference/directives/use-client); local Next 16.2.10 types | Browser APIs and non-serializable state stay in Client Components. |
| Next lazy loading | [Next Lazy Loading](https://nextjs.org/docs/app/guides/lazy-loading) | Call `dynamic(..., { ssr:false })` only from a Client Component and lazy-load a chart component, not the raw ECharts module. |
| Tailwind 4 | `apps/web/app/globals.css:1`; `apps/web/postcss.config.mjs:1-7`; [Tailwind theme variables](https://tailwindcss.com/docs/theme) | Keep `@import "tailwindcss"`; express approved colors and sizes as CSS variables. |
| shadcn | [Next installation](https://ui.shadcn.com/docs/installation/next); [Tailwind v4](https://ui.shadcn.com/docs/tailwind-v4); CLI 4.13.1 local help | Generate repository source components with `--base radix --css-variables`; import from `@/components/ui/*`. |
| ECharts | [Tree-shakable imports](https://echarts.apache.org/handbook/en/basics/import/); [container lifecycle](https://echarts.apache.org/handbook/en/concepts/chart-size/); ECharts 6.1.0 | Register explicit charts/components plus `CanvasRenderer`; initialize only a non-zero container and dispose on cleanup. |
| Browser SSE | [MDN EventSource](https://developer.mozilla.org/en-US/docs/Web/API/EventSource/EventSource); [SSE usage](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events) | Use GET, named events, `id`, `retry`, native reconnect, `readyState`, and `close()`. |
| Existing Web tests | `apps/web/package.json:5-12`; `apps/web/playwright.config.ts:1-32`; `apps/web/e2e/v0-source-audit.spec.ts:14-433` | Use Node native TS tests, production Next E2E server, loopback mocks, and role/label locators. |
| Electron security | `apps/studio/main.cjs:41-134`; `apps/studio/preload.cjs:1-30`; `apps/studio/navigation-guard.cjs:1-31` | Preserve dynamic loopback ports, context isolation, sandbox, narrow IPC, and strict same-origin navigation. |
| Electron packaging | [Electron packaging tutorial](https://www.electronjs.org/docs/latest/tutorial/tutorial-packaging); [Forge existing project](https://www.electronforge.io/import-existing-project.md); [Squirrel maker](https://www.electronforge.io/config/makers/squirrel.windows.md) | Use Forge/Packager/Squirrel rather than manual archive scripts. |
| Next standalone runtime | `apps/web/next.config.ts:1-7`; `apps/web/Dockerfile:11-21`; [Next standalone output](https://nextjs.org/docs/app/api-reference/config/next-config-js/output) | Stage `standalone`, `.next/static`, and `public`; never run `next dev` in a package. |
| Frozen API | [PyInstaller 6.21 usage](https://pyinstaller.org/en/stable/usage.html) | Build a one-directory API runtime with migrations and configuration resources. |
| Packaged Node child | [Electron utilityProcess](https://www.electronjs.org/docs/latest/api/utility-process) | Evaluate `utilityProcess.fork(server.js, ..., { env })` after app readiness for bundled Next standalone. |

### Allowed API summary

- Backend reads: existing Campaign, Task, AgentRun, Approval, PipelineStage,
  ValidationRun, PipelineRun, Candidate Hunter projection, and report-preview
  builders listed above.
- Backend mutation: durable approval decision, validation preflight, local-lab
  lease preview/approval, bounded-result recording, and submission-blocked
  report export only.
- Frontend: Server Components, serializable props, small Client Components,
  `useEffect` cleanup, native EventSource, shadcn generated imports, modular
  ECharts `use/init/setOption/resize/dispose`.
- Desktop: existing narrow preload channels, loopback launcher, bounded runner,
  Forge package/make, Squirrel maker, utility process, and bundled API child.

### Global anti-pattern guards

- No hard-coded operational KPI values or silent demo fallback.
- No in-memory SSE broker or long-lived SQLAlchemy session.
- No raw ORM payload, secret, header, cookie, token, raw body, or user data in a
  projection, event, screenshot, log, or report.
- No model/scanner/candidate output labeled confirmed without human-reviewed
  evidence state.
- No whole-page `"use client"`, whole-library ECharts import, zero-size chart
  initialization, missing chart disposal, or manual reconnect that leaks an old
  EventSource.
- No direct import from a nonexistent `shadcn/ui` package.
- No renderer access to filesystem, spawn, arbitrary IPC, arbitrary URL, or
  approval authority.
- No packaged runtime invocation of `npm`, `next dev`, system Python, system
  Node, or first-run browser download.

## Phase 1: UI Dependencies, Tokens, And Shared Primitives

### Files

- Modify `apps/web/package.json` and `apps/web/package-lock.json`.
- Add `apps/web/components.json`.
- Modify `apps/web/app/globals.css`.
- Add `apps/web/lib/utils.ts`.
- Add generated controls under `apps/web/components/ui/`.
- Add `apps/web/lib/control-center-display.ts`.
- Add `apps/web/lib/control-center-display.test.ts`.
- Add shared components under `apps/web/components/control-center/`:
  - `app-shell.tsx`
  - `command-bar.tsx`
  - `data-mode-badge.tsx`
  - `safety-state-badge.tsx`
  - `metric.tsx`
  - `section-header.tsx`
  - `panel-state.tsx`
  - `responsive-inspector.tsx`

### RED tests

1. Add `control-center-display.test.ts` first. Assert that data-mode and safety
   mappings cover `live`, `dry_run`, `demo`, `stale`, `offline`, `blocked`,
   `approval_required`, and `report_chain_unsafe`, with Chinese labels and no
   truthy execution/report permissions accepted from unsafe input.
2. Add a repository contract test that reads `components.json`, `globals.css`,
   and shared component sources. It must fail while the files/tokens are absent
   and must assert:
   - Radix base and `@/components/ui` alias.
   - Tailwind 4 `@import "tailwindcss"` remains present.
   - Approved Precision Ops variables exist.
   - No Tailwind 3 initialization appears.
   - Shared files do not contain hard-coded demo KPI values.

Run:

```powershell
cd apps/web
npm test -- lib/control-center-display.test.ts
```

Expected RED: missing module/config/tokens.

### GREEN implementation

1. Initialize exact CLI version:

```powershell
cd apps/web
npx --yes shadcn@4.13.1 init --template next --base radix --preset base-nova --css-variables --no-monorepo -y
npx --yes shadcn@4.13.1 add --yes button badge dialog sheet tabs tooltip input scroll-area separator skeleton select dropdown-menu
npm install --save-exact echarts@6.1.0
```

2. Keep the generated source components that are actually used. Do not add the
   shadcn Card component for every section; the design uses unframed layout bands
   and project-specific operational panels.
3. Replace generated palette tokens with the approved near-black, neutral,
   blue, green, amber, red, and violet semantics. Keep 4-6px radii and visible
   focus tokens. Do not add ambient glow or idle animation.
4. Implement pure label/state helpers in `control-center-display.ts`; UI
   components consume those helpers instead of duplicating status logic.
5. Build the shared shell and primitives with Lucide icons and semantic HTML.
   Icon-only actions require accessible names and tooltips.

### Verification

```powershell
cd apps/web
npm test -- lib/control-center-display.test.ts
npm run lint -- components/ui components/control-center lib/control-center-display.ts
npm run build
```

- Confirm the RED test is now green.
- Confirm `rg -n 'from "shadcn/ui"|@tailwind base|rounded-(2xl|3xl)' apps/web` finds no new misuse.
- Confirm generated components contain no application business rules.

## Phase 2: Truthful Backend Overview Projection

### Files

- Add `apps/api/app/control_center/__init__.py`.
- Add `apps/api/app/control_center/contracts.py`.
- Add `apps/api/app/control_center/service.py`.
- Modify `apps/api/app/main.py`.
- Add `apps/api/tests/test_control_center.py`.
- Modify `apps/api/tests/test_campaign_api.py` only if the existing campaign
  aggregate requires a regression assertion.

### RED tests

1. Copy the TestClient + SQLite `StaticPool` fixture from
   `test_campaign_api.py:17-30,55-60`.
2. Seed multiple campaigns with tasks, agent runs, approvals, validation runs,
   pipeline stages, Candidate Hunter stages, and report-preview state.
3. Assert `build_control_center_overview(repository, campaign_id=None, now=...)`
   returns:
   - explicit `data_mode`, `generated_at`, and `snapshot_version`;
   - running task count from real statuses;
   - retained high-value candidates from `load_candidate_hunter_projection`;
   - approval pressure from active durable records;
   - Scope Guard/policy blocks from safe aggregate state;
   - research-quality values only when the required denominators exist;
   - `None`/unavailable metric state instead of fabricated zero trends;
   - report readiness from the safe report builder, not client inference.
4. Seed secret-shaped strings in every payload and assert the serialized
   response omits authorization, cookie, password, token, raw headers, raw body,
   and unsafe free text. Copy redaction assertion style from
   `test_campaign_api.py:388-431`.
5. Assert identical safe projections produce the same SHA-256
   `snapshot_version`; a safe visible status change produces a different digest;
   secret-only/raw-payload changes do not appear in the output.
6. Add API coverage for `GET /mythos/control-center/overview`, optional campaign
   filtering, 404 for unknown filter, and explicit empty live state.

Run:

```powershell
cd apps/api
python -m pytest tests/test_control_center.py -q
```

Expected RED: package, builder, and route do not exist.

### GREEN implementation

1. Define strict Pydantic response contracts with `extra="forbid"`; use
   explicit safe summary types rather than raw dictionaries where practical.
2. Implement canonical JSON serialization with sorted keys and compact
   separators, then SHA-256 it for `snapshot_version`.
3. Reuse `_campaign_control_center_response` for campaign-level safe summaries.
   Load Candidate Hunter projection only for qualifying pipeline runs and catch
   invalid stage sequences as blocked/review-required, not as candidates.
4. Define research-quality formulas in one place:
   - retention = retained candidates / generated candidates;
   - refutation kill = refuted candidates / challenged candidates;
   - evidence completeness = satisfied safe evidence requirements / total safe
     requirements;
   - median human review time only from records with both request and decision
     timestamps.
5. Do not return a percentage when the denominator is absent.
6. Add a thin route to `main.py`; keep aggregation logic in the package.

### Verification

```powershell
cd apps/api
python -m pytest tests/test_control_center.py tests/test_campaign_api.py -q
```

- Grep the new package for raw payload returns and secret field names.
- Confirm no migration or second candidate store was added.
- Confirm `report_submission_allowed` is absent or fixed false on every root
  projection that exposes report state.

## Phase 3: Real Root Control Center

### Files

- Modify `apps/web/lib/api.ts` and `apps/web/lib/api.test.ts`.
- Add `apps/web/lib/control-center-data.ts` and
  `apps/web/lib/control-center-data.test.ts`.
- Replace `apps/web/app/page.tsx` composition.
- Add root-only components under `apps/web/components/control-center/`:
  - `control-center-overview.tsx`
  - `agent-pipeline.tsx`
  - `authorized-assets.tsx`
  - `candidate-queue.tsx`
  - `quality-charts.tsx`
  - `report-readiness.tsx`
  - `audit-event-stream.tsx`
- Add `apps/web/components/control-center/echarts-canvas.tsx`.

### RED tests

1. Add a strict `getControlCenterOverview()` API contract test using the fetch
   injection pattern in `api.test.ts:96-130`. Network failure and non-2xx must
   throw `ApiRequestError`; they must not return demo data.
2. Add pure mapper tests for safe labels, absent metrics, candidate ordering,
   report block, stale timestamp detection, and hostile `true` permission flags.
3. Add a source contract test for `app/page.tsx` that requires the Server
   Component to pass a serializable initial snapshot to a client overview and
   forbids a top-level `"use client"` directive and old hard-coded KPI constants.
4. Add chart-option tests that return an explicit empty-chart model when the
   server metric has no denominator.

Run:

```powershell
cd apps/web
npm test -- lib/api.test.ts lib/control-center-data.test.ts
```

Expected RED: strict helper, mappers, and root composition are absent.

### GREEN implementation

1. Add strict overview types and fetch helper without changing existing
   fallback-based routes outside this task.
2. Keep `app/page.tsx` async/server-side and pass only serializable safe data.
3. Implement the approved root layout and Chinese labels using shared shell
   primitives. Navigation must resolve to real existing routes; unavailable
   campaign-specific routes render disabled/needs-selection state instead of
   silently linking to `/campaigns` under the wrong label.
4. Add a Client Component chart leaf. Import from `echarts/core`, register only
   required chart/component modules plus `CanvasRenderer`, initialize after the
   container has non-zero size, observe resize, and cleanup both observer and
   chart.
5. Load the chart component with `dynamic(..., { ssr:false })` from a Client
   Component only. Do not dynamically import the raw ECharts library as a React
   component.
6. Render stable loading, empty, blocked, error, and stale layouts. Do not show a
   trend arrow or percent for unavailable data.

### Verification

```powershell
cd apps/web
npm test
npm run lint
npm run build
```

- Confirm no root hard-coded KPI values remain.
- Confirm the build does not include ECharts in the server-only page chunk.
- Confirm the report panel always displays `submission-blocked` and has no
  submit control.

## Phase 4: SSE Invalidation And Polling Degradation

### Files

- Add `apps/api/app/control_center/events.py`.
- Modify `apps/api/app/main.py`.
- Extend `apps/api/tests/test_control_center.py`.
- Add `apps/web/lib/control-center-live.ts` and
  `apps/web/lib/control-center-live.test.ts`.
- Add `apps/web/components/control-center/live-control-center.tsx`.
- Modify `apps/web/components/control-center/control-center-overview.tsx`.
- Extend `apps/web/e2e/v0-source-audit.spec.ts` only if its mock server helpers
  are reused; otherwise add `apps/web/e2e/control-center-live.spec.ts`.

### RED tests

1. Backend generator tests inject a session factory and clock. Assert:
   - initial event contains canonical digest as `id`;
   - unchanged digest emits keepalive only;
   - visible durable-state change emits one invalidation;
   - safe projection is rebuilt in a new short session per poll;
   - secret-only changes do not leak into event data;
   - disconnect cancellation closes the current session and generator.
2. Route test `GET /mythos/control-center/events` for media type,
   `Cache-Control: no-cache`, `X-Accel-Buffering: no`, campaign filtering, and
   invalid filter rejection. Keep the test bounded by injecting a finite
   generator; do not hang TestClient on the production loop.
3. Frontend pure tests inject an EventSource factory and fetch scheduler. Assert
   open/live state, named invalidation refresh, cleanup, visibility pause,
   native reconnect without duplicate manual connections, degraded polling after
   repeated errors, and recovery to live state.
4. E2E mock returns a valid SSE event and then closes. Assert the visible
   connection state changes and the overview refetches without full navigation.

Run targeted tests and confirm RED.

### GREEN implementation

1. Import `StreamingResponse` from `fastapi.responses`.
2. The async generator uses `get_session_factory()` and opens/closes one session
   around each digest computation. It never retains a request-scoped dependency.
3. Emit only:

```text
event: control-center-invalidated
id: <sha256 digest>
retry: 5000
data: {"snapshot_version":"...","scope":"global|campaign|studio","changed":["overview"]}
```

Keepalive is an SSE comment and contains no data.
4. The client uses `new EventSource(url)` with no headers. It closes the source
   on unmount/hidden state and creates one source on resume.
5. After repeated errors, start one five-second strict fetch loop and show
   degraded state. Stop the loop once EventSource is open again.
6. Refetch projections; do not apply event payloads as business state.

### Verification

```powershell
cd apps/api
python -m pytest tests/test_control_center.py -q

cd ../web
npm test -- lib/control-center-live.test.ts lib/control-center-data.test.ts
npm run e2e -- e2e/control-center-live.spec.ts
```

- Confirm no `setHeader`, custom EventSource header, POST SSE, process-global
  broker, or long-lived DB session was introduced.
- Confirm offline/stale timestamps remain visible during degradation.

## Phase 5: Studio Three-Column Visual Redesign

### Files

- Modify `apps/web/app/studio/studio-workbench.tsx`.
- Extend `apps/web/lib/studio-data.ts` and `studio-data.test.ts` only for new
  display projections.
- Add presentational components under `apps/web/components/studio/`:
  - `studio-shell.tsx`
  - `mission-stage-strip.tsx`
  - `research-conversation.tsx`
  - `candidate-inspector.tsx`
  - `evidence-inspector.tsx`
  - `validation-plan-inspector.tsx`
  - `report-inspector.tsx`
- Reuse shared controls from `components/control-center/` and `components/ui/`.
- Add `apps/web/e2e/studio-control-center.spec.ts`.

### RED tests

1. Extend Studio mapper tests for the approved Chinese labels, selected candidate
   projection, missing endpoint/code path, hostile permission normalization,
   and `submission-blocked` report state.
2. Add a source boundary test that requires `studio-workbench.tsx` to remain the
   controller and imported presentational sections to remain free of direct API
   mutations and `window.mythosStudio` calls.
3. Add Playwright coverage for three-column desktop layout, candidate selection
   updating the inspector without losing conversation, below-1100px inspector
   drawer behavior, mobile tab behavior, keyboard focus, and existing file/
   directory selectors.
4. Run RED before extracting any production JSX.

### GREEN implementation

1. Keep existing state and handlers in `studio-workbench.tsx`. Extract only the
   visual regions touched by this design and pass explicit, narrow props.
2. Apply the shared shell, command bar, status semantics, and responsive
   inspector. Do not put cards inside cards or scale desktop type down on mobile.
3. Keep the preload bridge declaration exactly as narrow as the existing seven
   methods. No new filesystem or arbitrary IPC access is needed for the redesign.
4. Preserve every existing disabled/blocked safety condition and review-only
   message while changing layout and Chinese copy.
5. Connect Studio to the same invalidation hook with a Studio run scope; refresh
   existing mission/candidate/report endpoints rather than replacing them with
   event payloads.

### Verification

```powershell
cd apps/web
npm test -- lib/studio-data.test.ts lib/control-center-live.test.ts
npm run lint
npm run build
npm run e2e -- e2e/studio-control-center.spec.ts e2e/v0-source-audit.spec.ts

cd ../studio
npm test
```

- Confirm `contextIsolation`, sandbox, navigation guard, and bridge types are
  unchanged.
- Confirm existing source-audit and explicit local-lab E2E flows still pass.

## Phase 6: Complete-Plan Approval And Immediate Bounded Execution

### Scope clarification

The first implementation treats the existing one-workflow local-lab lease as
the complete plan. It does not queue multiple workflows, resume after restart,
or execute when Studio is closed. This satisfies automatic execution after
approval without creating new authority or a background runner.

### Files

- Modify approval/preflight contracts and helpers in `apps/api/app/main.py` only
  where the existing local-lab endpoints live.
- Modify `apps/api/tests/test_black_box_lab_api.py` and
  `tests/test_black_box_remote_api.py`.
- Modify `apps/web/lib/api.ts` and `api.test.ts`.
- Modify `apps/web/app/studio/studio-workbench.tsx`.
- Modify `apps/web/lib/studio-data.test.ts`.
- Modify `apps/web/e2e/v0-source-audit.spec.ts` local-lab journey.
- Modify `apps/studio/black-box-runner.test.cjs` only if current one-trial state
  guards need an explicit regression assertion.

### RED tests

1. Backend: local auto-dispatch approval must fail unless the matching durable
   approval is approved, unexpired, campaign-bound, task/run-bound, asset/mode/
   plan-digest/scope-reference matched, and preflight allowed.
2. Backend: changing policy/current rule, scope reference, origin, plan digest,
   account aliases, readiness, or expiry must make approval response fail closed.
3. Backend: response may return `local_runner_dispatch_allowed=true`, approved
   workflow alias, plan/lease digest, and expiry, but must retain
   `execution_allowed=false` and `report_submission_allowed=false` as authority
   flags.
4. Frontend/API: add or reuse strict preflight helper. Test that confirmation
   does not call the bridge when approval or preflight fails.
5. E2E: replace the separate `Confirm bounded lab run` then `Run approved trial`
   clicks with one `Review and approve complete plan` click. Assert exactly one
   bridge trial call occurs immediately after the successful approval response.
6. E2E negative cases: mutate origin/session readiness/plan after review, expire
   approval, or return a stop event. Assert no trial request or report readiness
   promotion occurs.
7. Secret assertion remains identical to the existing local-lab journey.

### GREEN implementation

1. Reuse current durable approval and `_validation_run_currently_allowed_to_execute`.
   Add a narrow helper for local auto-dispatch eligibility; do not loosen general
   validation authority.
2. Require non-null future expiry and scope reference only for this auto-
   executable local plan. Existing review-only approvals remain compatible.
3. Return the immutable approved workflow/lease facts required by the immediate
   renderer dispatch. Do not persist a process-global grant.
4. In Studio, after the human confirmation response and a fresh preflight, call
   `window.mythosStudio.runBlackBoxTrial(...)` once using only server-approved
   aliases. Input-change handlers already invalidate preview/review state; keep
   that behavior.
5. Remove/hide the separate manual `Run approved trial` action in this flow.
6. On crash, close, or reload, discard local approval response state and require
   a new human confirmation.

### Verification

```powershell
cd apps/api
python -m pytest tests/test_black_box_lab_api.py tests/test_black_box_remote_api.py tests/test_scope_guard_api.py -q

cd ../web
npm test -- lib/api.test.ts lib/studio-data.test.ts
npm run e2e -- e2e/v0-source-audit.spec.ts

cd ../studio
npm test
```

- Grep for public origins, caller `human_approved`, background dispatch queues,
  and widened bridge methods; none may authorize the run.

## Phase 7: Sanitized Result And Automatic Report Preview Refresh

### Files

- Modify `apps/api/app/main.py` bounded-result/report projection only as needed.
- Modify `apps/api/tests/test_black_box_lab_api.py`, `test_campaign_api.py`, and
  `test_studio_api.py`.
- Modify `apps/web/lib/api.ts`, `control-center-data.ts`, and their tests.
- Modify Studio validation/report inspectors.
- Extend root and Studio E2E specs.

### RED tests

1. Record a bounded local result through the existing endpoint and assert only
   aliases, schema fingerprints, status/timing buckets, differences, safe
   counters, and provenance refs persist.
2. Assert raw request/response material and secret-shaped fields are rejected or
   redacted.
3. Assert report preview changes only after a safe result is durably recorded;
   a stop, failed preflight, or unreviewed trace does not change readiness.
4. Assert every refreshed preview keeps `human_review_required=true` and
   `submission_blocked=true` and no report-submission control exists.
5. E2E complete flow: approval -> immediate trial -> bounded-result POST -> SSE
   invalidation -> candidate evidence/report inspector refresh. File export
   remains a separate explicit command.

### GREEN implementation

1. Reuse `record_validation_run_bounded_result(...)`; add only the safe adapter
   required to convert the runner's normalized event into the endpoint contract.
2. Recompute the report preview from durable state on GET. Do not create a
   second persisted report draft solely for the dashboard.
3. Let the projection digest change trigger SSE invalidation. Both root and
   Studio refetch their existing safe projections.
4. Keep report file export explicit and local; automatic generation refers to
   the live preview, not submission or unsolicited filesystem writes.

### Verification

Run focused API, Web, Studio, and E2E tests from Phases 4-7. Then run safety
grep for `submit_report`, raw headers/bodies, storage state, and credentials.

## Phase 8: Responsive, Accessibility, Visual Regression, And Bundle Budget

### Files

- Modify `apps/web/playwright.config.ts`.
- Add `apps/web/e2e/control-center.visual.spec.ts`.
- Add screenshot baselines under the Playwright snapshot directory.
- Add `apps/web/scripts/check-control-center-bundle.mjs`.
- Modify `apps/web/package.json` with `check:bundle`.
- Adjust only approved control-center/Studio CSS and components found by tests.

### RED tests

1. Add Playwright projects/viewports for 1680x944, 1440x900, and 390x844.
2. Add `toHaveScreenshot()` baselines for `/` and `/studio` using deterministic
   mock data and disabled motion.
3. Add DOM assertions for no horizontal overflow, no incoherent overlap, stable
   chart/table bounds, visible brand, visible next content, inspector/drawer
   behavior, focus restoration, keyboard navigation, and reduced motion.
4. Add canvas pixel checks proving ECharts renders nonblank and remains framed
   after resize.
5. Add a bundle-budget script that reads Next build manifests and fails when
   root initial JS exceeds 500KB. The script reports exact files and bytes.

### GREEN implementation

1. Fix layout only inside approved surfaces. Do not restyle unrelated campaign,
   artifact, validation, or report pages unless a shared primitive requires it.
2. Disable chart animation under reduced motion and in visual tests.
3. Ensure status text accompanies color, landmarks/headings are correct, tables
   have headers, drawers trap/restore focus, and every icon-only action has a
   tooltip and accessible name.
4. Lazy-load chart leaves and remove unused shadcn components/dependencies if
   the bundle budget fails.

### Verification

```powershell
cd apps/web
npm test
npm run lint
npm run build
npm run check:bundle
npm run e2e
```

Review every screenshot at all three viewports. Update baselines only after
confirming the rendered page matches the approved design, not merely because the
diff is inconvenient.

## Phase 9: Windows x64 Electron Installer

### Deliverable

Produce an internal, unsigned Windows x64 Squirrel installer:

```text
BountyMythosLite Setup.exe
```

Public distribution and code signing remain blocked until a later release task.

### Files

- Modify `apps/studio/package.json` and `package-lock.json`.
- Add `apps/studio/forge.config.cjs`.
- Add `apps/studio/package-runtime.cjs`.
- Modify `apps/studio/main.cjs` and `launcher.cjs`.
- Add `apps/studio/packaged-runtime.cjs` and tests.
- Add `apps/api/app/desktop_server.py` and tests.
- Add `apps/api/requirements-desktop.txt` pinned to `pyinstaller==6.21.0`.
- Add `apps/api/mythos-api.spec` after a reproducible PyInstaller dry run.
- Modify bundled browser path handling in `apps/studio/black-box-runner.cjs`
  and tests without changing its safety policy.
- Add packaging instructions to `apps/studio/README.md`.

### RED tests

1. API entry tests parse a loopback port, choose a database under an injected
   user-data directory, run migrations from an injected resources directory,
   and refuse non-loopback host values.
2. Packaged-runtime Node tests assert:
   - development mode keeps current source launcher;
   - packaged mode resolves only under `process.resourcesPath`;
   - API executable, Web `server.js`, static/public assets, migrations, and
     Chromium must exist before launch;
   - no PATH `python`, `node`, `npm`, `uvicorn`, or `next dev` command is used;
   - database and workspace paths use Electron `app.getPath("userData")`;
   - all children stop on app exit.
3. Forge config contract test requires `asar:true`, executable/browser assets in
   real `extraResource`, Squirrel lifecycle handling, and Windows x64 maker.
4. Build staging test fails when `.next/static`, `public`, frozen API, migrations,
   or browser executable is absent.

### GREEN implementation

1. Install exact packaging packages:

```powershell
cd apps/studio
npm install --save-dev --save-exact @electron-forge/cli@7.11.2 @electron-forge/maker-squirrel@7.11.2
npm install --save-exact electron-squirrel-startup@1.0.1
```

2. Add `package`/`make` scripts without replacing the existing development
   startup until packaged startup tests are green.
3. Stage Web runtime by running `npm run build`, copying `.next/standalone`,
   `.next/static`, and `public` as shown in `apps/web/Dockerfile:11-21`.
4. Add a dedicated loopback-only Python entry and freeze it with PyInstaller
   `--onedir`, including `alembic.ini`, migrations, and verified hidden imports.
5. At build time set `PLAYWRIGHT_BROWSERS_PATH` to the runtime staging
   directory, run `npx playwright install chromium`, and copy that directory to
   `resources/playwright` outside ASAR. In packaged mode set
   `PLAYWRIGHT_BROWSERS_PATH=path.join(process.resourcesPath, "playwright")`
   before the black-box runner loads. Do not download at first launch.
6. In packaged mode, start Next standalone from the staged `server.js` via an
   Electron utility process after `app.ready`; start the frozen API executable
   from resources. Pass dynamic loopback ports and user-data paths explicitly.
7. Preserve BrowserWindow security flags and navigation guard exactly.
8. Configure Forge Squirrel and run:

```powershell
cd apps/studio
npm run make -- --platform=win32 --arch=x64
```

### Verification

1. Run all API, Web, and Studio tests before packaging.
2. Verify package contents contain no source `.env`, credentials, caches, test
   artifacts, or authorized target packages.
3. On a clean Windows x64 VM with networking disabled:
   - install;
   - launch;
   - wait for API/Web readiness;
   - open Studio and root control center;
   - complete a synthetic local-only smoke workflow;
   - exit with no child process left;
   - relaunch with user data retained;
   - uninstall and verify the documented user-data retention policy.
4. Record installer size, Chromium path, API startup time, Web startup time, and
   SmartScreen/signing warning. Do not label the unsigned build public-ready.

## Phase 10: Final Verification And Safety Audit

### Full commands

```powershell
cd apps/api
python -m pytest -q

cd ../web
npm test
npm run lint
npm run build
npm run check:bundle
npm run e2e

cd ../studio
npm test
npm run make -- --platform=win32 --arch=x64
```

### Final checks

1. Re-read the approved design acceptance criteria and map each criterion to a
   passing test, screenshot, or package smoke record.
2. Inspect root and Studio screenshots at all required viewports and confirm
   nonblank charts, stable framing, no overlap, readable Chinese text, visible
   focus, and correct status colors/text.
3. Confirm all visible metrics trace to durable records or explicit empty state.
4. Confirm live failure never becomes demo data and degraded connection remains
   visible.
5. Confirm one human approval leads to at most one exact bounded local workflow,
   and every mutation/expiry/preflight failure prevents dispatch.
6. Confirm every report remains submission-blocked and no submission command,
   endpoint, IPC method, or automation exists.
7. Confirm the installer runs offline without system Node/Python/npm or runtime
   downloads and preserves Electron's security boundaries.
8. Run safety grep:

```powershell
rg -n "auto_submit|submit_report|execute_live_validation|launchPersistentContext|storageState|nodeIntegration:\s*true|contextIsolation:\s*false|sandbox:\s*false" apps/api apps/web apps/studio
```

Review every match. Allowed matches are fixed-false safety labels, blocked
actions, negative tests, or existing explicitly bounded local-lab terminology.

## Plan Self-Review Checklist

- Documentation: all new libraries and runtime APIs have a verified local or
  official source.
- Placeholders: no unresolved marker or unspecified production decision remains.
- Scope: root, Studio, local auto-validation, report preview, and Windows x64
  packaging are sequenced independently.
- Simplicity: snapshot digest avoids a cross-domain timestamp migration;
  immediate one-workflow dispatch avoids a background execution queue.
- Safety: public attack automation, raw data, secret storage, approval bypass,
  and automatic submission remain prohibited.
- Testability: every behavior phase begins with a failing test and has explicit
  commands and anti-pattern checks.
