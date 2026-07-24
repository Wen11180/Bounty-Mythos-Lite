# Startup Self-Check Implementation Plan

> Execute one phase at a time. Every production behavior starts with a focused
> failing test. This slice changes only local desktop startup diagnostics; Scope
> Guard, human approval, redaction, validation, and submission-blocked report
> contracts remain unchanged.

## Phase 0: Verified Contracts and Allowed APIs

| Need | Existing contract | Source |
| --- | --- | --- |
| API health contract | `GET /health` returns exactly `{"status": "ok", "service": "bounty-mythos-api"}` | `apps/api/app/main.py:1958-1960`, `apps/api/tests/test_api.py:24-28` |
| Loopback launch config | `createStudioLaunchConfig`, `findAvailablePort`, and `waitForUrl` derive `127.0.0.1` API/Web URLs | `apps/studio/launcher.cjs:13-118` |
| Main startup boundary | `app.whenReady()` derives config, starts services, waits, and loads Studio | `apps/studio/main.cjs:242-262` |
| Frozen resource paths | `resolvePackagedRuntimePaths` and `assertPackagedRuntime` validate the API, migrations, Web, and Chromium | `apps/studio/packaged-runtime.cjs:4-60` |
| Packaged child lifecycle | `createPackagedRuntime().start()` uses non-shell API spawn and `utilityProcess.fork`; `.stop()` terminates children | `apps/studio/packaged-runtime.cjs:62-158` |
| Mutable state paths | database lives in `userData/data`; workspaces live in `userData/workspaces` | `apps/studio/packaged-runtime.cjs:15-32` |
| Electron utility child API | `utilityProcess.fork(modulePath, args?, options?)` emits `exit` and supports `kill()` | `apps/studio/node_modules/electron/electron.d.ts:15574-15801` |
| Existing Studio test patterns | Node `node:test`, loopback HTTP fixtures, `EventEmitter` child stubs, temp runtime fixtures | `apps/studio/launcher.test.cjs:1-168`, `apps/studio/packaged-runtime.test.cjs:1-332` |
| Windows package command | package runtime then Electron Forge Squirrel make | `apps/studio/package.json:8-14`, `apps/studio/forge.config.cjs:50-74` |

### Allowed APIs

- Node standard library `http`, `https`, `net`, `fs`, `path`, and
  `crypto.randomUUID`; use `ClientRequest.setTimeout`, response `resume`, and
  bounded stream reads only.
- Existing `createStudioLaunchConfig`, `assertPackagedRuntime`,
  `resolvePackagedRuntimePaths`, `createPackagedRuntime`, Electron
  `utilityProcess.fork`, and child `kill` seams.
- Existing Node-native Studio test runner: `node --test *.test.cjs`.
- Existing frozen API `/health` JSON contract and packaged `npm run make`
  runtime assembly.

### Guards

- Keep all readiness HTTP requests on derived `127.0.0.1` URLs; add no remote
  diagnostic request, endpoint, telemetry, renderer bridge, or persisted log.
- Map every failure to only the approved fixed identifiers. Never carry an
  exception string, path, command line, response body, header, token, cookie,
  or database content into the failure page.
- Use a generated transient probe inside only the selected mutable directories,
  delete it before readiness polling, and do not inspect Web response bodies.
- Keep frozen API spawning non-shell and preserve existing maintenance,
  loopback, shutdown, and renderer-isolation behavior.

## Phase 1: Fixed Diagnostics and Preflight (RED/GREEN)

### Files

- Add `apps/studio/startup-diagnostics.cjs`.
- Add `apps/studio/startup-diagnostics.test.cjs`.
- Extend `apps/studio/packaged-runtime.cjs` and
  `apps/studio/packaged-runtime.test.cjs` only where packaged preflight uses
  the new diagnostic helpers.

### RED tests

1. Unknown failure values normalize to `startup_unknown`; every public
   projection contains only a known identifier and fixed local instructions.
2. Missing development directories and failed packaged-resource assertion map
   to `resources_missing` without retaining the underlying path or message.
3. A file where `data` or `workspaces` must be created maps to
   `state_unwritable`; a successful generated write/delete probe leaves no
   probe file behind.
4. A liveness tracker records only the first API/Web early exit and ignores
   intentional exits after readiness is marked.

### GREEN implementation

1. Add a small pure diagnostics module with the approved identifier allowlist,
   `createStartupDiagnostic`, `createStartupDiagnosticError`, and
   `diagnosticFromError` functions. Copy the health contract values from
   `apps/api/app/main.py:1958-1960`; do not parse exception text.
2. Add directory and transient write/delete helpers using `fs.mkdirSync`,
   `fs.writeFileSync`, `fs.unlinkSync`, and `crypto.randomUUID`. Catch low-level
   errors at this boundary and expose only `state_unwritable`.
3. Add development preflight that verifies the existing `apps/api` and
   `apps/web` directories, then probes actual state directories.
4. Add packaged `preflight()` that reuses `resolvePackagedRuntimePaths` and
   `assertPackagedRuntime`, then probes `databaseFile`'s directory and
   `workspaceRoot`. It returns no raw failure detail.

### Verify

```powershell
Set-Location apps/studio
node --test startup-diagnostics.test.cjs packaged-runtime.test.cjs
```

### Anti-pattern guards

- Do not introduce a diagnostics HTTP API, local storage history, or renderer
  preload method.
- Do not use a fixed temporary filename, `fs.access`, broad recursive probes,
  or source-dependency commands in a packaged failure projection.
- Do not change `assertPackagedRuntime`'s direct validation contract; wrap it
  only at the startup preflight boundary.

## Phase 2: Strict Readiness and Child Liveness (RED/GREEN)

### Files

- Extend `apps/studio/launcher.cjs` and `apps/studio/launcher.test.cjs`.
- Extend `apps/studio/packaged-runtime.cjs` and
  `apps/studio/packaged-runtime.test.cjs`.

### RED tests

1. API readiness accepts only HTTP 200 and a bounded JSON object exactly equal
   to the frozen `/health` contract; malformed, wrong, non-200, and oversized
   responses fail as `api_unhealthy` without returning body text.
2. Web readiness accepts only HTTP 200 for `/studio`, drains but never reads its
   body, and maps other responses to `web_unhealthy`.
3. Missing responses respect a test-configurable total deadline and per-request
   timeout, mapping to `api_timeout` or `web_timeout`.
4. A liveness callback reporting `api_exited` or `web_exited` rejects before
   the deadline.
5. Packaged API and Web child `exit` or spawn-error events are captured before
   readiness; `markStartupReady()` disarms later normal shutdowns.

### GREEN implementation

1. Extend `waitForUrl` with explicit bounded timeout, polling, response
   validator, diagnostic codes, and optional liveness callback while preserving
   the existing derived loopback URL API. Reuse Node `http`/`https` request
   timeout and response-drain patterns from `apps/studio/launcher.cjs:80-118`.
2. Add API/Web wrappers with fixed service-specific codes. Accumulate at most a
   small fixed API health body budget and compare the parsed object exactly;
   never retain the body in an Error or diagnostic projection.
3. Reuse the Phase 1 liveness tracker in the packaged runtime. Attach it to
   the existing API child and `utilityProcess` child after spawning, expose
   `getStartupFailure()` and `markStartupReady()`, and disarm it before
   intentional stop/maintenance shutdown.

### Verify

```powershell
Set-Location apps/studio
node --test launcher.test.cjs packaged-runtime.test.cjs startup-diagnostics.test.cjs
```

### Anti-pattern guards

- Do not treat arbitrary `<500` responses as ready.
- Do not inspect the Web response body or add raw request/response details to
  errors, diagnostics, logs, or HTML.
- Do not wait for a deadline after a child has already exited.

## Phase 3: Electron Orchestration and Failure Page (RED/GREEN)

### Files

- Extend `apps/studio/main.cjs` and `apps/studio/desktop-shell.test.cjs`.
- Extend `apps/studio/launcher.cjs` and `apps/studio/launcher.test.cjs` for the
  safe failure-document input.

### RED tests

1. The failure document renders a fixed identifier, bounded explanation,
   mode-specific local steps, and the no-research/no-validation/no-submission
   reminder; unknown/raw input becomes `startup_unknown`.
2. A packaged failure document contains no source install command; development
   recovery retains only fixed local prerequisites.
3. The desktop startup source runs preflight before child start, passes a
   liveness callback into API and Web readiness, marks the controller ready
   only after both succeed, and calls child cleanup on every startup catch path.
4. Existing startup ordering remains: wakeup, program-rule pump, navigation
   guard, and Studio navigation start only after both strict readiness checks.

### GREEN implementation

1. Replace raw `Error` rendering in `startupErrorHtml` with a safe diagnostic
   projection and fixed mode-aware steps. Retain HTML escaping as defense in
   depth, but never use it to display a raw exception.
2. Make development service startup return the same minimal liveness interface
   as packaged runtime, using existing `spawnChild` children and Phase 1
   tracking.
3. In `app.whenReady()`, derive ports, run mode-specific preflight before any
   child launch, start services, use strict API/Web waits with the controller,
   mark ready only after both pass, then start existing local pumps and load
   Studio.
4. In the catch path, stop every started child before opening the sanitized
   failure document. Preserve `before-quit` session cleanup and no new
   renderer-facing diagnostics surface.

### Verify

```powershell
Set-Location apps/studio
node --test desktop-shell.test.cjs launcher.test.cjs packaged-runtime.test.cjs startup-diagnostics.test.cjs
```

### Anti-pattern guards

- Do not create a second window, automatic restore, automatic repair, or a
  diagnostics panel in the Studio renderer.
- Do not expose raw error objects through IPC/preload or interpolate them into
  the data-URL failure document.
- Do not start local research, validation, report, or program-rule work before
  strict API and Web readiness succeeds.

## Phase 4: Regression, Package, and Fresh-User-State Smoke

1. Run the focused Studio suites, then the full Studio suite.
2. Run API, Web unit/lint/build/bundle/E2E checks using the existing commands.
3. Build the frozen runtime and Windows x64 Squirrel installer with the
   existing Studio `make` command.
4. In a fresh Electron `userData` directory, launch the packaged app, verify
   only loopback `/health` returns the exact API JSON with 200 and `/studio`
   returns 200, then close the app and confirm no test/package service remains.
5. Run `git diff --check` and inspect the startup-diagnostics diff for raw
   exception interpolation, remote URL requests, renderer bridge additions,
   or changes to Scope Guard/report gates.

### Full verification commands

```powershell
Set-Location apps/studio
npm test
npm run make -- --platform=win32 --arch=x64

Set-Location ../api
& .\.venv\Scripts\python.exe -m pytest -q

Set-Location ../web
npm test
npm run lint
npm run build
npm run check:bundle
npm run e2e

Set-Location ../..
git diff --check
```

## Completion Evidence

This slice is complete only when fixed diagnostics, preflight, strict
readiness, early-exit cleanup, safe failure HTML, existing Studio behavior,
fresh packaged loopback startup, and all required regression commands pass.
No raw startup detail may be persisted, displayed, or sent outside the local
main process.
