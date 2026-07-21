# Startup Self-Check Design

Date: 2026-07-21

Status: Approved concept; pending written-spec review.

## Goal

Make local Studio startup fail fast and explainably when the packaged runtime,
mutable user state, API, or Web service cannot become ready. A successful
startup remains silent and opens Studio normally. A failed startup shows only
bounded, fixed diagnostic information and does not leak paths, exception text,
response bodies, credentials, or other state.

This slice is for the personal, Windows, loopback-only desktop workflow. It
does not change research behavior, Scope Guard decisions, validation gates,
redaction rules, or report-submission blocking.

## Existing Context

- `apps/studio/main.cjs` owns startup orchestration and the failure document.
- `apps/studio/launcher.cjs` derives loopback ports and currently waits for a
  generic HTTP response.
- `apps/studio/packaged-runtime.cjs` resolves and validates frozen resources,
  then owns the API and Web child processes.
- The frozen API runs migrations before serving `/health`.
- The packaged runtime already keeps mutable state below Electron `userData`
  and binds both services to `127.0.0.1`.

## Chosen Approach

Use an Electron-owned preflight plus post-launch readiness check. This covers
failures before the API can run, while keeping the implementation local to the
existing launcher and packaged-runtime boundaries.

Two alternatives were rejected:

1. An API-only diagnostics endpoint cannot explain missing packaged resources
   or an API that fails before binding its port.
2. A separate diagnostics executable would duplicate packaging, migration, and
   process-lifecycle logic for little benefit in a personal-use build.

## Diagnostic Contract

Diagnostics are in-memory values used by the main process and failure page.
They are not persisted, sent over HTTP, or exposed to the renderer as raw
objects.

Each check has a fixed identifier, status, and operator-safe action. The
implementation must allow only this identifier set (unknown internal errors
map to `startup_unknown`):

| Identifier | Meaning |
| --- | --- |
| `resources_missing` | A required packaged or development asset is absent. |
| `state_unwritable` | `userData/data` or `userData/workspaces` cannot be created or written. |
| `port_unavailable` | The derived loopback port pair cannot be reserved. |
| `api_exited` | The API child exited before readiness. |
| `api_unhealthy` | The API responded, but not with the expected health contract. |
| `api_timeout` | The API did not satisfy its health contract before the deadline. |
| `web_exited` | The Web child exited before readiness. |
| `web_unhealthy` | The Web service returned an unacceptable status. |
| `web_timeout` | The Web service did not become ready before the deadline. |
| `startup_unknown` | A failure did not match a known, safe category. |

No diagnostic includes an absolute path, command line, exception message,
HTTP body, header, token, cookie, or database content.

## Startup Flow

1. Derive the loopback API and Web ports using the existing launcher logic.
2. Run preflight checks before starting children:
   - packaged mode: validate the frozen API, migration, Web, Chromium, and
     standalone helper resources with the existing path validator;
   - development mode: validate only the existing local source directories;
   - create the `data` and `workspaces` directories below `userData` and run a
     short write/delete probe using a generated transient filename;
   - retain the existing loopback-only URL and port rules.
3. Start the API and Web children through the existing runtime. Child exit
   events are recorded as fixed `api_exited` or `web_exited` state.
4. Wait for exact readiness contracts with bounded per-request and total
   deadlines:
   - API: `GET /health`, HTTP 200, JSON object with
     `status: "ok"` and `service: "bounty-mythos-api"`;
   - Web: `GET /studio`, HTTP 200. The response body is never inspected or
     returned by diagnostics.
5. On success, clear transient diagnostic state and load the Studio URL with
   no self-check panel or extra startup screen.
6. On failure, stop every child that was started, map the failure to one fixed
   identifier, and load a sanitized failure document.

The readiness deadline is bounded and test-configurable. The production
default is 45 seconds total per service, with a two-second request timeout and
short polling interval. A child-exit signal takes precedence over waiting for
the deadline.

## Failure Document

`startupErrorHtml` will accept a safe diagnostic projection rather than a raw
`Error`. It will render:

- a stable title stating that local startup failed;
- the fixed diagnostic identifier and a short operator-safe explanation;
- mode-specific local steps (packaged app steps never instruct the operator to
  install source dependencies);
- a reminder that no research, validation, or report submission was started.

Unknown values are replaced with `startup_unknown`. Existing HTML escaping is
retained as defense in depth, but raw exception details are no longer passed
to the template.

## Component Changes

- Add a small `startup-diagnostics.cjs` module for fixed identifiers,
  preflight checks, readiness response validation, and safe projections.
- Extend `launcher.cjs` with bounded readiness polling and an optional child
  liveness callback; preserve its loopback URL derivation API.
- Extend `packaged-runtime.cjs` with child startup-failure state while
  retaining non-shell spawning, resource validation, maintenance lifecycle,
  and shutdown behavior.
- Update `main.cjs` to run preflight before child startup, pass liveness into
  readiness waits, stop children on all failure paths, and render the safe
  projection.
- Keep preload and Web renderer contracts unchanged. No startup diagnostic
  bridge or new network endpoint is introduced.

## Safety and Compatibility

- All network requests remain loopback HTTP requests created by the existing
  launcher; no public URL is contacted.
- The write probe is confined to `userData/data` and `userData/workspaces`,
  uses a generated transient name, and is deleted before readiness begins.
- No raw state is copied into diagnostics or logs.
- Migration failures remain represented by API non-readiness; the frozen API
  still owns migration execution and pre-migration backup behavior.
- Scope Guard, human approval, redaction, safe validation, and
  submission-blocked report contracts are untouched.
- Development startup remains supported; packaged startup continues to use
  only frozen resources and the bundled API/Web children.

## Verification

Focused tests will cover:

1. required-resource, directory-write, loopback-port, and transient-probe
   failures map to fixed identifiers;
2. API health accepts only the exact JSON contract and rejects malformed,
   non-200, oversized, or body-leaking responses;
3. Web readiness requires HTTP 200 and respects the bounded deadline;
4. API/Web early exits fail immediately and all started children are stopped;
5. startup HTML contains safe fixed text, escapes values, and excludes raw
   paths, errors, headers, bodies, and credentials;
6. existing launcher, packaged-runtime, Electron, and shutdown tests remain
   green;
7. a fresh packaged app still starts both loopback services and returns 200
   for `/health` and `/studio`;
8. full API, Web, Studio, lint, build, bundle, and Windows packaging checks
   remain green.

## Non-Goals

- No persistent diagnostics history.
- No automatic repair, migration rollback, or backup restore from the failure
  page.
- No free-form log viewer, shell command launcher, remote telemetry, or cloud
  health reporting.
- No visual redesign of the Studio workbench.
