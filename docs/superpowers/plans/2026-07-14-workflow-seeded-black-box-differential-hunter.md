# Workflow-Seeded Black-Box Differential Hunter Implementation Plan

> Execution rule: Every behavior change starts with a focused failing test.
> Preserve Scope Guard, durable human approval, redaction, test-object
> ownership, rate limits, rollback, and manual report submission.

> Rollout rule: Only local or dedicated labs may execute before the held-out
> live-lab gate passes. A real bounty target is never reached by default tests,
> a background worker, a root-URL crawler, or an unapproved browser session.

## Scope

This plan implements the approved design in:

- `docs/superpowers/specs/2026-07-14-workflow-seeded-black-box-differential-hunter-design.md`

It adds a separate black-box evidence lane:

```text
policy/scope + human lease + two ephemeral sessions + demonstrated workflows
-> observed ownership/state model
-> bounded differential trials
-> baseline, control, repeat, refutation
-> redacted review-ready candidate
-> human confirmation
-> submission-blocked report draft
```

The first supported families are BOLA/IDOR, role boundary failure,
authentication failure, and reversible state-machine authorization defects.

Do not change the existing A+B Candidate Hunter to accept pure black-box
candidates. Its terminal evidence contract requires code plus API/HAR
traceability. This lane has independent candidate/audit contracts and a
versioned Top-10 evaluator; it joins existing evidence/review/report rails only
after black-box evidence is review-ready.

The legacy Candidate Hunter must never receive a BlackBoxCandidate or a
synthetic code/API/HAR reference.

## Phase 0: Verified Documentation Boundaries

| Need | Existing source | Required use |
| --- | --- | --- |
| Scope decision | `apps/api/app/scope_guard/__init__.py:4-50` | Call `evaluate_validation_request(...)` first. A caller Boolean never grants authority. |
| Durable approval | `apps/api/app/main.py:2528-2605`; `apps/api/app/repository.py:749-1009` | Bind every lease to an approved, unexpired ApprovalRecord matching asset, action, and plan digest. |
| Preflight audit | `apps/api/app/repository.py:1249-1409`; `apps/api/app/db_models.py:365-391` | Reuse ValidationRunRecord, adding a narrow bounded-result writer instead of repurposing manual results. |
| Idempotent audit | `apps/api/app/candidate_hunter_loop.py:1147-1497,1500-1747`; `apps/api/app/repository.py:1011-1101` | Copy owner lookup, digest, idempotency, append-only discipline, and fail-closed projection validation. |
| Web/API surface plans | `apps/api/app/authorized_web_api/__init__.py:180-234,1017-1135` | Reuse offline surface/role planning only; it remains plan-only. |
| Containment/redaction | `apps/api/app/studio_workspace.py:79-145,201-258`; `apps/api/app/evidence/__init__.py:6-103`; `apps/api/app/repository.py:2016-2160` | Use workspace containment and structured recursive redaction. |
| Existing report evidence | `apps/api/app/mythos_report/__init__.py:38-56,860-902` | Add only the recognized sanitized differential evidence types. |
| Benchmark isolation | `apps/api/app/intelligence_benchmark/release_runner.py:170-234`; `typescript_release_gate.py:73-99` | Capture candidates before loading gold and separate development from held-out applications. |
| Studio shell | `apps/studio/main.cjs:1-112`; `preload.cjs:1-10`; `apps/web/app/studio/studio-workbench.tsx:45-53,247-392` | Retain Electron isolation and a small local bridge. |
| Product browser runtime | [Playwright library](https://playwright.dev/docs/library); [BrowserContext](https://playwright.dev/docs/api/class-browsercontext) | Add direct `playwright` to Studio and use two non-persistent `browser.newContext()` contexts. |
| Network events | [Request events](https://playwright.dev/docs/api/class-request) | Produce only sanitized operation metadata; never send raw headers, bodies, cookies, or response content to the backend. |

### Non-negotiable constraints

1. `apps/web` Playwright is test-only; no product browser/session runtime exists.
2. `AuthorizedBugBountyPlan` is offline, network-disabled, and plan-only.
3. `release_v1.py` is a Top-5 A+B evaluator. Add a versioned black-box
   Top-10 evaluator rather than modifying legacy thresholds.
4. `ValidationRunRecord.allowed_to_execute` is a preflight result, not an
   executor. Preserve the manual-result `execution_started=false` behavior.
5. Database stages are not immutable by schema; enforce append-only writes and
   projection checks in application code.
6. Do not persist profiles, cookies, tokens, credentials, CSRF values, raw
   URLs with query values, raw requests/responses, or concrete object IDs.

## Phase 1: Pure Contracts and Fail-Closed Lease Gate

### Files

- Add `apps/api/app/black_box_hunter/__init__.py`.
- Add `apps/api/tests/test_black_box_hunter.py`.
- Narrowly extend `apps/api/app/scope_guard/__init__.py`.
- Extend `apps/api/tests/test_scope_guard.py` and
  `apps/api/tests/test_scope_guard_api.py`.

### RED tests

1. Define the safe lease projection: ID, scope/policy digest, exact active and
   passive origins, account aliases, action classes, request/time budgets,
   expiry, and rollback requirement. Reject secret-looking keys and values.
2. Keep session handles and concrete object IDs in separate runtime-only maps;
   prove safe projections expose aliases or run-scoped hashes only.
3. Require all of scope decision, durable approval, matching preflight,
   unexpired lease/policy, exact active origin, supported action, owned object,
   and valid state before a trial is allowed.
4. Test fixed remote limits: concurrency one, three-second interval, fifty
   generated requests per workflow, three workflows, thirty minutes.
5. Reject root-URL discovery, wildcard host patterns, caller approval flags,
   allowed_to_execute alone, unsupported role, irreversible action, and expired
   session with terminal stop reasons.

### GREEN implementation

1. Add only these domain models: BlackBoxExecutionLease, SessionAlias,
   WorkflowStep, TestObjectAlias, DifferentialTrial, TrialObservation, and
   BlackBoxStop.
2. Add a nonserializable RuntimeSessionRegistry for live values.
3. Add pure validate_black_box_trial. It invokes Scope Guard first, then
   enforces lease, origin, object, state, and budget checks.
4. Permit only read-only replay, test-object creation, and already-demonstrated
   reversible updates. Block delete, payment, notification, invitation, export,
   role administration, upload, enumeration, brute force, and destructive work.
5. Keep all current Scope Guard behavior compatible; the new mode must not
   acquire authority from request input.

### Verification

```powershell
.\.venv\Scripts\python.exe -m pytest `
  apps/api/tests/test_black_box_hunter.py `
  apps/api/tests/test_scope_guard.py `
  apps/api/tests/test_scope_guard_api.py -q
```

### Guards

- No repository, browser, network, worker, or wall-clock import in the pure
  validator.
- No migration or generic policy/workflow framework in this phase.

## Phase 2: Observed State Model, Planner, and Local Lab Transport

### Files

- Extend `apps/api/app/black_box_hunter/__init__.py`.
- Extend `apps/api/tests/test_black_box_hunter.py`.
- Add `apps/api/tests/fixtures/black_box_differential_lab/` only if an
  in-test FastAPI application is less clear.

### RED tests

1. Demonstrate two normal flows which create A- and B-owned test objects.
   Persistent outputs may contain aliases, ownership, state, and reversibility
   only.
2. Allow only these single-variable trial classes: cross-account object swap,
   lower-role replay, unauthenticated read-only replay, owned parent/child
   swap, and reversible out-of-order state transition.
3. Refuse planning when baseline, role, state, provenance, or rollback
   information is missing.
4. Use a loopback FastAPI TestClient lab for BOLA, correctly guarded access,
   intended sharing, expired session, unstable response, 429, 5xx, and rollback
   failure.
5. Require stable A/B baselines, one trial, owner/session controls, and an
   independent repeat before review_ready.
6. Prove 200 versus 403 alone cannot retain a candidate. Require a sanitized
   structural identity, test-owned canary match, or confirmed state effect.
7. Stop and discard if third-party data markers, unknown objects, or off-origin
   redirects appear.

### GREEN implementation

1. Add ObservedWorkflowModel based only on demonstrated normalized steps.
2. Add finite planning for the five approved trial classes, including baseline,
   control, repeat, and rollback requirements.
3. Add one transport seam:
   `execute(trial: DifferentialTrial) -> TrialObservation`.
   This is only for local-lab and later Studio transport sharing; it is not a
   plugin system.
4. Implement a test-only local transport using the existing FastAPI TestClient
   pattern in `apps/api/tests/test_api.py:11`.
5. Add an oracle returning hypothesis, observed, reproduced, review_ready,
   refuted, or inconclusive based on safe fingerprints and state effects.
6. Allow a random non-secret canary only in a demonstrated benign field of an
   owned object, and persist only a hash/match Boolean.

### Verification

```powershell
.\.venv\Scripts\python.exe -m pytest `
  apps/api/tests/test_black_box_hunter.py `
  apps/api/tests/test_scope_guard.py -q
```

### Guards

- The lab is synthetic, loopback-only, and secret-free.
- No raw HTTP capture and no real target in this phase.

## Phase 3: Durable Audit, Candidate Lane, and Evidence Bridge

### Files

- Add `apps/api/app/black_box_hunter/audit.py` only if persistence makes the
  initial module too large.
- Update `apps/api/app/repository.py`, `apps/api/app/main.py`,
  `apps/api/app/evidence/__init__.py`, and `apps/api/app/mythos_report/__init__.py`.
- Extend black-box, repository, evidence, and report tests.

### RED tests

1. Create one black-box Campaign/Task/approval/ValidationRun owner for an
   in-scope local-lab run; a retry must resume it without duplicate stages.
2. Verify append-only black_box_lease, black_box_workflow, black_box_plan,
   black_box_trial, and black_box_decision stages contain only digest, aliases,
   normalized routes, safe fingerprints, stop reasons, and evidence refs.
3. Fail closed on corrupt owner linkage, stage order, digest, approval/preflight
   ref, redaction status, or terminal candidate state.
4. Preserve `record_validation_run_manual_result` and its
   `execution_started=false` result.
5. Add a bounded-result writer that requires preflight_passed, stores no
   session/header/body/query/object-ID data, and clears executable status at
   terminal completion.
6. Permit only sanitized_cross_account_diff and sanitized_parent_child_matrix
   as new evidence types. Reject raw traffic.
7. Permit a review_ready black-box candidate to build a submission-blocked
   review packet, but never human_confirmed, promoted, or submitted by code.

### GREEN implementation

1. Reuse ApprovalRecord and ValidationRunRecord; no new table. Safe lease data
   goes through existing payload sanitization. Runtime maps remain in memory.
2. Copy Candidate Hunter idempotency/projection techniques but keep the
   black-box candidate projection independent from candidate_hunter_inputs.
3. Bridge redacted review-ready evidence to report review only after the
   black-box gate; all validation/promotion/submission controls remain blocked.

### Verification

```powershell
.\.venv\Scripts\python.exe -m pytest `
  apps/api/tests/test_black_box_hunter.py `
  apps/api/tests/test_database_repository.py `
  apps/api/tests/test_evidence_model.py `
  apps/api/tests/test_scope_guard_api.py -q
```

### Guards

- Do not update old Stage payloads.
- Do not convert allowed_to_execute into generic automation permission.
- Do not add black-box candidates to legacy release-v1 output.

## Phase 4: Studio-Owned Ephemeral Two-Session Runner, Local Lab Only

### Files

- Add a direct pinned `playwright` runtime dependency to
  `apps/studio/package.json` and lockfile.
- Add `apps/studio/black-box-runner.cjs` and
  `apps/studio/black-box-runner.test.cjs`.
- Narrowly update `apps/studio/main.cjs`, `preload.cjs`, and Studio workbench
  declarations for a local IPC bridge.

### RED tests

1. Create exactly two independent non-persistent contexts; destroy both on
   stop, expiry, crash, and app exit.
2. Start recording only after the operator marks sessions_ready. Password-entry
   and login-submission activity never enter normalized traces.
3. Record loopback workflow data containing only method, route template,
   parameter locations/types, alias relationships, status class, response
   schema fingerprint, and timing bucket.
4. Prove IPC never returns headers, cookies, authorization values, bodies,
   query values, response content, downloads, screenshots, storage, or object
   IDs.
5. Reject every active origin not in the approved lease. Passive rendering
   origins may load but are never mutation candidates.
6. Emit a single no-retry stop for request failure, 429, off-origin redirect,
   CAPTCHA/WAF marker, page close, or session expiry.

### GREEN implementation

1. Use Playwright library, not the test runner: launch Chromium and create
   separate `browser.newContext()` sessions for A and B. Close them after run.
2. Implement local line-delimited IPC only for create_sessions,
   start_recording, stop_recording, run_trial, close_sessions, and redacted
   result/stop events.
3. Listen to request/response/requestfailed only long enough to form a safe
   trace. Keep actual object values/canaries inside the runner.
4. Accept no network listener, remote-control port, persistent storage state,
   arbitrary script, or arbitrary URL.
5. Add explicit browser installation/packaging verification. Browser download
   is never a default unit-test action.

### Verification

```powershell
Set-Location apps/studio
npm test
npx playwright install --dry-run chromium
Set-Location ../..
```

### Guards

- Never use launchPersistentContext, storageState, browser profiles, or
  context.cookies outside ephemeral execution.
- Do not import the Web test dependency as Studio production runtime.
- Do not record raw HARs or expose a generic browser-control bridge.

## Phase 5: Local-Lab Studio Flow and Top-10 Quality Gate

### Files

- Update `apps/api/app/main.py` with local-lab-only models/services.
- Update `apps/web/lib/api.ts`, `apps/web/lib/api.test.ts`,
  `apps/web/app/studio/studio-workbench.tsx`, and
  `apps/web/lib/studio-data.test.ts`.
- Add `apps/api/app/intelligence_benchmark/black_box_release_v1.py` and
  `black_box_release_runner.py`.
- Add benchmark tests and opaque application-level fixtures under
  `apps/api/tests/fixtures/black_box_differential_release/`.

### RED tests

1. Support two lab sessions, one to three workflows, trace review, and lab run
   approval. Reject remote hosts and credential fields.
2. Default Studio pages must have no active execution control; lab control is
   explicit and does not persist session state in the workspace manifest.
3. Build development and held-out application sets covering all five trial
   classes. Names, routes, labels, and staged inputs cannot reveal verdicts.
4. Add a separate evaluator for recall, precision@10, independent reproduction,
   traceability, and safety. Do not edit release_v1.py.
5. Require held-out recall >= 0.70, precision@10 >= 0.50, reproduction >= 0.90,
   traceability == 1.00, and safety == 1.00.
6. Capture candidates before gold load and prove opaque ID/order/label
   perturbations preserve outcomes.
7. Refute or mark inconclusive correct authorization, intended sharing, public
   test data, cache differences, CSRF rotation, expiry, rate limits, and
   rollback failures.

### GREEN implementation

1. Add minimal controls: session readiness, recording start/stop, normalized
   trace review, lab lease preview, run confirmation, stop status, and
   review-ready evidence.
2. Keep client/backend requests alias-only. This phase rejects production
   hosts.
3. Implement the independent Top-10 evaluator/runner; preserve legacy A+B
   Top-5 fixtures and metrics.
4. Add one real loopback E2E using the existing
   `apps/web/playwright.config.ts:6-30` pattern.

### Verification

```powershell
.\.venv\Scripts\python.exe -m pytest `
  apps/api/tests/test_black_box_hunter.py `
  apps/api/tests/test_black_box_release_benchmark.py `
  apps/api/tests/test_black_box_release_runner.py `
  apps/api/tests/test_studio_api.py -q

Set-Location apps/web
npm test
npm run lint
npm run build
npm run e2e
Set-Location ../..

Set-Location apps/studio
npm test
Set-Location ../..
```

### Guards

- Mocked/replay checks are contract proof only; the lab gate uses real loopback
  browser and HTTP behavior.
- Do not weaken legacy thresholds, alter gold to match output, or claim field
  readiness here.

## Phase 6: Remote Human-Lease Profile After Lab Qualification

### Prerequisite

Do not start until Phase 5 passes every live-lab threshold and the user
explicitly authorizes remote-profile implementation.

### RED tests

1. Require current policy/scope digest, exact active origin, selected account
   aliases, approved unexpired ApprovalRecord, matching preflight-passed
   ValidationRunRecord, and single-run lease digest.
2. Prove the runner cannot start from a root URL or discover targets; it uses
   only recorded approved workflow plans.
3. Use fake clock tests to enforce concurrency one, three-second delay, fifty
   requests per workflow, three workflows, and thirty minutes.
4. Permit only owned objects and approved read/create/reversible-update actions.
5. Stop entire path without retry on 429, CAPTCHA/WAF, off-origin redirect,
   third-party data, unowned object, ambiguity, rollback failure, or server
   instability.
6. Prove no remote run submits a report or sets human_confirmed.

### GREEN implementation

1. Add a default-disabled remote profile requiring a fresh human approval.
   Bind policy digest, exact active origin, actions, aliases, workflows, and
   budgets into immutable lease digest.
2. Recheck Scope Guard, approval, lease, provenance, and budget before each
   active request. Policy/lease/session changes invalidate the run.
3. Reuse the ephemeral runner only for recorded safe operations. Persist only
   summaries and stop reasons; clear executable state and close contexts on
   completion.
4. Surface expiry/re-login state in Studio without displaying secrets or raw
   content.

### Verification

```powershell
.\.venv\Scripts\python.exe -m pytest `
  apps/api/tests/test_black_box_hunter.py `
  apps/api/tests/test_scope_guard_api.py `
  apps/api/tests/test_studio_api.py `
  apps/api/tests/test_database_repository.py -q

Set-Location apps/studio
npm test
Set-Location ../..
```

### Guards

- No background scheduling, enumeration, retry after stop, proxy rotation,
  CAPTCHA bypass, or global automate-bounty-programs switch.
- A lease cannot increase fixed first-release limits.
- The first live remote run is a user-operated acceptance test, not CI.

## Phase 7: Field Pilot and Advisory Feedback

1. Reuse `DatabaseRepository.save_learning_signal` only after an operator
   records redacted valid, duplicate, invalid, out_of_scope, or needs_evidence
   labels.
2. Record aggregate researcher time and optional bounty value without report
   contents, credentials, raw traffic, or user data.
3. Feedback may explain future ranking only; it never grants a lease, relaxes
   limits, alters scope, or bypasses review.
4. Add tests proving feedback is redacted and advisory.
5. Require five independent authorized engagements, thirty manually reviewed
   candidates, Top-10 submit-worthy precision >= 0.30, and zero safety
   incidents for field_pilot status.
6. Reserve outcome_proven for ten externally valid reports across three
   programs, including five bounty outcomes; track bounty per researcher-hour.

## Final Verification and Handoff

1. Run phases in order and fix failures in their owning phase.
2. Run complete backend, Web test/lint/build/E2E, Studio tests, and Compose
   validation.
3. Inspect the diff for session fields, storage state, unrestricted URLs,
   retries, target discovery, unsafe actions, report-submit paths, and legacy
   evaluator changes.
4. Confirm audit contains only aliases, hashes, normalized routes, safe
   fingerprints, redacted evidence, approval/preflight refs, and stop reasons.
5. Confirm default startup has no Playwright launch, browser download, remote
   request, or remote lease.

```powershell
Set-Location apps/api
..\..\.venv\Scripts\python.exe -m pytest -q

Set-Location ../web
npm test
npm run lint
npm run build
npm run e2e

Set-Location ../studio
npm test

Set-Location ../..
docker compose -f infra/docker-compose.yml config --quiet
git diff --check
rg -n -i "storageState|launchPersistentContext|cookie|authorization|token|password" apps/studio/black-box-runner.cjs apps/api/app/black_box_hunter
rg -n "release_v1|candidate_hunter_inputs" apps/api/app/black_box_hunter
git status --short
```

## Completion Evidence

This plan is complete only when:

- two ephemeral manually authenticated sessions drive one to three workflows
  without secrets or raw traffic entering persistence;
- the object/state ledger proves every active trial uses owned aliases and one
  changed authorization variable;
- the local-lab runner proves baseline, controls, repeat, refutation, rollback,
  and stop behavior for positive and negative cases;
- black-box candidates remain separate from code-required A+B candidates but
  enter human review and submission-blocked reporting with sanitized evidence;
- the application-level held-out Top-10 lab gate meets every approved metric
  with zero safety incidents;
- remote operation remains unavailable until that gate passes and then still
  requires one explicit human lease per run; and
- field/outcome labels are reported honestly rather than inferred from replay
  or model confidence.
