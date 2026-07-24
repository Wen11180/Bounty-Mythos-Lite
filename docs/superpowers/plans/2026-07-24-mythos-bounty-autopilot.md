# Mythos Bounty Autopilot Implementation Plan

> Build the approved Autopilot design by extending the existing Mythos control
> plane. Every active operation remains traceable to current scope, a versioned
> recipe, an immutable plan, a risk decision, a bounded lease, and a sanitized
> outcome. Under the repository's current safety policy, all new active R1/R2
> execution is local-lab-only. A real-program field pilot requires a separate,
> explicit policy decision after the lab release gate passes.

## Outcome

Deliver a local-first Mythos mode that can continuously:

```text
approved program rules + seed asset + owned test accounts
-> effective scope and admitted assets
-> durable research branches
-> versioned R0-R2 lab recipes or R3 approval
-> plan-bound execution leases
-> scope-enforced browser/tool observations
-> sanitized evidence and independent refutation
-> ranked candidates
-> submission-blocked report drafts
```

The completed lab release must prove that a Campaign can survive restart,
continue independent work while one branch is parked or awaiting R3 approval,
revoke all leases on emergency stop, discard suspected third-party content,
and never retain raw credentials or submit a report.

## Assumptions and Explicit Boundaries

- Mythos remains the product and source of truth. Do not fork Strix or add a
  second control plane.
- PostgreSQL records are authoritative for Campaign state, authorization,
  branches, plans, leases, request reservations, and audit lineage.
- Electron main owns local secrets and live browser sessions. The web renderer,
  FastAPI, workers, models, artifacts, logs, and database receive aliases or
  opaque handles only.
- The first active recipe family is two-owned-account authorization testing.
  BFLA, mass assignment, workflow transitions, and GraphQL authorization are
  added only after the same execution boundary passes its release tests.
- WAF blocking is a branch observation. It never proves a vulnerability and
  does not end unrelated Campaign branches.
- Suspected third-party data stops the data-bearing branch. Response content is
  discarded in the execution process and is never stored or included in a
  report, even in nominally redacted form.
- R4 is not approvable. There is no override endpoint, environment variable, or
  operator role that can turn an R4 decision into an execution lease.
- Reports remain `submission_blocked=true`; submission occurs outside Mythos
  after human confirmation.
- Do not edit `AGENTS.md` as an implementation shortcut. Public-target R1/R2
  automation is a later, separately reviewed policy migration.

## Dependency Order

1. Freeze and test current contracts.
2. Add typed authorization, risk, and recipe contracts.
3. Unify the Autopilot Campaign lifecycle and durable branch scheduler.
4. Add admitted asset identity and continuous scope refresh.
5. Add immutable plans, atomic approval consumption, leases, and request ledger.
6. Add the lab execution boundary and scope enforcement.
7. Add the local vault and opaque Session Broker.
8. Add Browser Mapper and the first fixed authorization recipes.
9. Add sanitized observation, refutation, evidence, and report flow.
10. Add Studio live controls and emergency stop.
11. Pass the complete lab release gate.
12. Stop and request a separate field-pilot authorization.

Later phases must not be started when a preceding exit criterion is red.

## Phase 0: Verified Contracts and Baseline Freeze

### Existing contracts to preserve

| Need | Existing implementation to extend | Current source |
| --- | --- | --- |
| Public rule URL and bounded document intake | `ProgramRuleIntakeService`, `canonicalize_public_https_url`, same-origin one-hop normalization | `apps/api/app/program_rule_intake/contracts.py:408`, `apps/api/app/program_rule_intake/service.py:97` |
| Current effective scope | `resolve_effective_program_rule`, `intersect_scope_guard_rules` | `apps/api/app/program_rule_intake/scope_resolver.py:48`, `apps/api/app/program_rule_intake/scope_resolver.py:145` |
| Basic fail-closed validation | `ScopeGuardRule`, `ValidationRequest`, `evaluate_validation_request` | `apps/api/app/scope_guard/__init__.py:8` |
| One-step durable research advancement | `tick_autonomous_research_campaign` | `apps/api/app/autonomous_research_runtime.py:170` |
| Durable wakeup lease and heartbeat | `run_autonomous_research_wakeup`, repository wakeup claim/renew/finish methods | `apps/api/app/autonomous_research_wakeup.py`, `apps/api/app/repository.py` |
| Stable next-action digest | `ResearchDirectorContext`, `ResearchDirectorPlan`, `build_research_director_plan` | `apps/api/app/research_director/__init__.py:67` |
| Tool capability gate | `ToolCapability`, `ExecutionAuthorizationRequest`, `authorize_tool_execution` | `apps/api/app/execution_registry/__init__.py:29` |
| Atomic local budget reservation | `reserve_campaign_local_tool_call` and local execution slot | `apps/api/app/repository.py:1908`, `apps/api/app/db_models.py:404` |
| R3 contract prototype | `RemoteHumanLease`, `RemoteLeaseRuntime` | `apps/api/app/black_box_hunter/remote_profile.py:149` |
| In-memory secret-safe session semantics | `EphemeralSessionHandle`, `EphemeralSessionBroker` | `apps/api/app/black_box_hunter/browser_demo_intake.py:23` |
| Sanitized black-box evidence | `build_evidence_bundle` and typed differential projections | `apps/api/app/evidence/__init__.py:81` |
| Submission blocking | `build_black_box_report_review_packet` and report export gate | `apps/api/app/mythos_report/__init__.py:64` |
| Existing operator UI and live refresh | Control Center, Studio shell, SSE invalidation and LKG projections | `apps/web/components/control-center/control-center-overview.tsx:85`, `apps/web/lib/control-center-live.ts:77`, `apps/web/lib/studio-live.ts:42` |

### Baseline checks

Run the existing suites before the first implementation commit and preserve
the results as the phase baseline:

```powershell
& .\.venv\Scripts\python.exe -m pytest apps/api/tests -q

Push-Location apps/web
npm test
npm run lint
npm run build
npm run check:bundle
Pop-Location

Push-Location apps/studio
npm test
Pop-Location

docker compose -f infra/docker-compose.yml config --quiet
git diff --check
```

### Guards

- Do not treat the design specification as permission to run public-target
  R1/R2 work.
- Do not describe the current `remote_human_lease` as a durable Tool Gateway.
  It is process-local authorization logic and does not send HTTP.
- Do not describe `EphemeralSessionBroker` as a production vault or browser
  broker.
- Do not trust `CampaignRecord.autonomy_level`, client booleans such as
  `allowed_to_execute`, or a stored `ValidationRunRecord.allowed_to_execute`
  without resolving current authority.
- Do not weaken existing tests to establish a green baseline.

### Exit criteria

- Backend, web, Studio, bundle, and compose checks are green.
- The implementation branch contains no unrelated working-tree changes.
- The current prohibition on public-target active automation is recorded in
  the first Autopilot test fixture.

## Phase 1: Campaign Authorization, Risk, and Versioned Recipes

### Goal

Represent the operator's initial authorization as an immutable, digest-bound
server-side contract. Classify every planned action as R0-R4 before it can
become executable. Keep all R1/R2 recipes lab-only under the current policy.

### Files

- Add `apps/api/app/bounty_autopilot/__init__.py`.
- Add `apps/api/app/bounty_autopilot/contracts.py`.
- Add `apps/api/app/bounty_autopilot/risk.py`.
- Add `apps/api/app/bounty_autopilot/recipes.py`.
- Extend `apps/api/app/scope_guard/__init__.py` only with the minimum typed
  inputs needed to evaluate an Autopilot decision; preserve existing callers.
- Add `apps/api/tests/test_bounty_autopilot_contracts.py`.
- Add `apps/api/tests/test_bounty_autopilot_risk.py`.
- Add `apps/api/tests/test_bounty_autopilot_recipes.py`.

### RED tests

1. A Campaign authorization is rejected unless it binds:
   `campaign_id`, approved scope snapshot and digest, policy digest, exact
   asset IDs, account aliases, recipe IDs and versions, risk ceilings, active
   hours, request/time/cost budgets, expiry, and operator identity.
2. Canonical serialization produces a stable `sha256:` authorization digest;
   reordering sets does not change it, while changing any authority-bearing
   field does.
3. Unknown recipe IDs, unknown versions, duplicate aliases, an empty asset
   set, and unbounded budgets fail validation.
4. R0 can be selected without an execution-capable network profile.
5. R1 and R2 fail closed unless both the recipe and Campaign authorization
   permit the exact target, method class, account aliases, and budget.
6. Under the current repository policy, every R1/R2 decision outside
   `authorized_local_lab` returns `policy_mode_blocks_active_execution`.
7. R3 always returns `awaiting_exact_approval`; Campaign authorization alone
   cannot make it executable.
8. R4 always returns `prohibited` and has no approval transition.
9. A model-provided or task-payload recipe definition is rejected. Runtime
   selection accepts only an ID/version from the server registry.
10. Risk cannot be lowered by a client hint, model output, or tool metadata.

### GREEN implementation

1. Define frozen, `extra="forbid"` contracts for:
   - `RiskTier`;
   - `CampaignAuthorization`;
   - `RecipeRef`;
   - `VersionedRecipe`;
   - `MutationInventory`;
   - `RiskDecision`;
   - bounded request, concurrency, response-size, duration, account, and cost
     budgets.
2. Implement canonical digest helpers using sorted JSON and explicit schema
   versions.
3. Build a small code-owned recipe registry. Start with:
   - passive rule/snapshot analysis;
   - passive artifact/served-resource analysis;
   - lab browser mapping;
   - lab two-owned-account read-only authorization differential.
4. Encode R4 categories in a deterministic deny classifier. At minimum include
   DoS/resource exhaustion, credential attacks, social engineering,
   destructive/irreversible transactions, persistence/malware, scope or gate
   bypass, intentional third-party-data collection, raw-secret retention, and
   automatic report submission.
5. Make risk classification monotonic: deterministic rules may raise a tier;
   neither an agent nor a client may lower it.
6. Preserve the existing `ScopeGuardRule` path for legacy Campaigns. The new
   decision composes current effective scope with Campaign authorization and a
   registered recipe; it does not replace current scope checks.

### Verify

```powershell
& .\.venv\Scripts\python.exe -m pytest `
  apps/api/tests/test_bounty_autopilot_contracts.py `
  apps/api/tests/test_bounty_autopilot_risk.py `
  apps/api/tests/test_bounty_autopilot_recipes.py `
  apps/api/tests/test_scope_guard.py `
  apps/api/tests/test_execution_registry.py `
  -q
```

### Guards

- No network sender, browser launch, remote dispatch, or database migration in
  this phase.
- Do not add a generic plug-in marketplace or runtime-loaded recipe code.
- Do not make a recipe configurable enough to express arbitrary shell or HTTP.
- `R4 -> allowed` must be unrepresentable in the response model.

### Exit criteria

- Risk and recipe tests prove fail-closed behavior for unknown and ambiguous
  inputs.
- The only active R1/R2 mode accepted by the decision layer is the named local
  lab mode.

## Phase 2: Durable Authorization and One Autopilot Campaign Lifecycle

### Goal

Persist Campaign authorization and remove the split between legacy start
behavior and the durable autonomous state machine for new Autopilot Campaigns.
Legacy Campaigns remain backward compatible.

### Files

- Add `apps/api/migrations/versions/0020_bounty_autopilot_authority.py`.
- Extend `apps/api/app/db_models.py`.
- Extend `apps/api/app/repository.py`.
- Extend `apps/api/app/main.py`.
- Extend `apps/api/app/autonomous_research_runtime.py`.
- Extend `apps/api/app/autonomous_research_wakeup.py`.
- Extend `apps/api/app/research_director/__init__.py`.
- Extend `apps/api/tests/test_migrations.py`.
- Add `apps/api/tests/test_bounty_autopilot_authority.py`.
- Extend `apps/api/tests/test_campaign_api.py`.
- Extend `apps/api/tests/test_autonomous_research_wakeup.py`.
- Extend `apps/api/tests/test_research_director.py`.

### RED tests

1. Creating an Autopilot Campaign writes one immutable
   `CampaignAuthorizationRecord` whose digest validates against its typed
   payload.
2. The authorization cannot be edited in place. A scope, recipe, budget, or
   operator change creates a successor authorization and revokes the prior
   one.
3. Start refuses missing, expired, revoked, digest-invalid, stale-scope, or
   non-current authorization.
4. Starting an Autopilot Campaign schedules only
   `tick_autonomous_research_campaign`; it does not also call legacy
   `tick_campaign`.
5. Legacy Campaign start behavior remains unchanged when no Autopilot mode is
   selected.
6. Restart and concurrent start calls produce one due wakeup and no duplicate
   initial task.
7. Pause blocks new dispatch. Resume re-resolves the latest program rule and
   authorization before scheduling work.
8. A Program Rule pending drift freezes active branches but still permits
   explicitly passive local rule-review work.
9. A Campaign never derives trusted authority from
   `CampaignRecord.autonomy_level` or its generic payload.

### GREEN implementation

1. Add `CampaignAuthorizationRecord` with:
   - immutable schema version and canonical payload;
   - campaign, program, scope snapshot, policy, and authorization digests;
   - issued/expiry/revoked timestamps;
   - issuer and revocation reason;
   - a uniqueness constraint for one active authorization generation.
2. Add repository methods to create, resolve-current, revoke, and list
   authorizations. Use transactions; never mutate the signed payload.
3. Add a typed `campaign_mode` discriminator to Campaign creation. Route only
   `bounty_autopilot` Campaigns through the durable autonomous runtime.
4. Make the start path materialize the safe source snapshot required by
   `tick_autonomous_research_campaign`, rather than relying on Studio-only
   launch behavior.
5. Have the wakeup service resolve the current authorization on every due
   tick. Persist only its ID and digest in tasks/stages.
6. Extend `ResearchDirectorContext` with authority and recipe references; do
   not pass raw policy text or credentials.

### Verify

```powershell
& .\.venv\Scripts\python.exe -m pytest `
  apps/api/tests/test_migrations.py `
  apps/api/tests/test_bounty_autopilot_authority.py `
  apps/api/tests/test_campaign_api.py `
  apps/api/tests/test_autonomous_research_wakeup.py `
  apps/api/tests/test_autonomous_research_wakeup_core.py `
  apps/api/tests/test_research_director.py `
  -q
```

### Guards

- Do not delete `tick_campaign`; select the path by typed Campaign mode.
- Do not serialize program text, secrets, session material, or response bodies
  into authorization records.
- Do not add an API that accepts a caller-supplied authorization digest as
  proof of authority; the server recomputes and resolves it.

### Exit criteria

- One Autopilot start produces one durable runtime path.
- Restart, pause, resume, and current-scope invalidation are deterministic.
- Legacy Campaign tests remain green.

## Phase 3: Durable Research Branches and Admitted Asset Identity

### Goal

Replace the fixed, whole-Campaign linear stop behavior with bounded independent
branches, and give every discovered asset a stable identity and explicit
admission state before active work is possible.

### Files

- Add `apps/api/migrations/versions/0021_bounty_autopilot_assets_branches.py`.
- Add `apps/api/app/bounty_autopilot/asset_admission.py`.
- Add `apps/api/app/bounty_autopilot/branches.py`.
- Extend `apps/api/app/db_models.py`.
- Extend `apps/api/app/repository.py`.
- Extend `apps/api/app/autonomous_research_runtime.py`.
- Extend `apps/api/app/research_director/__init__.py`.
- Extend `apps/api/app/program_rule_intake/scope_resolver.py` only when a
  missing deterministic matcher is proven by a test.
- Add `apps/api/tests/test_bounty_autopilot_asset_admission.py`.
- Add `apps/api/tests/test_bounty_autopilot_branches.py`.
- Extend `apps/api/tests/test_program_rule_scope_gate.py`.
- Extend `apps/api/tests/test_autonomous_research_runtime.py`.

### RED tests

1. Seed, discovered, and linked assets receive deterministic IDs from
   canonical scheme, host, port, and path authority plus provenance.
2. Exact exclusions override wildcard inclusion; ambiguous wildcard,
   conflicting specificity, unsafe path prefix, stale scope, and unknown
   ownership produce `needs_scope_review`.
3. Discovery never implies admission. Active plans accept only an `admitted`
   asset bound to the current scope snapshot.
4. Admission records DNS, CNAME, resolved IP set, source, first/last seen,
   scope decision, and current identity digest without storing response
   content.
5. A changed DNS/CNAME/IP identity invalidates active eligibility and requires
   re-admission.
6. Branch states are explicit:
   `queued`, `active`, `parked`, `awaiting_r3`, `awaiting_human`,
   `blocked`, `completed`, or `closed`.
7. A WAF-parked or R3-waiting branch does not stop an unrelated eligible R0-R2
   lab branch.
8. Campaign request/time/cost limits and per-asset/per-account/per-hypothesis
   limits all participate in next-branch selection.
9. Equal-priority selection is stable by branch identity, and retry cannot
   duplicate a successful predecessor transition.
10. Policy drift freezes active work and creates one review signal; it does
    not rewrite prior asset or branch history.

### GREEN implementation

1. Add `CampaignAssetRecord` with immutable identity/provenance fields and
   append-only admission decisions.
2. Add `ResearchBranchRecord` with parent signal/hypothesis references,
   priority, status, recipe hints, budget counters, stop/park reason, and
   optimistic version.
3. Reuse `resolve_effective_program_rule` and
   `intersect_scope_guard_rules`; do not duplicate wildcard semantics.
4. Add passive discovery adapters only in this phase. They may consume
   approved rule links, imported artifacts, served-resource references already
   present in authorized artifacts, or approved provider results. They do not
   send active target requests.
5. Change Research Director selection from “any validation handoff stops the
   Campaign” to “select the highest-value eligible branch; leave blocked or
   waiting branches visible.”
6. Emit stable append-only events for discovery, admission, parking, scope
   review, selection, and closure.

### Verify

```powershell
& .\.venv\Scripts\python.exe -m pytest `
  apps/api/tests/test_bounty_autopilot_asset_admission.py `
  apps/api/tests/test_bounty_autopilot_branches.py `
  apps/api/tests/test_program_rule_scope_gate.py `
  apps/api/tests/test_program_rule_release_gate.py `
  apps/api/tests/test_autonomous_research_runtime.py `
  apps/api/tests/test_research_director.py `
  -q
```

### Guards

- No active DNS brute force, port scanning, crawling, browser launch, or HTTP
  replay in this phase.
- Do not represent one Campaign only by `default_asset`.
- Do not use a discovered hostname until its own admission record is current.
- Do not silently drop duplicate or excluded assets; preserve the decision and
  provenance.

### Exit criteria

- Asset admission is deterministic and fail closed.
- Independent branches continue safely around parked and approval-waiting
  work.

## Phase 4: Immutable Plans, Atomic Approval Consumption, and Durable Leases

### Goal

Turn a selected branch into an immutable plan and issue only the capability
that current authority permits. Persist every lease and request reservation so
restart cannot duplicate mutations or approvals.

### Files

- Add `apps/api/migrations/versions/0022_bounty_autopilot_execution_authority.py`.
- Add `apps/api/app/bounty_autopilot/plans.py`.
- Add `apps/api/app/bounty_autopilot/leases.py`.
- Add `apps/api/app/bounty_autopilot/request_ledger.py`.
- Extend `apps/api/app/db_models.py`.
- Extend `apps/api/app/repository.py`.
- Extend `apps/api/app/execution_registry/__init__.py`.
- Adapt reusable validation logic from
  `apps/api/app/black_box_hunter/remote_profile.py`; do not copy its
  process-local registry.
- Extend `apps/api/app/main.py` with focused plan/approval/lease services.
- Add `apps/api/tests/test_bounty_autopilot_plans.py`.
- Add `apps/api/tests/test_bounty_autopilot_leases.py`.
- Add `apps/api/tests/test_bounty_autopilot_request_ledger.py`.
- Extend `apps/api/tests/test_execution_registry.py`.
- Extend `apps/api/tests/test_database_repository.py`.
- Extend `apps/api/tests/test_black_box_remote_profile.py`.

### RED tests

1. A canonical plan binds every field required by the design:
   Campaign authorization, current scope snapshot, asset and resolved
   destination, hypothesis/branch, aliases or canary, risk and recipe version,
   methods, mutation inventory, budgets, rollback/cleanup, stop conditions,
   tool/container profile, and optional R3 approval.
2. Changing any bound field changes the plan digest and invalidates an
   unissued lease.
3. Lease issuance atomically:
   - re-resolves current authority and scope;
   - verifies risk and recipe;
   - reserves all relevant budgets;
   - consumes an R3 approval when required;
   - writes the durable lease.
4. Two concurrent issuers cannot consume the same approval, request budget, or
   mutation slot.
5. R3 approval is short-lived, single-use, non-empty for exact scope and
   account bindings, and invalid after plan/scope/policy/session change.
6. R4 cannot create an approval request or lease.
7. A request reservation binds lease, plan, exact destination, method,
   mutation class, body digest, remaining budgets, and idempotency key.
8. Completion is idempotent. Expiry revokes remaining capability.
9. An idempotent read may retry after a proven no-send failure. An uncertain
   mutation outcome becomes `awaiting_human` and cannot retry automatically.
10. Emergency stop atomically marks the Campaign stopped, revokes all active
    leases, releases only safe unused reservations, and blocks new issuance.
11. Restart reconstructs active/expired state from the database; no in-memory
    dictionary is authoritative.
12. Candidate promotion and report submission remain false in every lease and
    request decision.

### GREEN implementation

1. Add typed `ValidationPlanRecord`, `RiskDecisionRecord`,
   `ExecutionLeaseRecord`, and `ExecutionRequestLedgerRecord`.
2. Extend `ApprovalRecord` with `consumed_at`, `consumed_by_lease_id`, and a
   single-use nonce digest. Migrate existing approvals as non-consumable legacy
   records rather than granting them new authority.
3. Build one repository transaction for lease issuance and one for request
   reservation/completion. Use row locks or compare-and-swap versions supported
   by both PostgreSQL and the test SQLite path.
4. Generalize the safe checks in `RemoteLeaseRuntime` into pure server-side
   validation while keeping the old remote API compatible.
5. Make `ExecutionAuthorizationRequest` reference server-resolved authority,
   plan, and lease identities. Remove boolean-only trust from the new path.
6. Add a Campaign-level emergency-stop service used by API, scheduler, and
   execution gateway.

### Verify

```powershell
& .\.venv\Scripts\python.exe -m pytest `
  apps/api/tests/test_bounty_autopilot_plans.py `
  apps/api/tests/test_bounty_autopilot_leases.py `
  apps/api/tests/test_bounty_autopilot_request_ledger.py `
  apps/api/tests/test_execution_registry.py `
  apps/api/tests/test_database_repository.py `
  apps/api/tests/test_black_box_remote_profile.py `
  apps/api/tests/test_black_box_remote_api.py `
  apps/api/tests/test_migrations.py `
  -q
```

### Guards

- Never issue from a caller-supplied `human_approved`, `lease_active`, or
  `allowed_to_execute` boolean.
- Do not persist raw URLs with secret query strings, request bodies, headers,
  cookies, tokens, credentials, or response content in the request ledger.
- Do not reuse current process-local `_STUDIO_BLACK_BOX_REMOTE_RUNTIMES` as the
  durable store.
- Do not make emergency stop equivalent to the current pause handler; it must
  revoke leases in the same operation.

### Exit criteria

- Concurrency tests prove one approval consumption, one mutation reservation,
  and no budget overrun.
- A process restart cannot resurrect an expired or revoked capability.

## Phase 5: Lab Research Pod and Scope Enforcement Boundary

### Goal

Create the first actual active execution boundary, limited to local authorized
lab targets. Every browser and replay request must pass current scope and
lease checks before transmission and report a sanitized outcome afterward.

### Files

- Add `apps/api/app/bounty_autopilot/gateway.py`.
- Add `apps/api/app/bounty_autopilot/response_guard.py`.
- Add focused gateway authorize/complete/status routes in
  `apps/api/app/main.py`.
- Add `apps/studio/autopilot-pod.cjs`.
- Add `apps/studio/autopilot-network-guard.cjs`.
- Extend `apps/studio/black-box-runner.cjs` only for reusable isolated
  Playwright context lifecycle.
- Extend `apps/studio/main.cjs` and `apps/studio/preload.cjs` with a narrow,
  alias-only IPC surface.
- Add `apps/api/tests/test_bounty_autopilot_gateway.py`.
- Add `apps/api/tests/test_bounty_autopilot_response_guard.py`.
- Add `apps/studio/autopilot-pod.test.cjs`.
- Add `apps/studio/autopilot-network-guard.test.cjs`.
- Extend `apps/studio/desktop-shell.test.cjs`.
- Add local loopback fixture services under
  `apps/api/tests/fixtures/bounty_autopilot_lab/`.

### RED tests

1. The pod starts only for `authorized_local_lab`, current Campaign authority,
   and an active lease.
2. Before each request, navigation, subresource, redirect, and replay, the
   gateway rechecks current scope, canonical scheme/host/port, DNS/CNAME/IP
   identity, method, mutation, recipe, lease, stop state, rate, concurrency,
   request count, response size, and duration.
3. A cross-origin or cross-scope redirect is blocked before following it.
4. DNS rebinding, private/reserved-address drift, an unapproved port, stale
   admission, unknown method, unregistered recipe, or mismatched body digest
   fails closed.
5. Browser service workers are disabled. WebSockets, downloads, pop-ups,
   external protocols, and third-party origins are blocked unless a future
   fixed recipe explicitly supports them.
6. A tool cannot bypass the gateway through direct network access.
7. Request and response byte ceilings abort the operation without persisting
   content.
8. WAF/CAPTCHA, rate-limit, account-lock, off-scope redirect, session expiry,
   and suspected third-party data produce distinct safe outcomes.
9. WAF ends or parks only the current branch lease; genuine rate/account/scope
   stops apply at the appropriate asset/account/Campaign level.
10. Container/pod teardown closes browser contexts, revokes handles, completes
    or expires reservations, and deletes the temporary working directory.
11. No target request is attempted by unit tests; integration tests use only
    loopback fixtures explicitly tagged as local lab.

### GREEN implementation

1. Implement a pure gateway decision service over the durable plan, lease,
   asset, and request-ledger contracts.
2. Build a dedicated Studio utility process for each Campaign pod. The child
   receives IDs, digests, and opaque session handles, not database credentials
   or raw authority payloads.
3. Use Playwright request interception for HTTP method/redirect/recipe checks
   and a separate network guard for destination/DNS/IP egress. Block service
   workers and unsupported protocols.
4. Require all replay clients to use the same gateway authorize/complete
   endpoints; do not allow direct `httpx`, Playwright, or shell networking from
   a recipe.
5. Apply CPU, memory, process, time, output, and temporary-storage ceilings.
   Use a non-root, read-only container profile when Docker/WSL is available;
   fail closed instead of silently falling back to unrestricted host execution
   for active work.
6. Process response bytes in the pod. Persist only the typed safe outcome and
   bounded sanitized projection.

### Verify

```powershell
& .\.venv\Scripts\python.exe -m pytest `
  apps/api/tests/test_bounty_autopilot_gateway.py `
  apps/api/tests/test_bounty_autopilot_response_guard.py `
  apps/api/tests/test_scope_guard.py `
  apps/api/tests/test_program_rule_scope_gate.py `
  -q

Push-Location apps/studio
npm test
Pop-Location

docker compose -f infra/docker-compose.yml config --quiet
```

### Guards

- Do not add a generic arbitrary-URL fetch endpoint.
- Do not accept proxy exceptions from agents or tools.
- Do not implement WAF evasion, source rotation, rate escalation, or
  unrestricted shell.
- Do not allow active execution when Docker/WSL isolation requirements are not
  met; present an actionable blocked state.

### Exit criteria

- The local lab proves zero gateway bypass and zero cross-scope transmissions.
- All active attempts have a durable request-ledger predecessor and outcome.

## Phase 6: Encrypted Local Account Vault and Opaque Session Broker

### Goal

Allow the operator to provide at least two owned accounts without exposing raw
credentials, cookies, tokens, or authorization headers to the API, renderer,
models, database, logs, artifacts, or reports.

### Files

- Add `apps/studio/account-vault.cjs`.
- Add `apps/studio/autopilot-session-broker.cjs`.
- Extend `apps/studio/autopilot-pod.cjs`.
- Extend `apps/studio/main.cjs`.
- Extend `apps/studio/preload.cjs`.
- Add `apps/studio/account-vault.test.cjs`.
- Add `apps/studio/autopilot-session-broker.test.cjs`.
- Extend `apps/studio/black-box-runner.test.cjs`.
- Add safe alias/session projection contracts to
  `apps/api/app/bounty_autopilot/contracts.py`.
- Add `apps/api/tests/test_bounty_autopilot_session_projection.py`.

### RED tests

1. Vault creation fails closed when Electron
   `safeStorage.isEncryptionAvailable()` is false.
2. Secrets are encrypted with `safeStorage.encryptString()` before disk write;
   plaintext never appears in files, API calls, IPC responses, logs, snapshots,
   backups, crash metadata, or test output.
3. `safeStorage.setUsePlainTextEncryption()` is never called.
4. Renderer-visible APIs return account alias, role label, login-state class,
   and opaque handle only.
5. Opaque handles are random, short-lived, Campaign/pod/account bound,
   generation bound, non-serializable where possible, and revoked on close,
   logout, expiry, Campaign pause, emergency stop, or pod crash.
6. The broker injects session material directly into its owned Playwright
   context. The API and recipe receive only the handle.
7. Session refresh invalidates the old generation and all request grants
   derived from it.
8. Account creation automation stops for CAPTCHA, phone, payment, third-party
   identity, or policy ambiguity.
9. Backups exclude vault plaintext and live sessions. Restores cannot revive a
   live handle.
10. Existing `EphemeralSessionBroker` export behavior remains secret-free.

### GREEN implementation

1. Store only encrypted ciphertext and non-sensitive alias metadata under the
   Electron `userData` directory with restrictive local permissions.
2. Use Electron's existing documented `safeStorage` API; do not introduce a
   second key-management dependency.
3. Extend the lifecycle semantics of `EphemeralSessionHandle` and the existing
   Studio black-box runner, but keep secrets entirely in Electron main/pod
   memory.
4. Add a narrow one-way secret-entry IPC operation that acknowledges only an
   alias/version. Never expose a “read secret” operation to the renderer.
5. Send only session-handle projections to FastAPI for plan and lineage
   binding.

### Verify

```powershell
Push-Location apps/studio
npm test
rg -n "setUsePlainTextEncryption|decryptString" `
  account-vault.cjs preload.cjs
Pop-Location

& .\.venv\Scripts\python.exe -m pytest `
  apps/api/tests/test_bounty_autopilot_session_projection.py `
  apps/api/tests/test_black_box_browser_demo_intake.py `
  -q
```

Expected search result: no `setUsePlainTextEncryption`; `decryptString` is
confined to Electron main's vault implementation.

### Guards

- Do not send secrets through the Next.js API client.
- Do not persist browser storage state, HAR headers, or authenticated DOM.
- Do not log secret length, prefix, suffix, checksum, or reversible
  fingerprint.
- Do not auto-register accounts unless the approved rules and fixed recipe
  explicitly permit it.

### Exit criteria

- Secret canaries are absent from every persisted and rendered surface.
- Emergency stop and pod crash revoke every live handle.

## Phase 7: Browser Mapper and First Fixed Authorization Recipes

### Goal

Build sanitized subject/object/action/workflow models and execute only
versioned, lab-proven recipes derived from demonstrated owned-account
workflows.

### Files

- Add `apps/api/app/bounty_autopilot/browser_mapper.py`.
- Add `apps/api/app/bounty_autopilot/authorization_model.py`.
- Add `apps/api/app/bounty_autopilot/workflow_model.py`.
- Extend `apps/api/app/bounty_autopilot/recipes.py`.
- Extend `apps/api/app/research_director/__init__.py`.
- Extend `apps/api/app/research_director/runtime.py`.
- Reuse and extend safe projections in:
  - `apps/api/app/black_box_hunter/studio_trace_intake.py`;
  - `apps/api/app/black_box_hunter/har_intake.py`;
  - `apps/api/app/black_box_hunter/browser_demo_intake.py`.
- Add `apps/studio/autopilot-browser-runner.cjs`.
- Extend `apps/studio/autopilot-pod.cjs`.
- Add `apps/api/tests/test_bounty_autopilot_browser_mapper.py`.
- Add `apps/api/tests/test_bounty_autopilot_authorization_model.py`.
- Add `apps/api/tests/test_bounty_autopilot_workflow_model.py`.
- Add `apps/api/tests/test_bounty_autopilot_recipe_execution.py`.
- Add `apps/studio/autopilot-browser-runner.test.cjs`.

### RED tests

1. Browser mapping records only normalized route templates, methods, form/action
   shape, declared parameters, role/account aliases, object aliases, workflow
   states, and safe structural fingerprints.
2. Raw URLs with secret queries, request/response headers, cookies, tokens,
   credentials, DOM text, screenshots containing unreviewed content, and raw
   bodies are rejected from the control plane.
3. An active recipe can reference only a workflow previously demonstrated by
   the source owned account and an object proven owned by an operator account.
4. The first read-only two-account differential has a strict request ceiling,
   one active request, fixed methods, no mutation, current session generation,
   and stable rollback-not-required contract.
5. The same-account, public-by-design, global-middleware-protected, stale
   session, and cached-response fixtures do not become retained candidates.
6. A true owned-account object-authorization differential produces only a
   sanitized L3 observation, never an automatically confirmed finding.
7. A recipe cannot enumerate identifiers, paginate after a positive result,
   expand to an unknown account, or substitute a non-owned object.
8. BFLA and GraphQL read-only recipes remain disabled until their own fixtures
   and risk decisions are registered.
9. R2 mass-assignment/workflow recipes remain lab-only, declare exact writable
   fields and rollback, and stop on uncertain outcome.
10. The model may rank registered recipes but cannot generate an HTTP request
    or mutation outside their typed templates.

### GREEN implementation

1. Build append-only, digest-bound projections for subjects, roles, objects,
   ownership, operations, routes, and state transitions.
2. Derive request templates only from a demonstrated sanitized workflow and
   registered recipe.
3. Ship recipe families in this order, with a release sub-gate after each:
   - browser mapping;
   - two-owned-account read-only BOLA/IDOR differential;
   - read-only BFLA differential;
   - GraphQL operation/field authorization differential;
   - lab-only mass-assignment filter check;
   - lab-only reversible workflow transition.
4. Feed only structured model references and evidence gaps into Research
   Director. Preserve deterministic risk/gateway authority outside model
   control.

### Verify

```powershell
& .\.venv\Scripts\python.exe -m pytest `
  apps/api/tests/test_bounty_autopilot_browser_mapper.py `
  apps/api/tests/test_bounty_autopilot_authorization_model.py `
  apps/api/tests/test_bounty_autopilot_workflow_model.py `
  apps/api/tests/test_bounty_autopilot_recipe_execution.py `
  apps/api/tests/test_black_box_har_intake.py `
  apps/api/tests/test_black_box_browser_demo_intake.py `
  apps/api/tests/test_black_box_har_golden.py `
  -q

Push-Location apps/studio
npm test
Pop-Location
```

### Guards

- No fuzzing, identifier enumeration, unbounded crawling, or free-form payload
  generation.
- No screenshots or DOM exports enter evidence before a separate content-safe
  review path exists.
- Do not enable the next recipe family merely because its code exists; require
  its focused fixture gate.

### Exit criteria

- At least one true BOLA fixture is retained with sanitized L3 evidence.
- The negative authorization fixtures are refuted.
- Every request is generated from a registered recipe and demonstrated owned
  workflow.

## Phase 8: Sanitized Observations, Refutation, Evidence Judge, and Reports

### Goal

Complete the trustworthy research loop while enforcing branch-local WAF
handling, third-party-data discard, evidence grades, independent refutation,
duplicate review, and submission blocking.

### Files

- Add `apps/api/migrations/versions/0023_bounty_autopilot_evidence_lineage.py`.
- Add `apps/api/app/bounty_autopilot/observations.py`.
- Add `apps/api/app/bounty_autopilot/refutation.py`.
- Add `apps/api/app/bounty_autopilot/evidence_judge.py`.
- Extend `apps/api/app/evidence/__init__.py`.
- Extend `apps/api/app/candidate_hunter_loop.py`.
- Extend `apps/api/app/autonomous_research_runtime.py`.
- Extend `apps/api/app/mythos_report/__init__.py`.
- Extend `apps/api/app/db_models.py` and `apps/api/app/repository.py`.
- Add `apps/api/tests/test_bounty_autopilot_observations.py`.
- Add `apps/api/tests/test_bounty_autopilot_refutation.py`.
- Add `apps/api/tests/test_bounty_autopilot_evidence_judge.py`.
- Add `apps/api/tests/test_bounty_autopilot_data_discard.py`.
- Add `apps/api/tests/test_bounty_autopilot_report.py`.
- Extend `apps/api/tests/test_candidate_report_bridge.py`.
- Extend `apps/api/tests/test_evidence_model.py`.

### RED tests

1. Every observation references authorization, asset, branch, plan, risk
   decision, recipe, lease, request ledger, session generation, and timestamp.
2. Automated sources can create only L0-L3. L4/L5 require an explicit human
   review record.
3. Response processing detects a suspected third-party-data condition in
   memory, aborts the branch, discards content, and persists only:
   Tool Run/request ID, endpoint identity, stop reason, timestamp, and
   `discard_completed=true`.
4. No sample, screenshot, DOM, raw header, body fragment, value, count,
   content hash, or reversible fingerprint from suspected third-party data is
   persisted or included in a report.
5. After that stop, the runtime may create an owned-account/canary fallback
   branch and continue unrelated safe branches. It may not repeat, enumerate,
   paginate, or expand the data-bearing request.
6. WAF metadata permits only the small number of semantically equivalent
   variants declared by the recipe. Repeated block parks the branch without
   ending the Campaign.
7. Rate-limit warning, CAPTCHA, account-lock signal, scope escape, or budget
   exhaustion stops the correct account/asset/branch authority immediately.
8. Refutation checks global/gateway/middleware controls, public-by-design,
   self-only impact, role/tenant/ownership/workflow preconditions, expected
   behavior, stale session/cache, scope, duplicate root cause, reproducibility,
   and evidence gaps.
9. Evidence Judge returns only:
   `refuted`, `insufficient_evidence`, `retained_candidate`,
   `needs_human_review`, or `blocked_by_policy`.
10. Duplicate similarity cannot silently discard a candidate; it produces a
    recorded recommendation and review decision.
11. Every report draft remains submission blocked, shows evidence grade and
    gaps, and contains only sanitized owned-account/canary reproduction.
12. An imported or scanner/model claim cannot become a confirmed finding.

### GREEN implementation

1. Add typed, append-only `SanitizedObservationRecord`,
   `EvidenceClaimRecord`, `RefutationDecisionRecord`, and candidate/report
   revision lineage. Store bounded projections only.
2. Put response guard and discard enforcement in the execution pod before
   control-plane serialization.
3. Reuse Candidate Hunter's existing refutation/evidence/dedup/report flow, but
   accept dynamic observations only through the new typed contracts.
4. Make automated judge prompts consume structured facts, contradictions, and
   evidence references. Exclude secrets, response bodies, and hidden model
   reasoning.
5. Preserve the existing report export hard gate and add an explicit Autopilot
   lineage completeness check.

### Verify

```powershell
& .\.venv\Scripts\python.exe -m pytest `
  apps/api/tests/test_bounty_autopilot_observations.py `
  apps/api/tests/test_bounty_autopilot_refutation.py `
  apps/api/tests/test_bounty_autopilot_evidence_judge.py `
  apps/api/tests/test_bounty_autopilot_data_discard.py `
  apps/api/tests/test_bounty_autopilot_report.py `
  apps/api/tests/test_candidate_hunter_loop.py `
  apps/api/tests/test_candidate_hunter_evidence.py `
  apps/api/tests/test_candidate_report_bridge.py `
  apps/api/tests/test_evidence_model.py `
  -q
```

### Guards

- Do not implement “collect more but do not save” for third-party data.
  Collection itself is prohibited.
- Do not expose raw Tool Run output to models or the report writer.
- Do not let an automated judge set `confirmed`, L4, or L5.
- Do not auto-close a candidate solely from similarity scoring.

### Exit criteria

- Canary searches prove zero secret and third-party-content persistence.
- True and false golden cases reach the correct evidence/refutation states.
- Every generated report is visibly submission blocked.

## Phase 9: Continuous Scheduling, Steering, Approval Inbox, and Studio

### Goal

Expose the durable Autopilot state through the existing Control Center and
Studio without making the UI authoritative. Add bounded steering, exact R3
approval, real budget visibility, and Campaign-wide emergency stop.

### Files

- Add focused Autopilot projection/service contracts under
  `apps/api/app/control_center/`.
- Extend `apps/api/app/main.py` with new APIs; do not pretend these exist
  before this phase:
  - `GET /mythos/campaigns/{id}/autopilot`;
  - `GET /mythos/campaigns/{id}/autopilot/assets`;
  - `GET /mythos/campaigns/{id}/autopilot/branches`;
  - `GET /mythos/campaigns/{id}/autopilot/events`;
  - `GET /mythos/campaigns/{id}/autopilot/budgets`;
  - `GET /mythos/campaigns/{id}/autopilot/approvals`;
  - `POST /mythos/campaigns/{id}/autopilot/steering`;
  - `POST /mythos/campaigns/{id}/autopilot/emergency-stop`;
  - `POST /mythos/campaigns/{id}/autopilot/approvals/{approval_id}/decision`.
- Extend `apps/web/lib/api.ts`.
- Extend `apps/web/lib/control-center-data.ts`.
- Extend `apps/web/lib/control-center-live.ts`.
- Extend `apps/web/lib/studio-live.ts`.
- Add components under `apps/web/components/autopilot/` for:
  - Agent Graph;
  - Asset Map;
  - Live Timeline;
  - Research Queue;
  - Budget Monitor;
  - Approval Inbox;
  - Steering;
  - Emergency Stop.
- Compose them in `apps/web/app/studio/studio-workbench.tsx` and the Campaign
  detail page.
- Extend `apps/studio/main.cjs` and `apps/studio/preload.cjs` only for
  vault/pod actions that cannot safely live in Web.
- Add `apps/api/tests/test_bounty_autopilot_api.py`.
- Extend `apps/api/tests/test_control_center.py`.
- Add `apps/web/lib/autopilot-data.test.ts`.
- Extend `apps/web/lib/control-center-live.test.ts`.
- Extend `apps/web/lib/studio-live.test.ts`.
- Add `apps/web/e2e/bounty-autopilot.spec.ts`.
- Extend `apps/studio/desktop-shell.test.cjs`.

### RED tests

1. The projection exposes safe IDs, aliases, statuses, digests, budgets, and
   lineage only; no secrets or response content.
2. Agent Graph reflects persisted specialist dependencies and handoffs, not a
   hard-coded five-stage decoration.
3. Asset Map distinguishes discovered, admitted, parked, blocked, and
   review-required assets.
4. Live Timeline shows plan, risk, lease, Tool Run, sanitized observation,
   refutation, candidate, and report events in stable order.
5. Budget Monitor shows Campaign, asset, account, branch/hypothesis, recipe,
   request, time, retry, and model-cost remaining values.
6. Approval Inbox renders an exact R3 diff and cannot approve an expired,
   changed, consumed, or R4 plan.
7. Steering can change only branch priority or add bounded hypothesis guidance.
   It cannot widen scope, lower risk, add a recipe, change a request template,
   or alter budgets.
8. Emergency Stop requires explicit operator confirmation, then invokes the
   atomic server service and reflects revoked leases before the UI reports the
   Campaign stopped.
9. SSE invalidation plus polling/LKG fallback remains consistent after
   reconnect and process restart.
10. Headless API clients receive the same authority checks as Studio.
11. Mobile and desktop layouts keep emergency stop and approval state visible.

### GREEN implementation

1. Build one server-side safe projection used by API, Control Center, Studio,
   and CLI.
2. Extend the current SSE invalidation pattern instead of streaming raw event
   payloads or building a second socket system.
3. Reuse `control-center-live.ts` and `studio-live.ts` for atomic refresh and
   last-known-good behavior.
4. Reuse existing Control Center and Studio components where their semantics
   match; add topology and action components only for genuine gaps.
5. Keep all state changes behind server commands that re-resolve current
   authorization.

### Verify

```powershell
& .\.venv\Scripts\python.exe -m pytest `
  apps/api/tests/test_bounty_autopilot_api.py `
  apps/api/tests/test_control_center.py `
  apps/api/tests/test_campaign_api.py `
  -q

Push-Location apps/web
npm test
npm run lint
npm run build
npm run check:bundle
npx playwright test e2e/bounty-autopilot.spec.ts --workers=1
npx playwright test e2e/control-center-live.spec.ts --workers=1
npx playwright test e2e/studio-control-center.spec.ts --workers=1
Pop-Location

Push-Location apps/studio
npm test
Pop-Location
```

### Guards

- Do not call the existing Campaign pause endpoint “Emergency Stop”; it does
  not revoke leases.
- Do not put raw plan payloads, credentials, request content, or response
  content in SSE.
- Do not make the renderer the source of approval or stop truth.
- Do not build dashboard-only mock data for missing backend capabilities.

### Exit criteria

- An operator can see why work is next, what authority it has, what remains,
  and what is blocked.
- R3 approval and emergency stop are exact, durable, and race-safe.

## Phase 10: Lab Golden Suite, Crash Recovery, and Release Gate

### Goal

Prove the complete closed loop on deterministic local targets before any
field-pilot discussion.

### Files

- Expand `apps/api/tests/fixtures/bounty_autopilot_lab/`.
- Add `apps/api/tests/test_bounty_autopilot_lab_e2e.py`.
- Add `apps/api/tests/test_bounty_autopilot_release_gate.py`.
- Extend existing black-box golden fixtures where their labels and safe
  projections already match.
- Add `apps/web/e2e/bounty-autopilot-lab.spec.ts`.
- Add `.github/workflows/bounty-autopilot-lab-gate.yml`.
- Add `docs/BOUNTY_AUTOPILOT_LAB.md`.

### RED tests

Add the following golden cases as failing release tests before completing the
lab harness:

1. True two-owned-account object-authorization failure.
2. Global middleware protection that must be refuted.
3. Public-by-design data that must not become a disclosure candidate.
4. Same-owned-account behavior with no cross-account impact.
5. Mass assignment with and without server-side field filtering.
6. Guarded and unguarded reversible workflow transition.
7. GraphQL field/resolver authorization pair.
8. WAF-blocked branch plus a productive independent branch.
9. Suspected third-party-data response discarded before persistence.
10. DNS, CNAME, IP, port, and redirect scope escapes blocked before send.
11. R3 exact plan blocked before approval, issued once after approval, and
    invalid after plan change.
12. R4 plan impossible to approve.
13. Crash after request reservation but before send.
14. Crash after a possible mutation send with uncertain outcome.
15. Emergency stop racing with lease/request issuance.

Fixture gold labels are loaded only by the evaluator after capture. They are
never injected into the agent, Research Director, Refutation Agent, or
Evidence Judge context.

### End-to-end acceptance

1. Create a Campaign from a local rules URL/fixture, seed target, two owned
   account aliases, budgets, schedule, and approved recipe set.
2. Approve the scope snapshot and initial Campaign authorization.
3. Start continuous mapping and branch scheduling.
4. Establish two vault-backed sessions through opaque handles.
5. Execute at least one automatic lab R1 authorization recipe.
6. Refute a plausible false positive.
7. Retain a true candidate with sanitized L3 evidence.
8. Generate a submission-blocked report.
9. Restart API, scheduler, Studio, and pod at defined checkpoints without
   duplicate approval consumption or mutation.
10. Demonstrate R3 pause while an independent safe branch continues.
11. Trigger emergency stop and prove all leases and handles are revoked.

### GREEN implementation

1. Build one deterministic loopback target that exposes only the behaviors
   needed by the golden matrix. Keep fixture labels in evaluator-owned files.
2. Add a lab harness that starts the target, API, scheduler, Studio pod, and
   browser runner with fixed budgets and isolated temporary state.
3. Add fault injection at plan creation, lease issuance, request reservation,
   pre-send, post-send, response discard, evidence commit, and process restart.
4. Make the release evaluator trace every Tool Run backward through request,
   lease, plan, recipe, risk, scope, and Campaign authorization records.
5. Add the offline CI workflow and operator runbook. The workflow fails closed
   when Docker/WSL isolation or a required release counter is unavailable.

### Release counters

The gate fails unless all counters are exactly zero:

```text
scope_escape_requests
unauthorized_r3_executions
r4_execution_attempts_allowed
retained_third_party_content
raw_secret_leaks
automatic_report_submissions
duplicate_approval_consumptions
duplicate_mutations
gateway_bypass_attempts_allowed
untraced_tool_runs
```

### Verify

```powershell
& .\.venv\Scripts\python.exe -m pytest `
  apps/api/tests/test_bounty_autopilot_lab_e2e.py `
  apps/api/tests/test_bounty_autopilot_release_gate.py `
  -q

& .\.venv\Scripts\python.exe -m pytest apps/api/tests -q

Push-Location apps/web
npm test
npm run lint
npm run build
npm run check:bundle
npm run e2e
Pop-Location

Push-Location apps/studio
npm test
npm run make -- --platform=win32 --arch=x64
Pop-Location

docker compose -f infra/docker-compose.yml config --quiet
git diff --check

rg -n "setUsePlainTextEncryption|allowed_to_execute.*true|report_submission_allowed.*true" `
  apps/api/app apps/studio apps/web
rg -n "authorization|cookie|token|password|credential|set-cookie" `
  apps/api/tests/fixtures/bounty_autopilot_lab/captured-output
```

Any expected safe-schema field name found by the final searches must be
manually distinguished from a leaked value. The captured-output directory
must contain sanitized release projections only.

### Guards

- CI fixtures must never require internet access.
- Do not mark the release green by skipping crash, concurrency, or discard
  cases.
- Do not weaken an assertion to accommodate nondeterministic agent output;
  compare typed outcomes and cited observations.

### Exit criteria

- All phase and repository suites are green with fresh evidence.
- The complete lab loop meets every release counter.
- Windows Studio packaging succeeds and the packaged local runtime passes a
  smoke test.

## Phase 11: Separate Policy Migration and One Bounded Field Pilot

This phase is deliberately not authorized by this implementation plan.

After Phase 10 is green, stop and present:

- the final lab release evidence;
- the exact R1/R2 recipes proposed for a field pilot;
- the current program rules and approved scope snapshot;
- seed/admitted assets;
- owned test-account aliases;
- request, rate, active-hour, response-size, time, and cost ceilings;
- WAF/rate/CAPTCHA/data stop behavior;
- emergency-stop drill evidence;
- zero-incident counters; and
- a proposed amendment to the operational safety policy.

Only after a separate explicit approval may a new plan:

1. amend operational policy for one named authorized program;
2. enable the exact field-pilot recipe set behind a default-off feature gate;
3. conduct operator-monitored R1/R2 work using owned accounts;
4. evaluate candidates for manual confirmation and submission.

The field-pilot plan must not authorize intentional third-party-data
collection, R4, automatic report submission, unrestricted shell/networking,
WAF evasion, source rotation, or scope bypass.

## Final Completion Evidence

The Autopilot lab milestone is complete only when fresh test and audit evidence
shows:

- one authoritative Campaign runtime;
- immutable Campaign authorization and current scope binding;
- deterministic asset admission;
- independent durable research branches;
- fixed versioned recipes with monotonic risk decisions;
- atomic R3 approval consumption;
- restart-safe plan, lease, request, and mutation handling;
- enforced local-lab browser/tool egress;
- vault-backed opaque sessions with zero persisted raw secrets;
- third-party-data discard with zero retained content;
- WAF branch parking without Campaign-wide termination;
- automated evidence capped at L3;
- independent refutation and recorded duplicate decisions;
- submission-blocked reports;
- operator-visible budgets, approvals, steering, lineage, and emergency stop;
- every Tool Run traceable to authorization, scope, plan, risk, recipe, lease,
  request reservation, and sanitized outcome.

No claim about public-target maximum automation is made until the separate
Phase 11 policy and field-pilot gate is approved and completed.
