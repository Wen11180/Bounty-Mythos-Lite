# Public Program Rule URL Intake Implementation Plan

**Date:** 2026-07-16

**Design:** `docs/superpowers/specs/2026-07-16-public-program-rule-url-intake-design.md`

**Status:** Ready for implementation; no production code has been changed

> Execution rule: every behavior change starts with a focused failing test.
> Fetched content is untrusted data. It never grants scope, validation, a lease,
> review bypass, or report submission authority.

> Network rule: default and CI tests never contact a real bounty platform. The
> only production fetch path is a Studio-owned, public-HTTPS-only transport with
> DNS pinning, connected-peer enforcement, strict budgets, and human review.

## Goal

Implement the approved V1 flow:

```text
operator-supplied public HTTPS rule URL
-> Studio claims a due fetch
-> pinned static HTTPS fetch
-> bounded normalization and deterministic extraction
-> optional advisory AI extraction
-> evidence-backed pending snapshot
-> human approve or reject
-> effective per-asset rules and approved OpenAPI facts
-> Scope Guard runtime freeze/check
```

The result must automatically refresh while Studio is running, catch up on the
next Studio start when it was closed, and remain fail-closed whenever the first
snapshot, a changed snapshot, or a stale source has not been approved.

## Implementation Decisions Locked by This Plan

1. **The API owns authority; Studio owns public network acquisition.** The API
   owns source state, claims, normalization, extraction, snapshots, diffs,
   review, effective rules, and runtime authorization. Electron main owns both
   the static HTTPS transport and the optional Playwright renderer. The Web
   renderer never receives a fetched body, claim token, or arbitrary fetch URL.
2. **V1 uses a pull claim protocol.** Electron main asks the loopback API for a
   due source, holds a single-use claim token in memory, normalizes each bounded
   document through a claim-bound API endpoint, and posts only normalized data
   for completion. The database stores only the token digest and expiry.
3. **Playwright is placed behind a loopback CONNECT proxy.** Playwright
   `Response.serverAddr()` is response-time telemetry, not connection-time SSRF
   protection. A Studio-owned proxy resolves every CONNECT request, rejects any
   non-public result, pins one validated address, verifies the upstream socket's
   `remoteAddress`, and permits only the claimed origin. Playwright adds a
   second route/method/redirect/WebSocket boundary.
4. **No Celery Beat is added in V1.** The repository has no current Beat or
   API-lifespan scheduler, and the desktop runtime already owns the browser.
   Electron main starts a coalescing due-time pump after the API is ready,
   schedules the next known due time with a one-hour maximum wake interval, and
   is explicitly kicked after registration or manual refresh. An overdue source
   is claimed immediately on the next Studio launch. A server-only deployment
   without Studio reports `studio_required` and does not pretend it refreshed.
5. **The static path stays browser-free.** Node `https.request()` retrieves the
   bytes with a pinned lookup and no redirects. Python standard-library
   `HTMLParser`, `json`, and explicitly pinned `PyYAML` normalize the body in a
   transient, claim-bound request. Chromium starts only when normalized HTML is
   not meaningful without JavaScript.
6. **OpenAPI raw bodies are never persisted.** During transient normalization,
   an explicitly linked JSON/YAML OpenAPI document is reduced with
   `normalize_artifact("openapi", payload)` to safe path/method facts. The
   snapshot stores only its URL metadata, content digest, evidence reference,
   and safe normalized candidate. `ArtifactRecord` is created idempotently only
   after the containing snapshot is approved.
7. **Snapshot approval is not generic validation approval.** Do not reuse
   `ApprovalRecord`; its decision path can synchronize validation execution.
   Snapshot review uses its own strict request and immutable review digest, and
   every snapshot/rule response keeps all five authority fields fixed to false.
8. **`Program.scope_status` is not extended with `frozen`.** A registered source
   creates a coarse Program summary in `needs_review`. An active approved source
   may project it to `in_scope`; pending/stale/rejected source state projects it
   back to `needs_review`. Runtime authorization always consults the source and
   current effective rule directly, so a stale coarse row cannot authorize work.
9. **Existing programs remain compatible.** Programs without a registered rule
   source continue through the current policy/campaign path. Source-backed
   programs gain an additional fail-closed current-rule gate; caller input can
   never widen the approved rule.
10. **AI remains advisory and optional.** Deterministic extraction always runs.
    A configured existing `LLMRegistry` may return exact JSON to a strict schema,
    but it has no tools or network and every evidence excerpt must match the
    normalized corpus. Missing configuration, invalid JSON, or provider failure
    records `ai_status=unavailable` without blocking deterministic results.

## State Invariants

| Event | Fetch status | Review state | Effective scope |
| --- | --- | --- | --- |
| Register source | `scheduled` | none | `needs_review` |
| First distinct snapshot | `ok` | `pending` | `needs_review` |
| Approve first snapshot | `ok` | `approved` | `active` only for approved `in_scope` rules |
| Refresh with same normalized digest | `ok` | no new review | unchanged |
| Refresh with changed digest | `ok` | new `pending` | `frozen` immediately |
| Reject changed snapshot | `ok` | `rejected` remains pending pointer | `frozen` |
| Transient fetch failure under 72 hours | `failed` | last approval retained | active with warning |
| No successful check for 72 hours | any | last approval retained | `frozen` |

The effective state is derived from approved/pending snapshot pointers,
`last_succeeded_at`, and the current time. It is not trusted from a caller or
represented by an overloaded Program enum.

## Phase 0: Verified Documentation and Repository Boundaries

| Need | Verified source | Required use |
| --- | --- | --- |
| Approved behavior | `docs/superpowers/specs/2026-07-16-public-program-rule-url-intake-design.md:1-403` | Preserve every limit, review gate, fixed-false permission, and non-goal. |
| Program model | `apps/api/app/models.py:6-46`; `apps/api/app/db_models.py:20-33` | Keep `frozen` out of `ScopeStatus`; retain Program as a coarse summary. |
| Repository patterns | `apps/api/app/repository.py:82-101,208-330,1469-1559,2077-2241` | Copy typed queries, content dedupe, race rollback, and recursive redaction. Do not reference rule-source methods before adding them. |
| Migration/adoption | `apps/api/app/db.py:14-124`; `apps/api/migrations/versions/0006_p0_autonomous_audit_records.py:13-93`; `apps/api/tests/test_migrations.py:10-125` | Add head `0013_program_rule_intake` after `0012_field_pilot_feedback` and extend unversioned adoption. |
| Strict review schema | `apps/api/app/black_box_hunter/field_pilot.py:56-128,152-206` | Copy `extra="forbid"`, `Literal[True]`, bounded aliases, fixed-false permissions, and digest/idempotency checks. |
| Existing policy and guard | `apps/api/app/policy_ingestion/__init__.py:1-107`; `apps/api/app/scope_guard/__init__.py:1-50`; `apps/api/app/main.py:1433-1497,3170-3247,14076-14115` | Reuse conservative parsing and final validation decisions, but add a current per-asset resolver and freeze gate. |
| OpenAPI/artifacts | `apps/api/app/artifact_ingestion/__init__.py:10-109`; `apps/api/app/repository.py:208-330`; `apps/api/tests/test_artifact_repository.py:16-110,369-509` | Reduce linked OpenAPI to safe facts, then save only after snapshot approval with provenance and dedupe. |
| API style | `apps/api/app/main.py:2432-2461,2561-2579,2799-2840` | Keep domain logic in a package and add thin synchronous/async FastAPI endpoints in `main.py`. |
| Existing worker reality | `apps/api/app/worker/celery_app.py:1-13`; `apps/api/app/worker/tasks.py:23-56`; `infra/docker-compose.yml:1-80` | Do not claim a periodic scheduler exists and do not pass fetched bodies through Celery. |
| Electron boundary | `apps/studio/main.cjs:1-134`; `apps/studio/preload.cjs:1-30`; `apps/studio/navigation-guard.cjs:1-31` | Preserve context isolation, sandboxing, loopback Web origin, narrow IPC, and one application-exit path. |
| Runner lifecycle | `apps/studio/black-box-runner.cjs:116-234,670-722,979-1038`; `apps/studio/black-box-runner.test.cjs:19-234,600-657,1285-1380,1588-1665` | Copy memoized create/close, generation checks, route-before-page ordering, bounded line parsing, and injected fakes. |
| Pinned Playwright surface | `apps/studio/package.json:1-16`; `apps/web/node_modules/playwright-core/types/types.d.ts:9324-9389,9441-9467,10077-10160,20198-20375,20502-20632,23584-23952` | Use Playwright 1.61.1 public context, route, redirect, response, and option types only. |
| Node DNS | [Node.js 24.x DNS](https://nodejs.org/docs/latest-v24.x/api/dns.html) | Use `dns.promises.lookup(host, { all: true, order: "verbatim" })`; validate every returned address. |
| Node HTTPS and peer | [Node.js 24.x HTTPS](https://nodejs.org/docs/latest-v24.x/api/https.html); [Node.js 24.x Net](https://nodejs.org/docs/latest-v24.x/api/net.html) | Use `https.request`, `agent:false`, a pinned `lookup`, `net.connect`, and `socket.remoteAddress`. |
| Browser interception | [Playwright BrowserContext](https://playwright.dev/docs/api/class-browsercontext); [Playwright Response](https://playwright.dev/docs/api/class-response); [Playwright Request](https://playwright.dev/docs/api/class-request) | Block before navigation, disable service workers, reject redirected requests, and treat `serverAddr()` as response-time evidence only. |
| SSRF threat model | [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) | Apply allow-by-invariant URL, DNS, redirect, and connected-peer checks on every document and proxy tunnel. |

### Non-negotiable constraints

1. Only an operator-supplied public HTTPS source is supported; no platform
   enumeration, authenticated page, login state, HAR capture, or test account.
2. Every initial and depth-one URL repeats URL, DNS, public-address, peer,
   redirect, content-type, size, count, and timeout checks.
3. The source origin is exact scheme + hostname + effective port. A wildcard,
   registrable-domain comparison, DNS suffix, or caller-provided allowlist is
   insufficient.
4. Maximum traversal depth is one, document count eight, raw bytes 8 MiB,
   individual document bytes 2 MiB, and individual timeout 10 seconds.
   Normalized visible text is capped at 512 KiB per document and 2 MiB per
   completed corpus; advisory AI receives at most 64 KiB.
5. Raw HTML, complete response bodies, response headers, Cookie,
   Authorization, storage state, browser profiles, downloads, screenshots, and
   concrete credentials are never persisted or returned to the Web renderer.
6. A first, changed, rejected, stale, ambiguous, unsupported-language,
   evidence-less, or missing-rate snapshot cannot authorize validation.
7. No production code or fixture can automatically attack a target or submit a
   report.

## API Contract to Implement

### Operator API

| Method and path | Success | Contract |
| --- | --- | --- |
| `POST /program-rule-sources` | `201` | Register `{ program_alias, public_rule_url }`; create a deterministic coarse Program in `needs_review`; schedule immediate fetch. Duplicate canonical URL is `409`. |
| `GET /program-rule-sources` | `200` | List safe source state, warning, next due time, approved/pending IDs, and derived effective state. |
| `GET /program-rule-sources/{source_id}` | `200` | Return one safe source projection; missing is `404`. |
| `POST /program-rule-sources/{source_id}/refresh` | `202` | Coalesce scheduled/fetching work; enforce a five-minute manual cooldown with `429` and `Retry-After`. |
| `GET /program-rule-sources/{source_id}/snapshots` | `200` | Return metadata, extraction proposals, redacted evidence, review state, and no raw body. |
| `GET /program-rule-sources/{source_id}/snapshots/{snapshot_id}/diff` | `200` | Return canonical added/removed/modified rules, prohibitions, rates, and linked artifacts. |
| `POST /program-rule-sources/{source_id}/snapshots/{snapshot_id}/approve` | `200` | Require `{ reviewer_alias, expected_review_digest, operator_confirmed:true }`; materialize only evidence-backed rules. |
| `POST /program-rule-sources/{source_id}/snapshots/{snapshot_id}/reject` | `200` | Require the same confirmation/digest contract; keep a replacement frozen. |
| `GET /programs/{program_id}/scope-rules` | `200` | List rules belonging to the current approved snapshot and derived source state. |

Every response containing a snapshot or rule includes these exact constants:

```text
execution_allowed=false
lease_grant_allowed=false
scope_change_allowed=false
review_bypass_allowed=false
report_submission_allowed=false
```

### Electron-main-only claim API

| Method and path | Contract |
| --- | --- |
| `POST /mythos/studio/program-rule-fetch/claims/next` | Atomically claim one due source or return `{ claim:null, next_due_at }`. A claim includes a 15-minute in-memory token and server-owned fixed limits. |
| `POST /mythos/studio/program-rule-fetch/claims/{claim_id}/normalize` | Accept one bounded static `body_base64` envelope or browser DOM projection, verify token/source/depth/type/digest, and return one canonical redacted `NormalizedRuleDocument` plus eligible same-origin links. Persist nothing from the raw request. |
| `POST /mythos/studio/program-rule-fetch/claims/{claim_id}/complete` | Revalidate the normalized corpus and budgets, run extraction/diff, create or reuse a content-addressed snapshot, clear the claim, and schedule 24 hours from success. |
| `POST /mythos/studio/program-rule-fetch/claims/{claim_id}/fail` | Accept only a fixed failure-code enum, clear the claim, increment failure count, and schedule the next 24-hour attempt without fabricating a policy change. |

The claim token is generated with `secrets.token_urlsafe`, stored only as a
SHA-256 digest, never logged, never returned by an operator endpoint, and never
crosses the preload bridge. `claim_id` is a separate random safe identifier
stored with the source; it locates the claim but is never sufficient without the
token.

## Phase 1: Pure Contracts, Normalization, and Evidence-Backed Extraction

### Files

- Add `apps/api/app/program_rule_intake/__init__.py`.
- Add `apps/api/app/program_rule_intake/contracts.py`.
- Add `apps/api/app/program_rule_intake/normalizer.py`.
- Add `apps/api/app/program_rule_intake/extractor.py`.
- Add `apps/api/tests/test_program_rule_intake.py`.
- Add `apps/api/tests/fixtures/program_rule_intake/` with synthetic English,
  non-English, HTML table/list, JSON, YAML, OpenAPI, ambiguous wildcard,
  prompt-injection, and secret-marker documents.
- Explicitly add `PyYAML==6.0.3` to `apps/api/requirements.txt`.

### RED tests

1. Reject non-HTTPS URLs, credentials, fragments, invalid ports, empty hosts,
   secret-shaped query keys/values, overlong URLs, control characters, and
   non-canonical hostname forms. Canonicalize host casing, IDNA, default port, and
   empty path without changing query semantics.
2. Compare exact scheme, canonical hostname, and effective port for linked
   documents. Reject protocol-relative, userinfo, cross-origin, `data:`,
   `file:`, `javascript:`, attachment, and depth-two links.
3. Normalize HTML with `HTMLParser`: ignore script/style/form/noscript and
   hidden/`aria-hidden` subtrees; retain bounded visible text, table cells, list
   items, and explicit anchors. Prove the raw HTML sentinel is absent.
4. Normalize plain text, JSON, and `yaml.safe_load` output without constructing
   arbitrary objects. Reject multiple YAML documents, every YAML anchor/alias,
   non-dict OpenAPI roots, unsupported media types, and decoded or normalized
   data over the fixed bounds.
5. Redact secret-shaped keys/values, JWTs, cookies, authorization values,
   emails, and user-data markers before creating a 500-character evidence
   excerpt. Retain a source document digest and stable locator for each excerpt.
6. Deterministically extract exact hosts, wildcard hosts, URL prefixes, API base
   paths, in/out/needs-review status, prohibited classes, automation language,
   structured rate values/units, and explicit OpenAPI links from fixtures.
7. Treat missing evidence, conflicting deterministic signals, ambiguous
   wildcard scope, unsupported language, and absent automation/rate language as
   `needs_review`. An out-of-scope signal wins over an equal-specificity
   in-scope signal.
8. Define a strict advisory-AI result schema and reject prose, code fences,
   extra fields, tools, invented excerpts, unmatched document digests, invalid
   assets, and attempts to widen deterministic out-of-scope rules.
9. Put prompt-injection phrases in headings, tables, and JSON values and prove
   they remain inert evidence text.

### GREEN implementation

1. Define string enums for fetch, review, effective scope, document, link, AI,
   and failure states plus strict Pydantic contracts for source projections,
   normalized documents, evidence excerpts, candidate rules, rate limits,
   linked artifact candidates, diffs, review requests, and fixed-false response
   permissions.
2. Implement pure `canonicalize_public_https_url(value: str) -> str` and
   `is_same_origin(source: str, candidate: str) -> bool`. Syntactic validation
   is duplicated in Studio before network use; DNS authority is never inferred
   in Python from URL syntax.
3. Implement a bounded normalizer that never writes a raw body. Compute both
   raw-content and normalized-content SHA-256 digests; only the normalized
   digest drives human-review changes.
4. For the static envelope, strictly base64-decode to bytes, enforce the
   post-decode byte limit, recompute `raw_sha256`, and accept UTF-8/ASCII only.
   Unsupported HTML charset requests browser fallback; unsupported text/JSON/
   YAML charset fails closed. Browser envelopes contain only bounded visible
   strings/tables/lists/anchors and no encoded page body.
5. Detect English conservatively from normalized text. English may produce
   high-confidence deterministic proposals; every other language preserves
   evidence but forces `needs_review`.
6. Reuse `parse_policy_text(policy_text, asset)` only as one conservative signal
   for each already extracted asset. Do not claim that it parses tables, links,
   multiple assets, or rate limits.
7. Recognize OpenAPI only for an explicitly linked JSON/YAML document containing
   a valid `openapi` or `swagger` marker and a dict `paths`. Immediately reduce
   it to `NormalizedArtifact.openapi_like`; discard the parsed raw payload after
   the request.
8. Define an async `AdvisoryRuleExtractor` Protocol plus a pure strict result
   parser. Tests inject a fake implementation; this phase does not import or
   call a provider. The later service adapter sends at most 64 KiB of normalized
   public text and maps every parse failure to `ai_status=unavailable`.
9. Merge candidates by canonical asset identity and specificity. Evidence is
   mandatory, deterministic out-of-scope cannot be widened, conflicts stay
   review-only, and approval never changes a candidate's extracted status.

### Verification

```powershell
.\.venv\Scripts\python.exe -m pytest `
  apps/api/tests/test_program_rule_intake.py `
  apps/api/tests/test_policy_ingestion.py `
  apps/api/tests/test_artifact_ingestion.py -q
```

### Guards

- No database, HTTP client, browser, worker, or wall-clock import in the pure
  normalizer/extractor core.
- No `yaml.load`, BeautifulSoup/lxml, dynamic code execution, model tool call,
  or persistence of the AI prompt/normalized corpus.
- No evidence excerpt longer than 500 characters.

## Phase 2: Durable Source, Snapshot, and Effective-Rule Persistence

### Files

- Extend `apps/api/app/db_models.py`.
- Extend `apps/api/app/repository.py`.
- Add `apps/api/migrations/versions/0013_program_rule_intake.py` with
  `down_revision = "0012_field_pilot_feedback"`.
- Extend `apps/api/app/db.py` unversioned-schema adoption highest-first.
- Add `apps/api/tests/test_program_rule_repository.py`.
- Extend `apps/api/tests/test_database_repository.py` and
  `apps/api/tests/test_migrations.py`.

### RED tests

1. Upgrade empty SQLite and PostgreSQL-compatible metadata to one Alembic head;
   downgrade removes only the three new tables; supported unversioned 0013
   adoption stamps without replaying DDL.
2. Enforce one source per canonical URL and one V1 source per Program, one
   snapshot per `(source_id, normalized_digest)`, and one rule per
   `(approved_snapshot_id, canonical_asset)`.
3. Store timezone-aware timestamps, JSON lists/dicts, fixed-false booleans, and
   hard snapshot-to-source/rule-to-program foreign keys. A source's approved and
   pending snapshot pointers are nullable validated IDs; avoid a cyclic table-
   creation dependency.
4. Race two claim attempts and prove only one conditional update wins. Expired
   15-minute claims become eligible; a live claim cannot be replaced.
5. Store a claim-token digest but never the raw token. Reject complete/fail for
   a wrong, expired, already-consumed, or cross-source claim.
6. Reuse an existing snapshot for an unchanged normalized digest; preserve a
   rejected snapshot as rejected; never create a second pending review for the
   same content.
7. Recursively inspect every persisted text/JSON field and prove fixture HTML,
   secret values, Cookie/Authorization, query secrets, browser state, and raw
   OpenAPI payloads are absent.

### GREEN implementation

1. Add `ProgramRuleSourceRecord` with: ID, Program FK, safe alias, registered and
   canonical URL, fixed 86,400-second interval, fetch status/timestamps,
   `next_check_at`, failure count/code, last manual refresh, non-secret claim ID,
   claim-token digest/start/expiry, approved and pending snapshot IDs, and
   created/updated timestamps.
2. Add `ProgramRuleSnapshotRecord` with: source FK, raw aggregate and normalized
   digests, fetch time/mode/content types/language, structured extraction,
   bounded evidence, linked-document metadata, safe OpenAPI candidates, AI
   status, review status/actor/time/digest, and five false permission columns.
3. Add `ProgramScopeRuleRecord` with: Program/source/snapshot IDs, canonical
   asset and kind, source evidence reference, extracted scope/automation,
   allowed and prohibited classes, structured rate limit, approval digest, and
   effective timestamp. Historical rows remain immutable and queryable.
4. Add narrow repository methods for source create/list/get, refresh state,
   conditional next-due claim, snapshot find/save/list, review update, scope-rule
   replace/list, and coarse Program projection. Keep state-machine policy in the
   domain service, not in ORM conversion helpers.
5. Use a deterministic ID derived from the canonical URL for the V1 source and
   coarse Program. Create the Program with name=alias, platform=`public_url`,
   `scope_status=needs_review`, `automation=needs_review`, and explicit unknown/
   not-provided values for the remaining legacy summary fields.
6. Copy the existing pre-query + `IntegrityError` rollback/reload pattern for
   content-addressed snapshot races. Use conditional SQL updates for claims so
   both SQLite tests and PostgreSQL deployments fail closed.
7. Derive effective state from pointers and time. Do not add `frozen` to the
   legacy Program enum and do not trust a stored caller-supplied effective flag.

### Verification

```powershell
Push-Location apps/api
..\..\.venv\Scripts\python.exe -m alembic heads
..\..\.venv\Scripts\python.exe -m pytest `
  tests/test_program_rule_repository.py `
  tests/test_database_repository.py `
  tests/test_migrations.py -q
Pop-Location
```

### Guards

- Persistent schema changes use Alembic, never `Base.metadata.create_all()`.
- Do not reuse generic `ApprovalRecord` or mutate historical effective rules.
- Do not put raw content or raw claim tokens in a database column, exception,
  log, fixture snapshot, or API response.

## Phase 3: Intake Coordinator, Claim Protocol, Diff, and Human Review API

### Files

- Add `apps/api/app/program_rule_intake/service.py`.
- Add `apps/api/app/program_rule_intake/advisory.py` as the only rule-intake
  adapter to the existing `LLMRegistry`.
- Extend `apps/api/app/main.py` with only the documented thin endpoints and
  request/response bindings.
- Extend `apps/api/app/config.py`, `apps/api/.env.example`, `.env.example`, and
  `infra/docker-compose.yml` with optional `PROGRAM_RULE_AI_PROVIDER` and
  `PROGRAM_RULE_AI_MODEL`; an empty model disables the advisory call.
- Add `apps/api/tests/test_program_rule_api.py`.
- Extend `apps/api/tests/test_api.py` only where shared API behavior requires it.

### RED tests

1. Registration validates and canonicalizes before creating records, creates a
   `needs_review` Program/source, schedules `next_check_at=now`, and never makes
   an outbound request in the API process.
2. Exact duplicate canonical URL returns `409`; invalid source is `422`; missing
   source/snapshot is `404`; stale review digest or wrong state is `409`.
3. Manual refresh is `202`, coalesces `scheduled`/`fetching`, and returns `429`
   with `Retry-After` inside five minutes. It cannot alter approved scope.
4. Claim-next returns a due claim and server limits or `{claim:null,
   next_due_at}`. It recovers expired work, skips live claims, orders oldest due
   first, and never exposes the token through operator APIs.
5. Normalize requires a valid claim and accepts only the fixed static-body or
   browser-DOM schema. It validates type/depth/count/bytes/same-origin again,
   persists no raw input, and returns only a canonical redacted document.
   Static input carries `body_base64`, declared content type/charset, depth,
   source URL, and `raw_sha256`; the API recomputes every value it can derive.
6. Complete recomputes document and aggregate digests. Same normalized content
   reuses approval; first/new content creates one pending snapshot; changed
   content freezes immediately even if an old approval exists.
7. Fail accepts only enumerated reasons. One transient failure retains a recent
   approval with a warning; 72-hour staleness derives `frozen`; failure never
   fabricates a changed snapshot.
8. Approve/reject require `operator_confirmed=true`, reviewer alias, current
   review digest, and a pending snapshot belonging to the source. Retry with the
   identical decision is idempotent; an opposite decision is `409`.
9. Approval materializes only candidates with valid evidence references.
   `needs_review` candidates stay non-authorizing; missing rate/automation never
   becomes an implicit allow.
10. Every snapshot/rule response serializes the five false permission fields,
    and no review endpoint issues a validation approval, lease, or report action.
11. Fake advisory AI valid JSON merges conservatively; failure, prose, or prompt
    injection cannot block deterministic extraction or widen scope.

### GREEN implementation

1. Implement `ProgramRuleIntakeService` with injected repository, clock, token
   factory, and optional advisory extractor. Keep registration, refresh, claim,
   normalize, complete/fail, diff, and review transitions in this service.
2. Use a 15-minute claim TTL. Hash tokens before persistence, compare with
   `hmac.compare_digest`, clear claim fields on every terminal path, and accept
   only safe failure codes such as DNS rejected, redirect rejected, content
   rejected, budget exceeded, browser unavailable, and fetch failed.
3. Complete a fetch in this order: validate claim -> validate canonical corpus
   -> run deterministic extraction -> optionally run advisory extraction ->
   merge/evidence-check -> compute normalized digest -> create/reuse snapshot ->
   set pointers/freeze -> clear claim -> set last success/next +24h.
4. Compute diffs from canonical structured proposals, not display text. Include
   added/removed/modified assets, automation, prohibitions, rate limits, and
   linked artifact digests beside evidence references.
5. Compute a review digest over source ID, snapshot ID, normalized digest, and
   canonical diff. Approval/rejection writes the reviewer alias/time/digest once.
6. Approval writes immutable rules for that snapshot, moves the source approved
   pointer, clears the pending pointer only when it points to the approved
   snapshot, and projects the coarse Program safely. Rejection leaves a changed
   pending pointer so the effective state remains frozen.
7. Add the exact operator and claim API routes listed above. Use strict Pydantic
   models, `Session = Depends(get_session)`, `response_model`, and narrow
   `HTTPException` translation. The normalize endpoint must remain stateless
   with respect to raw bodies.
8. Keep advisory defaults off unless both provider/model and a matching existing
   key are configured. The adapter uses temperature zero, an untrusted-data
   system boundary, a JSON-only prompt, and no tool surface, then passes text to
   the Phase 1 strict parser. Return only status, prompt hash, and safe error
   category; never store the prompt or provider text.

### Verification

```powershell
.\.venv\Scripts\python.exe -m pytest `
  apps/api/tests/test_program_rule_api.py `
  apps/api/tests/test_program_rule_repository.py `
  apps/api/tests/test_program_rule_intake.py -q
```

### Guards

- No `httpx`, socket, Playwright, Celery task, or startup network side effect in
  the API coordinator.
- No caller-provided refresh interval, document budget, claim TTL, AI tool, or
  execution permission.
- No raw-body echo in validation errors or logs.

## Phase 4: Effective-Rule Resolver, Scope Guard Freeze, and OpenAPI Promotion

### Files

- Add `apps/api/app/program_rule_intake/scope_resolver.py`.
- Narrowly extend `apps/api/app/main.py` at campaign creation, Scope Guard
  evaluation, validation preflight, and `_program_or_404_in_scope` call sites.
- Extend `apps/api/app/scope_guard/__init__.py` only if a source provenance field
  is required; do not add rate-budget authority without a request-budget model.
- Add `apps/api/tests/test_program_rule_scope_gate.py`.
- Extend `apps/api/tests/test_scope_guard.py`,
  `apps/api/tests/test_scope_guard_api.py`, and
  `apps/api/tests/test_artifact_repository.py`.

### RED tests

1. Resolve exact host, wildcard subdomain, URL-prefix, and API-base-path rules.
   Wildcards do not include the apex; path prefixes match segment boundaries;
   the most specific rule wins; equal-specificity conflict fails closed.
2. A source with no approved snapshot, changed pending snapshot, rejected
   replacement, or 72-hour staleness blocks current validation with a stable
   reason even if the legacy Program row still says `in_scope`.
3. A recent transient failure can use the last approved rule, but a rule in
   `needs_review`, out-of-scope, missing automation, prohibited validation, or
   absent asset match cannot authorize work.
4. Campaign creation for a source-backed Program stores the approved snapshot
   and evidence provenance. Caller policy text may narrow but cannot widen the
   current effective rule.
5. Existing campaigns are not silently rewritten. At validation time, intersect
   their stored rule with the current effective rule: allowed validations are
   intersected, forbidden classes unioned, human approval remains required, and
   current out-of-scope/frozen state blocks.
6. Programs without a rule source preserve every existing Scope Guard test and
   behavior.
7. Snapshot approval saves one Artifact per safe OpenAPI candidate only after
   approval. Provenance contains Program/source/snapshot/evidence/digest; payload
   summary and derived facts contain paths/methods only; retry deduplicates.
8. OpenAPI promotion failure cannot widen scope or roll back a valid review.
   Surface a safe artifact warning and allow idempotent retry from the persisted
   safe candidate.

### GREEN implementation

1. Implement `resolve_effective_program_rule(repository, program_id, asset,
   now)` returning a rule plus provenance or a fixed fail-closed reason. Always
   derive current source state before selecting a rule.
2. Add pure canonical asset matching and conservative rule intersection. Never
   convert a review decision into validation approval; continue calling
   `evaluate_validation_request(...)` after the source gate.
3. Wire the gate into every current source-backed path that can reach campaign
   creation, `/scope-guard/evaluate`, validation preflight, and Program in-scope
   enforcement. Preserve existing fallback only when no source record exists.
4. Keep structured rate limits in effective-rule responses and evidence. They
   are advisory constraints in V1 and grant no authority; a future executor-rate
   contract must fail closed before turning them into automated budgets.
5. After snapshot approval, call the existing artifact normalizer/repository on
   only the stored safe OpenAPI candidate. Use `source_type=program_rule_link`,
   the fetched document digest as `source_hash`, and fixed non-authorizing safety
   metadata.

### Verification

```powershell
.\.venv\Scripts\python.exe -m pytest `
  apps/api/tests/test_program_rule_scope_gate.py `
  apps/api/tests/test_scope_guard.py `
  apps/api/tests/test_scope_guard_api.py `
  apps/api/tests/test_artifact_repository.py -q
```

### Guards

- Never make the registered URL, Program summary, campaign payload, or snapshot
  approval sufficient authority by itself.
- Never update an old campaign to a wider rule or activate a `needs_review`
  candidate because the whole snapshot was approved.
- Do not add `frozen` to `ScopeStatus` or reuse validation ApprovalRecord.

## Phase 5: Studio Public-HTTPS Transport and DNS-Pinned CONNECT Proxy

### Files

- Add direct dependency `ipaddr.js@2.4.0` to `apps/studio/package.json` and
  update `apps/studio/package-lock.json` with `npm install --package-lock-only`.
- Add `apps/studio/program-rule-network.cjs`.
- Add `apps/studio/program-rule-network.test.cjs`.

### RED tests

1. Accept only canonical HTTPS URLs with no credentials/fragment/secret-shaped
   query. Recheck exact origin and server-owned limits in Node; never trust the
   API response as a reason to skip safety checks.
2. Use injected DNS results to reject empty answers or any loopback, private,
   link-local, multicast, unspecified, reserved, documentation, benchmark,
   carrier-grade NAT, IPv4-mapped-private, or otherwise non-unicast IPv4/IPv6.
   All answers must be globally routable, not merely the selected one.
3. Static fetch uses one selected validated address through a custom lookup,
   preserves hostname/SNI certificate validation, sets `agent:false`, and fails
   when `socket.remoteAddress` differs after IPv4-mapped normalization.
4. Reject every 3xx without following it; reject missing/unsupported media type,
   body over 2 MiB, aggregate over 8 MiB, more than eight documents, timeout,
   every non-identity `Content-Encoding`, and network error with fixed codes.
5. Prove the request sends no Cookie, Authorization, proxy credential, client
   certificate, referrer, or caller header and never logs response headers/body.
6. CONNECT proxy listens only on `127.0.0.1` with an ephemeral port, accepts
   only `CONNECT` to the exact claimed hostname/effective port, re-resolves and
   pins every tunnel, checks upstream `remoteAddress`, limits header/request/
   tunneled bytes, tracks sockets, and closes them on job shutdown.
7. Reject absolute-form HTTP, cross-origin CONNECT, nested proxying, malformed
   authorities, extra bytes before tunnel establishment, and DNS rebinding
   simulations.
8. Unit and local HTTPS integration tests use injected DNS/public-IP policy for
   loopback fixtures. There is no environment flag capable of weakening the
   production classifier.

### GREEN implementation

1. Use `ipaddr.process(address)` and permit only `range() === "unicast"`, then
   compare normalized addresses. Treat parser errors and unknown ranges as
   blocked. Keep an explicit regression corpus for IANA special ranges.
2. Implement `resolvePinnedPublicAddress(hostname, dependencies)` with
   `dns.promises.lookup(..., {all:true, order:"verbatim"})`, validate every
   answer, and select deterministically without a second uncontrolled lookup.
3. Implement `fetchPublicRuleDocument(request, dependencies)` with
   `https.request`, method GET/HEAD only, `agent:false`, pinned `lookup`, 10s
   abort, `Accept-Encoding: identity`, rejection of any encoded response,
   streaming byte counters, and no redirect recursion. Return bytes as bounded
   base64 plus a SHA-256 digest for the claim-bound normalization request.
4. Implement `createPinnedConnectProxy({allowedOrigin, limits, dependencies})`
   using `net.createServer` and `net.connect` to the selected IP. The proxy is a
   raw tunnel, not a TLS MITM; Chromium still validates the origin certificate.
5. Return only safe metadata and bounded body bytes to Electron main. Error
   objects expose fixed reason codes, never URL query values, resolved address
   lists, headers, or body snippets.

### Verification

```powershell
Push-Location apps/studio
node --test program-rule-network.test.cjs
npm test
Pop-Location
```

### Guards

- No production global proxy setting, OS hosts-file change, VPN assumption,
  `NODE_TLS_REJECT_UNAUTHORIZED=0`, or certificate bypass.
- No ordinary `fetch()`/Axios path for public program URLs.
- No keep-alive connection reuse across documents or jobs.

## Phase 6: Studio Runner, Browser Fallback, Due-Time Pump, and IPC

### Files

- Add `apps/studio/program-rule-api-client.cjs` and test.
- Add `apps/studio/program-rule-renderer.cjs` and test.
- Add `apps/studio/program-rule-runner.cjs` and test.
- Add `apps/studio/program-rule-refresh-pump.cjs` and test.
- Extend `apps/studio/main.cjs`, `apps/studio/preload.cjs`,
  `apps/studio/desktop-shell.test.cjs`, and
  `apps/studio/black-box-runner.test.cjs` only where shared exit behavior is
  asserted.

### RED tests

1. API client accepts only the exact loopback API origin, uses redirect=`error`,
   timeout and response-byte caps, parses strict JSON, and implements only
   claim/normalize/complete/fail. It never accepts a public base URL.
2. Runner claims once, statically fetches root, asks the API to normalize,
   follows only returned same-origin depth-one links, accumulates document/byte
   budgets, and completes or fails exactly once. Concurrent kicks share one
   promise.
3. HTML marked `browser_render_required` launches a browser lazily. JSON/YAML,
   meaningful static HTML, fetch rejection, or no claim never launches one.
4. Each browser render creates a fresh headless browser/context with no
   storageState and options `acceptDownloads:false`, `serviceWorkers:"block"`,
   and the per-job loopback proxy. Route and WebSocket guards are installed
   before `newPage()` and `goto()`.
5. Route guard permits only exact-origin GET/HEAD requests, blocks
   `request.redirectedFrom()`, cross-origin requests, POST/PUT/PATCH/DELETE,
   unsupported resource types, and over-budget request count. WebSockets close
   with policy code; downloads are canceled and fail the render.
6. `page.goto(url, {timeout:10000, waitUntil:"domcontentloaded"})` is used; never
   `networkidle`. Poll `body.innerText()` for a bounded two-second stable-text
   window, then collect bounded body/table/list/anchor values with Locator APIs,
   not `page.evaluate()`.
7. Proxy upstream peer verification is the connection-time authority. If
   `Response.serverAddr()` is available, record only a boolean consistency/
   proxy-observation signal; do not expose the address or treat response-time
   observation as the SSRF boundary.
8. Context and browser close on success, route failure, timeout, API failure,
   concurrent shutdown, incomplete creation, and application exit. Close waits
   for creation and is memoized.
9. Due-time pump starts only after the loopback API is ready, catches overdue
   work immediately, schedules the API-provided `next_due_at` with a maximum
   one-hour wake, and coalesces UI kicks. Closing clears timers and active work.
10. Preload exposes only `refreshProgramRules()` with no URL, claim, script,
    browser option, or body argument. The IPC result is bounded status only.
11. Keep one `before-quit` handler: pass an aggregate close function to the
    existing `createAppExitHandler`; do not register a second preventDefault/
    recursive-exit path.

### GREEN implementation

1. Copy the loopback-origin and bounded-response pattern from
   `remote-api-client.cjs`; do not share its remote-lease operations or tokens.
2. Implement a single-source in-memory runner state with `runPromise`,
   `closePromise`, generation, shutdown flag, active proxy/browser/context, and
   exact terminal completion. Raw claim token and normalized working corpus die
   with the job.
3. Use the Phase 5 static transport first. For each normalized document, follow
   only the API-returned eligible links and re-run the full network checks.
4. Implement the Playwright fallback with the Phase 5 proxy plus supported
   Playwright 1.61.1 APIs: `chromium.launch`, `browser.newContext`,
   `context.route`, `context.routeWebSocket`, `Request.redirectedFrom`, Locator
   text/attribute methods, and deterministic `context.close`/`browser.close`.
5. Add a due-time pump that drains due claims sequentially, then schedules the
   next check. It does not launch Playwright or make a public request until a
   claim is returned.
6. After API and Web readiness, construct the client/runner/pump and call
   `pump.start()`. Register one IPC kick and one preload wrapper. Aggregate
   `programRulePump.close("app_exit")` with the existing black-box session close
   before killing child services and exiting.

### Verification

```powershell
Push-Location apps/studio
node --test `
  program-rule-api-client.test.cjs `
  program-rule-renderer.test.cjs `
  program-rule-runner.test.cjs `
  program-rule-refresh-pump.test.cjs `
  desktop-shell.test.cjs
npm test
Pop-Location
```

### Guards

- No `launchPersistentContext`, storageState input/output, `recordHar`,
  `recordVideo`, screenshot, download path, `page.evaluate`, `addInitScript`,
  user proxy, HTTP credentials, or client certificate.
- No arbitrary URL or browser command in preload/IPC.
- No response-listener-only redirect or peer enforcement.
- No fire-and-forget shutdown and no second application exit handler.

## Phase 7: Typed Web Client and Small Studio Review Surface

### Files

- Extend `apps/web/lib/api.ts` and `apps/web/lib/api.test.ts`.
- Add `apps/web/lib/program-rule-data.ts` and
  `apps/web/lib/program-rule-data.test.ts`.
- Add `apps/web/app/studio/program-rule-intake.tsx`.
- Narrowly extend `apps/web/app/studio/studio-workbench.tsx` to render the new
  component.
- Extend `apps/web/lib/studio-data.test.ts` for the bridge contract.
- Add `apps/web/e2e/program-rule-intake.spec.ts` with mocked loopback API and a
  fake fixed-shape desktop bridge.

### RED tests

1. Define exact TypeScript types for source, snapshot, diff, scope rule, review,
   and fixed-false permissions. Reject/mask unknown authority values in the view
   mapper rather than treating truthy data as permission.
2. Add API methods for all operator endpoints with real mutation errors. No
   fallback object may make a failed register/approve/refresh look successful.
3. Registration form accepts only safe alias and public HTTPS URL; it has no
   credential, cookie, token, account, HAR, proxy, header, or crawl-depth input.
4. After successful registration/manual refresh, Electron mode calls the no-
   argument `window.mythosStudio.refreshProgramRules()`. Browser-only mode shows
   `studio_required`; it never tries to fetch the public URL from Next.js.
5. Render scheduled/fetching/static/browser/failed states plus active,
   pending-review, stale, and frozen effective state. Never collapse fetch,
   review, and effective status into one badge.
6. Snapshot review shows added/removed/modified rules, prohibitions, rate limits,
   linked artifact digests, language/AI status, and 500-character evidence
   excerpts. It never renders raw HTML/body/header/browser state.
7. Approve/reject require a reviewer alias, explicit confirmation checkbox, and
   the current review digest. Disable actions while busy; surface `409`, `429`,
   stale, and Studio-unavailable errors safely.
8. The UI never labels extracted data as verified vulnerability evidence or
   exposes validation, lease, scope-change, review-bypass, or submit actions.

### GREEN implementation

1. Add `apiGet`/`apiPost` wrappers only for the documented operator paths and
   reuse existing error propagation. Keep claim endpoints absent from Web code.
2. Implement a fail-closed view mapper patterned after `studio-data.ts`; map
   unknown/invalid statuses to review-required and all authority to false.
3. Build one compact intake/review component using existing Studio section,
   form, action, status, and mutation-failure patterns. Do not create a new
   dashboard or redesign unrelated Studio surfaces.
4. Refresh list/source/snapshot/diff after each mutation. Kick the desktop pump
   only after the API has accepted a registration or refresh request.
5. Extend the global `MythosStudioDesktopBridge` with only
   `refreshProgramRules(): Promise<SafeRefreshStatus>`.

### Verification

```powershell
Push-Location apps/web
npm test
npm run lint
npm run build
npx playwright test e2e/program-rule-intake.spec.ts
Pop-Location
```

### Guards

- No client-side public fetch, claim endpoint, URL discovery, raw content view,
  or optimistic approval.
- Do not modify unrelated home/campaign/report design or fallback data.
- Do not expose the advisory AI prompt/provider text.

## Phase 8: Deterministic Security Corpus, CI Gate, Runbook, and Full Closure

### Files

- Extend `apps/api/tests/fixtures/program_rule_intake/` with versioned expected
  extraction/diff JSON.
- Add `apps/api/tests/test_program_rule_release_gate.py`.
- Add Studio synthetic HTTPS fixture helpers inside test files; do not add a
  production localhost bypass.
- Add `.github/workflows/program-rule-intake-gate.yml`.
- Add `docs/PROGRAM_RULE_INTAKE.md`.
- Update `README.md` with the public-URL intake entry point and safety boundary.

### RED tests and acceptance gate

1. Run static HTML, table/list, JSON/YAML, explicit depth-one OpenAPI, wildcard,
   exclusion, automation, rate-limit, changed-policy, unsupported-language, and
   prompt-injection fixtures through the full pure/backend path. Run the JS-
   rendered fixture through the Studio runner and the same backend normalizer.
2. Run local HTTPS transport fixtures for dual-stack DNS, private answer among
   public answers, rebinding, peer mismatch, redirects, oversize, timeout,
   third-party links, browser third-party egress, writes, WebSockets, service
   workers, and downloads. All use injected test dependencies and no internet.
3. Prove every accepted field has a valid document digest and evidence excerpt;
   zero fixture becomes effective without `operator_confirmed=true` and matching
   review digest.
4. Prove a changed or 72-hour-stale source blocks current validation across API,
   campaign, and Studio paths while offline modeling remains non-executing.
5. Scan test databases and API/UI payloads for raw HTML markers, fixture secrets,
   Cookie, Authorization, JWT, email/user-data markers, browser storage, and raw
   OpenAPI examples; the count must be zero.
6. CI installs backend dependencies, Studio dependencies, and Web dependencies,
   then runs targeted backend rule tests, Studio tests, Web tests/lint/build, and
   Compose config. Install only Chromium for Web E2E. It makes no request to a
   real bounty platform.
7. Run the entire existing backend, Studio, Web, and Compose gates before
   completion; any pre-existing failure must be separated from new regressions
   with concrete evidence.

### GREEN implementation

1. Make corpus outputs deterministic and reviewable. Gold files contain only
   synthetic domains such as `*.example.test`, synthetic aliases, and redacted
   excerpts; they never contain a real bounty target.
2. A real-Chromium synthetic HTTPS test may wrap only its injected test Browser
   factory with `ignoreHTTPSErrors:true` for the ephemeral fixture certificate.
   Production renderer code, settings, environment, IPC, and context options
   must not expose that bypass; assert this separation in `desktop-shell.test.cjs`.
3. Document registration, Studio-required acquisition, immediate/manual/24-hour
   behavior, next-launch catch-up, first/change/stale approval rules, browser
   fallback constraints, optional AI status, and fixed-false authority.
4. Document that server-only Compose currently cannot acquire rules without a
   Studio worker. It may host/review existing snapshots, but must show
   `studio_required`; future headless deployment needs a separately reviewed
   network worker, not a hidden API startup fetcher.
5. Add a release checklist mapping every approved design acceptance criterion to
   one named automated test and one safe UI/API observation.

### Final verification

```powershell
New-Item -ItemType Directory -Force .\tmp | Out-Null
$env:TEMP = (Resolve-Path .\tmp).Path
$env:TMP = $env:TEMP
$env:TMPDIR = $env:TEMP

.\.venv\Scripts\python.exe -m pytest apps/api/tests -q

Push-Location apps/studio
npm ci
npm test
Pop-Location

Push-Location apps/web
npm ci
npx playwright install chromium
npm test
npm run lint
npm run build
npx playwright test e2e/program-rule-intake.spec.ts
Pop-Location

docker compose -f infra/docker-compose.yml config --quiet
git diff --check
```

Also run a bounded repository check before sign-off:

```powershell
rg -n "launchPersistentContext|recordHar|recordVideo|storageState|page\.evaluate|NODE_TLS_REJECT_UNAUTHORIZED|ignoreHTTPSErrors" `
  apps/studio -g "program-rule-*.cjs" -g "program-rule-*.test.cjs"
rg -n "execution_allowed.*true|lease_grant_allowed.*true|scope_change_allowed.*true|review_bypass_allowed.*true|report_submission_allowed.*true" `
  apps/api/app/program_rule_intake apps/web/app/studio/program-rule-intake.tsx
```

Any match must be an explicit negative assertion or the isolated test-only TLS
fixture wrapper described above, never product code.

## Completion Criteria

Implementation is complete only when all of the following are true:

1. Registering a synthetic public English rule URL creates a scheduled,
   non-authorizing source and a `needs_review` Program.
2. Studio can acquire the fixture through pinned static HTTPS or the bounded
   Playwright fallback without exposing raw content to Web or storage.
3. Explicit same-origin depth-one documents and OpenAPI candidates remain inside
   all document, byte, timeout, method, redirect, DNS, and peer limits.
4. First, changed, rejected, stale, ambiguous, unsupported-language, missing-
   evidence, and missing-rate states fail closed.
5. Human approval materializes only evidence-backed per-asset rules; it does not
   grant validation, a lease, scope change, review bypass, or report submission.
6. Current source state and current effective rules are consulted at runtime, so
   old campaigns and coarse Program rows cannot bypass a freeze.
7. Approved OpenAPI links produce only deduplicated safe path/method artifacts
   with complete source/snapshot/evidence provenance.
8. Due refresh works while Studio runs, overdue work catches up on next launch,
   and server-only mode honestly reports `studio_required`.
9. No persisted or rendered output contains raw HTML, response headers/bodies,
   cookies, authorization values, secrets, browser state, real user data, or raw
   OpenAPI examples.
10. The full existing backend, Studio, Web, E2E, migration, and Compose gates are
    green, and CI never contacts a real bounty target.

## Explicitly Out of Scope

- Platform program enumeration or platform-specific adapters.
- Authenticated/private program pages and browser login persistence.
- Local rule-file import; it can reuse the normalization/review contracts in a
  later design without inheriting public-network permissions.
- PDF/archive/executable attachments.
- HAR discovery, real account credentials, cookies, tokens, or authorization
  headers.
- Automatic target scanning, validation, exploitation, or report submission.
- A headless server acquisition worker or Celery Beat deployment.
- Editing extracted fields inside a snapshot; ambiguous fields remain
  `needs_review` until a later explicitly designed override workflow exists.
