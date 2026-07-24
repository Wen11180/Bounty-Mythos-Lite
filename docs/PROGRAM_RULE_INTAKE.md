# Public Program Rule Intake

## Purpose and boundary

Public Program Rule Intake lets an operator register one public HTTPS bounty-policy page in Mythos Studio. The feature extracts reviewable scope facts, prohibitions, automation rules, rate limits, and explicitly linked OpenAPI candidates. It does not enumerate bounty platforms, authenticate to private pages, scan extracted assets, execute validation, grant a lease, change scope, bypass review, or submit a report.

Only these registration fields are accepted:

- a synthetic operator-facing program alias;
- one canonical public HTTPS rule URL without credentials, fragments, or secret-shaped query parameters.

Local rule-file import, HAR discovery, authenticated program pages, cookies, tokens, credentials, PDF/archive attachments, and a headless server acquisition worker are intentionally outside this version.

## Lifecycle

1. Registration creates a scheduled source and a coarse `needs_review` Program. Every authority flag is false.
2. Studio explicitly kicks the local refresh pump after registration or manual refresh. The API never fetches a public URL during startup or an operator request.
3. Studio first performs a certificate-validating, DNS-pinned static HTTPS GET. It rejects any private or special address in the complete DNS answer set, redirects, peer mismatch, unsupported media, excess bytes, excess documents, or timeout.
4. HTML may return the fixed `browser_render_required` signal. Only then does Studio create a fresh isolated Chromium context behind the pinned loopback proxy. The renderer allows exact-origin bounded GET/HEAD resources only; it blocks writes, redirects, third-party egress, WebSockets, downloads, service workers, persistence, HAR/video capture, storage state, and page evaluation.
5. At most the root and explicit same-origin depth-one documents enter normalization. An OpenAPI candidate must be an explicitly linked JSON/YAML document and is reduced to safe path/method facts.
6. The backend normalizes and redacts the bounded corpus, runs deterministic extraction, optionally applies advisory AI, creates a content-addressed pending snapshot, and destroys the claim capability and working corpus.
7. A successful source is scheduled for another check in 24 hours. While Studio is open the due-time pump drains sequentially; overdue work catches up on the next Studio launch. Manual refreshes are coalesced and cooldown-limited.

The Web application never fetches the registered policy URL. It calls only operator APIs and a no-argument desktop refresh bridge.

## Review and effective scope

Fetch state, snapshot review state, and current effective state are independent:

- The first snapshot is `pending`; no rule is effective before explicit review.
- A changed snapshot freezes current validation until the new digest is reviewed.
- A rejected, ambiguous, unsupported-language, missing-evidence, missing-rate, or more-than-72-hour-stale source fails closed.
- Approval requires a safe reviewer alias, `operator_confirmed=true`, and the exact current review digest. A stale or opposite decision is a conflict.
- Approval materializes only evidence-backed per-asset rules. It never sets execution, validation, lease, scope-change, review-bypass, or report-submission authority.
- Runtime campaign creation, campaign approval, validation preflight, and existing campaign checks intersect their stored view with the current source and current effective rule. Old coarse Program rows cannot bypass a freeze.

Optional AI extraction is advisory. Disabled configuration records `not_requested`; provider/config/output failures record a safe unavailable/rejected state. AI cannot block deterministic extraction, widen an out-of-scope rule, create evidence, or grant authority.

## Operator runbook

1. Start Mythos Studio so its local API, Web UI, and bounded network worker are available.
2. Open `/studio` and find **Program rules**.
3. Enter a program alias and a public HTTPS policy URL, then select **Register source**.
4. Review the distinct fetch/effective/review states. If acquisition is due, Studio performs it locally; browser-only mode shows `studio_required` and does not fetch.
5. Inspect the snapshot diff, scope status, prohibitions, rate limits, language/AI state, linked digests, and redacted evidence excerpts.
6. Enter a reviewer alias, confirm the displayed current digest, then approve or reject. Approval remains non-executing and submission-blocked.
7. Use **Manual refresh** only when an operator wants a new check; cooldown and single-flight rules still apply.

Server-only Docker Compose can host the API and review already persisted snapshots, but it cannot acquire a public rule page. It must report `studio_required`. A future headless deployment requires a separately reviewed network-worker design; do not add an API-startup fetcher or TLS bypass.

## Data handling

Persisted and Web-visible contracts enumerate safe fields. They exclude raw HTML, response headers/bodies, Cookie and Authorization values, secrets, browser storage, real user data, raw OpenAPI examples, claim tokens, and browser/proxy internals. Evidence excerpts are redacted and capped at 500 characters. Linked documents and artifacts are represented by safe metadata and digests.

The versioned release corpus under `apps/api/tests/fixtures/program_rule_intake/` uses only `*.example.test` domains and synthetic aliases. The E2E suite intercepts the synthetic policy host and asserts the browser makes zero requests to it.

## Verification

From the repository root on Windows:

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
npx playwright test e2e/program-rule-intake.spec.ts --workers=1
Pop-Location

docker compose -f infra/docker-compose.yml config --quiet
git diff --check
```

The dedicated CI workflow is `.github/workflows/program-rule-intake-gate.yml`. It installs backend, Studio, and Web dependencies; installs Chromium only; runs the targeted backend/Studio/Web/E2E gates; validates Compose; and scans production code for forbidden authority or browser-persistence capabilities.

## Release checklist

| Acceptance criterion | Named automated evidence | Safe observation |
| --- | --- | --- |
| Registration is scheduled and non-authorizing | `test_service_registration_refresh_and_claim_protocol_are_fail_closed`; `program-rule operator helpers use only documented non-claim endpoints` | Studio shows scheduled/fetch state separately from `needs_review` effective state. |
| Static and browser acquisition remain bounded | `static HTTPS fetch pins lookup, strips caller headers, and returns bounded bytes`; `only an HTML browser_render_required signal creates a fresh renderer`; `route guard permits only exact-origin bounded GET and HEAD requests` | No browser acquisition control or target request is exposed in Web. |
| Depth-one/OpenAPI corpus stays bounded | `test_explicit_links_resolve_only_one_hop_on_the_exact_origin`; `test_explicitly_linked_openapi_is_reduced_to_safe_path_method_candidates` | UI shows only linked digests and reduced OpenAPI promotion-false metadata. |
| First/change/reject/stale/ambiguous states fail closed | `test_resolver_fails_closed_for_unapproved_changed_rejected_and_stale_sources`; `test_conflicts_ambiguous_wildcards_and_missing_controls_force_review` | Review/effective/fetch statuses remain visibly distinct. |
| Approval requires current digest and grants no authority | `test_claim_api_normalizes_completes_reviews_and_never_grants_authority`; `test_versioned_policy_change_matches_reviewed_diff_gold` | Approve/reject require alias plus explicit current-digest confirmation. |
| Current rules gate campaign and validation runtime | `test_existing_campaign_runtime_intersects_current_rule_and_freezes_without_rewrite`; `test_validation_runtime_and_preflight_recheck_current_source` | No validation execution or lease action exists in the intake surface. |
| OpenAPI promotion retains provenance | `test_service_diff_review_materializes_only_evidence_backed_rules_and_artifacts`; `test_versioned_release_extraction_matches_reviewed_gold` | Artifact display contains safe digests, evidence count, and promotion false before review. |
| Due refresh and server-only honesty work | `start immediately catches overdue work and drains claimed jobs sequentially`; `browser-only registration fails closed with studio_required and never fetches the policy URL` | Browser-only UI shows `studio_required`; Studio uses a no-argument refresh kick. |
| Raw/secrets/browser state never persist or render | `test_fetch_envelopes_forbid_headers_secrets_and_raw_browser_bodies`; `renderer source uses Locator APIs and excludes persistence and capture features`; `test_release_gold_contains_only_synthetic_review_safe_values` | Evidence is redacted/capped; raw response and browser controls are absent. |
| Full release gates remain green without real targets | `program-rule-intake-gate` workflow; `Studio registers, refreshes, and reviews one public rule source without browser acquisition` | CI corpus uses only reserved synthetic domains and local mocks. |
