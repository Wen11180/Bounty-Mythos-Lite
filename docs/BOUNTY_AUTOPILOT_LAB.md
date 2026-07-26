# Bounty Autopilot Lab Runbook

Local-lab Autopilot only. Public-target R1/R2 automation is not authorized by this release.

## Preconditions

- Policy mode: `authorized_local_lab`
- Strict loopback destinations only; surrounding private networks are blocked
- Owned account aliases only (vault secrets never leave Electron main)
- Docker/WSL isolation preferred for active pods; fail closed if isolation required and unavailable

## Golden path

Execution sequence: `reserve -> gateway authorize -> bounded transport -> signed receipt -> complete -> receipt-bound observation -> release gate`.

1. Create Campaign with `campaign_mode=bounty_autopilot` and typed authorization.
2. Admit seed assets against current scope snapshot.
3. Open research branches; scheduler continues eligible branches while others wait/park.
4. Build immutable validation plans (`POST /mythos/campaigns/{id}/autopilot/plans`).
5. Issue plan-bound leases (`POST .../autopilot/leases`).
6. Reserve a request through the ledger.
7. Authorize each egress via gateway (`POST .../autopilot/gateway/authorize`), which returns a server challenge and execution binding.
8. Run only the gateway-bound, bounded transport; discard response content and retain metadata only.
9. Submit the signed transport receipt (`POST .../autopilot/requests/receipt`), then complete the reservation.
10. Persist only sanitized observations bound to the matching receipt digest, then evaluate the release gate.
11. Refute false positives; retain L3 candidates as submission-blocked report drafts.
12. Emergency stop revokes leases and releases safe reservations before waiting briefly for a Studio local runner/session teardown acknowledgement. Direct API callers receive `confirmed` or `unconfirmed`; an unavailable local acknowledgement never restores server authority.

## Release counters

All must be zero before claiming lab complete:

- scope_escape_requests
- unauthorized_r3_executions
- r4_execution_attempts_allowed
- retained_third_party_content
- raw_secret_leaks
- automatic_report_submissions
- duplicate_approval_consumptions
- duplicate_mutations
- gateway_bypass_attempts_allowed
- untraced_tool_runs

## Evidence tiers

1. Deterministic release fixtures and replay gates prove repeatable candidate/refutation behavior only.
2. `multilang-production-breadth` proves the current lab language-by-pattern matrix beyond held-out cases; it is not a full commercial SAST or live-target claim.
3. Precision, false-positive, duplicate, report-readiness, valid-report, human-minute, accepted-report, and bounty outcomes require a closed authorized pilot with redacted human-confirmed evidence.

CI must pass tiers 1 and 2. Tier 3 remains fail-closed when no authorized evidence package is attached. None of these tiers grants live execution or report-submission authority.

## Verification record (2026-07-26)

- Backend full suite with the local PostgreSQL runtime enabled: `3169 passed, 0 skipped`; the three PostgreSQL concurrency/idempotency tests passed.
- Studio tests: `269 passed`; the Windows x64 package flow completed through Next, PyInstaller, Playwright runtime staging, and Electron Forge.
- Web tests: `281 passed`; typecheck, lint, production build, bundle check, and E2E (`34 passed, 4 viewport-applicability skips`) all exited successfully. Local E2E used `E2E_MOCK_API_PORT=43111` because Docker occupied the default port range.
- Full npm audit: Web `0 vulnerabilities`; Studio `0 vulnerabilities`. Production-only audit is enforced in CI.
- SQLite and PostgreSQL migration head (`0030_bounty_autopilot_observation_replay_guard`), Alembic drift checks, Compose configuration, and the 10-language production-breadth gate passed.
- Precision@top-K, false-positive/duplicate rate, report-readiness rate, human-minute cost, and valid-report rate still require a traceable closed authorized pilot; this lab record does not claim those metrics or 10/10 completion.
- Field-pilot feedback schema `v2` records only a redacted `report_ready` aggregate. Its status endpoint exposes false-positive, duplicate, report-readiness, and valid-report rates only when their required human-confirmed evidence is complete; legacy `v1` rows remain readable but cannot fill missing readiness evidence.

## Operator notes

- Pause is not emergency stop: emergency stop revokes active leases.
- R3 approvals are single-use and plan/scope/auth bound.
- R4 cannot plan, lease, or approve.
- Gateway authorization alone is not a send: a signed receipt is required before completion, and completed observations must carry its digest.
- Reports remain submission-blocked.
