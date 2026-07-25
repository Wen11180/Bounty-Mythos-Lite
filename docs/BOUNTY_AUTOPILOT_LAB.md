# Bounty Autopilot Lab Runbook

Local-lab Autopilot only. Public-target R1/R2 automation is not authorized by this release.

## Preconditions

- Policy mode: `authorized_local_lab`
- Loopback / private destinations only
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

## Operator notes

- Pause is not emergency stop: emergency stop revokes active leases.
- R3 approvals are single-use and plan/scope/auth bound.
- R4 cannot plan, lease, or approve.
- Gateway authorization alone is not a send: a signed receipt is required before completion, and completed observations must carry its digest.
- Reports remain submission-blocked.
