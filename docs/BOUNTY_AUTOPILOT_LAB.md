# Bounty Autopilot Lab Runbook

Local-lab Autopilot only. Public-target R1/R2 automation is not authorized by this release.

## Preconditions

- Policy mode: `authorized_local_lab`
- Loopback / private destinations only
- Owned account aliases only (vault secrets never leave Electron main)
- Docker/WSL isolation is required for active pods; startup fails closed when unavailable

## Golden path

1. Create Campaign with `campaign_mode=bounty_autopilot` and typed authorization.
2. Admit seed assets against current scope snapshot.
3. Open research branches; scheduler continues eligible branches while others wait/park.
4. Build immutable validation plans (`POST /mythos/campaigns/{id}/autopilot/plans`).
5. Issue plan-bound leases (`POST .../autopilot/leases`).
6. Reserve/complete requests through the ledger.
7. Authorize each egress via gateway (`POST .../autopilot/gateway/authorize`).
8. Persist only sanitized observations.
9. Refute false positives; retain L3 candidates as submission-blocked report drafts.
10. Emergency stop revokes leases, releases safe reservations, and revokes session handles.

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
- Reports remain submission-blocked.
