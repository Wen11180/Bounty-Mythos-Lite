# A+B Candidate → Report Draft Bridge

Generated: 2026-07-12T15:40:35Z

Safety: submission blocked; no live validation; hunter candidates remain unverified.

- packages: 2
- total drafts: 1
- report_submission_allowed: `False`

## Packages

| package | retained | drafts | submission_blocked | multi_engine |
| --- | --- | --- | --- | --- |
| `my-local-ssrf-webhook-retain-lab` | 1 | 1 | `True` | `local_static_consistent,needs_human_review` |
| `my-gh-cal-webhook-ssrf-lab` | 0 | 0 | `True` | `false_positive_likely` |

## my-local-ssrf-webhook-retain-lab

Multi-engine verdicts (non-executing, not confirmed):

- `H-001`: `local_static_consistent` (agreement=1.0, confirmed=False)
- `H-002`: `needs_human_review` (agreement=0.6667, confirmed=False)

### H-001 — missing_ssrf_validation:deliver_local_lab_webhook

- route: `POST /local/lab/webhooks/deliver`
- status: `unverified_hypothesis`
- multi_engine_verdict: `local_static_consistent`
- confirmed_vulnerability: `False`
- human_review_required: `True`
- submission_blocked: `True`
- title: Possible ssrf issue on POST /local/lab/webhooks/deliver (root=missing_ssrf_validation:deliver_local_lab_webhook). Unverified hunter candidate; local review only.
- next_allowed_action: Human review of the cited local evidence.
- safety_blockers: `execute_live_validation, touch_real_user_data, submit_report`

Validation plan steps:

- Local review only for POST /local/lab/webhooks/deliver: confirm whether an ownership or authorization guard runs before the sensitive sink reached via deliver_local_lab_webhook.
- Do not execute live validation, access production accounts, or submit a report.

Validation workspace (prep only):

- status: `awaiting_approval`
- allowed_to_execute: `False`
- human_approval_required: `True`
- non_destructive_only: `True`
- no_real_user_data: `True`

Refutation questions:

- Does an observed local authorization guard execute before the sensitive sink?
- Does observed local data flow prove the route is public or otherwise non-sensitive?

## my-gh-cal-webhook-ssrf-lab

Multi-engine verdicts (non-executing, not confirmed):

- `H-001`: `false_positive_likely` (agreement=1.0, confirmed=False)
- `H-002`: `false_positive_likely` (agreement=1.0, confirmed=False)

_No retained candidates; no report drafts._

## Pass rule reminder

- Drafts are not confirmed vulnerabilities.
- multi_engine_verdict is local static agreement only; not exploit verification.
- Submission remains blocked.
- Teaching labs must not be treated as bounty submissions.
