# A+B Operator Trial Scorecard

Generated: 2026-07-12T15:23:36Z

Source protocol: `docs/hunter-ab-usability-acceptance.md` §6

Safety: local fixtures only; no live validation; no report submission.

Note: per-case `evaluation_status=failed` often means metric zero-denominator on a single disposition family (e.g. retain-only case has no refute/dedupe denominator). Decision quality and suite-level metrics are authoritative.

## Trial matrix

| Trial | case_id | expected | eval | loop | finals | decisions |
| --- | --- | --- | --- | --- | --- | --- |
| my-local-ssrf-webhook-retain-lab | my-local-ssrf-webhook-retain-lab | retain | failed | ready | 1 | 2 |

## Decision quality (machine)

| case_id | expected | decision_quality | note |
| --- | --- | --- | --- |
| my-local-ssrf-webhook-retain-lab | retain | pass | single-case metric zero_denominator is expected; use suite for thresholds |

## Human scorecard (H1-H6 machine-prefill; H7 human)

| case_id | candidate_id | H1 endpoint | H2 code path | H3 root cause | H4 evidence | H5 refute Q | H6 safe plan | H7 worth 10m | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| my-local-ssrf-webhook-retain-lab | H-001 | yes | yes | yes | yes | yes | yes | human | machine-prefill; H7 needs researcher judgment |

## my-local-ssrf-webhook-retain-lab (lab / ssrf)

- expected disposition: `retain`
- evaluation: `failed`
- loop audit: `ready`
- events: `inputs_staged, candidates_captured, loop_projected, gold_loaded`

### Gold roots

- `observed-primary-root` disposition=`retain` root=`missing_ssrf_validation:deliver_local_lab_webhook` route=`POST /local/lab/webhooks/deliver` worth=True

### Candidate decisions

- `H-001` → `retained` root=`missing_ssrf_validation:deliver_local_lab_webhook` duplicate_of=`None` evidence=['scope:scope_context', 'policy:policy_context', 'api:api_surface', 'api:POST:/local/lab/webhooks/deliver', 'har:har_context', 'code:code.ts:deliver_local_lab_webhook', 'code:code.ts:String', 'code:code.ts:current_user', 'code:code.ts:send_payload', 'evidence:875db6c55675cae4b047965ab23611067800894df8115bc472a09ff8bc4e1aa3', 'evidence:d29082a475f16e2297a5c9ce3c7517cdb6127d32ad51dd69ac65456e0fe08c57', 'evidence:064a66f2cf3a11fb3a43431f14c54361b166534383df85a918ec8adb77a2eb62', 'evidence:3595b304975e26341bc49d07677ab0fc414c75fd90079d10f47b9522db20303d']
- `H-002` → `deduplicated` root=`missing_ssrf_validation:test_local_lab_webhook` duplicate_of=`missing_ssrf_validation:deliver_local_lab_webhook` evidence=['code:code.ts:send_payload']

### Final retained candidates

#### rank 1 / H-001

- vuln_type: `ssrf`
- root_cause_id: `missing_ssrf_validation:deliver_local_lab_webhook`
- route: `POST /local/lab/webhooks/deliver`
- affected_code_path: `code:code.ts:deliver_local_lab_webhook`
- source_fact_refs: `['scope:scope_context', 'policy:policy_context', 'api:api_surface', 'api:POST:/local/lab/webhooks/deliver', 'har:har_context', 'code:code.ts:deliver_local_lab_webhook', 'code:code.ts:String', 'code:code.ts:current_user', 'code:code.ts:send_payload', 'evidence:875db6c55675cae4b047965ab23611067800894df8115bc472a09ff8bc4e1aa3', 'evidence:d29082a475f16e2297a5c9ce3c7517cdb6127d32ad51dd69ac65456e0fe08c57', 'evidence:064a66f2cf3a11fb3a43431f14c54361b166534383df85a918ec8adb77a2eb62', 'evidence:3595b304975e26341bc49d07677ab0fc414c75fd90079d10f47b9522db20303d']`
- evidence_trace_status: `traceable`
- human_validation_readiness: `ready`
- execution_allowed: `False`
- validation_allowed: `False`
- report_submission_allowed: `False`
- safety_blockers: `['execute_live_validation', 'touch_real_user_data', 'submit_report']`
- next_allowed_action: Human review of the cited local evidence.

refutation_questions:

- Does an observed local authorization guard execute before the sensitive sink?
- Does observed local data flow prove the route is public or otherwise non-sensitive?

safe_validation_plan:

- Local review only for POST /local/lab/webhooks/deliver: confirm whether an ownership or authorization guard runs before the sensitive sink reached via deliver_local_lab_webhook.
- Do not execute live validation, access production accounts, or submit a report.

### Evaluator notes

- schema_failures: `[{'path': 'metrics.effective_refutation_rate', 'reason': 'zero_denominator'}, {'path': 'metrics.duplicate_suppression_rate', 'reason': 'zero_denominator'}]`
- metrics:
  - precision_at_5: passed=True value=1.0 (1/1)
  - valuable_recall_at_5: passed=True value=1.0 (1/1)
  - evidence_traceability_rate: passed=True value=1.0 (2/2)
  - effective_refutation_rate: passed=False value=None (0/0)
  - duplicate_suppression_rate: passed=False value=None (0/0)
  - human_worth_validation_rate: passed=True value=1.0 (1/1)

## Pass rule reminder

- Automated suite remains green.
- For retain trials: H1-H6 should be yes; H7 yes for majority.
- Zero invented code paths; zero auto-validation/submit signals.

