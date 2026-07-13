# A+B Operator Trial Scorecard

Generated: 2026-07-12T08:22:47Z

Source protocol: `docs/hunter-ab-usability-acceptance.md` §6

Safety: local fixtures only; no live validation; no report submission.

Note: per-case `evaluation_status=failed` often means metric zero-denominator on a single disposition family (e.g. retain-only case has no refute/dedupe denominator). Decision quality and suite-level metrics are authoritative.

## Trial matrix

| Trial | case_id | expected | eval | loop | finals | decisions |
| --- | --- | --- | --- | --- | --- | --- |
| my-local-dvwa-authz-lab | my-local-dvwa-authz-lab | retain | failed | ready | 1 | 1 |

## Decision quality (machine)

| case_id | expected | decision_quality | note |
| --- | --- | --- | --- |
| my-local-dvwa-authz-lab | retain | pass | single-case metric zero_denominator is expected; use suite for thresholds |

## Human scorecard (H1-H6 machine-prefill; H7 human)

| case_id | candidate_id | H1 endpoint | H2 code path | H3 root cause | H4 evidence | H5 refute Q | H6 safe plan | H7 worth 10m | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| my-local-dvwa-authz-lab | H-001 | yes | yes | yes | yes | yes | yes | human | machine-prefill; H7 needs researcher judgment |

## my-local-dvwa-authz-lab (lab / authorization)

- expected disposition: `retain`
- evaluation: `failed`
- loop audit: `ready`
- events: `inputs_staged, candidates_captured, loop_projected, gold_loaded`

### Gold roots

- `observed-primary-root` disposition=`retain` root=`missing_object_ownership_check:export_local_dvwa_user` route=`GET /local/dvwa/users/{user_id}/export` worth=True

### Candidate decisions

- `H-001` → `retained` root=`missing_object_ownership_check:export_local_dvwa_user` duplicate_of=`None` evidence=['scope:scope_context', 'policy:policy_context', 'api:api_surface', 'api:GET:/local/dvwa/users/{user_id}/export', 'har:har_context', 'code:code.ts:export_local_dvwa_user', 'code:code.ts:find_user', 'code:code.ts:export_file', 'evidence:798ec8609968f84c05e675f57f3c4c071ec578f0dbe4c93968f6c2718e892200', 'evidence:b3f13d828734a30bb4920581809751e7781332802a1cff9bf1df5edb21f1f237', 'evidence:291d5f2a14050d343f74bc110b7beef1b52bf6dc67e2e5db9fa1ad14111300b7']

### Final retained candidates

#### rank 1 / H-001

- vuln_type: `authorization`
- root_cause_id: `missing_object_ownership_check:export_local_dvwa_user`
- route: `GET /local/dvwa/users/:user_id/export`
- affected_code_path: `code:code.ts:export_local_dvwa_user`
- source_fact_refs: `['scope:scope_context', 'policy:policy_context', 'api:api_surface', 'api:GET:/local/dvwa/users/{user_id}/export', 'har:har_context', 'code:code.ts:export_local_dvwa_user', 'code:code.ts:find_user', 'code:code.ts:export_file', 'evidence:798ec8609968f84c05e675f57f3c4c071ec578f0dbe4c93968f6c2718e892200', 'evidence:b3f13d828734a30bb4920581809751e7781332802a1cff9bf1df5edb21f1f237', 'evidence:291d5f2a14050d343f74bc110b7beef1b52bf6dc67e2e5db9fa1ad14111300b7']`
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

- Local review only for GET /local/dvwa/users/:user_id/export: confirm whether an ownership or authorization guard runs before the sensitive sink reached via export_local_dvwa_user.
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

