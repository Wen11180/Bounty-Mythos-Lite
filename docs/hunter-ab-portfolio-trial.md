# A+B Operator Trial Scorecard

Generated: 2026-07-12T08:55:56Z

Source protocol: `docs/hunter-ab-usability-acceptance.md` §6

Safety: local fixtures only; no live validation; no report submission.

Note: per-case `evaluation_status=failed` often means metric zero-denominator on a single disposition family (e.g. retain-only case has no refute/dedupe denominator). Decision quality and suite-level metrics are authoritative.

## Trial matrix

| Trial | case_id | expected | eval | loop | finals | decisions |
| --- | --- | --- | --- | --- | --- | --- |
| my-h1-gitlab-own-instance | my-h1-gitlab-own-instance | refute | skipped_no_gold | ready | 0 | 5 |
| my-h1-wordpress-core-rest | my-h1-wordpress-core-rest | refute | skipped_no_gold | ready | 0 | 4 |
| my-h1-nodejs-core-permission | my-h1-nodejs-core-permission | refute | skipped_no_gold | ready | 0 | 5 |
| my-local-dvwa-authz-lab | my-local-dvwa-authz-lab | retain | failed | ready | 1 | 1 |
| my-local-juice-shop-basket-lab | my-local-juice-shop-basket-lab | retain | failed | ready | 1 | 1 |
| my-local-new-api-access-key-lab | my-local-new-api-access-key-lab | refute | skipped_no_gold | ready | 0 | 3 |

## Decision quality (machine)

| case_id | expected | decision_quality | note |
| --- | --- | --- | --- |
| my-h1-gitlab-own-instance | refute | pass | inspect evaluator notes |
| my-h1-wordpress-core-rest | refute | pass | inspect evaluator notes |
| my-h1-nodejs-core-permission | refute | pass | inspect evaluator notes |
| my-local-dvwa-authz-lab | retain | pass | single-case metric zero_denominator is expected; use suite for thresholds |
| my-local-juice-shop-basket-lab | retain | pass | single-case metric zero_denominator is expected; use suite for thresholds |
| my-local-new-api-access-key-lab | refute | pass | inspect evaluator notes |

## Human scorecard (H1-H6 machine-prefill; H7 human)

| case_id | candidate_id | H1 endpoint | H2 code path | H3 root cause | H4 evidence | H5 refute Q | H6 safe plan | H7 worth 10m | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| my-h1-gitlab-own-instance | (none) | n/a | n/a | n/a | n/a | n/a | n/a | human | correct empty retain set |
| my-h1-wordpress-core-rest | (none) | n/a | n/a | n/a | n/a | n/a | n/a | human | correct empty retain set |
| my-h1-nodejs-core-permission | (none) | n/a | n/a | n/a | n/a | n/a | n/a | human | correct empty retain set |
| my-local-dvwa-authz-lab | H-001 | yes | yes | yes | yes | yes | yes | human | machine-prefill; H7 needs researcher judgment |
| my-local-juice-shop-basket-lab | H-001 | yes | yes | yes | yes | yes | yes | human | machine-prefill; H7 needs researcher judgment |
| my-local-new-api-access-key-lab | (none) | n/a | n/a | n/a | n/a | n/a | n/a | human | correct empty retain set |

## my-h1-gitlab-own-instance (lab / authorization)

- expected disposition: `refute`
- evaluation: `skipped_no_gold`
- loop audit: `ready`
- events: `inputs_staged, candidates_captured, loop_projected, gold_optional_skipped`

### Gold roots


### Candidate decisions

- `H-001` → `refuted` root=`missing_object_ownership_check:get_local_project` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']
- `H-002` → `refuted` root=`missing_object_ownership_check:download_local_project_export` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']
- `H-003` → `refuted` root=`missing_object_ownership_check:download_local_repository_archive` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']
- `H-004` → `refuted` root=`missing_object_ownership_check:start_local_project_export` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']
- `H-005` → `refuted` root=`missing_object_ownership_check:start_local_project_export_relations` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']

### Final retained candidates

_none_
### Evaluator notes

- no evaluator failure lists

## my-h1-wordpress-core-rest (lab / authorization)

- expected disposition: `refute`
- evaluation: `skipped_no_gold`
- loop audit: `ready`
- events: `inputs_staged, candidates_captured, loop_projected, gold_optional_skipped`

### Gold roots


### Candidate decisions

- `H-001` → `refuted` root=`missing_object_ownership_check:delete_local_wp_post` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']
- `H-002` → `refuted` root=`missing_object_ownership_check:get_local_wp_post` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']
- `H-003` → `refuted` root=`missing_object_ownership_check:export_local_wp_post` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']
- `H-004` → `refuted` root=`missing_object_ownership_check:update_local_wp_post` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']

### Final retained candidates

_none_
### Evaluator notes

- no evaluator failure lists

## my-h1-nodejs-core-permission (lab / authorization)

- expected disposition: `refute`
- evaluation: `skipped_no_gold`
- loop audit: `ready`
- events: `inputs_staged, candidates_captured, loop_projected, gold_optional_skipped`

### Gold roots


### Candidate decisions

- `H-001` → `refuted` root=`missing_object_ownership_check:delete_local_node_resource` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']
- `H-002` → `refuted` root=`missing_object_ownership_check:export_local_node_resource` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']
- `H-003` → `refuted` root=`missing_object_ownership_check:read_local_node_resource` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']
- `H-004` → `refuted` root=`missing_object_ownership_check:symlink_local_node_resource` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']
- `H-005` → `refuted` root=`missing_object_ownership_check:write_local_node_resource` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']

### Final retained candidates

_none_
### Evaluator notes

- no evaluator failure lists

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

## my-local-juice-shop-basket-lab (lab / authorization)

- expected disposition: `retain`
- evaluation: `failed`
- loop audit: `ready`
- events: `inputs_staged, candidates_captured, loop_projected, gold_loaded`

### Gold roots

- `observed-primary-root` disposition=`retain` root=`missing_object_ownership_check:export_local_juice_basket` route=`GET /local/juice/rest/basket/{basket_id}` worth=True

### Candidate decisions

- `H-001` → `retained` root=`missing_object_ownership_check:export_local_juice_basket` duplicate_of=`None` evidence=['scope:scope_context', 'policy:policy_context', 'api:api_surface', 'api:GET:/local/juice/rest/basket/{basket_id}', 'har:har_context', 'code:code.ts:export_local_juice_basket', 'code:code.ts:find_basket', 'code:code.ts:export_file', 'evidence:5600d3e754e4615872885c0ab49a5048197c459fa7a76f46a69ba1063a23d5fe', 'evidence:ac03c5e8f1ad53b75e413f9e122db47ee7e2ad6fcdeb6fd8ad6bcaf309dbd7f4', 'evidence:42867290bf9bbab5328ab0dee16a48d39906d81ca782cea4f3de5b74c0ab960e']

### Final retained candidates

#### rank 1 / H-001

- vuln_type: `authorization`
- root_cause_id: `missing_object_ownership_check:export_local_juice_basket`
- route: `GET /local/juice/rest/basket/:basket_id`
- affected_code_path: `code:code.ts:export_local_juice_basket`
- source_fact_refs: `['scope:scope_context', 'policy:policy_context', 'api:api_surface', 'api:GET:/local/juice/rest/basket/{basket_id}', 'har:har_context', 'code:code.ts:export_local_juice_basket', 'code:code.ts:find_basket', 'code:code.ts:export_file', 'evidence:5600d3e754e4615872885c0ab49a5048197c459fa7a76f46a69ba1063a23d5fe', 'evidence:ac03c5e8f1ad53b75e413f9e122db47ee7e2ad6fcdeb6fd8ad6bcaf309dbd7f4', 'evidence:42867290bf9bbab5328ab0dee16a48d39906d81ca782cea4f3de5b74c0ab960e']`
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

- Local review only for GET /local/juice/rest/basket/:basket_id: confirm whether an ownership or authorization guard runs before the sensitive sink reached via export_local_juice_basket.
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

## my-local-new-api-access-key-lab (lab / authorization)

- expected disposition: `refute`
- evaluation: `skipped_no_gold`
- loop audit: `ready`
- events: `inputs_staged, candidates_captured, loop_projected, gold_optional_skipped`

### Gold roots


### Candidate decisions

- `H-001` → `refuted` root=`missing_object_ownership_check:delete_local_newapi_access_key` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']
- `H-002` → `refuted` root=`missing_object_ownership_check:get_local_newapi_access_key` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']
- `H-003` → `refuted` root=`missing_object_ownership_check:update_local_newapi_access_key` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']

### Final retained candidates

_none_
### Evaluator notes

- no evaluator failure lists

## Pass rule reminder

- Automated suite remains green.
- For retain trials: H1-H6 should be yes; H7 yes for majority.
- Zero invented code paths; zero auto-validation/submit signals.

