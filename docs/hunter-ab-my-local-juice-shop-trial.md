# A+B Operator Trial Scorecard

Generated: 2026-07-12T08:27:47Z

Source protocol: `docs/hunter-ab-usability-acceptance.md` §6

Safety: local fixtures only; no live validation; no report submission.

Note: per-case `evaluation_status=failed` often means metric zero-denominator on a single disposition family (e.g. retain-only case has no refute/dedupe denominator). Decision quality and suite-level metrics are authoritative.

## Trial matrix

| Trial | case_id | expected | eval | loop | finals | decisions |
| --- | --- | --- | --- | --- | --- | --- |
| my-local-juice-shop-basket-lab | my-local-juice-shop-basket-lab | retain | failed | ready | 1 | 1 |

## Decision quality (machine)

| case_id | expected | decision_quality | note |
| --- | --- | --- | --- |
| my-local-juice-shop-basket-lab | retain | pass | single-case metric zero_denominator is expected; use suite for thresholds |

## Human scorecard (H1-H6 machine-prefill; H7 human)

| case_id | candidate_id | H1 endpoint | H2 code path | H3 root cause | H4 evidence | H5 refute Q | H6 safe plan | H7 worth 10m | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| my-local-juice-shop-basket-lab | H-001 | yes | yes | yes | yes | yes | yes | human | machine-prefill; H7 needs researcher judgment |

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

## Pass rule reminder

- Automated suite remains green.
- For retain trials: H1-H6 should be yes; H7 yes for majority.
- Zero invented code paths; zero auto-validation/submit signals.

