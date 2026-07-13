# A+B Operator Trial Scorecard

Generated: 2026-07-12T15:24:24Z

Source protocol: `docs/hunter-ab-usability-acceptance.md` §6

Safety: local fixtures only; no live validation; no report submission.

Note: per-case `evaluation_status=failed` often means metric zero-denominator on a single disposition family (e.g. retain-only case has no refute/dedupe denominator). Decision quality and suite-level metrics are authoritative.

## Trial matrix

| Trial | case_id | expected | eval | loop | finals | decisions |
| --- | --- | --- | --- | --- | --- | --- |
| my-local-inject-search-retain-lab | my-local-inject-search-retain-lab | retain | failed | ready | 1 | 2 |

## Decision quality (machine)

| case_id | expected | decision_quality | note |
| --- | --- | --- | --- |
| my-local-inject-search-retain-lab | retain | pass | single-case metric zero_denominator is expected; use suite for thresholds |

## Human scorecard (H1-H6 machine-prefill; H7 human)

| case_id | candidate_id | H1 endpoint | H2 code path | H3 root cause | H4 evidence | H5 refute Q | H6 safe plan | H7 worth 10m | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| my-local-inject-search-retain-lab | H-001 | yes | yes | yes | yes | yes | yes | human | machine-prefill; H7 needs researcher judgment |

## my-local-inject-search-retain-lab (lab / injection)

- expected disposition: `retain`
- evaluation: `failed`
- loop audit: `ready`
- events: `inputs_staged, candidates_captured, loop_projected, gold_loaded`

### Gold roots

- `observed-primary-root` disposition=`retain` root=`missing_injection_validation:preview_local_lab_campaign_query` route=`GET /local/lab/campaigns/query-preview` worth=True

### Candidate decisions

- `H-001` → `retained` root=`missing_injection_validation:preview_local_lab_campaign_query` duplicate_of=`None` evidence=['scope:scope_context', 'policy:policy_context', 'api:api_surface', 'api:GET:/local/lab/campaigns/query-preview', 'har:har_context', 'code:code.ts:preview_local_lab_campaign_query', 'code:code.ts:String', 'code:code.ts:run_sql', 'evidence:6a8bb9c9520023108d90e0830796d25919f339b28c4d775049a805511564da02', 'evidence:1d5a18fa3c1c389dc6dda32ce9ef222ecd727b6f40942a8e67b51ffc6c1ff161', 'evidence:c699017d835a7f5fa6a8b8b6d892a3312fcf41ac27dd6e76511ae92250e16b5f']
- `H-002` → `deduplicated` root=`missing_injection_validation:search_local_lab_campaigns` duplicate_of=`missing_injection_validation:preview_local_lab_campaign_query` evidence=['code:code.ts:run_sql']

### Final retained candidates

#### rank 1 / H-001

- vuln_type: `injection`
- root_cause_id: `missing_injection_validation:preview_local_lab_campaign_query`
- route: `GET /local/lab/campaigns/query-preview`
- affected_code_path: `code:code.ts:preview_local_lab_campaign_query`
- source_fact_refs: `['scope:scope_context', 'policy:policy_context', 'api:api_surface', 'api:GET:/local/lab/campaigns/query-preview', 'har:har_context', 'code:code.ts:preview_local_lab_campaign_query', 'code:code.ts:String', 'code:code.ts:run_sql', 'evidence:6a8bb9c9520023108d90e0830796d25919f339b28c4d775049a805511564da02', 'evidence:1d5a18fa3c1c389dc6dda32ce9ef222ecd727b6f40942a8e67b51ffc6c1ff161', 'evidence:c699017d835a7f5fa6a8b8b6d892a3312fcf41ac27dd6e76511ae92250e16b5f']`
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

- Local review only for GET /local/lab/campaigns/query-preview: confirm whether an ownership or authorization guard runs before the sensitive sink reached via preview_local_lab_campaign_query.
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

