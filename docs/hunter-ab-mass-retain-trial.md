# A+B Operator Trial Scorecard

Generated: 2026-07-12T15:24:22Z

Source protocol: `docs/hunter-ab-usability-acceptance.md` §6

Safety: local fixtures only; no live validation; no report submission.

Note: per-case `evaluation_status=failed` often means metric zero-denominator on a single disposition family (e.g. retain-only case has no refute/dedupe denominator). Decision quality and suite-level metrics are authoritative.

## Trial matrix

| Trial | case_id | expected | eval | loop | finals | decisions |
| --- | --- | --- | --- | --- | --- | --- |
| my-local-mass-user-retain-lab | my-local-mass-user-retain-lab | retain | failed | ready | 1 | 2 |

## Decision quality (machine)

| case_id | expected | decision_quality | note |
| --- | --- | --- | --- |
| my-local-mass-user-retain-lab | retain | pass | single-case metric zero_denominator is expected; use suite for thresholds |

## Human scorecard (H1-H6 machine-prefill; H7 human)

| case_id | candidate_id | H1 endpoint | H2 code path | H3 root cause | H4 evidence | H5 refute Q | H6 safe plan | H7 worth 10m | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| my-local-mass-user-retain-lab | H-001 | yes | yes | yes | yes | yes | yes | human | machine-prefill; H7 needs researcher judgment |

## my-local-mass-user-retain-lab (lab / mass_assignment)

- expected disposition: `retain`
- evaluation: `failed`
- loop audit: `ready`
- events: `inputs_staged, candidates_captured, loop_projected, gold_loaded`

### Gold roots

- `observed-primary-root` disposition=`retain` root=`missing_mass_assignment_guard:update_local_lab_profile` route=`PUT /local/lab/users/profile-update` worth=True

### Candidate decisions

- `H-001` → `retained` root=`missing_mass_assignment_guard:update_local_lab_profile` duplicate_of=`None` evidence=['scope:scope_context', 'policy:policy_context', 'api:api_surface', 'api:PUT:/local/lab/users/profile-update', 'har:har_context', 'code:code.ts:update_local_lab_profile', 'code:code.ts:String', 'code:code.ts:Boolean', 'code:code.ts:current_user', 'code:code.ts:update_user', 'evidence:b4f4e3964c2ec83eccde3496e92875001a9e5dae77c92f2997ae0cc51ce88ab7', 'evidence:7facaf54b2ab88904c1ccb58d562697b0a6ede7e329ddf29e9d18fcf1283ad23', 'evidence:a40c600807dfd4c4d679344f9ab9cf8b5b91345c8f4aa979bae0e538aa761ee5', 'evidence:ad25b56ddcfa7d4622e42a9bef75beacb8e6e2f1d70a9f73e45496521d2d1c6a', 'evidence:8c56db2bc3d98308ec962ac7664e7bc0f0ac09a69c1abb8a2012d23bf6e95888']
- `H-002` → `deduplicated` root=`missing_mass_assignment_guard:update_local_lab_self_user` duplicate_of=`missing_mass_assignment_guard:update_local_lab_profile` evidence=['code:code.ts:update_user']

### Final retained candidates

#### rank 1 / H-001

- vuln_type: `mass_assignment`
- root_cause_id: `missing_mass_assignment_guard:update_local_lab_profile`
- route: `PUT /local/lab/users/profile-update`
- affected_code_path: `code:code.ts:update_local_lab_profile`
- source_fact_refs: `['scope:scope_context', 'policy:policy_context', 'api:api_surface', 'api:PUT:/local/lab/users/profile-update', 'har:har_context', 'code:code.ts:update_local_lab_profile', 'code:code.ts:String', 'code:code.ts:Boolean', 'code:code.ts:current_user', 'code:code.ts:update_user', 'evidence:b4f4e3964c2ec83eccde3496e92875001a9e5dae77c92f2997ae0cc51ce88ab7', 'evidence:7facaf54b2ab88904c1ccb58d562697b0a6ede7e329ddf29e9d18fcf1283ad23', 'evidence:a40c600807dfd4c4d679344f9ab9cf8b5b91345c8f4aa979bae0e538aa761ee5', 'evidence:ad25b56ddcfa7d4622e42a9bef75beacb8e6e2f1d70a9f73e45496521d2d1c6a', 'evidence:8c56db2bc3d98308ec962ac7664e7bc0f0ac09a69c1abb8a2012d23bf6e95888']`
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

- Local review only for PUT /local/lab/users/profile-update: confirm whether an ownership or authorization guard runs before the sensitive sink reached via update_local_lab_profile.
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

