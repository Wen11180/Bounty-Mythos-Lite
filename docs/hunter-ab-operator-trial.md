# A+B Operator Trial Scorecard

Generated: 2026-07-12T06:43:48Z

Source protocol: `docs/hunter-ab-usability-acceptance.md` §6

Safety: local fixtures only; no live validation; no report submission.

Note: per-case `evaluation_status=failed` often means metric zero-denominator on a single disposition family (e.g. retain-only case has no refute/dedupe denominator). Decision quality and suite-level metrics are authoritative.

## Trial matrix

| Trial | case_id | expected | eval | loop | finals | decisions |
| --- | --- | --- | --- | --- | --- | --- |
| T1 retain | dev-001 | retain | failed | ready | 1 | 1 |
| T2 refute | dev-002 | refute | failed | ready | 0 | 1 |
| T3 dedupe | dev-003 | deduplicate | failed | ready | 1 | 2 |
| T4 held-out retain | rel-001 | retain | failed | ready | 1 | 1 |
| T4 held-out refute | rel-002 | refute | failed | ready | 0 | 1 |

## Decision quality (machine)

| case_id | expected | decision_quality | note |
| --- | --- | --- | --- |
| dev-001 | retain | pass | single-case metric zero_denominator is expected; use suite for thresholds |
| dev-002 | refute | pass | single-case metric zero_denominator is expected; use suite for thresholds |
| dev-003 | deduplicate | pass | single-case metric zero_denominator is expected; use suite for thresholds |
| rel-001 | retain | pass | single-case metric zero_denominator is expected; use suite for thresholds |
| rel-002 | refute | pass | single-case metric zero_denominator is expected; use suite for thresholds |

## Human scorecard (H1-H6 machine-prefill; H7 human)

| case_id | candidate_id | H1 endpoint | H2 code path | H3 root cause | H4 evidence | H5 refute Q | H6 safe plan | H7 worth 10m | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| dev-001 | H-001 | yes | yes | yes | yes | yes | yes | **yes** | Unguarded `send_file(record_id)`; classic object-id gap worth local review |
| dev-002 | (none) | n/a | n/a | n/a | n/a | n/a | n/a | n/a | Correct empty retain; ownership guard present in code |
| dev-003 | H-001 | yes | yes | yes | yes | yes | yes | **yes** | Canonical of shared `load_record` root; dual-route noise correctly collapsed |
| rel-001 | H-001 | yes | yes | yes | yes | yes | yes | **yes** | Unguarded transfer path; high-impact authz family, worth more than 10m |
| rel-002 | (none) | n/a | n/a | n/a | n/a | n/a | n/a | n/a | Correct empty retain; `verify_transfer_access` owner check observed |

## dev-001 (development / authorization)

- expected disposition: `retain`
- evaluation: `failed`
- loop audit: `ready`
- events: `inputs_staged, candidates_captured, loop_projected, gold_loaded`

### Gold roots

- `observed-primary-root` disposition=`retain` root=`missing_object_ownership_check:read_record` route=`GET /local/records/q7m4/{record_id}` worth=True

### Candidate decisions

- `H-001` → `retained` root=`missing_object_ownership_check:read_record` duplicate_of=`None` evidence=['scope:scope_context', 'policy:policy_context', 'api:api_surface', 'api:GET:/local/records/q7m4/{record_id}', 'har:har_context', 'code:code.ts:read_record', 'code:code.ts:send_file', 'evidence:7831d3a4755eb4e859542be36a27540e1270b554b38ea2b4d8012cfff2ca7304', 'evidence:10c9d555ded1e88fb10aba1c70d5bb1ef25571c55618899c7841711190f4d113']

### Final retained candidates

#### rank 1 / H-001

- vuln_type: `authorization`
- root_cause_id: `missing_object_ownership_check:read_record`
- route: `GET /local/records/q7m4/:record_id`
- affected_code_path: `code:code.ts:read_record`
- source_fact_refs: `['scope:scope_context', 'policy:policy_context', 'api:api_surface', 'api:GET:/local/records/q7m4/{record_id}', 'har:har_context', 'code:code.ts:read_record', 'code:code.ts:send_file', 'evidence:7831d3a4755eb4e859542be36a27540e1270b554b38ea2b4d8012cfff2ca7304', 'evidence:10c9d555ded1e88fb10aba1c70d5bb1ef25571c55618899c7841711190f4d113']`
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

- Local review only for GET /local/records/q7m4/:record_id: confirm whether an ownership or authorization guard runs before the sensitive sink reached via read_record.
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

## dev-002 (development / authorization)

- expected disposition: `refute`
- evaluation: `failed`
- loop audit: `ready`
- events: `inputs_staged, candidates_captured, loop_projected, gold_loaded`

### Gold roots

- `observed-primary-root` disposition=`refute` root=`missing_object_ownership_check:read_record` route=`GET /local/records/x2k9/{record_id}` worth=False

### Candidate decisions

- `H-001` → `refuted` root=`missing_object_ownership_check:read_record` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']

### Final retained candidates

_none_
### Evaluator notes

- schema_failures: `[{'path': 'metrics.precision_at_5', 'reason': 'zero_denominator'}, {'path': 'metrics.valuable_recall_at_5', 'reason': 'zero_denominator'}, {'path': 'metrics.evidence_traceability_rate', 'reason': 'zero_denominator'}, {'path': 'metrics.duplicate_suppression_rate', 'reason': 'zero_denominator'}, {'path': 'metrics.human_worth_validation_rate', 'reason': 'zero_denominator'}]`
- metrics:
  - precision_at_5: passed=False value=None (0/0)
  - valuable_recall_at_5: passed=False value=None (0/0)
  - evidence_traceability_rate: passed=False value=None (0/0)
  - effective_refutation_rate: passed=True value=1.0 (1/1)
  - duplicate_suppression_rate: passed=False value=None (0/0)
  - human_worth_validation_rate: passed=False value=None (0/0)

## dev-003 (development / authorization)

- expected disposition: `deduplicate`
- evaluation: `failed`
- loop audit: `ready`
- events: `inputs_staged, candidates_captured, loop_projected, gold_loaded`

### Gold roots

- `observed-primary-root` disposition=`retain` root=`missing_object_ownership_check:read_record` route=`GET /local/records/n8v3/{record_id}` worth=True
- `observed-summary-root` disposition=`deduplicate` root=`missing_object_ownership_check:read_record_summary` route=`GET /local/records/n8v3/{record_id}/summary` worth=False

### Candidate decisions

- `H-001` → `retained` root=`missing_object_ownership_check:read_record` duplicate_of=`None` evidence=['scope:scope_context', 'policy:policy_context', 'api:api_surface', 'api:GET:/local/records/n8v3/{record_id}', 'har:har_context', 'code:code.ts:read_record', 'code:code.ts:load_record', 'code:code.ts:send_file', 'evidence:0cdc5c9f125508ff107338df3f8df78259ac615c9f4473220219c720c6a93d6d', 'evidence:efeea531ea697ba53a006b20ec27f7b6f346726fc6873b63114d839398c27d6a', 'evidence:7e5607a608712852df7559855eb4d2c04c813a14880c9780021cab496b91a2ba']
- `H-002` → `deduplicated` root=`missing_object_ownership_check:read_record_summary` duplicate_of=`missing_object_ownership_check:read_record` evidence=['code:code.ts:load_record']

### Final retained candidates

#### rank 1 / H-001

- vuln_type: `authorization`
- root_cause_id: `missing_object_ownership_check:read_record`
- route: `GET /local/records/n8v3/:record_id`
- affected_code_path: `code:code.ts:read_record`
- source_fact_refs: `['scope:scope_context', 'policy:policy_context', 'api:api_surface', 'api:GET:/local/records/n8v3/{record_id}', 'har:har_context', 'code:code.ts:read_record', 'code:code.ts:load_record', 'code:code.ts:send_file', 'evidence:0cdc5c9f125508ff107338df3f8df78259ac615c9f4473220219c720c6a93d6d', 'evidence:efeea531ea697ba53a006b20ec27f7b6f346726fc6873b63114d839398c27d6a', 'evidence:7e5607a608712852df7559855eb4d2c04c813a14880c9780021cab496b91a2ba']`
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

- Local review only for GET /local/records/n8v3/:record_id: confirm whether an ownership or authorization guard runs before the sensitive sink reached via read_record.
- Do not execute live validation, access production accounts, or submit a report.

### Evaluator notes

- schema_failures: `[{'path': 'metrics.effective_refutation_rate', 'reason': 'zero_denominator'}]`
- metrics:
  - precision_at_5: passed=True value=1.0 (1/1)
  - valuable_recall_at_5: passed=True value=1.0 (1/1)
  - evidence_traceability_rate: passed=True value=1.0 (3/3)
  - effective_refutation_rate: passed=False value=None (0/0)
  - duplicate_suppression_rate: passed=True value=1.0 (1/1)
  - human_worth_validation_rate: passed=True value=1.0 (1/1)

## rel-001 (release / authentication)

- expected disposition: `retain`
- evaluation: `failed`
- loop audit: `ready`
- events: `inputs_staged, candidates_captured, loop_projected, gold_loaded`

### Gold roots

- `observed-primary-root` disposition=`retain` root=`missing_object_ownership_check:transfer_funds` route=`GET /local/transfers/p4x8/{record_id}` worth=True

### Candidate decisions

- `H-001` → `retained` root=`missing_object_ownership_check:transfer_funds` duplicate_of=`None` evidence=['scope:scope_context', 'policy:policy_context', 'api:api_surface', 'api:GET:/local/transfers/p4x8/{record_id}', 'har:har_context', 'code:code.ts:transfer_funds', 'code:code.ts:transfer', 'evidence:1985e08e304774b07dfec15c6b4a76e2312c5bf8bf91ba8da15d01f580e0fadd', 'evidence:29c45108ba5e5b060b4c127a22f933f83b03695e00af141a0caa0b15ce9d3cf0']

### Final retained candidates

#### rank 1 / H-001

- vuln_type: `authorization`
- root_cause_id: `missing_object_ownership_check:transfer_funds`
- route: `GET /local/transfers/p4x8/:record_id`
- affected_code_path: `code:code.ts:transfer_funds`
- source_fact_refs: `['scope:scope_context', 'policy:policy_context', 'api:api_surface', 'api:GET:/local/transfers/p4x8/{record_id}', 'har:har_context', 'code:code.ts:transfer_funds', 'code:code.ts:transfer', 'evidence:1985e08e304774b07dfec15c6b4a76e2312c5bf8bf91ba8da15d01f580e0fadd', 'evidence:29c45108ba5e5b060b4c127a22f933f83b03695e00af141a0caa0b15ce9d3cf0']`
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

- Local review only for GET /local/transfers/p4x8/:record_id: confirm whether an ownership or authorization guard runs before the sensitive sink reached via transfer_funds.
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

## rel-002 (release / authentication)

- expected disposition: `refute`
- evaluation: `failed`
- loop audit: `ready`
- events: `inputs_staged, candidates_captured, loop_projected, gold_loaded`

### Gold roots

- `observed-primary-root` disposition=`refute` root=`missing_object_ownership_check:transfer_funds` route=`GET /local/transfers/h9d2/{record_id}` worth=False

### Candidate decisions

- `H-001` → `refuted` root=`missing_object_ownership_check:transfer_funds` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']

### Final retained candidates

_none_
### Evaluator notes

- schema_failures: `[{'path': 'metrics.precision_at_5', 'reason': 'zero_denominator'}, {'path': 'metrics.valuable_recall_at_5', 'reason': 'zero_denominator'}, {'path': 'metrics.evidence_traceability_rate', 'reason': 'zero_denominator'}, {'path': 'metrics.duplicate_suppression_rate', 'reason': 'zero_denominator'}, {'path': 'metrics.human_worth_validation_rate', 'reason': 'zero_denominator'}]`
- metrics:
  - precision_at_5: passed=False value=None (0/0)
  - valuable_recall_at_5: passed=False value=None (0/0)
  - evidence_traceability_rate: passed=False value=None (0/0)
  - effective_refutation_rate: passed=True value=1.0 (1/1)
  - duplicate_suppression_rate: passed=False value=None (0/0)
  - human_worth_validation_rate: passed=False value=None (0/0)


## L4 sign-off (fixture operator trial)

Date: 2026-07-12

Reviewer role: local researcher review of authorized synthetic fixtures + hunter cards
(not a claim of production Bug Bounty discovery readiness).

### Method

1. Machine trial via `apps/api/scripts/run_ab_operator_trial.py` (T1-T4).
2. Decision quality: all five cases **pass**.
3. H1-H6: machine-prefill **yes** on all retained cards.
4. H7: human review of retained cards against fixture `inputs/code.ts` and gold roots.

### H7 rationale (retained only)

| case | Why H7 = yes |
| --- | --- |
| dev-001 | Handler calls sensitive sink with path parameter and no ownership/authz check. A researcher would open the file and plan a two-account local check. |
| dev-003 | Same root across two routes; hunter retained one and deduplicated the other. Noise control works; remaining card is still a real unguarded object access path. |
| rel-001 | Transfer endpoint without ownership guard is high impact even as a hypothesis. Held-out family still produced a clear, actionable card. |

### Safety checks on retained cards

- `execution_allowed` / `validation_allowed` / `report_submission_allowed` all **false**
- required `safety_blockers` present
- next action remains human local evidence review

### Verdict

| Gate | Result |
| --- | --- |
| L0 safety on trial cards | **Pass** |
| L1 decision quality T1-T4 | **Pass** |
| L3 card fields (endpoint/code/refute/plan) | **Pass** for fixture trial |
| L4 H7 majority on retained | **Pass** (3/3 yes) |
| A+B **fixture-trial ready** | **Yes** |
| A+B **real authorized-package ready** | **Not yet** (needs non-fixture local lab package) |
| Final research factory ready | **No** (verifier/multi-engine/patch still out of scope) |

### Explicit residual risks

1. Fixtures are small synthetic TS/Express packages; H7-yes here does not prove large multi-service repos.
2. Impact narrative (G8) is still thin: cards are actionable but not ?report-ready prose.?
3. Refutation questions are useful defaults, not case-specific deep questions.
4. Per-case evaluator `failed` for zero-denominator metrics is expected; suite metrics remain the automated gate.

### Next after this sign-off

1. Keep hunter gate green (regression only unless a real package fails).
2. Run one **user-supplied authorized local lab package** (scope+policy+api/har+code) and repeat H1-H7.
3. Only if that fails: fix proven gaps (prefer G8 impact text or mapping misses).
4. Do not expand dashboard, suite counts, or auto-validation for A+B.

## Pass rule reminder

- Automated suite remains green.
- For retain trials: H1-H6 should be yes; H7 yes for majority.
- Zero invented code paths; zero auto-validation/submit signals.

## Delegated H7 completion (2026-07-12)

Operator authorized agent ("?????") to complete H7 for synthetic/educational L4.

- Record: `docs/hunter-ab-h7-signoff-record.md`
- Page: `docs/hunter-ab-h7-signoff-page.md`
- Verdict: **L4 synthetic/educational usable = Yes**
- Submission: still **blocked**
- Live residual product trust: still **open**
