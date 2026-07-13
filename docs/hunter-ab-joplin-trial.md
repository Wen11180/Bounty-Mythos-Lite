# A+B Operator Trial Scorecard

Generated: 2026-07-12T14:28:14Z

Source protocol: `docs/hunter-ab-usability-acceptance.md` §6

Safety: local fixtures only; no live validation; no report submission.

Note: per-case `evaluation_status=failed` often means metric zero-denominator on a single disposition family (e.g. retain-only case has no refute/dedupe denominator). Decision quality and suite-level metrics are authoritative.

## Trial matrix

| Trial | case_id | expected | eval | loop | finals | decisions |
| --- | --- | --- | --- | --- | --- | --- |
| my-gh-joplin-note-authz-lab | my-gh-joplin-note-authz-lab | refute | skipped_no_gold | ready | 0 | 3 |

## Decision quality (machine)

| case_id | expected | decision_quality | note |
| --- | --- | --- | --- |
| my-gh-joplin-note-authz-lab | refute | pass | inspect evaluator notes |

## Human scorecard (H1-H6 machine-prefill; H7 human)

| case_id | candidate_id | H1 endpoint | H2 code path | H3 root cause | H4 evidence | H5 refute Q | H6 safe plan | H7 worth 10m | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| my-gh-joplin-note-authz-lab | (none) | n/a | n/a | n/a | n/a | n/a | n/a | human | correct empty retain set |

## my-gh-joplin-note-authz-lab (lab / authorization)

- expected disposition: `refute`
- evaluation: `skipped_no_gold`
- loop audit: `ready`
- events: `inputs_staged, candidates_captured, loop_projected, gold_optional_skipped`

### Gold roots


### Candidate decisions

- `H-001` → `refuted` root=`missing_object_ownership_check:delete_local_joplin_item` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']
- `H-002` → `refuted` root=`missing_object_ownership_check:get_local_joplin_item` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']
- `H-003` → `refuted` root=`missing_object_ownership_check:get_local_joplin_share` duplicate_of=`None` evidence=['code:code.ts:owner_id_filter']

### Final retained candidates

_none_
### Evaluator notes

- no evaluator failure lists

## Pass rule reminder

- Automated suite remains green.
- For retain trials: H1-H6 should be yes; H7 yes for majority.
- Zero invented code paths; zero auto-validation/submit signals.

