# A+B Operator Trial Scorecard

Generated: 2026-07-12T20:38:57Z

Source protocol: `docs/hunter-ab-usability-acceptance.md` §6

Safety: local fixtures only; no live validation; no report submission.

Note: per-case `evaluation_status=failed` often means metric zero-denominator on a single disposition family (e.g. retain-only case has no refute/dedupe denominator). Decision quality and suite-level metrics are authoritative.

## Trial matrix

| Trial | case_id | expected | eval | loop | finals | decisions |
| --- | --- | --- | --- | --- | --- | --- |
| my-gh-paperless-doc-path-lab | my-gh-paperless-doc-path-lab | refute | skipped_no_gold | ready | 0 | 2 |

## Decision quality (machine)

| case_id | expected | decision_quality | note |
| --- | --- | --- | --- |
| my-gh-paperless-doc-path-lab | refute | pass | inspect evaluator notes |

## Human scorecard (H1-H6 machine-prefill; H7 human)

| case_id | candidate_id | H1 endpoint | H2 code path | H3 root cause | H4 evidence | H5 refute Q | H6 safe plan | H7 worth 10m | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| my-gh-paperless-doc-path-lab | (none) | n/a | n/a | n/a | n/a | n/a | n/a | human | correct empty retain set |

## my-gh-paperless-doc-path-lab (lab / path_traversal)

- expected disposition: `refute`
- evaluation: `skipped_no_gold`
- loop audit: `ready`
- events: `inputs_staged, candidates_captured, loop_projected, residual_checklist_loaded, gold_optional_skipped`

### Gold roots


### Candidate decisions

- `H-001` → `refuted` root=`missing_path_validation:read_local_paperless_source` duplicate_of=`None` evidence=['code:code.ts:sanitize_filename']
- `H-002` → `refuted` root=`missing_path_validation:prepare_local_paperless_filename` duplicate_of=`None` evidence=['code:code.ts:sanitize_filename']

### Final retained candidates

_none_
### Evaluator notes

- no evaluator failure lists

## Pass rule reminder

- Automated suite remains green.
- For retain trials: H1-H6 should be yes; H7 yes for majority.
- Zero invented code paths; zero auto-validation/submit signals.

