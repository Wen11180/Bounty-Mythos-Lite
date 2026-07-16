# Black-box HAR Golden Sprint (implemented slice)

Date: 2026-07-15

## Goal

Dual-role HAR golden packages -> local-lab observe -> Top-N candidates with
falsify attempts -> retain/refute quality gate. No remote, no A+B merge, no submit.

## Delivered

| Item | Path |
| --- | --- |
| Retain golden | `apps/api/tests/fixtures/black_box_har_golden/retain_bola_widgets/` |
| Refute golden | `apps/api/tests/fixtures/black_box_har_golden/refute_guarded_widgets/` |
| Runner + gate | `apps/api/app/intelligence_benchmark/black_box_har_golden.py` |
| Falsify projection | `apps/api/app/black_box_hunter/local_lab_pipeline.py` (`falsify_attempts`) |
| CLI | `python -m app black-box-golden` |
| Tests | `tests/test_black_box_har_golden.py`, `test_black_box_falsify_audit.py`, `test_black_box_dual_intake_iso.py` |

## Verify

```powershell
cd apps/api
python -m pytest tests/test_black_box_har_golden.py tests/test_black_box_falsify_audit.py tests/test_black_box_dual_intake_iso.py -q
python -m app black-box-golden --all --out-dir ../../tmp/bb-golden
```

## Gate rules

- `retain_bola_widgets` + lab `bola` -> `cross_account_object_swap` retained in Top-N
- `refute_guarded_widgets` + lab `guarded` -> same class suppressed (not retained)
- Every matching candidate must include `falsify_attempts`
- Output must not re-emit raw secrets; execution/report submit always false

## Non-goals (unchanged)

Remote observe, Playwright product runtime, A+B Candidate Hunter merge, auto report submission.
