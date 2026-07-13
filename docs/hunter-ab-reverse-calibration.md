# A+B Reverse Calibration Matrix (non-authz families)

Updated: 2026-07-12T15:24:51Z

Purpose: prove the candidate hunter can **retain** unguarded teaching models and **refute** guarded OSS models for the same four non-authz families. Complements authz retain (DVWA/Juice) + authz refute (GitHub portfolio).

Safety: local static packages only; no live attack; report submission blocked; no secrets.

## Pair matrix

| Family | Retain (teaching) | Trial | Refute (OSS seed) | Trial | Root cause family |
| --- | --- | --- | --- | --- | --- |
| SSRF | my-local-ssrf-retain | 1 retained / 1 deduped; P/R=1.0 | my-gh-cal-ssrf | 2/0 refuted | missing_ssrf_validation |
| Path traversal | my-local-path-retain | 1 retained / 1 deduped; P/R=1.0 | my-gh-listmonk-path | 2/0 refuted | missing_path_validation |
| Mass assignment | my-local-mass-retain | 1 retained / 1 deduped; P/R=1.0 | my-gh-mealie-mass | 2/0 refuted | missing_mass_assignment_guard |
| Injection | my-local-inject-retain | 1 retained / 1 deduped; P/R=1.0 | my-gh-listmonk-inject | 2/0 refuted | missing_injection_validation |

## Decision quality notes

- Retain trials often show evaluation_status=failed solely from zero-denominator metrics (effective_refutation_rate, duplicate_suppression_rate) when gold only expects retain. Authoritative signals: precision_at_5, valuable_recall_at_5, evidence_traceability_rate, human_worth_validation_rate, empty missed_retained_roots / false_positives / safety_failures.
- All four retain packages: safety flags **false** for execution/validation/submission; blockers present.
- Authz reverse calibration already green via my-local-dvwa / my-local-juice-shop retain vs GitHub authz refute portfolio.

## Trial artifacts

- docs/hunter-ab-ssrf-retain-trial.{json,md}
- docs/hunter-ab-path-retain-trial.{json,md}
- docs/hunter-ab-mass-retain-trial.{json,md}
- docs/hunter-ab-inject-retain-trial.{json,md}
- Prior refute: docs/hunter-ab-cal-ssrf-trial.*, hunter-ab-listmonk-path-trial.*, hunter-ab-mealie-mass-trial.* (name may vary), hunter-ab-listmonk-inject-trial.*

## Product read

Reverse calibration for A+B multi-family hunter is **closed** for the four seeded non-authz families plus existing authz retain labs.

Still out of scope for this matrix: multi-engine verifier, live H1 re-acquisition (401), automatic validation/submission.
