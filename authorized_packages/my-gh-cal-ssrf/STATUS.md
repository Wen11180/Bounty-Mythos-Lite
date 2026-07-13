# my-gh-cal-ssrf status

## Acquisition push result
- Source: public GitHub calcom/cal.com (no H1 API required)
- Version pin: **v6.2.0** + static excerpts (ssrfProtection + sendPayload)
- Faithful webhook SSRF model: validateUrlForSSRF before fetch/send_payload
- Trial: **2/0 decisions / 0 finals / all refuted** (decision_quality pass)
- Evidence: code:code.ts:validateUrlForSSRF
- Residual CAL-SSRF-R1..R5: static held / self-hosted residual documented

## Product read
First **non-authz (SSRF)** GitHub package:
- Exercises outbound HTTP sinks (`fetch` / `send_payload`) and `ssrf_validation_check`
- Hunter root_cause: `missing_ssrf_validation` (not object ownership)
- Complements booking authz package `my-gh-cal`
- Not a bounty auto-submit package

Updated: 2026-07-12T16:05:00Z
