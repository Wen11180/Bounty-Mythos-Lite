# Hunter A+B — Cal.com webhook SSRF GitHub package

## Package
- Path: `authorized_packages/my-gh-cal-ssrf`
- package_id: `my-gh-cal-webhook-ssrf-lab`
- Upstream: calcom/cal.com
- Version pin: **v6.2.0**
- Risk family: **ssrf** (first non-authz family package)
- Expected disposition: **refute**

## Model
Webhook deliver/test via `validateUrlForSSRF` before `fetch`/`send_payload`:
1. blocked hostnames / cloud metadata
2. private IP residual (SaaS)
3. self-hosted private HTTP residual (documented, not treated as product bug)
4. optional webhook owner residual on deliver path

## Hunter engine delta
- `codebase_map`: outbound sinks `fetch`/`send_payload`/`_send_payload`
- SSRF guards recognized as protective checks (`validateUrlForSSRF`, `isPrivateIP`, …)
- Gap root: `missing_ssrf_validation` when outbound sink lacks guard
- Loop prefers `ssrf_validation_check` control evidence for SSRF roots

## Trial
- `docs/hunter-ab-cal-ssrf-trial.json` / `.md`
- **2 decisions / 0 finals / all refuted** / decision_quality **pass**
- Evidence refs: `code:code.ts:validateUrlForSSRF`

## Residuals
See `authorized_packages/my-gh-cal-ssrf/_extract/RESIDUAL_CHECKLIST.md` (CAL-SSRF-R1..R5).

## Notes
- Live residual only on researcher-owned self-hosted Cal.com.
- Do not run real third-party SSRF pivots.
- Security contact: security@cal.com
