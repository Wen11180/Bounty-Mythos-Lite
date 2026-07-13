# my-gh-miniflux-ssrf status

## Acquisition push result
- Source: public GitHub miniflux/v2 (no H1 API required)
- Version pin: **v2.3.2** + static excerpts (IsNonPublicIP + BlockPrivateNetworks dial guard)
- Faithful feed SSRF model: private-network block before outbound fetch
- Trial: **2/0 decisions / 0 finals / all refuted** (decision_quality pass)
- Evidence: code:code.ts:validateUrlForSSRF
- Residual MF-SSRF-R1..R5: static held / allow-private residual documented

## Product read
Second **non-authz (SSRF)** GitHub package (diversity beyond Cal.com webhooks):
- Exercises outbound HTTP sinks (`fetch` / `send_payload`) and `ssrf_validation_check`
- Hunter root_cause: `missing_ssrf_validation` (not object ownership)
- Complements cal webhook SSRF package `my-gh-cal-ssrf`
- Not a bounty auto-submit package

Updated: 2026-07-12T20:31:36Z
