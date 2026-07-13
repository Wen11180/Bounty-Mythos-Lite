# my-gh-freshrss-ssrf status

## Acquisition push result
- Source: public GitHub FreshRSS/FreshRSS (no H1 API required)
- Version pin: **1.29.1** + static excerpts (serverIsPublic + checkUrl + httpGet)
- Faithful SSRF model: validateUrlForSSRF / isPrivateIP before send_payload
- Trial: **2/0 decisions / 0 finals / all refuted** (decision_quality pass)
- Evidence: code:code.ts:validateUrlForSSRF
- Residual FR-SSRF-R1..R5: static held / documented

## Product read
Third **non-authz (SSRF)** GitHub package (diversity beyond cal-ssrf + miniflux-ssrf):
- Exercises outbound HTTP sinks (send_payload / fetch) and ssrf_validation_check
- Hunter root_cause: missing_ssrf_validation
- Complements authz-heavy portfolio without pure authz spam
- Not a bounty auto-submit package

Updated: 2026-07-13T01:30:08Z
