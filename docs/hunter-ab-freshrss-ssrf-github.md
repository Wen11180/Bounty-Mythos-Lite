# FreshRSS feed SSRF package (ssrf family)

Updated: 2026-07-13T01:30:08Z

Package: authorized_packages/my-gh-freshrss-ssrf
Package id: my-gh-freshrss-feed-ssrf-lab
Upstream: FreshRSS/FreshRSS **1.29.1**
Risk family: **ssrf**
Expected disposition: **refute**
Trial: **2/0 refuted** (docs/hunter-ab-freshrss-ssrf-trial.{json,md})

## What this proves
- Third SSRF GitHub package (diversity beyond cal-ssrf + miniflux-ssrf).
- Engine maps outbound HTTP sinks (send_payload/fetch) to missing_ssrf_validation.
- Controls validateUrlForSSRF / isPrivateIP / isBlockedHostname refute via ssrf_validation_check.
- Complements authz-heavy portfolio without pure authz spam.

## Faithful upstream model
- Minz_Request::serverIsPublic: local DNS suffixes + RFC1918/loopback IPv4 + ULA/link-local IPv6; resolve-and-recheck
- FreshRSS_http_Util::checkUrl: absolute http(s) + FILTER_VALIDATE_URL
- FreshRSS_http_Util::httpGet: outbound curl fetch of feed URL after guards
- Feed path: FreshRSS_Feed uses checkUrl / httpGet residual

## Residual
See _extract/RESIDUAL_CHECKLIST.md FR-SSRF-R1..R5.

## Do not
- Attack third-party FreshRSS hosts
- Treat refute package as confirmed vuln
- Store secrets / real user data
- Re-probe H1 while 401
