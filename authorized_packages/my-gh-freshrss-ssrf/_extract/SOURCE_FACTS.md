# Source facts - my-gh-freshrss-ssrf

- Upstream: FreshRSS/FreshRSS **1.29.1**
- Primary control: `Minz_Request::serverIsPublic` (local DNS suffixes + RFC1918/loopback IPv4 + ULA/link-local IPv6; resolve-and-recheck)
- URL accept: `FreshRSS_http_Util::checkUrl` absolute http(s) + FILTER_VALIDATE_URL
- Outbound sink: `FreshRSS_http_Util::httpGet` (curl) of user-controlled feed URL
- Feed path: `FreshRSS_Feed` uses checkUrl / httpGet for load/create residual
- Package models validation-before-fetch for expected **refute**
