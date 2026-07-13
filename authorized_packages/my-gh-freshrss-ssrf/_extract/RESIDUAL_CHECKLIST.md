# Residual checklist - my-gh-freshrss-ssrf (optional)

Static package trial expected **refute** (checkUrl + serverIsPublic present before httpGet).

| ID | Question | Static status |
| --- | --- | --- |
| FR-SSRF-R1 | Feed URL absolute http(s) before accept? | **held** (checkUrl / FILTER_VALIDATE_URL) |
| FR-SSRF-R2 | Private/loopback/LAN hosts blocked before fetch? | **held** (serverIsPublic IPv4/IPv6/local DNS) |
| FR-SSRF-R3 | Hostname resolve re-checked for non-public IP? | **held** (serverIsPublic resolveHostname recurse) |
| FR-SSRF-R4 | internal_host_allowlist / * disable residual? | **held_documented** (master-line SSRF allowlist residual; pin models default public check) |
| FR-SSRF-R5 | Proxy / curl_params residual? | **held_documented** (sanitizeCurlParams path; primary model is direct httpGet) |

Live residual: researcher-owned loopback only; no real third-party pivots.
