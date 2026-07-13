# Residual checklist — my-gh-cal-ssrf (optional)

Static package trial expected **refute** (validateUrlForSSRF present before fetch).

| ID | Question | Static status |
| --- | --- | --- |
| CAL-SSRF-R1 | subscriberUrl validated before outbound fetch? | **held** (validateUrlForSSRF) |
| CAL-SSRF-R2 | cloud metadata hosts blocked always? | **held** (isBlockedHostname model) |
| CAL-SSRF-R3 | private IP blocked on SaaS path? | **held** (isPrivateIP model) |
| CAL-SSRF-R4 | self-hosted allows private HTTP? | **held_documented** residual (not product bug) |
| CAL-SSRF-R5 | DNS rebinding async resolve residual? | **held_documented** (async validateUrlForSSRF) |

Live residual: researcher-owned loopback only; no real third-party pivots.
