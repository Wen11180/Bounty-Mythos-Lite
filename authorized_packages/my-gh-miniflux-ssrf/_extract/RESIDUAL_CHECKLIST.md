# Residual checklist ? my-gh-miniflux-ssrf (optional)

Static package trial expected **refute** (IsNonPublicIP / BlockPrivateNetworks present before fetch).

| ID | Question | Static status |
| --- | --- | --- |
| MF-SSRF-R1 | Feed URL absolute http(s) before accept? | **held** (IsAbsoluteURL in feed validator) |
| MF-SSRF-R2 | Non-public IPs blocked at connect time? | **held** (IsNonPublicIP + DialContext) |
| MF-SSRF-R3 | DNS rebinding TOCTOU mitigated by dial-time check? | **held** (client.go comment + Control dial) |
| MF-SSRF-R4 | FetcherAllowPrivateNetworks opt-in residual? | **held_documented** (operator config residual; default block) |
| MF-SSRF-R5 | Feed proxy URL path residual? | **held_documented** (proxy must still be valid absolute URL; static model primary path is direct fetch) |

Live residual: researcher-owned loopback only; no real third-party pivots.
